package internal

// gormCasbinAdapter is a minimal casbin persist.Adapter backed by gorm.
// It replaces casbin/gorm-adapter/v3 to avoid the duplicate sqlite driver
// registration conflict between glebarez/go-sqlite and modernc.org/sqlite.
//
// Option A – tenant filter: construct the adapter with a filterField / filterValue
// to apply a WHERE clause on every LoadPolicy call, isolating one tenant's rows.
//
// Option B – per-tenant table: pass a resolved table name (e.g. "casbin_rule_acme")
// so each tenant's policies live in a dedicated table.

import (
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// identWriter wraps strings.Builder to satisfy clause.Writer (which requires
// both WriteString and WriteByte).  It is used to invoke dialector.QuoteTo so
// that identifier quoting is database-specific (backticks for MySQL/SQLite,
// double-quotes for PostgreSQL).
type identWriter struct{ strings.Builder }

func (w *identWriter) WriteByte(b byte) error { return w.Builder.WriteByte(b) }

// quoteIdent returns name quoted as an identifier using the dialector's own
// quoting rules, making SQL safe to use on MySQL, PostgreSQL and SQLite.
func quoteIdent(db *gorm.DB, name string) string {
	var w identWriter
	db.Dialector.QuoteTo(&w, name)
	return w.String()
}

// validFilterFields is the set of column names allowed in a filter to prevent
// SQL injection when building dynamic WHERE clauses.
var validFilterFields = map[string]bool{
	"v0": true, "v1": true, "v2": true,
	"v3": true, "v4": true, "v5": true,
}

// GORMFilter specifies a WHERE clause for tenant-scoped policy loading.
// It is the concrete filter type accepted by gormAdapter.LoadFilteredPolicy.
type GORMFilter struct {
	// Field is the column name to filter on (one of "v0" through "v5").
	Field string
	// Value is the value the column must equal.
	Value string
}

// casbinRule mirrors the table schema used by the upstream gorm-adapter.
// The composite uniqueness constraint is NOT declared in the struct tags because
// GORM uses the literal tag name as the index name (e.g. "unique_index"), which
// conflicts in SQLite's global index namespace when multiple tenant tables are
// created from the same struct.  The index is instead created by migrateTable
// with a per-table name ("uidx_<tableName>").
type casbinRule struct {
	ID    uint   `gorm:"primarykey;autoIncrement"`
	Ptype string `gorm:"size:512"`
	V0    string `gorm:"size:512"`
	V1    string `gorm:"size:512"`
	V2    string `gorm:"size:512"`
	V3    string `gorm:"size:512"`
	V4    string `gorm:"size:512"`
	V5    string `gorm:"size:512"`
}

// TableName returns the default gorm table name.
// When a custom table name is needed the caller uses db.Table(name) explicitly.
func (casbinRule) TableName() string { return "casbin_rule" }

// gormAdapter implements persist.FilteredAdapter using a gorm.DB.
// When filterField/filterValue are non-empty all load/save operations are
// scoped to rows where filterField = filterValue (Option A).
// The tableName field enables per-tenant tables (Option B).
//
// FilteredAdapter contract (Casbin v2):
//   - IsFiltered() must return false before the first LoadPolicy call so that
//     NewEnforcer will call LoadPolicy during initialisation.
//   - IsFiltered() returns true once a filtered load has been performed, which
//     tells the Casbin enforcer not to allow a bulk SavePolicy.
//   - The filter is applied automatically inside LoadPolicy when filterField /
//     filterValue are configured, so callers need not use LoadFilteredPolicy.
type gormAdapter struct {
	db          *gorm.DB
	tableName   string
	filterField string // Option A: column name (e.g. "v0"); empty = no filter
	filterValue string // Option A: value to match
	filtered    bool   // true after the first filtered LoadPolicy; starts false
}

// validTableNameRune returns true when ch is allowed in a table name used as a
// raw SQL identifier.  Only ASCII letters, digits, underscores and hyphens are
// accepted; this prevents characters that could break %q SQL quoting.
func validTableNameRune(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '_' || ch == '-'
}

// table returns a *gorm.DB scoped to the adapter's table name.
func (a *gormAdapter) table() *gorm.DB {
	return a.db.Table(a.tableName)
}

// newGORMAdapter auto-migrates the table and returns an adapter.
// filterField and filterValue implement Option A (tenant-scoped WHERE clause).
// Pass empty strings to disable filtering.
func newGORMAdapter(db *gorm.DB, tableName, filterField, filterValue string) (*gormAdapter, error) {
	if tableName == "" {
		tableName = "casbin_rule"
	}
	// Validate tableName to prevent SQL injection via the raw CREATE INDEX SQL
	// constructed in migrateTable.  Only allow characters that are safe to use
	// inside a double-quoted SQL identifier without additional escaping.
	for _, ch := range tableName {
		if !validTableNameRune(ch) {
			return nil, fmt.Errorf("gorm casbin adapter: invalid character %q in table name %q", ch, tableName)
		}
	}
	if filterField != "" && !validFilterFields[filterField] {
		return nil, fmt.Errorf("gorm casbin adapter: invalid filter_field %q (must be v0-v5)", filterField)
	}
	// filterField and filterValue must be set together; partial configuration is
	// ambiguous and would silently skip filtering while looking like it is enabled.
	if (filterField == "") != (filterValue == "") {
		return nil, fmt.Errorf("gorm casbin adapter: filter_field and filter_value must both be set or both be empty")
	}
	if err := migrateTable(db, tableName); err != nil {
		return nil, fmt.Errorf("gorm casbin adapter: migrate: %w", err)
	}
	return &gormAdapter{
		db:          db,
		tableName:   tableName,
		filterField: filterField,
		filterValue: filterValue,
	}, nil
}

// migrateTable creates the casbin rule table for tableName.
//
// The composite unique constraint is created as a named index "uidx_<tableName>"
// rather than via struct tags so that each tenant table gets its own index name.
// This avoids SQLite's flat index namespace where two tables migrated from the
// same struct with the same named index tag would conflict.
//
// On SQLite, AutoMigrate is skipped when the table already exists because the
// generic GORM migrator's HasColumn falls back to information_schema (which does
// not exist in SQLite), causing unintended ALTER TABLE attempts.  On PostgreSQL
// and MySQL, AutoMigrate always runs so that schema drift is corrected.
func migrateTable(db *gorm.DB, tableName string) error {
	isSQLite := db.Dialector.Name() == "sqlite"
	tableExists := db.Migrator().HasTable(tableName)

	if !isSQLite || !tableExists {
		if err := db.Table(tableName).AutoMigrate(&casbinRule{}); err != nil {
			return err
		}
	}
	// Create a composite unique index with a per-table name.
	// We check for existence first so the operation is idempotent on all
	// supported databases (SQLite, PostgreSQL, MySQL).
	idxName := "uidx_" + strings.ReplaceAll(tableName, "-", "_")
	if db.Migrator().HasIndex(tableName, idxName) {
		return nil
	}
	// Use the dialector's identifier quoting so the SQL is correct for every
	// supported database: backticks on MySQL/SQLite, double-quotes on PostgreSQL.
	cols := []string{"ptype", "v0", "v1", "v2", "v3", "v4", "v5"}
	quotedCols := make([]string, len(cols))
	for i, c := range cols {
		quotedCols[i] = quoteIdent(db, c)
	}
	return db.Exec(fmt.Sprintf(
		"CREATE UNIQUE INDEX %s ON %s (%s)",
		quoteIdent(db, idxName),
		quoteIdent(db, tableName),
		strings.Join(quotedCols, ", "),
	)).Error
}

// IsFiltered returns true once a filtered LoadPolicy has been performed.
// Before the first load it returns false so that casbin.NewEnforcer will call
// LoadPolicy during initialisation (Casbin skips LoadPolicy when IsFiltered is
// true at construction time).
func (a *gormAdapter) IsFiltered() bool {
	return a.filtered
}

// LoadPolicy loads all (or filtered) policies from the database into the model.
// When filterField/filterValue are configured the WHERE clause is applied and
// filtered is set to true so that subsequent SavePolicy calls are scoped.
func (a *gormAdapter) LoadPolicy(mdl model.Model) error {
	if err := a.loadWithFilter(mdl, a.filterField, a.filterValue); err != nil {
		return err
	}
	if a.filterField != "" && a.filterValue != "" {
		a.filtered = true
	}
	return nil
}

// LoadFilteredPolicy loads only policies matching the supplied filter.
// filter must be a GORMFilter value.  On success the active filter is stored on
// the adapter so that subsequent SavePolicy calls are correctly scoped, and
// IsFiltered is set to true.
func (a *gormAdapter) LoadFilteredPolicy(mdl model.Model, filter interface{}) error {
	f, ok := filter.(GORMFilter)
	if !ok {
		return fmt.Errorf("gorm casbin adapter: LoadFilteredPolicy expects GORMFilter, got %T", filter)
	}
	if f.Field != "" && !validFilterFields[f.Field] {
		return fmt.Errorf("gorm casbin adapter: invalid filter field %q (must be v0-v5)", f.Field)
	}
	if err := a.loadWithFilter(mdl, f.Field, f.Value); err != nil {
		return err
	}
	// Persist the active filter so that subsequent SavePolicy calls can correctly
	// scope their operations.  When no effective filter was provided, clear any
	// previously stored filter to avoid inconsistent SavePolicy behavior.
	if f.Field != "" && f.Value != "" {
		a.filterField = f.Field
		a.filterValue = f.Value
		a.filtered = true
	} else {
		a.filterField = ""
		a.filterValue = ""
		a.filtered = false
	}
	return nil
}

// loadWithFilter is the shared implementation used by LoadPolicy and
// LoadFilteredPolicy.  field must be a pre-validated column name (v0-v5) or
// empty.  clause.Eq is used for the WHERE clause so that identifier quoting is
// handled by GORM's dialector, making it correct on MySQL, PostgreSQL and SQLite.
func (a *gormAdapter) loadWithFilter(mdl model.Model, field, value string) error {
	q := a.table()
	if field != "" && value != "" {
		q = q.Where(clause.Eq{Column: clause.Column{Name: field}, Value: value})
	}
	var rules []casbinRule
	if err := q.Find(&rules).Error; err != nil {
		return err
	}
	for _, rule := range rules {
		persist.LoadPolicyLine(ruleToLine(rule), mdl)
	}
	return nil
}

// SavePolicy saves all policies from the model into the database.
// When a tenant filter is active only the matching rows are replaced, so that
// other tenants' data is not affected.
func (a *gormAdapter) SavePolicy(mdl model.Model) error {
	var rules []casbinRule
	for ptype, assertions := range mdl["p"] {
		for _, assertion := range assertions.Policy {
			rules = append(rules, lineToRule(ptype, assertion))
		}
	}
	for ptype, assertions := range mdl["g"] {
		for _, assertion := range assertions.Policy {
			rules = append(rules, lineToRule(ptype, assertion))
		}
	}

	if a.IsFiltered() {
		// Delete only rows belonging to this tenant, then re-insert.
		if err := a.table().Where(clause.Eq{Column: clause.Column{Name: a.filterField}, Value: a.filterValue}).Delete(&casbinRule{}).Error; err != nil {
			return err
		}
	} else {
		// Delete all rows in the table.
		if err := a.table().Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&casbinRule{}).Error; err != nil {
			return err
		}
	}

	if len(rules) > 0 {
		return a.table().CreateInBatches(rules, 100).Error
	}
	return nil
}

// checkTenantScope returns an error when the adapter is in filtered mode and
// the rule's field at the filter index does not match filterValue.  This
// prevents accidental cross-tenant writes via AddPolicy / RemovePolicy.
func (a *gormAdapter) checkTenantScope(rule []string) error {
	if a.filterField == "" {
		return nil
	}
	// filterField is validated to be "v0"–"v5"; extract the numeric index.
	fieldIdx := int(a.filterField[1] - '0')
	if fieldIdx >= len(rule) {
		return fmt.Errorf("gorm casbin adapter: rule has %d field(s), filter requires %s", len(rule), a.filterField)
	}
	if rule[fieldIdx] != a.filterValue {
		return fmt.Errorf("gorm casbin adapter: rule %s=%q does not match tenant filter %s=%q; cross-tenant writes are not allowed",
			a.filterField, rule[fieldIdx], a.filterField, a.filterValue)
	}
	return nil
}

// AddPolicy adds a policy rule to the database.
// When a tenant filter is active the rule is validated to ensure it belongs to
// the configured tenant before being written.
func (a *gormAdapter) AddPolicy(sec, ptype string, rule []string) error {
	if err := a.checkTenantScope(rule); err != nil {
		return err
	}
	r := lineToRule(ptype, rule)
	return a.table().Create(&r).Error
}

// RemovePolicy removes a policy rule from the database.
// When a tenant filter is active the rule is validated to ensure it belongs to
// the configured tenant before deletion is attempted.
func (a *gormAdapter) RemovePolicy(sec, ptype string, rule []string) error {
	if err := a.checkTenantScope(rule); err != nil {
		return err
	}
	r := lineToRule(ptype, rule)
	return a.table().Where(&r).Delete(&casbinRule{}).Error
}

// RemoveFilteredPolicy removes policy rules matching the given filter.
func (a *gormAdapter) RemoveFilteredPolicy(sec, ptype string, fieldIndex int, fieldValues ...string) error {
	query := a.table().Where("ptype = ?", ptype)
	fields := []string{"v0", "v1", "v2", "v3", "v4", "v5"}
	for i, v := range fieldValues {
		if v != "" {
			col := fields[fieldIndex+i]
			query = query.Where(col+" = ?", v)
		}
	}
	return query.Delete(&casbinRule{}).Error
}

// ruleToLine converts a casbinRule row to a casbin policy line string.
func ruleToLine(rule casbinRule) string {
	parts := []string{rule.Ptype}
	for _, v := range []string{rule.V0, rule.V1, rule.V2, rule.V3, rule.V4, rule.V5} {
		if v == "" {
			break
		}
		parts = append(parts, v)
	}
	return strings.Join(parts, ", ")
}

// lineToRule converts a ptype + rule slice to a casbinRule row.
func lineToRule(ptype string, rule []string) casbinRule {
	r := casbinRule{Ptype: ptype}
	vs := []*string{&r.V0, &r.V1, &r.V2, &r.V3, &r.V4, &r.V5}
	for i, v := range rule {
		if i >= len(vs) {
			break
		}
		*vs[i] = v
	}
	return r
}

// Compile-time interface check – gormAdapter must satisfy FilteredAdapter
// (which is a superset of Adapter).
var _ persist.FilteredAdapter = (*gormAdapter)(nil)
