package internal

// gormCasbinAdapter is a minimal casbin persist.Adapter backed by gorm.
// It replaces casbin/gorm-adapter/v3 to avoid the duplicate sqlite driver
// registration conflict between glebarez/go-sqlite and modernc.org/sqlite.

import (
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"gorm.io/gorm"
)

// casbinRule mirrors the table schema used by the upstream gorm-adapter.
type casbinRule struct {
	ID    uint   `gorm:"primarykey;autoIncrement"`
	Ptype string `gorm:"size:512;uniqueIndex:unique_index"`
	V0    string `gorm:"size:512;uniqueIndex:unique_index"`
	V1    string `gorm:"size:512;uniqueIndex:unique_index"`
	V2    string `gorm:"size:512;uniqueIndex:unique_index"`
	V3    string `gorm:"size:512;uniqueIndex:unique_index"`
	V4    string `gorm:"size:512;uniqueIndex:unique_index"`
	V5    string `gorm:"size:512;uniqueIndex:unique_index"`
}

// TableName returns the gorm table name.
func (casbinRule) TableName() string { return "casbin_rule" }

// gormAdapter implements persist.Adapter using a gorm.DB.
type gormAdapter struct {
	db        *gorm.DB
	tableName string
}

// newGORMAdapter auto-migrates the casbin_rule table and returns an adapter.
func newGORMAdapter(db *gorm.DB, tableName string) (*gormAdapter, error) {
	if tableName == "" {
		tableName = "casbin_rule"
	}
	if err := db.AutoMigrate(&casbinRule{}); err != nil {
		return nil, fmt.Errorf("gorm casbin adapter: migrate: %w", err)
	}
	return &gormAdapter{db: db, tableName: tableName}, nil
}

// LoadPolicy loads all policies from the database into the model.
func (a *gormAdapter) LoadPolicy(mdl model.Model) error {
	var rules []casbinRule
	if err := a.db.Find(&rules).Error; err != nil {
		return err
	}
	for _, rule := range rules {
		persist.LoadPolicyLine(ruleToLine(rule), mdl)
	}
	return nil
}

// SavePolicy saves all policies from the model into the database.
func (a *gormAdapter) SavePolicy(mdl model.Model) error {
	if err := a.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&casbinRule{}).Error; err != nil {
		return err
	}
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
	if len(rules) > 0 {
		return a.db.CreateInBatches(rules, 100).Error
	}
	return nil
}

// AddPolicy adds a policy rule to the database.
func (a *gormAdapter) AddPolicy(sec, ptype string, rule []string) error {
	r := lineToRule(ptype, rule)
	return a.db.Create(&r).Error
}

// RemovePolicy removes a policy rule from the database.
func (a *gormAdapter) RemovePolicy(sec, ptype string, rule []string) error {
	r := lineToRule(ptype, rule)
	return a.db.Where(&r).Delete(&casbinRule{}).Error
}

// RemoveFilteredPolicy removes policy rules matching the given filter.
func (a *gormAdapter) RemoveFilteredPolicy(sec, ptype string, fieldIndex int, fieldValues ...string) error {
	query := a.db.Where("ptype = ?", ptype)
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

// Compile-time interface check.
var _ persist.Adapter = (*gormAdapter)(nil)
