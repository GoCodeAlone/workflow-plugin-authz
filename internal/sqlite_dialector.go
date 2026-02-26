package internal

// sqliteDialector is a minimal GORM dialector that opens a modernc.org/sqlite
// database via database/sql, avoiding the double-registration conflict between
// gorm.io/driver/sqlite and modernc.org/sqlite.

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // registers "sqlite" driver

	"gorm.io/gorm"
	"gorm.io/gorm/callbacks"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/migrator"
	"gorm.io/gorm/schema"
)

type sqliteDialector struct {
	dsn string
}

func openSQLite(dsn string) gorm.Dialector {
	return &sqliteDialector{dsn: dsn}
}

func (d *sqliteDialector) Name() string { return "sqlite" }

func (d *sqliteDialector) Initialize(db *gorm.DB) error {
	sqlDB, err := sql.Open("sqlite", d.dsn)
	if err != nil {
		return fmt.Errorf("sqlite open %q: %w", d.dsn, err)
	}

	// Enable WAL mode for better concurrency.
	if _, err := sqlDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		sqlDB.Close()
		return fmt.Errorf("sqlite WAL pragma: %w", err)
	}

	db.ConnPool = sqlDB

	callbacks.RegisterDefaultCallbacks(db, &callbacks.Config{
		CreateClauses: []string{"INSERT", "VALUES", "ON CONFLICT"},
		UpdateClauses: []string{"UPDATE", "SET", "FROM", "WHERE"},
		DeleteClauses: []string{"DELETE", "FROM", "WHERE"},
		QueryClauses:  []string{"SELECT", "FROM", "WHERE", "GROUP BY", "ORDER BY", "LIMIT", "FOR"},
	})

	for k, v := range d.ClauseBuilders() {
		db.ClauseBuilders[k] = v
	}

	return nil
}

func (d *sqliteDialector) ClauseBuilders() map[string]clause.ClauseBuilder {
	return map[string]clause.ClauseBuilder{}
}

func (d *sqliteDialector) DefaultValueOf(field *schema.Field) clause.Expression {
	return clause.Expr{SQL: "NULL"}
}

func (d *sqliteDialector) Migrator(db *gorm.DB) gorm.Migrator {
	return migrator.Migrator{Config: migrator.Config{
		DB:                          db,
		Dialector:                   d,
		CreateIndexAfterCreateTable: true,
	}}
}

func (d *sqliteDialector) BindVarTo(writer clause.Writer, stmt *gorm.Statement, v interface{}) {
	writer.WriteByte('?')
}

func (d *sqliteDialector) QuoteTo(writer clause.Writer, str string) {
	writer.WriteByte('`')
	writer.WriteString(str)
	writer.WriteByte('`')
}

func (d *sqliteDialector) DataTypeOf(field *schema.Field) string {
	switch field.DataType {
	case schema.Bool:
		return "numeric"
	case schema.Int, schema.Uint:
		if field.AutoIncrement {
			return "integer"
		}
		return "integer"
	case schema.Float:
		return "real"
	case schema.String:
		return "text"
	case schema.Time:
		return "datetime"
	case schema.Bytes:
		return "blob"
	default:
		return "text"
	}
}

func (d *sqliteDialector) Explain(sql string, vars ...interface{}) string {
	return logger.ExplainSQL(sql, nil, `"`, vars...)
}

func (d *sqliteDialector) SavePoint(tx *gorm.DB, name string) error {
	return tx.Exec("SAVEPOINT " + name).Error
}

func (d *sqliteDialector) RollbackTo(tx *gorm.DB, name string) error {
	return tx.Exec("ROLLBACK TO SAVEPOINT " + name).Error
}
