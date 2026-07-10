package internal

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestMigrationModeProtobufFieldHasPresence(t *testing.T) {
	t.Parallel()

	field := (&contracts.AdapterConfig{}).ProtoReflect().Descriptor().Fields().ByName("migration_mode")
	if field == nil || !field.HasPresence() {
		t.Fatalf("migration_mode presence = %v, want proto3 optional presence", field != nil && field.HasPresence())
	}
}

func TestMigrationModeRawModuleRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		mode any
	}{
		{name: "unknown string", mode: "repair"},
		{name: "non string", mode: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := newCasbinModule("authz", migrationModuleConfig(":memory:", tt.mode, true))
			if err == nil || !strings.Contains(err.Error(), "migration_mode") {
				t.Fatalf("newCasbinModule() error = %v, want migration_mode rejection", err)
			}
		})
	}
}

func TestMigrationModeRawModuleDefaultsAbsentToAuto(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		mode    any
		present bool
	}{
		{name: "absent"},
		{name: "explicit auto", mode: "auto", present: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dsn := filepath.Join(t.TempDir(), "authz.db")
			module, err := newCasbinModule("authz", migrationModuleConfig(dsn, tt.mode, tt.present))
			if err != nil {
				t.Fatalf("newCasbinModule(): %v", err)
			}
			if err := module.Init(); err != nil {
				t.Fatalf("Init(): %v", err)
			}

			db := openMigrationTestDB(t, dsn)
			if !db.Migrator().HasTable("casbin_rule") || !db.Migrator().HasIndex("casbin_rule", "uidx_casbin_rule") {
				t.Fatal("auto migration did not create the required table and unique index")
			}
		})
	}
}

func TestMigrationModeValidateRejectsDriftWithoutDDL(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "authz.db")
	db := openMigrationTestDB(t, dsn)
	createMigrationSchema(t, db, false)
	before := migrationSchemaVersion(t, db)

	module, err := newCasbinModule("authz", migrationModuleConfig(dsn, "validate", true))
	if err != nil {
		t.Fatalf("newCasbinModule(): %v", err)
	}
	err = module.Init()
	const want = "authz storage schema v1 unique index"
	if err == nil || err.Error() != want {
		t.Fatalf("Init() error = %v, want exactly %q", err, want)
	}
	if after := migrationSchemaVersion(t, db); after != before {
		t.Fatalf("validate mode changed schema version from %d to %d", before, after)
	}
	if db.Migrator().HasIndex("casbin_rule", "uidx_casbin_rule") {
		t.Fatal("validate mode created the missing unique index")
	}
}

func TestMigrationModeValidateAcceptsExactSchemaWithoutDDL(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "authz.db")
	db := openMigrationTestDB(t, dsn)
	createMigrationSchema(t, db, true)
	before := migrationSchemaVersion(t, db)

	module, err := newCasbinModule("authz", migrationModuleConfig(dsn, "validate", true))
	if err != nil {
		t.Fatalf("newCasbinModule(): %v", err)
	}
	if err := module.Init(); err != nil {
		t.Fatalf("Init(): %v", err)
	}
	if after := migrationSchemaVersion(t, db); after != before {
		t.Fatalf("validate mode changed schema version from %d to %d", before, after)
	}
}

func TestMigrationModeTypedProtobufPropagation(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "authz.db")
	db := openMigrationTestDB(t, dsn)
	createMigrationSchema(t, db, false)
	before := migrationSchemaVersion(t, db)
	raw := casbinModuleConfigToMap(&contracts.CasbinModuleConfig{
		Model:   testModel,
		Adapter: adapterConfigWithMigrationWire(t, dsn, "validate"),
	})
	adapter, ok := raw["adapter"].(map[string]any)
	if !ok {
		t.Fatalf("typed adapter map = %#v", raw["adapter"])
	}
	if got := adapter["migration_mode"]; got != "validate" {
		t.Fatalf("typed migration_mode = %#v, want validate", got)
	}
	module, err := newCasbinModule("authz", raw)
	if err != nil {
		t.Fatalf("newCasbinModule(): %v", err)
	}
	if err := module.Init(); err == nil || err.Error() != "authz storage schema v1 unique index" {
		t.Fatalf("Init() error = %v, want typed validate-mode drift rejection", err)
	}
	if after := migrationSchemaVersion(t, db); after != before {
		t.Fatalf("typed validate mode changed schema version from %d to %d", before, after)
	}
}

func TestMigrationModeTypedProtobufPresentEmptyRejected(t *testing.T) {
	t.Parallel()

	raw := casbinModuleConfigToMap(&contracts.CasbinModuleConfig{
		Model:   testModel,
		Adapter: adapterConfigWithMigrationWire(t, ":memory:", ""),
	})
	_, err := newCasbinModule("authz", raw)
	if err == nil || !strings.Contains(err.Error(), "migration_mode") {
		t.Fatalf("newCasbinModule() error = %v, want present-empty migration_mode rejection", err)
	}
}

func TestMigrationModeTypedProtobufAbsentDefaultsToAuto(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "authz.db")
	raw := casbinModuleConfigToMap(&contracts.CasbinModuleConfig{
		Model: testModel,
		Adapter: &contracts.AdapterConfig{
			Type:   "gorm",
			Driver: "sqlite3",
			Dsn:    dsn,
		},
	})
	module, err := newCasbinModule("authz", raw)
	if err != nil {
		t.Fatalf("newCasbinModule(): %v", err)
	}
	if err := module.Init(); err != nil {
		t.Fatalf("Init(): %v", err)
	}

	db := openMigrationTestDB(t, dsn)
	if !db.Migrator().HasTable("casbin_rule") || !db.Migrator().HasIndex("casbin_rule", "uidx_casbin_rule") {
		t.Fatal("absent typed migration_mode did not preserve auto migration")
	}
}

func migrationModuleConfig(dsn string, mode any, present bool) map[string]any {
	adapter := map[string]any{
		"type":   "gorm",
		"driver": "sqlite3",
		"dsn":    dsn,
	}
	if present {
		adapter["migration_mode"] = mode
	}
	return map[string]any{
		"model":   testModel,
		"adapter": adapter,
	}
}

func adapterConfigWithMigrationWire(t *testing.T, dsn, mode string) *contracts.AdapterConfig {
	t.Helper()
	base, err := proto.Marshal(&contracts.AdapterConfig{
		Type:   "gorm",
		Driver: "sqlite3",
		Dsn:    dsn,
	})
	if err != nil {
		t.Fatalf("marshal typed adapter base: %v", err)
	}
	base = protowire.AppendTag(base, 9, protowire.BytesType)
	base = protowire.AppendString(base, mode)
	var adapter contracts.AdapterConfig
	if err := proto.Unmarshal(base, &adapter); err != nil {
		t.Fatalf("unmarshal typed adapter migration_mode: %v", err)
	}
	return &adapter
}

func openMigrationTestDB(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(openSQLite(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open migration test database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get migration test database: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

func createMigrationSchema(t *testing.T, db *gorm.DB, withIndex bool) {
	t.Helper()
	if err := db.Exec(`CREATE TABLE casbin_rule (
		id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
		ptype text NOT NULL,
		v0 text NOT NULL,
		v1 text NOT NULL,
		v2 text NOT NULL,
		v3 text NOT NULL,
		v4 text NOT NULL,
		v5 text NOT NULL
	)`).Error; err != nil {
		t.Fatalf("create migration table: %v", err)
	}
	if withIndex {
		if err := db.Exec("CREATE UNIQUE INDEX uidx_casbin_rule ON casbin_rule (ptype, v0, v1, v2, v3, v4, v5)").Error; err != nil {
			t.Fatalf("create migration index: %v", err)
		}
	}
}

func migrationSchemaVersion(t *testing.T, db *gorm.DB) int {
	t.Helper()
	var version int
	if err := db.Raw("PRAGMA schema_version").Scan(&version).Error; err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	return version
}
