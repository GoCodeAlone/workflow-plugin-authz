package internal

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
	workflowconfig "github.com/GoCodeAlone/workflow/config"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestMigrationModeProtobufFieldPreservesJSONKinds(t *testing.T) {
	t.Parallel()

	registry := NewAuthzPlugin().(sdk.ContractProvider).ContractRegistry()
	files, err := protodesc.NewFiles(registry.FileDescriptorSet)
	if err != nil {
		t.Fatalf("published descriptor set: %v", err)
	}
	adapter, err := files.FindDescriptorByName("workflow.plugins.authz.v1.AdapterConfig")
	if err != nil {
		t.Fatalf("published AdapterConfig descriptor: %v", err)
	}
	field := adapter.(protoreflect.MessageDescriptor).Fields().ByName("migration_mode")
	if field == nil || field.Kind() != protoreflect.MessageKind || field.Message().FullName() != "google.protobuf.Value" {
		t.Fatalf("migration_mode descriptor = %v, want google.protobuf.Value", field)
	}
}

func TestMigrationModeTypedFactoryValueBoundary(t *testing.T) {
	provider := NewAuthzPlugin().(sdk.TypedModuleProvider)

	for _, tt := range []struct {
		name      string
		present   bool
		value     any
		wantError bool
	}{
		{name: "absent"},
		{name: "explicit null", present: true, value: nil, wantError: true},
		{name: "auto", present: true, value: "auto"},
		{name: "validate", present: true, value: "validate"},
		{name: "empty string", present: true, value: "", wantError: true},
		{name: "unknown string", present: true, value: "repair", wantError: true},
		{name: "boolean", present: true, value: true, wantError: true},
		{name: "number", present: true, value: 1, wantError: true},
		{name: "object", present: true, value: map[string]any{"mode": "auto"}, wantError: true},
		{name: "list", present: true, value: []any{"auto"}, wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			adapter := map[string]any{"type": "gorm", "driver": "sqlite3", "dsn": ":memory:"}
			if tt.present {
				adapter["migration_mode"] = tt.value
			}
			raw, err := json.Marshal(map[string]any{"model": testModel, "adapter": adapter})
			if err != nil {
				t.Fatalf("marshal typed config: %v", err)
			}
			var cfg contracts.CasbinModuleConfig
			if err := protojson.Unmarshal(raw, &cfg); err != nil {
				t.Fatalf("protojson must preserve %s for plugin validation: %v", tt.name, err)
			}
			packed, err := anypb.New(&cfg)
			if err != nil {
				t.Fatalf("pack typed config: %v", err)
			}
			_, err = provider.CreateTypedModule("authz.casbin", "authz-"+strings.ReplaceAll(tt.name, " ", "-"), packed)
			if tt.wantError {
				if err == nil || !strings.Contains(err.Error(), "migration_mode") {
					t.Fatalf("CreateTypedModule() error = %v, want migration_mode rejection", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateTypedModule(): %v", err)
			}
		})
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

func TestMigrationModeRawWorkflowYAMLModuleBoundary(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name       string
		modeYAML   string
		want       MigrationMode
		wantReject bool
	}{
		{name: "absent", want: MigrationModeAuto},
		{name: "empty", modeYAML: "        migration_mode: \"\"\n", wantReject: true},
		{name: "null", modeYAML: "        migration_mode: null\n", wantReject: true},
		{name: "unknown", modeYAML: "        migration_mode: repair\n", wantReject: true},
		{name: "valid", modeYAML: "        migration_mode: validate\n", want: MigrationModeValidate},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := workflowconfig.LoadFromString("modules:\n  - name: authz\n    type: authz.casbin\n    config:\n      model: |\n" + indentYAML(testModel, 8) + "      adapter:\n        type: gorm\n        driver: sqlite3\n        dsn: ':memory:'\n" + tt.modeYAML)
			if err != nil {
				t.Fatalf("LoadFromString(): %v", err)
			}
			module, err := newCasbinModule("authz", cfg.Modules[0].Config)
			if tt.wantReject {
				if err == nil || !strings.Contains(err.Error(), "migration_mode") {
					t.Fatalf("newCasbinModule() error = %v, want raw Workflow migration_mode rejection", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("newCasbinModule(): %v", err)
			}
			if got := module.config.Adapter.MigrationMode; got != tt.want {
				t.Fatalf("migration mode = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMigrationModeRawWorkflowJSONModuleBoundary(t *testing.T) {
	t.Parallel()

	cfg, err := workflowconfig.LoadFromString(`{"modules":[{"name":"authz","type":"authz.casbin","config":{"model":"` + strings.ReplaceAll(testModel, "\n", `\n`) + `","adapter":{"type":"gorm","driver":"sqlite3","dsn":":memory:","migration_mode":null}}}]}`)
	if err != nil {
		t.Fatalf("LoadFromString(): %v", err)
	}
	_, err = newCasbinModule("authz", cfg.Modules[0].Config)
	if err == nil || !strings.Contains(err.Error(), "migration_mode") {
		t.Fatalf("newCasbinModule() error = %v, want raw Workflow JSON null rejection", err)
	}
}

func TestMigrationModeMySQLValidateRejectsDialectBeforeOpen(t *testing.T) {
	t.Parallel()

	for _, dsn := range []string{"", "RAW_DSN_SECRET"} {
		module, err := newCasbinModule("authz", map[string]any{
			"model": testModel,
			"adapter": map[string]any{
				"type":           "gorm",
				"driver":         "  MySQL  ",
				"dsn":            dsn,
				"migration_mode": "validate",
			},
		})
		if err != nil {
			t.Fatalf("newCasbinModule(): %v", err)
		}
		const want = "authz storage schema v1 dialect"
		if err := module.Init(); err == nil || err.Error() != want {
			t.Fatalf("Init() with DSN %q error = %v, want exactly %q before DSN validation or gorm.Open", dsn, err, want)
		}
	}
}

func TestMigrationModeMySQLAutoPreservesLegacyDSNValidation(t *testing.T) {
	t.Parallel()

	module, err := newCasbinModule("authz", map[string]any{
		"model": testModel,
		"adapter": map[string]any{
			"type":           "gorm",
			"driver":         "  MySQL  ",
			"migration_mode": "auto",
		},
	})
	if err != nil {
		t.Fatalf("newCasbinModule(): %v", err)
	}
	if err := module.Init(); err == nil || !strings.Contains(err.Error(), "adapter.dsn is required") {
		t.Fatalf("Init() error = %v, want legacy DSN validation", err)
	}
}

func indentYAML(value string, spaces int) string {
	prefix := strings.Repeat(" ", spaces)
	return prefix + strings.ReplaceAll(strings.TrimSuffix(value, "\n"), "\n", "\n"+prefix) + "\n"
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

func TestStorageSQLitePreservesAndRejectsPartialIndexes(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		setup func(*testing.T, *gorm.DB)
	}{
		{
			name: "required index is partial",
			setup: func(t *testing.T, db *gorm.DB) {
				createMigrationSchema(t, db, false)
				execMigrationSQL(t, db, "CREATE UNIQUE INDEX uidx_casbin_rule ON casbin_rule (ptype, v0, v1, v2, v3, v4, v5) WHERE v0 <> ''")
			},
		},
		{
			name: "extra unique index is partial",
			setup: func(t *testing.T, db *gorm.DB) {
				createMigrationSchema(t, db, true)
				execMigrationSQL(t, db, "CREATE UNIQUE INDEX uidx_extra_partial ON casbin_rule (v0) WHERE v0 <> ''")
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			db := openMigrationTestDB(t, filepath.Join(t.TempDir(), "authz.db"))
			tt.setup(t, db)

			indexes, err := db.Migrator().GetIndexes("casbin_rule")
			if err != nil {
				t.Fatalf("GetIndexes(): %v", err)
			}
			partialFound := false
			for _, index := range indexes {
				if index.Option() != "" {
					partialFound = true
				}
			}
			if !partialFound {
				t.Fatal("SQLite partial-index predicate metadata was discarded")
			}

			const want = "authz storage schema v1 unique index"
			if err := ValidateStorage(t.Context(), db, "casbin_rule"); err == nil || err.Error() != want {
				t.Fatalf("ValidateStorage() error = %v, want exactly %q", err, want)
			}
		})
	}
}

func execMigrationSQL(t *testing.T, db *gorm.DB, query string) {
	t.Helper()
	if err := db.Exec(query).Error; err != nil {
		t.Fatalf("execute migration fixture SQL: %v", err)
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
		Adapter: adapterConfigWithMigrationValue(t, dsn, "validate"),
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
		Adapter: adapterConfigWithMigrationValue(t, ":memory:", ""),
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

func adapterConfigWithMigrationValue(t *testing.T, dsn, mode string) *contracts.AdapterConfig {
	t.Helper()
	return &contracts.AdapterConfig{
		Type:          "gorm",
		Driver:        "sqlite3",
		Dsn:           dsn,
		MigrationMode: structpb.NewStringValue(mode),
	}
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
