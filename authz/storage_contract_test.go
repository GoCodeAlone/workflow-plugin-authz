package authz_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-authz/authz"
	"github.com/GoCodeAlone/workflow-plugin-authz/internal/contracts"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"
)

func TestMigrationModeDecodeDefaultsOnlyWhenAbsent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     map[string]any
		want    authz.MigrationMode
		wantErr string
	}{
		{name: "nil map", want: authz.MigrationModeAuto},
		{name: "absent", raw: map[string]any{}, want: authz.MigrationModeAuto},
		{name: "auto", raw: map[string]any{"migration_mode": "auto"}, want: authz.MigrationModeAuto},
		{name: "validate", raw: map[string]any{"migration_mode": "validate"}, want: authz.MigrationModeValidate},
		{name: "empty present", raw: map[string]any{"migration_mode": ""}, wantErr: "migration_mode"},
		{name: "unknown", raw: map[string]any{"migration_mode": "repair"}, wantErr: "migration_mode"},
		{name: "wrong raw type", raw: map[string]any{"migration_mode": 1}, wantErr: "migration_mode"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := authz.DecodeMigrationMode(tt.raw)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("DecodeMigrationMode() error = %v, want category %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeMigrationMode() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("DecodeMigrationMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMigrationModeTypedStorageRequiresExplicitValue(t *testing.T) {
	t.Parallel()

	for _, mode := range []authz.MigrationMode{"", "repair"} {
		cfg := authz.RuntimeConfig{Storage: &authz.StorageConfig{MigrationMode: mode}}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "migration mode") {
			t.Fatalf("RuntimeConfig.Validate() with mode %q error = %v, want migration mode category", mode, err)
		}
	}

	for _, mode := range []authz.MigrationMode{authz.MigrationModeAuto, authz.MigrationModeValidate} {
		cfg := authz.RuntimeConfig{Storage: &authz.StorageConfig{MigrationMode: mode}}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("RuntimeConfig.Validate() with mode %q: %v", mode, err)
		}
	}
}

func TestLegacyAdapterConfigProtobufCompatibility(t *testing.T) {
	t.Parallel()

	// Serialized by the v0.5.13 AdapterConfig before migration_mode existed.
	legacy, err := hex.DecodeString("0a04676f726d1a08706f737467726573221f706f7374677265733a2f2f6c65676163792e6578616d706c652f617574687a2a0c617574687a5f706f6c696379")
	if err != nil {
		t.Fatalf("decode golden: %v", err)
	}

	var cfg contracts.AdapterConfig
	if err := proto.Unmarshal(legacy, &cfg); err != nil {
		t.Fatalf("unmarshal legacy AdapterConfig: %v", err)
	}
	if cfg.GetType() != "gorm" || cfg.GetDriver() != "postgres" || cfg.GetDsn() != "postgres://legacy.example/authz" || cfg.GetTableName() != "authz_policy" {
		t.Fatalf("legacy AdapterConfig changed: %+v", &cfg)
	}
	if cfg.GetMigrationMode() != "" {
		t.Fatalf("legacy migration_mode = %q, want absent", cfg.GetMigrationMode())
	}

	mode, err := authz.DecodeMigrationMode(nil)
	if err != nil {
		t.Fatalf("default legacy migration mode: %v", err)
	}
	if mode != authz.MigrationModeAuto {
		t.Fatalf("legacy migration mode = %q, want %q", mode, authz.MigrationModeAuto)
	}

	roundTrip, err := proto.Marshal(&cfg)
	if err != nil {
		t.Fatalf("marshal legacy AdapterConfig: %v", err)
	}
	if !bytes.Equal(roundTrip, legacy) {
		t.Fatalf("legacy wire bytes changed:\n got  %x\n want %x", roundTrip, legacy)
	}
}

func TestStorageSchemaDescriptorIsPublished(t *testing.T) {
	t.Parallel()

	descriptor := authz.StorageSchema("")
	if authz.StorageSchemaVersion < 1 || descriptor.Version != authz.StorageSchemaVersion {
		t.Fatalf("storage schema version = %d / %d, want matching published version", descriptor.Version, authz.StorageSchemaVersion)
	}
	if descriptor.Table != "casbin_rule" {
		t.Fatalf("default table = %q, want casbin_rule", descriptor.Table)
	}

	wantColumns := []string{"id", "ptype", "v0", "v1", "v2", "v3", "v4", "v5"}
	if len(descriptor.Columns) != len(wantColumns) {
		t.Fatalf("columns = %+v, want %v", descriptor.Columns, wantColumns)
	}
	for i, want := range wantColumns {
		if descriptor.Columns[i].Name != want {
			t.Fatalf("columns[%d] = %q, want %q", i, descriptor.Columns[i].Name, want)
		}
	}
	if len(descriptor.PrimaryKey) != 1 || descriptor.PrimaryKey[0] != "id" {
		t.Fatalf("primary key = %v, want [id]", descriptor.PrimaryKey)
	}
	if len(descriptor.UniqueIndexes) != 1 {
		t.Fatalf("unique indexes = %+v, want one", descriptor.UniqueIndexes)
	}
	if got := descriptor.UniqueIndexes[0].Columns; !slices.Equal(got, []string{"ptype", "v0", "v1", "v2", "v3", "v4", "v5"}) {
		t.Fatalf("unique index columns = %v", got)
	}
}

func TestValidateStorageAcceptsExactSchemaWithoutDDL(t *testing.T) {
	t.Parallel()

	descriptor := authz.StorageSchema("authz_policy")
	fixture := exactStorageFixture(descriptor)
	db := openStorageFixture(t, fixture)

	if err := authz.ValidateStorage(t.Context(), db, descriptor.Table); err != nil {
		t.Fatalf("ValidateStorage() error = %v", err)
	}
	if fixture.ddlCalls != 0 {
		t.Fatalf("ValidateStorage() executed %d DDL operation(s)", fixture.ddlCalls)
	}
}

func TestValidateStorageRejectsSchemaDriftByCategory(t *testing.T) {
	t.Parallel()

	descriptor := authz.StorageSchema("authz_policy")
	tests := []struct {
		name     string
		category string
		mutate   func(*storageFixture)
	}{
		{name: "missing table", category: "table", mutate: func(f *storageFixture) { f.tableExists = false }},
		{name: "missing column", category: "columns", mutate: func(f *storageFixture) { f.columns = f.columns[:len(f.columns)-1] }},
		{name: "wrong column type", category: "types", mutate: func(f *storageFixture) { f.columns[7].(*fixtureColumn).columnType = "jsonb" }},
		{name: "wrong nullability", category: "nullability", mutate: func(f *storageFixture) { f.columns[7].(*fixtureColumn).nullable = true }},
		{name: "wrong primary key", category: "primary key", mutate: func(f *storageFixture) { f.columns[0].(*fixtureColumn).primaryKey = false }},
		{name: "missing unique index", category: "unique index", mutate: func(f *storageFixture) { f.indexes = nil }},
		{name: "non unique index", category: "unique index", mutate: func(f *storageFixture) { f.indexes[0].(*fixtureIndex).unique = false }},
		{name: "wrong unique index", category: "unique index", mutate: func(f *storageFixture) { f.indexes[0].(*fixtureIndex).columns = []string{"ptype", "v0"} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixture := exactStorageFixture(descriptor)
			tt.mutate(fixture)
			db := openStorageFixture(t, fixture)

			err := authz.ValidateStorage(t.Context(), db, descriptor.Table)
			assertStorageError(t, err, tt.category)
			if fixture.ddlCalls != 0 {
				t.Fatalf("ValidateStorage() executed %d DDL operation(s)", fixture.ddlCalls)
			}
		})
	}
}

func TestValidateStorageSanitizesInspectionErrors(t *testing.T) {
	t.Parallel()

	descriptor := authz.StorageSchema("authz_policy")
	fixture := exactStorageFixture(descriptor)
	fixture.columnErr = errors.New("SELECT RAW_SQL_SECRET FROM postgres://secret-dsn")
	db := openStorageFixture(t, fixture)

	err := authz.ValidateStorage(t.Context(), db, descriptor.Table)
	assertStorageError(t, err, "columns")
}

func assertStorageError(t *testing.T, err error, category string) {
	t.Helper()
	if err == nil {
		t.Fatalf("ValidateStorage() error = nil, want %q category", category)
	}
	message := err.Error()
	want := fmt.Sprintf("authz storage schema v%d %s", authz.StorageSchemaVersion, category)
	if message != want {
		t.Fatalf("ValidateStorage() error = %q, want exactly %q", message, want)
	}
	for _, secret := range []string{"authz_policy", "v5", "uidx_authz_policy", "secret-dsn", "RAW_SQL_SECRET", "SELECT ", "CREATE ", "ALTER ", "DROP "} {
		if strings.Contains(message, secret) {
			t.Fatalf("ValidateStorage() error leaked %q: %q", secret, message)
		}
	}
}

type storageFixture struct {
	gorm.Migrator
	tableExists bool
	columns     []gorm.ColumnType
	indexes     []gorm.Index
	columnErr   error
	indexErr    error
	ddlCalls    int
}

func exactStorageFixture(descriptor authz.StorageDescriptor) *storageFixture {
	fixture := &storageFixture{tableExists: true}
	for _, column := range descriptor.Columns {
		fixture.columns = append(fixture.columns, &fixtureColumn{
			name:          column.Name,
			columnType:    column.Type,
			nullable:      column.Nullable,
			primaryKey:    slices.Equal(descriptor.PrimaryKey, []string{column.Name}),
			metadataKnown: true,
		})
	}
	for _, index := range descriptor.UniqueIndexes {
		fixture.indexes = append(fixture.indexes, &fixtureIndex{
			name:          index.Name,
			columns:       append([]string(nil), index.Columns...),
			unique:        true,
			metadataKnown: true,
		})
	}
	return fixture
}

func (f *storageFixture) HasTable(any) bool { return f.tableExists }

func (f *storageFixture) ColumnTypes(any) ([]gorm.ColumnType, error) {
	return f.columns, f.columnErr
}

func (f *storageFixture) GetIndexes(any) ([]gorm.Index, error) {
	return f.indexes, f.indexErr
}

func (f *storageFixture) AutoMigrate(...any) error {
	f.ddlCalls++
	return errors.New("unexpected AutoMigrate")
}

func (f *storageFixture) CreateTable(...any) error {
	f.ddlCalls++
	return errors.New("unexpected CreateTable")
}

func (f *storageFixture) AddColumn(any, string) error {
	f.ddlCalls++
	return errors.New("unexpected AddColumn")
}

func (f *storageFixture) AlterColumn(any, string) error {
	f.ddlCalls++
	return errors.New("unexpected AlterColumn")
}

func (f *storageFixture) CreateIndex(any, string) error {
	f.ddlCalls++
	return errors.New("unexpected CreateIndex")
}

type fixtureColumn struct {
	columnTypeDefaults
	name          string
	columnType    string
	nullable      bool
	primaryKey    bool
	metadataKnown bool
}

type columnTypeDefaults interface {
	gorm.ColumnType
}

func (c *fixtureColumn) Name() string { return c.name }

func (c *fixtureColumn) DatabaseTypeName() string { return c.columnType }

func (c *fixtureColumn) ColumnType() (string, bool) { return c.columnType, c.metadataKnown }

func (c *fixtureColumn) Nullable() (bool, bool) { return c.nullable, c.metadataKnown }

func (c *fixtureColumn) PrimaryKey() (bool, bool) { return c.primaryKey, c.metadataKnown }

func (c *fixtureColumn) Length() (int64, bool) {
	if c.columnType == "varchar(512)" {
		return 512, true
	}
	return 0, false
}

type fixtureIndex struct {
	gorm.Index
	name          string
	columns       []string
	unique        bool
	metadataKnown bool
}

func (i *fixtureIndex) Name() string { return i.name }

func (i *fixtureIndex) Columns() []string { return i.columns }

func (i *fixtureIndex) Unique() (bool, bool) { return i.unique, i.metadataKnown }

type fixtureDialector struct {
	gorm.Dialector
	fixture *storageFixture
}

func (d *fixtureDialector) Name() string { return "storage-fixture" }

func (d *fixtureDialector) Initialize(*gorm.DB) error { return nil }

func (d *fixtureDialector) Migrator(*gorm.DB) gorm.Migrator { return d.fixture }

func openStorageFixture(t *testing.T, fixture *storageFixture) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(&fixtureDialector{fixture: fixture}, &gorm.Config{DisableAutomaticPing: true})
	if err != nil {
		t.Fatalf("open GORM storage fixture: %v", err)
	}
	return db
}
