package authz_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
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

func TestStorageSchemaDescriptorsByDialect(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name      string
		dialect   authz.StorageDialect
		idType    string
		valueType string
	}{
		{name: "postgres", dialect: authz.StorageDialectPostgres, idType: "bigint", valueType: "varchar(512)"},
		{name: "sqlite", dialect: authz.StorageDialectSQLite, idType: "integer", valueType: "text"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := authz.StorageSchemaForDialect(tt.dialect, "authz_policy")
			if err != nil {
				t.Fatalf("StorageSchemaForDialect(): %v", err)
			}
			want := expectedStorageDescriptor(tt.dialect, "authz_policy", tt.idType, tt.valueType)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("StorageSchemaForDialect() =\n%#v\nwant\n%#v", got, want)
			}
		})
	}

	postgres, err := authz.StorageSchemaForDialect(authz.StorageDialectPostgres, "authz_policy")
	if err != nil {
		t.Fatalf("postgres descriptor: %v", err)
	}
	if got := authz.StorageSchema("authz_policy"); !reflect.DeepEqual(got, postgres) {
		t.Fatalf("legacy StorageSchema() = %#v, want PostgreSQL descriptor %#v", got, postgres)
	}

	if _, err := authz.StorageSchemaForDialect(authz.StorageDialect("mysql"), "authz_policy"); err == nil || err.Error() != "authz storage schema v1 dialect" {
		t.Fatalf("MySQL descriptor error = %v, want sanitized dialect rejection", err)
	}
}

func expectedStorageDescriptor(dialect authz.StorageDialect, table, idType, valueType string) authz.StorageDescriptor {
	return authz.StorageDescriptor{
		Version: authz.StorageSchemaVersion,
		Dialect: dialect,
		Table:   table,
		Columns: []authz.StorageColumn{
			{Name: "id", Type: idType, Nullable: false},
			{Name: "ptype", Type: valueType, Nullable: false},
			{Name: "v0", Type: valueType, Nullable: false},
			{Name: "v1", Type: valueType, Nullable: false},
			{Name: "v2", Type: valueType, Nullable: false},
			{Name: "v3", Type: valueType, Nullable: false},
			{Name: "v4", Type: valueType, Nullable: false},
			{Name: "v5", Type: valueType, Nullable: false},
		},
		PrimaryKey: []string{"id"},
		UniqueIndexes: []authz.StorageIndex{
			{Name: "uidx_authz_policy", Columns: []string{"ptype", "v0", "v1", "v2", "v3", "v4", "v5"}},
		},
	}
}

func TestStoragePublicTypesOwnedByAuthz(t *testing.T) {
	t.Parallel()

	const wantPackage = "github.com/GoCodeAlone/workflow-plugin-authz/authz"
	for name, typ := range map[string]reflect.Type{
		"MigrationMode":     reflect.TypeOf(authz.MigrationMode("")),
		"StorageColumn":     reflect.TypeOf(authz.StorageColumn{}),
		"StorageIndex":      reflect.TypeOf(authz.StorageIndex{}),
		"StorageDescriptor": reflect.TypeOf(authz.StorageDescriptor{}),
	} {
		if typ.PkgPath() != wantPackage {
			t.Errorf("%s package = %q, want %q", name, typ.PkgPath(), wantPackage)
		}
	}
	if _, ok := reflect.TypeOf(authz.StorageDescriptor{}).FieldByName("Dialect"); !ok {
		t.Error("StorageDescriptor is missing its physical dialect")
	}
}

func TestValidateStorageAcceptsExactSchemaWithoutDDL(t *testing.T) {
	t.Parallel()

	descriptor := authz.StorageSchema("authz_policy")
	fixture := exactStorageFixture(descriptor)
	fixture.indexes = append(fixture.indexes,
		&fixtureIndex{name: "authz_policy_pkey", columns: []string{"id"}, unique: true, primaryKey: true, metadataKnown: true},
		&fixtureIndex{name: "idx_non_unique", columns: []string{"v0"}, metadataKnown: true},
	)
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
		{name: "extra unique index", category: "unique index", mutate: func(f *storageFixture) {
			f.indexes = append(f.indexes, &fixtureIndex{name: "uidx_extra", columns: []string{"v0"}, unique: true, metadataKnown: true})
		}},
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

func TestValidateStorageRejectsUnsupportedDialectBeforeInspection(t *testing.T) {
	t.Parallel()

	descriptor := authz.StorageSchema("authz_policy")
	fixture := exactStorageFixture(descriptor)
	db := openStorageFixtureDialect(t, fixture, "mysql")

	err := authz.ValidateStorage(t.Context(), db, descriptor.Table)
	assertStorageError(t, err, "dialect")
	if fixture.readCalls != 0 || fixture.ddlCalls != 0 {
		t.Fatalf("unsupported dialect performed reads=%d DDL=%d", fixture.readCalls, fixture.ddlCalls)
	}
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
	readCalls   int
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

func (f *storageFixture) HasTable(any) bool {
	f.readCalls++
	return f.tableExists
}

func (f *storageFixture) ColumnTypes(any) ([]gorm.ColumnType, error) {
	f.readCalls++
	return f.columns, f.columnErr
}

func (f *storageFixture) GetIndexes(any) ([]gorm.Index, error) {
	f.readCalls++
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
	primaryKey    bool
	metadataKnown bool
}

func (i *fixtureIndex) Name() string { return i.name }

func (i *fixtureIndex) Columns() []string { return i.columns }

func (i *fixtureIndex) Unique() (bool, bool) { return i.unique, i.metadataKnown }

func (i *fixtureIndex) PrimaryKey() (bool, bool) { return i.primaryKey, i.metadataKnown }

type fixtureDialector struct {
	gorm.Dialector
	fixture *storageFixture
	name    string
}

func (d *fixtureDialector) Name() string { return d.name }

func (d *fixtureDialector) Initialize(*gorm.DB) error { return nil }

func (d *fixtureDialector) Migrator(*gorm.DB) gorm.Migrator { return d.fixture }

func openStorageFixture(t *testing.T, fixture *storageFixture) *gorm.DB {
	return openStorageFixtureDialect(t, fixture, "postgres")
}

func openStorageFixtureDialect(t *testing.T, fixture *storageFixture, dialect string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(&fixtureDialector{fixture: fixture, name: dialect}, &gorm.Config{DisableAutomaticPing: true})
	if err != nil {
		t.Fatalf("open GORM storage fixture: %v", err)
	}
	return db
}
