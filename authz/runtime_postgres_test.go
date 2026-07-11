package authz

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestRuntimeConstructionCancelsBlockedPolicyLoad(t *testing.T) {
	dsn := os.Getenv("AUTHZ_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_POSTGRES_DSN is not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open PostgreSQL fixture: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("fixture DB(): %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	table := fmt.Sprintf("authz_runtime_cancel_%d", time.Now().UnixNano())
	index := "uidx_" + table
	t.Cleanup(func() { _ = db.Exec("DROP TABLE IF EXISTS " + table).Error })
	if err := db.Exec(fmt.Sprintf(`CREATE TABLE %s (
		id bigserial PRIMARY KEY,
		ptype varchar(80) NOT NULL,
		v0 varchar(80) NOT NULL,
		v1 varchar(80) NOT NULL,
		v2 varchar(80) NOT NULL,
		v3 varchar(80) NOT NULL,
		v4 varchar(80) NOT NULL,
		v5 varchar(80) NOT NULL,
		CONSTRAINT %s UNIQUE (ptype, v0, v1, v2, v3, v4, v5)
	)`, table, index)).Error; err != nil {
		t.Fatalf("create runtime schema: %v", err)
	}

	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("begin lock transaction: %v", tx.Error)
	}
	if err := tx.Exec("LOCK TABLE " + table + " IN ACCESS EXCLUSIVE MODE").Error; err != nil {
		_ = tx.Rollback().Error
		t.Fatalf("lock runtime table: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 75*time.Millisecond)
	defer cancel()
	type result struct {
		runtime *Runtime
		err     error
	}
	resultCh := make(chan result, 1)
	go func() {
		runtime, err := NewRuntime(ctx, RuntimeConfig{
			Model: runtimeTestModel,
			Storage: &StorageConfig{
				Driver:        "postgres",
				DSN:           dsn,
				TableName:     table,
				MigrationMode: MigrationModeValidate,
			},
		})
		resultCh <- result{runtime: runtime, err: err}
	}()

	var got result
	completedBeforeUnlock := false
	select {
	case got = <-resultCh:
		completedBeforeUnlock = true
	case <-time.After(250 * time.Millisecond):
	}
	if err := tx.Rollback().Error; err != nil {
		t.Fatalf("release runtime table lock: %v", err)
	}
	if !completedBeforeUnlock {
		got = <-resultCh
	}
	if got.runtime != nil {
		_ = got.runtime.Close()
	}
	if !completedBeforeUnlock || !errors.Is(got.err, context.DeadlineExceeded) {
		t.Fatalf("NewRuntime() completed before unlock=%v error=%v, want prompt deadline cancellation", completedBeforeUnlock, got.err)
	}
}

func TestRuntimePostgresRestart(t *testing.T) {
	dsn := os.Getenv("AUTHZ_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_POSTGRES_DSN is not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open PostgreSQL fixture: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("fixture DB(): %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	table := fmt.Sprintf("authz_runtime_%d", time.Now().UnixNano())
	index := "uidx_" + table
	t.Cleanup(func() { _ = db.Exec("DROP TABLE IF EXISTS " + table).Error })
	if err := db.Exec(fmt.Sprintf(`CREATE TABLE %s (
		id bigserial PRIMARY KEY,
		ptype varchar(80) NOT NULL,
		v0 varchar(80) NOT NULL,
		v1 varchar(80) NOT NULL,
		v2 varchar(80) NOT NULL,
		v3 varchar(80) NOT NULL,
		v4 varchar(80) NOT NULL,
		v5 varchar(80) NOT NULL,
		CONSTRAINT %s UNIQUE (ptype, v0, v1, v2, v3, v4, v5)
	)`, table, index)).Error; err != nil {
		t.Fatalf("create runtime schema: %v", err)
	}
	if err := db.Exec("INSERT INTO "+table+" (ptype, v0, v1, v2, v3, v4, v5) VALUES (?, ?, ?, ?, '', '', '')", "p", "super_admin", "admin:status", "read").Error; err != nil {
		t.Fatalf("seed runtime policy: %v", err)
	}

	cfg := RuntimeConfig{
		Model: runtimeTestModel,
		Storage: &StorageConfig{
			Driver:        "postgres",
			DSN:           dsn,
			TableName:     table,
			MigrationMode: MigrationModeValidate,
		},
	}
	first, err := NewRuntime(t.Context(), cfg)
	if err != nil {
		t.Fatalf("first NewRuntime(): %v", err)
	}
	firstPolicies, err := first.Policies(t.Context())
	if err != nil {
		t.Fatalf("first Policies(): %v", err)
	}
	firstDecision, err := first.Decide(t.Context(), DecisionRequest{Subject: "super_admin", Object: "admin:status", Action: "read"})
	if err != nil || !firstDecision.Allowed {
		t.Fatalf("first Decide() = %#v, %v", firstDecision, err)
	}
	if health := first.Health(t.Context()); health.Status != HealthReady {
		t.Fatalf("first Health() = %#v, want ready", health)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close(): %v", err)
	}

	second, err := NewRuntime(t.Context(), cfg)
	if err != nil {
		t.Fatalf("second NewRuntime(): %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	secondPolicies, err := second.Policies(t.Context())
	if err != nil {
		t.Fatalf("second Policies(): %v", err)
	}
	secondDecision, err := second.Decide(t.Context(), DecisionRequest{Subject: "super_admin", Object: "admin:status", Action: "read"})
	if err != nil {
		t.Fatalf("second Decide(): %v", err)
	}
	if !reflect.DeepEqual(secondPolicies, firstPolicies) || secondDecision != firstDecision {
		t.Fatalf("restart changed snapshot: policies=%#v/%#v decision=%#v/%#v", firstPolicies, secondPolicies, firstDecision, secondDecision)
	}
	seeded, err := NewRuntime(t.Context(), RuntimeConfig{
		Model: runtimeTestModel,
		Seed:  &SeedConfig{Policies: [][]string{{"super_admin", "admin:status", "read"}}},
	})
	if err != nil {
		t.Fatalf("seeded NewRuntime(): %v", err)
	}
	t.Cleanup(func() { _ = seeded.Close() })
	seededPolicies, err := seeded.Policies(t.Context())
	if err != nil {
		t.Fatalf("seeded Policies(): %v", err)
	}
	seededDecision, err := seeded.Decide(t.Context(), DecisionRequest{Subject: "super_admin", Object: "admin:status", Action: "read"})
	if err != nil {
		t.Fatalf("seeded Decide(): %v", err)
	}
	if !reflect.DeepEqual(seededPolicies, firstPolicies) || seededDecision != firstDecision {
		t.Fatalf("seeded runtime differs: policies=%#v/%#v decision=%#v/%#v", firstPolicies, seededPolicies, firstDecision, seededDecision)
	}
}
