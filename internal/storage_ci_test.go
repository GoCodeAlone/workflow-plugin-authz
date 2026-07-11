package internal

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStoragePostgresIntegrationIsRequiredByCI(t *testing.T) {
	t.Parallel()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	workflow, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read CI workflow: %v", err)
	}
	contents := string(workflow)
	for _, required := range []string{
		"services:",
		"postgres:",
		"image: postgres:16",
		"docker exec \"${{ job.services.postgres.id }}\" pg_isready",
		"AUTHZ_TEST_POSTGRES_DSN: postgres://postgres:postgres@localhost:5432/authz_test?sslmode=disable",
		"GOWORK=off go test ./internal -run '^TestStoragePostgresIntegrationContract$' -v -race -count=1 | tee",
		"--- PASS: TestStoragePostgresIntegrationContract",
		"! grep -q -- '--- SKIP: TestStoragePostgresIntegrationContract'",
	} {
		if !strings.Contains(contents, required) {
			t.Errorf("blocking CI job is missing %q", required)
		}
	}
}
