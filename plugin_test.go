package workflowpluginauthz_test

import (
	"testing"

	workflowpluginauthz "github.com/GoCodeAlone/workflow-plugin-authz"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func TestNewAuthzPluginIsPubliclyImportable(t *testing.T) {
	plugin := workflowpluginauthz.NewAuthzPlugin()
	if plugin == nil {
		t.Fatal("NewAuthzPlugin() returned nil")
	}
	if _, ok := plugin.(sdk.ModuleProvider); !ok {
		t.Fatal("NewAuthzPlugin() must expose authz module providers")
	}
	if _, ok := plugin.(sdk.StepProvider); !ok {
		t.Fatal("NewAuthzPlugin() must expose authz step providers")
	}
}
