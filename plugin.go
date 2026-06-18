// Package workflowpluginauthz provides the authz workflow plugin.
package workflowpluginauthz

import (
	"github.com/GoCodeAlone/workflow-plugin-authz/internal"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// NewAuthzPlugin returns the authz SDK plugin provider.
func NewAuthzPlugin() sdk.PluginProvider {
	return internal.NewAuthzPlugin()
}
