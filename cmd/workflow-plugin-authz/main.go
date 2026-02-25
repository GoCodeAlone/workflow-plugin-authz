// Command workflow-plugin-authz is a workflow engine external plugin that
// provides RBAC authorization via Casbin. It runs as a subprocess and
// communicates with the host workflow engine via the go-plugin protocol.
package main

import (
	"github.com/GoCodeAlone/workflow-plugin-authz/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func main() {
	sdk.Serve(internal.NewAuthzPlugin())
}
