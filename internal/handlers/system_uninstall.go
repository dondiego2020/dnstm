package handlers

import (
	"github.com/dondiego2020/dnstm/internal/actions"
	"github.com/dondiego2020/dnstm/internal/installer"
)

func init() {
	actions.SetSystemHandler(actions.ActionUninstall, HandleUninstall)
}

// HandleUninstall performs a full system uninstall.
func HandleUninstall(ctx *actions.Context) error {
	// Note: Confirmation is handled by the adapter before calling the handler
	return installer.PerformFullUninstall(ctx.Output, ctx.IsInteractive)
}
