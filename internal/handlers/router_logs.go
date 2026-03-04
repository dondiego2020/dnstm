package handlers

import (
	"fmt"

	"github.com/dondiego2020/dnstm/internal/actions"
	"github.com/dondiego2020/dnstm/internal/dnsrouter"
)

func init() {
	actions.SetRouterHandler(actions.ActionRouterLogs, HandleRouterLogs)
}

// HandleRouterLogs shows logs from the DNS router.
func HandleRouterLogs(ctx *actions.Context) error {
	if err := CheckRequirements(ctx, true, false); err != nil {
		return err
	}

	lines := ctx.GetInt("lines")
	if lines == 0 {
		lines = 50 // default
	}

	svc := dnsrouter.NewService()
	logs, err := svc.GetLogs(lines)
	if err != nil {
		return fmt.Errorf("failed to get logs: %w", err)
	}

	ctx.Output.Println(logs)
	return nil
}
