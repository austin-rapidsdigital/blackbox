package gui

import (
	"reflect"
	"testing"

	"github.com/casea1/blackbox/internal/install"
)

// The window asks what the console asks, in the same order.
func TestPagesFor(t *testing.T) {
	for role, want := range map[string][]page{
		install.RoleStandalone: {pWelcome, pRole, pReports, pCollect, pSummary, pInstall},
		install.RoleCollector:  {pWelcome, pRole, pReports, pInbox, pCollect, pSummary, pInstall},
		install.RoleSender:     {pWelcome, pRole, pSendTo, pCollect, pSummary, pInstall},
	} {
		if got := pagesFor(role); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", role, got, want)
		}
	}
	if step(install.RoleSender, pRole, 1) != pSendTo || step(install.RoleCollector, pCollect, -1) != pInbox ||
		step(install.RoleStandalone, pWelcome, -1) != pWelcome {
		t.Error("step moves to the wrong page")
	}
}
