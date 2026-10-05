package collect

import (
	"testing"

	"github.com/casea1/blackbox/internal/event"
)

// W1: events from before a new server was renamed are filed under its
// current name, with the former name kept.
func TestOnThisComputer(t *testing.T) {
	e := &event.Event{Host: "WIN-R5L5B9EF403"}
	OnThisComputer(e, "SRV25")
	if e.Host != "SRV25" || len(e.Details) != 1 || e.Details[0].Value != "its former name WIN-R5L5B9EF403" {
		t.Errorf("renamed: %+v", e)
	}
	e = &event.Event{Host: "srv25.corp.example"}
	OnThisComputer(e, "SRV25")
	if e.Host != "SRV25" || len(e.Details) != 0 {
		t.Errorf("same computer: %+v", e)
	}
}
