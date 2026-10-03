package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// A10: the SBOM names Blackbox, the Go standard library, and every module
// go.mod requires (none today).
func TestSBOM(t *testing.T) {
	gomod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	d := build("0.10.2", string(gomod), "go1.24.4", time.Unix(0, 0))
	b, _ := json.Marshal(d)
	s := string(b)
	for _, want := range []string{`"spdxVersion":"SPDX-2.3"`, `"name":"blackbox"`, `pkg:golang/github.com/casea1/blackbox@v0.10.2`, `pkg:golang/stdlib@go1.24.4`, `"DESCRIBES"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	if len(d.Packages) != 2 {
		t.Errorf("Blackbox has no third-party modules, but the SBOM lists %d packages", len(d.Packages))
	}
	_, reqs := requires("module x\n\nrequire (\n\tgolang.org/x/sys v0.1.0 // indirect\n)\nrequire example.com/y v1.2.3\n")
	if strings.Join(reqs, ",") != "golang.org/x/sys@v0.1.0,example.com/y@v1.2.3" {
		t.Errorf("requires: %v", reqs)
	}
}
