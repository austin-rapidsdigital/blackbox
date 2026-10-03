// Command sbom writes Blackbox's software bill of materials as SPDX 2.3
// JSON (A10): the program, the Go standard library and toolchain it is
// built with, and any modules go.mod requires (none: Blackbox uses only
// the standard library).
//
//	go run ./scripts/sbom -version 0.10.2 > blackbox-0.10.2.spdx.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type pkg struct {
	SPDXID           string        `json:"SPDXID"`
	Name             string        `json:"name"`
	VersionInfo      string        `json:"versionInfo"`
	Supplier         string        `json:"supplier"`
	DownloadLocation string        `json:"downloadLocation"`
	FilesAnalyzed    bool          `json:"filesAnalyzed"`
	LicenseConcluded string        `json:"licenseConcluded"`
	LicenseDeclared  string        `json:"licenseDeclared"`
	CopyrightText    string        `json:"copyrightText"`
	ExternalRefs     []externalRef `json:"externalRefs,omitempty"`
	PrimaryPurpose   string        `json:"primaryPackagePurpose,omitempty"`
}

type externalRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type relationship struct {
	Element string `json:"spdxElementId"`
	Type    string `json:"relationshipType"`
	Related string `json:"relatedSpdxElement"`
}

type doc struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      creation       `json:"creationInfo"`
	Packages          []pkg          `json:"packages"`
	Relationships     []relationship `json:"relationships"`
}

type creation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

// requires lists the modules go.mod requires, as path@version.
func requires(gomod string) (module string, reqs []string) {
	block := false
	for _, l := range strings.Split(gomod, "\n") {
		l = strings.TrimSpace(strings.SplitN(l, "//", 2)[0])
		switch {
		case strings.HasPrefix(l, "module "):
			module = strings.TrimSpace(strings.TrimPrefix(l, "module "))
		case l == "require (":
			block = true
		case block && l == ")":
			block = false
		case block && l != "":
			reqs = append(reqs, strings.Join(strings.Fields(l), "@"))
		case strings.HasPrefix(l, "require "):
			reqs = append(reqs, strings.Join(strings.Fields(strings.TrimPrefix(l, "require ")), "@"))
		}
	}
	return module, reqs
}

// build makes the document.
func build(version, gomod, goVersion string, created time.Time) doc {
	module, reqs := requires(gomod)
	main := pkg{SPDXID: "SPDXRef-Package-blackbox", Name: "blackbox", VersionInfo: version, Supplier: "Organization: Blackbox project",
		DownloadLocation: "https://" + module, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION",
		PrimaryPurpose: "APPLICATION",
		ExternalRefs:   []externalRef{{"PACKAGE-MANAGER", "purl", "pkg:golang/" + module + "@v" + strings.TrimPrefix(version, "v")}}}
	std := pkg{SPDXID: "SPDXRef-Package-go-stdlib", Name: "Go standard library", VersionInfo: strings.TrimPrefix(goVersion, "go"),
		Supplier: "Organization: The Go Authors", DownloadLocation: "https://go.dev/dl/", LicenseConcluded: "BSD-3-Clause",
		LicenseDeclared: "BSD-3-Clause", CopyrightText: "NOASSERTION",
		ExternalRefs: []externalRef{{"PACKAGE-MANAGER", "purl", "pkg:golang/stdlib@" + goVersion}}}
	d := doc{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: "blackbox-" + version,
		DocumentNamespace: "https://" + module + "/spdx/blackbox-" + version,
		CreationInfo:      creation{Created: created.UTC().Format(time.RFC3339), Creators: []string{"Tool: blackbox-sbom", "Organization: Blackbox project"}},
		Packages:          []pkg{main, std},
		Relationships: []relationship{{"SPDXRef-DOCUMENT", "DESCRIBES", main.SPDXID},
			{main.SPDXID, "DEPENDS_ON", std.SPDXID}}}
	for i, r := range reqs {
		path, v, _ := strings.Cut(r, "@")
		id := fmt.Sprintf("SPDXRef-Package-dep-%d", i+1)
		d.Packages = append(d.Packages, pkg{SPDXID: id, Name: path, VersionInfo: v, Supplier: "NOASSERTION", DownloadLocation: "https://" + path,
			LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION",
			ExternalRefs: []externalRef{{"PACKAGE-MANAGER", "purl", "pkg:golang/" + path + "@" + v}}})
		d.Relationships = append(d.Relationships, relationship{main.SPDXID, "DEPENDS_ON", id})
	}
	return d
}

func main() {
	version := flag.String("version", "dev", "Blackbox version")
	gomodPath := flag.String("gomod", "go.mod", "path to go.mod")
	flag.Parse()
	gomod, err := os.ReadFile(*gomodPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sbom:", err)
		os.Exit(1)
	}
	created := time.Now()
	if s := os.Getenv("SOURCE_DATE_EPOCH"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			created = time.Unix(n, 0)
		}
	}
	out, _ := json.MarshalIndent(build(*version, string(gomod), runtime.Version(), created), "", "  ")
	os.Stdout.Write(append(out, '\n'))
}
