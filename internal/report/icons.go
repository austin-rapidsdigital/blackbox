package report

import (
	"embed"
	"html/template"
	"regexp"
	"strings"
	"sync"
)

// Icons are Lucide icons (ISC licence, icons/LICENSE), drawn inline so the
// report needs no files or fonts for them.
//
//go:embed icons/*.svg
var iconFS embed.FS

var (
	iconMu    sync.Mutex
	iconCache = map[string]template.HTML{}
	svgClean  = regexp.MustCompile(`(?s)<!--.*?-->|\s+class="[^"]*"`)
	svgSpace  = regexp.MustCompile(`\s+`)
)

// icon returns the named icon as inline SVG, size pixels square.
func icon(name string, size int) template.HTML {
	key := name + "/" + itoa(size)
	iconMu.Lock()
	defer iconMu.Unlock()
	if s, ok := iconCache[key]; ok {
		return s
	}
	b, err := iconFS.ReadFile("icons/" + name + ".svg")
	if err != nil {
		panic("report: no icon " + name)
	}
	s := svgClean.ReplaceAllString(string(b), "")
	s = svgSpace.ReplaceAllString(strings.TrimSpace(s), " ")
	s = strings.Replace(s, `width="24"`, `width="`+itoa(size)+`"`, 1)
	s = strings.Replace(s, `height="24"`, `height="`+itoa(size)+`"`, 1)
	s = strings.Replace(s, `stroke-width="2"`, `stroke-width="1.6"`, 1)
	s = strings.Replace(s, "<svg ", `<svg class="ic" aria-hidden="true" `, 1)
	h := template.HTML(s)
	iconCache[key] = h
	return h
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
