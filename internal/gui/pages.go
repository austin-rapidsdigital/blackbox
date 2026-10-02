// Package gui is Blackbox's setup window and status icon on Windows (see
// docs/redesign/SETUP-SPEC.md). Elsewhere it reports that it is Windows
// only. The decisions (which pages, which icon) are kept in plain Go,
// separate from the Windows calls, so they are tested on every platform.
package gui

import "github.com/casea1/blackbox/internal/install"

// page is one step of the setup window.
type page int

const (
	pWelcome page = iota
	pRole
	pReports
	pInbox
	pSendTo
	pCollect
	pSummary
	pInstall
)

// pagesFor lists the pages in order for a role: the same questions the
// console setup asks, in the same order.
func pagesFor(role string) []page {
	switch role {
	case install.RoleSender:
		return []page{pWelcome, pRole, pSendTo, pCollect, pSummary, pInstall}
	case install.RoleCollector:
		return []page{pWelcome, pRole, pReports, pInbox, pCollect, pSummary, pInstall}
	}
	return []page{pWelcome, pRole, pReports, pCollect, pSummary, pInstall}
}

// step moves from p by delta (+1 next, -1 back) in the role's order.
func step(role string, p page, delta int) page {
	list := pagesFor(role)
	for i, x := range list {
		if x == p {
			j := i + delta
			if j < 0 {
				j = 0
			}
			if j >= len(list) {
				j = len(list) - 1
			}
			return list[j]
		}
	}
	return list[0]
}
