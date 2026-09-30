package share

import "testing"

func TestRootAndUser(t *testing.T) {
	for _, c := range [][3]string{
		{`\\COLLECTOR\BlackboxInbox`, `\\COLLECTOR\BlackboxInbox`, ""},
		{`\\COLLECTOR\Share\Blackbox\Inbox`, `\\COLLECTOR\Share`, `Blackbox\Inbox`},
		{`//collector/BlackboxInbox`, `//collector/BlackboxInbox`, ""},
		{`//collector/share/sub`, `//collector/share`, "sub"},
	} {
		root, rest := Root(c[0])
		if root != c[1] || rest != c[2] {
			t.Errorf("Root(%q) = %q, %q", c[0], root, rest)
		}
	}
	for _, c := range [][3]string{{`LAB\bbsend`, "LAB", "bbsend"}, {"bbsend@lab.local", "lab.local", "bbsend"}, {"bbsend", "", "bbsend"}} {
		d, u := SplitUser(c[0])
		if d != c[1] || u != c[2] {
			t.Errorf("SplitUser(%q) = %q, %q", c[0], d, u)
		}
	}
}
