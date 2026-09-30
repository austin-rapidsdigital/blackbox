package event

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	cases := [][2]string{
		{`powershell -c "$env:BLACKBOX_SHARE_PASSWORD='Qx7!Harbor-L26'; blackbox.exe install --yes"`, `$env:BLACKBOX_SHARE_PASSWORD=********; blackbox.exe install --yes`},
		{`sudo BLACKBOX_SHARE_PASSWORD=hunter2 ./blackbox install --yes`, `BLACKBOX_SHARE_PASSWORD=******** ./blackbox`},
		{`net user bbsend "Qx7!Harbor-L26" /add`, `net user bbsend ******** /add`},
		{`net user bbsend * /add`, `net user bbsend * /add`},
		{`net use Z: \\COLLECTOR\BlackboxInbox s3cret /user:bbsend`, `net use Z: \\COLLECTOR\BlackboxInbox ******** /user:bbsend`},
		{`New-LocalUser bob -Password (ConvertTo-SecureString 'P@ss1' -AsPlainText -Force)`, `ConvertTo-SecureString ******** -AsPlainText`},
		{`sshpass -p hunter2 ssh admin@ws12`, `sshpass -p ******** ssh`},
		{`printf 'hunter2\n' | sudo -S sh -c 'it-pull'`, `printf ******** | sudo -S`},
		{`wevtutil cl Security`, `wevtutil cl Security`},
		{`passwd jsmith`, `passwd jsmith`},
	}
	for _, c := range cases {
		got := Redact(c[0])
		if !strings.Contains(got, c[1]) {
			t.Errorf("Redact(%q)\n got %q\nwant it to contain %q", c[0], got, c[1])
		}
		for _, secret := range []string{"Qx7!Harbor-L26", "hunter2", "s3cret", "P@ss1"} {
			if strings.Contains(got, secret) {
				t.Errorf("Redact(%q) kept the secret: %q", c[0], got)
			}
		}
	}
}

func TestRedactSecretsCoversEverything(t *testing.T) {
	e := &Event{Summary: "ran: net user bob hunter2 /add", Command: "net user bob hunter2 /add",
		Details: []Detail{{"Command line", "net user bob hunter2 /add"}}, Fields: map[string]string{"CommandLine": "net user bob hunter2 /add"}}
	orig := e.Fields
	e.RedactSecrets()
	all := e.Summary + e.Command + e.Details[0].Value + e.Fields["CommandLine"]
	if strings.Contains(all, "hunter2") {
		t.Errorf("secret left in %q", all)
	}
	if orig["CommandLine"] != "net user bob hunter2 /add" {
		t.Error("the original event data map must not be modified in place")
	}
}
