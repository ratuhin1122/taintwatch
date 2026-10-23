package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type memorySource [][]byte

func (s memorySource) ScanAudit(fn func([]byte) error) error {
	for _, b := range s {
		if e := fn(b); e != nil {
			return e
		}
	}
	return nil
}
func TestQuery(t *testing.T) {
	var source memorySource
	for _, r := range []Record{
		{TS: time.Unix(3, 0), Session: "new", Hook: "PreToolUse", Decision: "ask", Reason: (fakeCredential("token=", "abcdefghijk12345"))},
		{TS: time.Unix(1, 0), Session: "old", Hook: "PreToolUse", Decision: "ask"},
		{TS: time.Unix(2, 0), Session: "new", Hook: "PostToolUse", Decision: "allow"},
	} {
		b, _ := json.Marshal(r)
		source = append(source, b)
	}
	h, e := Query(source, "", 1)
	if e != nil || h.Session != "new" || h.Asks != 1 || len(h.Records) != 1 || h.Records[0].TS.Unix() != 3 || strings.Contains(h.Records[0].Reason, "abcdefghijk") {
		t.Fatalf("%+v %v", h, e)
	}
	h, e = Query(source, "old", 10)
	if e != nil || h.Asks != 1 || len(h.Records) != 1 {
		t.Fatalf("%+v %v", h, e)
	}
	if _, e = Query(source, "", 0); e == nil {
		t.Fatal("accepted invalid count")
	}
	if _, e = Query(memorySource{[]byte("{")}, "", 10); e == nil {
		t.Fatal("accepted corrupt history")
	}
}
func TestTypedRedaction(t *testing.T) {
	for _, tc := range []struct{ input, kind, secret string }{
		{(fakeCredential("AKIA", "ABCDEFGHIJKLMNOP")), "aws", (fakeCredential("AKIA", "ABCDEFGHIJKLMNOP"))},
		{(fakeCredential("ASIA", "ABCDEFGHIJKLMNOP")), "aws", (fakeCredential("ASIA", "ABCDEFGHIJKLMNOP"))},
		{(fakeCredential("github_pat_", "123456789abcdef")), "github", "123456789abcdef"},
		{(fakeCredential("ghp_", "123456789abcdef")), "github", "123456789abcdef"},
		{(fakeCredential("Bearer ", "publicfixture123456")), "bearer", "publicfixture123456"},
		{(fakeCredential("-----BEG", "IN RSA PRIVATE KEY-----") + "\nprivatefixture\n-----END RSA PRIVATE KEY-----"), "private-key", "privatefixture"},
		{(fakeCredential("-----BEG", "IN OPENSSH PRIVATE KEY-----") + "\nincompletefixture"), "private-key", "incompletefixture"},
		{("\"" + fakeCredential("password\": \"", "A9z7L2wX8rV6pQ4sT1u") + "\""), "credential", "A9z7L2wX8rV6pQ4sT1u"},
		{"client_secret='two word secret'", "credential", "two word secret"},
		{(fakeCredential("API_KEY=", "AbCd0123456789ZZxx")), "credential", "AbCd0123456789ZZxx"},
		{`token="[REDACTED:github] stillsecret"`, "credential", "stillsecret"},
		{`password="start\"trailingsecret"`, "credential", "trailingsecret"},
	} {
		got := Redact(tc.input)
		if strings.Contains(got, tc.secret) || !strings.Contains(got, "[REDACTED:"+tc.kind+"]") {
			t.Fatalf("%s => %s", tc.kind, got)
		}
		if Redact(got) != got {
			t.Fatalf("not idempotent: %s => %s", got, Redact(got))
		}
	}
}
