package main

import (
	"bytes"
	"testing"
)

func TestRedactSensitiveJSON_StringValue(t *testing.T) {
	input := `{"join_secret": "abc123", "other": "ok"}`
	got := string(redactSensitiveJSON([]byte(input)))
	want := `{"join_secret": "[REDACTED]", "other": "ok"}`
	if got != want {
		t.Errorf("string value:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestRedactSensitiveJSON_ArrayValue(t *testing.T) {
	// join_secret is stored as a single-element JSON array by Weka.
	input := `{"join_secret": ["abc123"], "other": "ok"}`
	got := string(redactSensitiveJSON([]byte(input)))
	want := `{"join_secret": ["[REDACTED]"], "other": "ok"}`
	if got != want {
		t.Errorf("array value:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestRedactSensitiveJSON_ArrayValueWithBracket(t *testing.T) {
	// Array element containing ] must not truncate the match.
	input := `{"join_secret": ["abc]def"], "other": "ok"}`
	got := string(redactSensitiveJSON([]byte(input)))
	want := `{"join_secret": ["[REDACTED]"], "other": "ok"}`
	if got != want {
		t.Errorf("array value with bracket:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestRedactSensitiveJSON_Password(t *testing.T) {
	input := `{"password": "hunter2", "name": "bob"}`
	got := string(redactSensitiveJSON([]byte(input)))
	want := `{"password": "[REDACTED]", "name": "bob"}`
	if got != want {
		t.Errorf("password:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestRedactSensitiveJSON_NoFalsePositives(t *testing.T) {
	input := `{"cluster_name": "prod-cluster", "size": 42}`
	got := string(redactSensitiveJSON([]byte(input)))
	if got != input {
		t.Errorf("should not redact non-sensitive keys:\ngot:  %s\nwant: %s", got, input)
	}
}

func TestRedactSensitiveYAML_JoinSecret(t *testing.T) {
	input := "join_secret: abc123\nother: value\n"
	got := string(redactSensitiveYAML([]byte(input)))
	// join_secret contains "secret" so it should be redacted by the YAML redactor too.
	if got == input {
		t.Errorf("YAML redactor did not redact join_secret:\n%s", got)
	}
}

func TestRedactSensitiveValues_AuthHeader(t *testing.T) {
	cases := []struct {
		input string
		desc  string
	}{
		{"Authorization: Bearer SRTabcdefghijklmnopqrstuvwxyz1234", "Bearer header"},
		{"Authorization: Token SRTabcdefghijklmnopqrstuvwxyz1234", "Token header"},
		{"authorization: bearer someOtherLongToken12345678901234", "lowercase bearer"},
	}
	for _, tc := range cases {
		got := string(redactSensitiveValues([]byte(tc.input)))
		if bytes.Contains([]byte(got), []byte("SRTabcdef")) || bytes.Contains([]byte(got), []byte("someOther")) {
			t.Errorf("%s: token not redacted:\n%s", tc.desc, got)
		}
		if !bytes.Contains([]byte(got), []byte("[REDACTED]")) {
			t.Errorf("%s: [REDACTED] not present:\n%s", tc.desc, got)
		}
	}
}

func TestRedactSensitiveValues_CLIFlag(t *testing.T) {
	cases := []struct {
		input string
		desc  string
	}{
		{"weka agent --token SRTabcdefghijklmnopqrstuvwxyz1234 --other arg", "space-separated token flag"},
		{"weka agent --token=SRTabcdefghijklmnopqrstuvwxyz1234", "equals-separated token flag"},
		{"proc --password=hunter2 --verbose", "password flag"},
	}
	for _, tc := range cases {
		got := string(redactSensitiveValues([]byte(tc.input)))
		if bytes.Contains([]byte(got), []byte("SRTabcdef")) || bytes.Contains([]byte(got), []byte("hunter2")) {
			t.Errorf("%s: credential not redacted:\n%s", tc.desc, got)
		}
		if !bytes.Contains([]byte(got), []byte("[REDACTED]")) {
			t.Errorf("%s: [REDACTED] not present:\n%s", tc.desc, got)
		}
	}
}

func TestRedactSensitiveValues_SRTToken(t *testing.T) {
	token := "SRTsomeverylongtokenvalue1234567890abcdef"
	input := "download token: " + token
	got := string(redactSensitiveValues([]byte(input)))
	if bytes.Contains([]byte(got), []byte(token)) {
		t.Errorf("bare SRT token not redacted:\n%s", got)
	}
	if !bytes.Contains([]byte(got), []byte("[REDACTED]")) {
		t.Errorf("[REDACTED] not present:\n%s", got)
	}
}

func TestRedactSensitiveValues_NoFalsePositives(t *testing.T) {
	cases := []struct {
		input string
		desc  string
	}{
		{"Authorization: negotiate", "negotiate auth (no token value)"},
		{"--verbose --output /tmp/out.tar.gz", "innocent flags"},
		{"status: SRT", "SRT too short to be a token"},
	}
	for _, tc := range cases {
		got := string(redactSensitiveValues([]byte(tc.input)))
		if got != tc.input {
			t.Errorf("%s: false positive — input was modified:\ninput: %q\ngot:   %q", tc.desc, tc.input, got)
		}
	}
}

func TestRedactSensitive_PsAuxLine(t *testing.T) {
	// Simulate a ps aux line where weka runs with a token in its args.
	line := "root  1234  0.0  0.1  weka agent --token SRTabcdefghijklmnopqrstuvwxyz1234 --debug"
	got := string(redactSensitive([]byte(line)))
	if bytes.Contains([]byte(got), []byte("SRTabcdef")) {
		t.Errorf("SRT token survived redactSensitive on ps aux line:\n%s", got)
	}
}

func TestRedactSensitive_ShelldLogBearerLine(t *testing.T) {
	// Simulate a shelld.log HTTP request line with an Authorization header.
	line := `2026-09-21T10:00:00Z GET https://get.weka.io/dist/v1/pkg Authorization: Bearer SRTabcdefghijklmnopqrstuvwxyz1234`
	got := string(redactSensitive([]byte(line)))
	if bytes.Contains([]byte(got), []byte("SRTabcdef")) {
		t.Errorf("Bearer token survived redactSensitive on shelld.log line:\n%s", got)
	}
}

func TestSanitizeErrStr_StripsBinary(t *testing.T) {
	input := "normal text\x00\x01\x02more text\nand newline"
	got := sanitizeErrStr(input)
	for _, r := range got {
		if r != '\n' && r != '\t' && (r < 32 || r == 127) {
			t.Errorf("sanitizeErrStr left non-printable rune %d in output: %q", r, got)
		}
	}
	if got == "" {
		t.Error("sanitizeErrStr returned empty string")
	}
}

func TestSanitizeErrStr_PreservesText(t *testing.T) {
	input := "Error from server (Forbidden): secrets is forbidden"
	got := sanitizeErrStr(input)
	if got != input {
		t.Errorf("sanitizeErrStr modified clean text:\ngot:  %q\nwant: %q", got, input)
	}
}

func TestMaskIPv6_TimestampNotRedacted(t *testing.T) {
	a := newAnonymizer(true)
	a.finalize()
	// HH:MM:SS timestamps must not be anonymized — they are not IPv6 addresses.
	cases := []string{
		"collected at 10:58:19 today",
		"10:58:20",
		"00:00:00",
	}
	for _, input := range cases {
		got := string(a.Apply([]byte(input)))
		if got != input {
			t.Errorf("timestamp falsely anonymized:\ninput: %q\ngot:   %q", input, got)
		}
	}
}

func TestMaskIPv6_CppScopeNotRedacted(t *testing.T) {
	a := newAnonymizer(true)
	a.finalize()
	// C++ scope expressions that are all hex-letter (no digits) must not be
	// anonymized — they have no decimal digit unlike real IPv6 addresses.
	cases := []string{
		"abc::def",
		"dead::beef",
		"cafe::babe",
	}
	for _, input := range cases {
		got := string(a.Apply([]byte(input)))
		if got != input {
			t.Errorf("C++ scope falsely anonymized:\ninput: %q\ngot:   %q", input, got)
		}
	}
}

func TestMaskIPv6_PCISlotNotRedacted(t *testing.T) {
	a := newAnonymizer(true)
	a.finalize()
	// PCI slot IDs (all-decimal, ≤4 groups) must not be anonymized.
	cases := []string{
		"pci slot 0000:00:02",
		"0000:00:1f",
	}
	for _, input := range cases {
		got := string(a.Apply([]byte(input)))
		if got != input {
			t.Errorf("PCI slot falsely anonymized:\ninput: %q\ngot:   %q", input, got)
		}
	}
}

func TestMaskIPv6_RealIPv6Redacted(t *testing.T) {
	a := newAnonymizer(true)
	a.finalize()
	// Real IPv6 addresses must be fully masked to x:x:x:x:x:x:x:<last>.
	// The full address must be consumed in one regex match so host-identifier
	// groups after :: are not left unmasked.
	cases := []struct {
		input string
		want  string
	}{
		{"fe80::1", "x:x:x:x:x:x:x:1"},
		// Compressed form: trailing groups after :: must also be masked.
		{"2001:db8:85a3::8a2e:370:7334", "x:x:x:x:x:x:x:7334"},
		// Leading-:: form.
		{"::1", "x:x:x:x:x:x:x:1"},
	}
	for _, tc := range cases {
		got := string(a.Apply([]byte(tc.input)))
		if got != tc.want {
			t.Errorf("IPv6 masking:\ninput: %q\ngot:   %q\nwant:  %q", tc.input, got, tc.want)
		}
	}
}
