package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// fakeBearer and fakeSRT are placeholder strings used in tests below.
// They are intentionally low-entropy (all-X padding) so that secret-scanning
// tools do not flag them as real credentials.
const (
	fakeBearer = "FAKE-TEST-BEARER-TOKEN-XXXXXXXXXXXX"
	fakeSRT    = "SRTFAKE-TEST-TOKEN-XXXXXXXXXXXXXXXXX"
	fakePW     = "FAKE-TEST-PW-XXXXXXXXXX"
)

func TestRedactSensitiveValues_AuthHeader(t *testing.T) {
	cases := []struct {
		input string
		want  string
		desc  string
	}{
		{"Authorization: Bearer " + fakeBearer, "Authorization: Bearer [REDACTED]", "Bearer header"},
		{"Authorization: Token " + fakeBearer, "Authorization: Token [REDACTED]", "Token header"},
		{"authorization: bearer " + fakeBearer, "authorization: bearer [REDACTED]", "lowercase bearer"},
	}
	for _, tc := range cases {
		got := string(redactSensitiveValues([]byte(tc.input)))
		if bytes.Contains([]byte(got), []byte(fakeBearer)) {
			t.Errorf("%s: token not redacted:\n%s", tc.desc, got)
		}
		if got != tc.want {
			t.Errorf("%s: unexpected output:\ngot:  %q\nwant: %q", tc.desc, got, tc.want)
		}
	}
}

func TestRedactSensitiveValues_CLIFlag(t *testing.T) {
	cases := []struct {
		input string
		desc  string
	}{
		{"weka agent --token " + fakeSRT + " --other arg", "space-separated --token flag"},
		{"weka agent --token=" + fakeSRT, "equals-separated --token flag"},
		{"proc --password=" + fakePW + " --verbose", "--password flag"},
		{"weka --access-token=" + fakeBearer, "compound --access-token flag"},
		{"weka --refresh-token " + fakeBearer, "compound --refresh-token flag"},
		{"weka --join-secret=" + fakeBearer, "compound --join-secret flag"},
		{"weka --private-key=" + fakeBearer, "compound --private-key flag"},
	}
	for _, tc := range cases {
		got := string(redactSensitiveValues([]byte(tc.input)))
		for _, secret := range []string{fakeSRT, fakePW, fakeBearer} {
			if bytes.Contains([]byte(got), []byte(secret)) {
				t.Errorf("%s: credential not redacted:\n%s", tc.desc, got)
			}
		}
		if !bytes.Contains([]byte(got), []byte("[REDACTED]")) {
			t.Errorf("%s: [REDACTED] not present:\n%s", tc.desc, got)
		}
	}
}

func TestRedactSensitiveValues_StructuralDelimiters(t *testing.T) {
	// Verify that surrounding JSON/structured text is not consumed by the regex.
	cases := []struct {
		input       string
		mustContain string
		desc        string
	}{
		{
			`{"cmd":"weka --token=` + fakeSRT + `","other":"ok"}`,
			`","other":"ok"}`,
			"JSON trailing text preserved after --token=",
		},
		{
			`Authorization: Bearer ` + fakeBearer + `, X-Other: val`,
			`, X-Other: val`,
			"comma-delimited header suffix preserved",
		},
		{
			`"Authorization: Bearer ` + fakeBearer + `","key":"val"`,
			`","key":"val"`,
			"JSON quote delimiter preserved after Bearer token",
		},
	}
	for _, tc := range cases {
		got := string(redactSensitiveValues([]byte(tc.input)))
		if !bytes.Contains([]byte(got), []byte(tc.mustContain)) {
			t.Errorf("%s: structural text corrupted:\ngot:  %q\nwant to contain: %q", tc.desc, got, tc.mustContain)
		}
		if !bytes.Contains([]byte(got), []byte("[REDACTED]")) {
			t.Errorf("%s: [REDACTED] not present:\n%s", tc.desc, got)
		}
	}
}

func TestRedactSensitiveValues_SRTToken(t *testing.T) {
	input := "download token: " + fakeSRT
	got := string(redactSensitiveValues([]byte(input)))
	if bytes.Contains([]byte(got), []byte(fakeSRT)) {
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
	line := "root  1234  0.0  0.1  weka agent --token " + fakeSRT + " --debug"
	got := string(redactSensitive([]byte(line)))
	if bytes.Contains([]byte(got), []byte(fakeSRT)) {
		t.Errorf("SRT token survived redactSensitive on ps aux line:\n%s", got)
	}
}

func TestRedactSensitive_ShelldLogBearerLine(t *testing.T) {
	line := "2026-09-21T10:00:00Z GET https://get.weka.io/dist/v1/pkg Authorization: Bearer " + fakeBearer
	got := string(redactSensitive([]byte(line)))
	if bytes.Contains([]byte(got), []byte(fakeBearer)) {
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

func TestBundledTraceExtractorNames(t *testing.T) {
	cases := []struct {
		goos, goarch string
		want         string
	}{
		{"linux", "amd64", "trace_extractor"},
		{"linux", "arm64", "trace_extractor-arm64"},
		{"darwin", "arm64", "trace_extractor"},
		{"darwin", "amd64", "trace_extractor"},
	}
	for _, c := range cases {
		got := bundledTraceExtractorNames(c.goos, c.goarch)
		if len(got) == 0 || got[0] != c.want {
			t.Errorf("%s/%s: got %v, want first %q", c.goos, c.goarch, got, c.want)
		}
	}
}

const sampleExtractorOutput = `verbose: /opt/weka/traces: 120 files match glob *.shard
verbose:   skip (filename parse failed): weird_name.shard
verbose: /opt/weka/traces: 1 skipped (parse), 30 skipped (filter), 89 remaining
verbose: /opt/weka/traces/histograms: 4 skipped (parse), 0 skipped (filter), 10 remaining
Collecting:
  42 shards
  7 histogram files
  3 cache files
  weka local ps -J: OK
Writing host-traces.tar.gz ...
Done: host-traces.tar.gz
`

func TestParseExtractorOutput(t *testing.T) {
	var r TraceResult
	parseExtractorOutput(sampleExtractorOutput, &r)
	if r.Shards != 42 || r.Histograms != 7 || r.UnparsedFiles != 5 {
		t.Errorf("got shards=%d histograms=%d unparsed=%d, want 42/7/5", r.Shards, r.Histograms, r.UnparsedFiles)
	}
	if r.Reason != "" {
		t.Errorf("unexpected reason %q", r.Reason)
	}
}

func TestParseExtractorOutput_DirWarning(t *testing.T) {
	var r TraceResult
	parseExtractorOutput("warning: cannot read trace directory /opt/weka/traces: permission denied\nCollecting:\n  0 shards\n  0 histogram files\n", &r)
	if r.Shards != 0 || !strings.Contains(r.Reason, "cannot read trace directory") {
		t.Errorf("got shards=%d reason=%q", r.Shards, r.Reason)
	}
}

// writeFakeExtractor creates a shell script that mimics trace_extractor:
// prints body to stderr, optionally sleeps, and writes an archive into cwd.
func writeFakeExtractor(t *testing.T, body string, sleepSecs int, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fake_extractor")
	script := fmt.Sprintf("#!/bin/sh\ncat >&2 <<'OUT'\n%sOUT\n[ %d -gt 0 ] && exec sleep %d\necho data > host-traces-x.tar.gz\nexit %d\n", body, sleepSecs, sleepSecs, exitCode)
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func runFakeExtractor(t *testing.T, path string, timeout time.Duration) (*TraceResult, map[string]string) {
	t.Helper()
	oldPath, oldTimeout := resolvedTraceExtractorPath, traceTimeout
	resolvedTraceExtractorPath, traceTimeout = path, timeout
	defer func() { resolvedTraceExtractorPath, traceTimeout = oldPath, oldTimeout }()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	res := runTraceExtractor(tw, "root", "h1", time.Now().Add(-30*time.Minute), time.Now())
	tw.Close()

	files := map[string]string{}
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		data, _ := io.ReadAll(tr)
		files[hdr.Name] = string(data)
	}
	return res, files
}

func TestRunTraceExtractor_OK(t *testing.T) {
	res, files := runFakeExtractor(t, writeFakeExtractor(t, sampleExtractorOutput, 0, 0), time.Minute)
	if res.Status != "ok" || res.Shards != 42 || len(res.Archives) != 1 {
		t.Fatalf("got %+v", res)
	}
	if _, ok := files["root/hosts/h1/traces/host-traces-x.tar.gz"]; !ok {
		t.Errorf("archive not added; files=%v", files)
	}
	log := files["root/hosts/h1/traces/extractor.log"]
	if !strings.Contains(log, "--verbose") || !strings.Contains(log, "42 shards") {
		t.Errorf("extractor.log missing args or output:\n%s", log)
	}
}

func TestRunTraceExtractor_NoShards(t *testing.T) {
	res, _ := runFakeExtractor(t, writeFakeExtractor(t, "Collecting:\n  0 shards\n  0 histogram files\n", 0, 0), time.Minute)
	if res.Status != "no_shards" {
		t.Errorf("got %+v", res)
	}
}

func TestRunTraceExtractor_Failed(t *testing.T) {
	res, files := runFakeExtractor(t, writeFakeExtractor(t, "error: --from: bad time\n", 0, 1), time.Minute)
	if res.Status != "failed" || res.ExitCode != 1 || !strings.Contains(res.Reason, "bad time") {
		t.Errorf("got %+v", res)
	}
	if _, ok := files["root/hosts/h1/traces/extractor.log"]; !ok {
		t.Errorf("extractor.log not written on failure")
	}
}

func TestRunTraceExtractor_Timeout(t *testing.T) {
	start := time.Now()
	res, _ := runFakeExtractor(t, writeFakeExtractor(t, "Collecting:\n", 30, 0), time.Second)
	if res.Status != "timeout" {
		t.Errorf("got %+v", res)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("timeout not enforced: took %s", d)
	}
}

func TestRemoteNodeArgs_TraceDeployFailed(t *testing.T) {
	oldCT, oldPath := collectTraces, resolvedTraceExtractorPath
	collectTraces, resolvedTraceExtractorPath = true, "/x/trace_extractor"
	defer func() { collectTraces, resolvedTraceExtractorPath = oldCT, oldPath }()

	traceDeployFailed.Store("bad-host", "scp failed")
	defer traceDeployFailed.Delete("bad-host")

	has := func(args []string, s string) bool {
		for _, a := range args {
			if a == s {
				return true
			}
		}
		return false
	}
	if args := remoteNodeArgs("good-host", time.Time{}, time.Time{}, nil); !has(args, "--collect-traces") {
		t.Errorf("good host should collect traces: %v", args)
	}
	if args := remoteNodeArgs("bad-host", time.Time{}, time.Time{}, nil); has(args, "--collect-traces") {
		t.Errorf("host with failed extractor deploy should not collect traces: %v", args)
	}
	if tr := hostTraceResult("bad-host", nil); tr == nil || tr.Status != "skipped" {
		t.Errorf("hostTraceResult for failed deploy: %+v", tr)
	}
	cmd := remoteShellCommand("good-host", "/opt/weka/weka-log-collector/wlc", "true", time.Minute)
	if !strings.Contains(cmd, remoteTraceExtractorPath) {
		t.Errorf("remote cleanup should remove trace_extractor: %s", cmd)
	}
}

func TestMergeArchive_ReturnsHostManifest(t *testing.T) {
	m := HostManifest{Hostname: "h1", Traces: &TraceResult{Status: "no_shards"}}
	mj, _ := json.Marshal(m)
	var src bytes.Buffer
	gw := gzip.NewWriter(&src)
	tw := tar.NewWriter(gw)
	for name, data := range map[string][]byte{
		"old/hosts/h1/collection_manifest.json": mj,
		"old/hosts/h1/system/uptime.txt":        []byte("up"),
	} {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))})
		_, _ = tw.Write(data)
	}
	tw.Close()
	gw.Close()

	var out bytes.Buffer
	otw := tar.NewWriter(&out)
	got, err := mergeArchive(otw, &src, "new")
	otw.Close()
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Traces == nil || got.Traces.Status != "no_shards" {
		t.Errorf("manifest not returned: %+v", got)
	}
}

func TestParseInputTime_Zones(t *testing.T) {
	want := time.Date(2026, 3, 4, 10, 30, 0, 0, time.UTC)
	for _, in := range []string{"2026-03-04T10:30:00Z", "2026-03-04T12:30:00+02:00", "2026-03-04T05:30:00-05:00"} {
		got, err := parseInputTime(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if !got.Equal(want) {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
		if got.Location() != time.Local {
			t.Errorf("%s: want local time, got zone %s", in, got.Location())
		}
	}
	local, err := parseInputTime("2026-03-04T10:30")
	if err != nil || !local.Equal(time.Date(2026, 3, 4, 10, 30, 0, 0, time.Local)) {
		t.Errorf("zone-less input should be local: %v %v", local, err)
	}
	if _, err := parseInputTime("yesterday"); err == nil {
		t.Errorf("expected error for unparseable input")
	}
}

func TestRemoteNodeArgs_UTCWindow(t *testing.T) {
	from := time.Date(2026, 3, 4, 12, 30, 15, 0, time.FixedZone("X", 2*3600))
	to := from.Add(45 * time.Minute)
	args := strings.Join(remoteNodeArgs("h", from, to, nil), " ")
	if !strings.Contains(args, "--start-time 2026-03-04T10:30:15Z") || !strings.Contains(args, "--end-time 2026-03-04T11:15:15Z") {
		t.Errorf("remote window not sent as UTC RFC3339 with seconds: %s", args)
	}
	// Round trip: what the remote parses is the same instant.
	got, err := parseInputTime(remoteTimeArg(from))
	if err != nil || !got.Equal(from) {
		t.Errorf("round trip: got %v (%v), want %v", got, err, from)
	}
}

func TestSplitCommaList(t *testing.T) {
	got := splitCommaList([]string{"drives0,compute0", " frontend0 ", ",", "s3"})
	want := []string{"drives0", "compute0", "frontend0", "s3"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestRemoteNodeArgs_ContainerNamesRepeated(t *testing.T) {
	args := remoteNodeArgs("h", time.Time{}, time.Time{}, []string{"drives0", "compute0"})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--container-name drives0") || !strings.Contains(joined, "--container-name compute0") {
		t.Errorf("each container name must be its own flag: %v", args)
	}
	if strings.Contains(joined, "drives0,compute0") {
		t.Errorf("names must not be comma-joined: %v", args)
	}
	// What the remote receives parses back to the same list.
	var f multiStringFlag
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--container-name" {
			_ = f.Set(args[i+1])
		}
	}
	if got := splitCommaList([]string(f)); strings.Join(got, ",") != "drives0,compute0" {
		t.Errorf("round trip: %v", got)
	}
}

func TestDeployFailureResults(t *testing.T) {
	hosts := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	res := deployFailureResults(hosts, map[string]string{"10.0.0.2": "Permission denied (publickey)"})
	if len(res) != 1 || res[0].Host != "10.0.0.2" || res[0].Err == nil || !strings.Contains(res[0].Err.Error(), "Permission denied") {
		t.Errorf("got %+v", res)
	}
}

const fakeVault = "hvs.FAKE-TEST-VAULT-TOKEN-XXXXXXXXXXXX"

func TestRedactSensitiveYAML_KeepsTimestampAndContext(t *testing.T) {
	cases := []struct{ input, want string }{
		{
			"Nov 25 10:00:01 node-1 kernel: Speculative Store Bypass: Mitigation: SSB disabled",
			"Nov 25 10:00:01 node-1 kernel: Speculative Store Bypass: [REDACTED]",
		},
		{
			"2026-11-25 10:00:01.123 app[42]: password: " + fakePW,
			"2026-11-25 10:00:01.123 app[42]: password: [REDACTED]",
		},
		{"join_secret: abc123", "join_secret: [REDACTED]"},
		{"password:", "password:"}, // no value: unchanged
	}
	for _, tc := range cases {
		if got := string(redactSensitiveYAML([]byte(tc.input))); got != tc.want {
			t.Errorf("got  %q\nwant %q", got, tc.want)
		}
	}
}

func TestRedactSensitiveValues_Assignments(t *testing.T) {
	cases := []struct{ input, want string }{
		{"export VAULT_TOKEN=" + fakeVault, "export VAULT_TOKEN=[REDACTED]"},
		{"DB_PASS=\"" + fakePW + " x\" next", "DB_PASS=[REDACTED] next"},
		{"password = " + fakePW, "password = [REDACTED]"},
		{"GET /api?user=bob&token=" + fakeBearer + "&x=1", "GET /api?user=bob&token=[REDACTED]&x=1"},
		{"A_SECRET=" + fakePW + " B_TOKEN=" + fakeBearer, "A_SECRET=[REDACTED] B_TOKEN=[REDACTED]"},
	}
	for _, tc := range cases {
		if got := string(redactSensitiveValues([]byte(tc.input))); got != tc.want {
			t.Errorf("got  %q\nwant %q", got, tc.want)
		}
	}
}

func TestRedactSensitiveValues_VaultAndWekaCLI(t *testing.T) {
	cases := []struct{ input, want string }{
		{"vault login " + fakeVault, "vault login [REDACTED]"},
		{"weka user login admin " + fakePW, "weka user login admin [REDACTED]"},
		{"weka user passwd " + fakePW + " --username bob", "weka user passwd [REDACTED] --username bob"},
		{"weka user add bob clusteradmin " + fakePW, "weka user add bob clusteradmin [REDACTED]"},
	}
	for _, tc := range cases {
		if got := string(redactSensitiveValues([]byte(tc.input))); got != tc.want {
			t.Errorf("got  %q\nwant %q", got, tc.want)
		}
	}
}

func TestRedactSensitiveValues_AssignmentNoFalsePositives(t *testing.T) {
	for _, in := range []string{
		"PWD=/root",
		"BOOT_IMAGE=/vmlinuz root=/dev/sda1 spec_store_bypass_disable=on",
		"max_token_count=5 token_bucket_size=10",
		"weka user login admin --org default",
		"weka user add bob clusteradmin --posix-uid 1001",
		"tokens: 5",
	} {
		if got := string(redactSensitiveValues([]byte(in))); got != in {
			t.Errorf("false positive:\ninput: %q\ngot:   %q", in, got)
		}
	}
}
