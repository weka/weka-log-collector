package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
		{"linux", "amd64", "trace_extractor-amd64"},
		{"linux", "arm64", "trace_extractor-arm64"},
		{"darwin", "arm64", "trace_extractor-amd64"},
		{"darwin", "amd64", "trace_extractor-amd64"},
	}
	for _, c := range cases {
		got := bundledTraceExtractorNames(c.goos, c.goarch)
		if len(got) != 2 || got[0] != c.want || got[1] != "trace_extractor" {
			t.Errorf("%s/%s: got %v, want [%s trace_extractor]", c.goos, c.goarch, got, c.want)
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
	if !regexp.MustCompile(`(?m)^sha256: [0-9a-f]{64}$`).MatchString(log) {
		t.Errorf("extractor.log missing the extractor's sha256:\n%s", log)
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
	if !strings.Contains(cmd, remoteTraceExtractorPath()) {
		t.Errorf("remote cleanup should remove trace_extractor: %s", cmd)
	}
}

// hostArchive builds a gzip'd tar shaped like a --node-only host archive:
// <root>/collection_manifest.json at the top, data under hosts/<host>/.
func hostArchive(t *testing.T, host string, m HostManifest) *bytes.Buffer {
	t.Helper()
	mj, _ := json.Marshal(m)
	var src bytes.Buffer
	gw := gzip.NewWriter(&src)
	tw := tar.NewWriter(gw)
	for _, e := range []struct {
		name string
		data []byte
	}{
		{"old-root/hosts/" + host + "/system/uptime.txt", []byte("up")},
		{"old-root/collection_manifest.json", mj},
	} {
		_ = tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0644, Size: int64(len(e.data))})
		_, _ = tw.Write(e.data)
	}
	tw.Close()
	gw.Close()
	return &src
}

func TestMergeArchive_ReturnsHostManifest(t *testing.T) {
	var out bytes.Buffer
	otw := tar.NewWriter(&out)
	for _, h := range []string{"h1", "h2"} {
		got, err := mergeArchive(otw, hostArchive(t, h, HostManifest{Hostname: h, Traces: &TraceResult{Status: "no_shards"}}), "new")
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || got.Hostname != h || got.Traces == nil || got.Traces.Status != "no_shards" {
			t.Errorf("%s: manifest not returned: %+v", h, got)
		}
	}
	otw.Close()

	names := map[string]bool{}
	tr := tar.NewReader(&out)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if names[hdr.Name] {
			t.Errorf("duplicate entry %s in merged archive", hdr.Name)
		}
		names[hdr.Name] = true
	}
	for _, want := range []string{"new/hosts/h1/collection_manifest.json", "new/hosts/h2/collection_manifest.json"} {
		if !names[want] {
			t.Errorf("missing %s; entries: %v", want, names)
		}
	}
	if names["new/collection_manifest.json"] {
		t.Errorf("host manifest left at the bundle root")
	}
}

func TestMergeArchive_UnsafeManifestHostnameStaysAtRoot(t *testing.T) {
	var out bytes.Buffer
	otw := tar.NewWriter(&out)
	if _, err := mergeArchive(otw, hostArchive(t, "h1", HostManifest{Hostname: "../evil"}), "new"); err != nil {
		t.Fatal(err)
	}
	otw.Close()
	tr := tar.NewReader(&out)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if strings.Contains(hdr.Name, "..") {
			t.Errorf("unsafe path written: %s", hdr.Name)
		}
	}
}

func TestRemoteKillCommand(t *testing.T) {
	oldCT, oldPath := collectTraces, resolvedTraceExtractorPath
	collectTraces, resolvedTraceExtractorPath = true, "/x/trace_extractor"
	defer func() { collectTraces, resolvedTraceExtractorPath = oldCT, oldPath }()

	cmd := remoteKillCommand("/opt/weka/weka-log-collector/weka-log-collector-123")
	tePat := pkillSelfSafePattern(remoteTraceExtractorPath()) + "( |$)"
	for _, want := range []string{
		"pkill -f '[w]eka-log-collector-123( |$)'",
		"pkill -f '" + tePat + "'",
		"rm -f /opt/weka/weka-log-collector/[w]eka-log-collector-123 " + pkillSelfSafePattern(remoteTraceExtractorPath()),
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("kill command %q missing %q", cmd, want)
		}
	}
	if remoteNeedsSudo() && !strings.Contains(cmd, `sudo sh -c "rm -f `) {
		t.Errorf("non-root cleanup must run the glob rm in a root shell: %q", cmd)
	}
	// The pkill patterns must not match their own command line, must match
	// the real process, and must not match a longer PID.
	for _, c := range []struct{ pat, real, other string }{
		{"[w]eka-log-collector-123( |$)", "/opt/weka/weka-log-collector/weka-log-collector-123 --local", "/opt/weka/weka-log-collector/weka-log-collector-1234 --local"},
		{tePat, remoteTraceExtractorPath() + " --verbose", remoteTraceExtractorPath() + "9 --verbose"},
	} {
		re := regexp.MustCompile(c.pat)
		if re.MatchString(cmd) {
			t.Errorf("pattern %q matches the cleanup command itself", c.pat)
		}
		if !re.MatchString(c.real) || !re.MatchString(strings.Fields(c.real)[0]) {
			t.Errorf("pattern %q does not match the process %q", c.pat, c.real)
		}
		if re.MatchString(c.other) {
			t.Errorf("pattern %q also matches another run %q", c.pat, c.other)
		}
	}
}

func TestRemoteTraceExtractorPathIsPerRun(t *testing.T) {
	p := remoteTraceExtractorPath()
	if p == legacyTraceExtractorPath || !strings.HasPrefix(p, wlcBaseDir+"/trace_extractor-") {
		t.Errorf("remote extractor path should be per-run: %s", p)
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

func TestBuildWindowedDefaultCmds_Events(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	cmds := buildWindowedDefaultCmdsAt(now.Add(-90*time.Minute), now.Add(-37*time.Minute-30*time.Second), now)
	byName := map[string]string{}
	for _, c := range cmds {
		byName[c.Name] = c.Cmd
	}
	major, warning := byName["weka_events_major"], byName["weka_events_warning"]
	for name, cmd := range map[string]string{"major": major, "warning": warning} {
		for _, want := range []string{"--start-time -2h", "--end-time -37m", "--num-results " + eventsMaxResults} {
			if !strings.Contains(cmd, want) {
				t.Errorf("%s events command %q missing %q", name, cmd, want)
			}
		}
	}
	if !strings.Contains(major, "--severity major") || !strings.Contains(warning, "--severity warning") {
		t.Errorf("severity: major=%q warning=%q", major, warning)
	}
	// Window ending now: no --end-time.
	for _, c := range buildWindowedDefaultCmdsAt(now.Add(-30*time.Minute), now.Add(-20*time.Second), now) {
		if strings.Contains(c.Cmd, "--end-time") {
			t.Errorf("window ending now should not pass --end-time: %q", c.Cmd)
		}
	}
}

func TestRedactSensitiveValues_NoNewlineCrossing(t *testing.T) {
	for _, in := range []string{
		"weka user passwd\nweka status -v",
		"weka user login\nweka status -v",
		"weka user add bob clusteradmin\nweka cluster drive",
		"VAULT_TOKEN=\nHOME=/root",
		"password =\n[server]",
		"--password\nnext-line",
		"Authorization: Bearer\nnext-line",
	} {
		if got := string(redactSensitiveValues([]byte(in))); got != in {
			t.Errorf("match crossed a line break:\ninput: %q\ngot:   %q", in, got)
		}
	}
}

func TestRedactSensitiveValues_WekaUserPasswordForms(t *testing.T) {
	cases := []struct{ input, want string }{
		{"weka user login admin 'P@ss w0rd'", "weka user login admin [REDACTED]"},
		{`weka user login admin "P@ss w0rd" --org acme`, "weka user login admin [REDACTED] --org acme"},
		{"weka user login --org acme admin " + fakePW, "weka user login --org acme admin [REDACTED]"},
		{"weka user login admin " + fakePW + ",x;y", "weka user login admin [REDACTED]"},
		{"weka -H node1 user login admin " + fakePW, "weka -H node1 user login admin [REDACTED]"},
		{"weka user passwd --username bob " + fakePW, "weka user passwd --username bob [REDACTED]"},
		{"weka user add bob clusteradmin --posix-uid 1001 " + fakePW, "weka user add bob clusteradmin --posix-uid 1001 [REDACTED]"},
		{`{"cmd":"weka user login admin ` + fakePW + `","x":1}`, `{"cmd":"weka user login admin [REDACTED]","x":1}`},
	}
	for _, tc := range cases {
		if got := string(redactSensitiveValues([]byte(tc.input))); got != tc.want {
			t.Errorf("got  %q\nwant %q", got, tc.want)
		}
	}
}

func TestRedactSensitive_SecretID(t *testing.T) {
	in := "Nov 25 10:00:01 host app: secret_id=" + fakePW + " role auth: approle"
	got := string(redactSensitive([]byte(in)))
	if strings.Contains(got, fakePW) {
		t.Errorf("secret_id value survived: %q", got)
	}
	if !strings.HasPrefix(got, "Nov 25 10:00:01 host app: ") {
		t.Errorf("line context lost: %q", got)
	}
}

func TestRedactAssignments_StringBoundaries(t *testing.T) {
	cases := []struct{ input, want string }{
		{`{"url":"https://h/api?token=","next":"value"}`, `{"url":"https://h/api?token=","next":"value"}`},
		{`["PATH=/usr/bin","VAULT_TOKEN=","HOME=/root"]`, `["PATH=/usr/bin","VAULT_TOKEN=","HOME=/root"]`},
		{`["A_TOKEN=","B_TOKEN=` + fakePW + `"]`, `["A_TOKEN=","B_TOKEN=[REDACTED]"]`},
		{`export DB_PASSWORD=\"` + fakePW + `\" && run`, `export DB_PASSWORD=[REDACTED] && run`},
		{`"cmd":"export DB_PASSWORD=\"` + fakePW + `\" && run"`, `"cmd":"export DB_PASSWORD=[REDACTED] && run"`},
		{"GITHUB_TOKEN= HOME=/root", "GITHUB_TOKEN= HOME=/root"},
		{"API_KEY= --y", "API_KEY= --y"},
		{"(hostId=1, secret=" + fakePW + ")", "(hostId=1, secret=[REDACTED])"},
		{"Config{user=bob, password=" + fakePW + "}", "Config{user=bob, password=[REDACTED]}"},
	}
	for _, tc := range cases {
		if got := string(redactSensitiveValues([]byte(tc.input))); got != tc.want {
			t.Errorf("got  %s\nwant %s", got, tc.want)
		}
	}
}

func TestRedactSensitive_QuotedKeysInText(t *testing.T) {
	cases := []struct{ input, want string }{
		{
			"# command: journalctl\nNov 25 10:00:01 h weka-agent[1]:     \"access_token\": \"" + fakeBearer + "\",",
			"# command: journalctl\nNov 25 10:00:01 h weka-agent[1]:     \"access_token\": \"[REDACTED]\",",
		},
		{"log: {'password': '" + fakePW + "', 'user': 'bob'}", "log: {'password': '[REDACTED]', 'user': 'bob'}"},
		{`msg="{\"refresh_token\": \"` + fakeBearer + `\", \"x\": 1}"`, `msg="{\"refresh_token\": \"[REDACTED]\", \"x\": 1}"`},
		{`{"Authorization": "Bearer ` + fakeBearer + `"}`, `{"Authorization": "[REDACTED]"}`},
	}
	for _, tc := range cases {
		if got := string(redactSensitive([]byte(tc.input))); got != tc.want {
			t.Errorf("got  %q\nwant %q", got, tc.want)
		}
	}
}

func TestRedactSensitive_MoreCLIPasswords(t *testing.T) {
	cases := []struct{ input, want string }{
		{"weka smb domain join Administrator " + fakePW, "weka smb domain join Administrator [REDACTED]"},
		{"weka smb domain leave Administrator " + fakePW, "weka smb domain leave Administrator [REDACTED]"},
		{"weka tenant create acme admin " + fakePW + " --ssd-quota 1TB", "weka tenant create acme admin [REDACTED] --ssd-quota 1TB"},
		{"weka org create acme admin " + fakePW, "weka org create acme admin [REDACTED]"},
		{"weka user ldap setup-ad ldap://dc1 corp.local reader " + fakePW, "weka user ldap setup-ad ldap://dc1 corp.local reader [REDACTED]"},
		{"weka user ldap setup ldap://h dc=x,dc=y person uid group member gid reader " + fakePW, "weka user ldap setup ldap://h dc=x,dc=y person uid group member gid reader [REDACTED]"},
		{"weka nfs ldap setup-ad-nokrb dc1 corp.local nfs01 Administrator " + fakePW, "weka nfs ldap setup-ad-nokrb dc1 corp.local nfs01 Administrator [REDACTED]"},
		{"weka nfs ldap setup-openldap ldap1 example.com cn=reader,dc=example,dc=com " + fakePW, "weka nfs ldap setup-openldap ldap1 example.com cn=reader,dc=example,dc=com [REDACTED]"},
	}
	for _, tc := range cases {
		if got := string(redactSensitive([]byte(tc.input))); got != tc.want {
			t.Errorf("got  %q\nwant %q", got, tc.want)
		}
	}
	// Without the password the CLI prompts; nothing to redact.
	for _, in := range []string{"weka smb domain join Administrator", "weka user ldap setup-ad ldap://dc1 corp.local reader", "weka tenant create acme admin"} {
		if got := string(redactSensitive([]byte(in))); got != in {
			t.Errorf("false positive: %q -> %q", in, got)
		}
	}
}

func TestRedactSensitive_ConfigCredentialNames(t *testing.T) {
	cases := []struct{ input, want string }{
		{"ldap_default_authtok = " + fakePW, "ldap_default_authtok = [REDACTED]"},
		{"MYSQL_PWD=" + fakePW, "MYSQL_PWD=[REDACTED]"},
	}
	for _, tc := range cases {
		if got := string(redactSensitive([]byte(tc.input))); got != tc.want {
			t.Errorf("got  %q\nwant %q", got, tc.want)
		}
	}
	for _, in := range []string{
		"Token timeouts used for authentication were updated: access=1d, refresh=30d, max_mount_token=30d",
		"PWD=/root OLDPWD=/home",
	} {
		if got := string(redactSensitive([]byte(in))); got != in {
			t.Errorf("non-secret value redacted:\ninput: %q\ngot:   %q", in, got)
		}
	}
}

func TestRedactSensitive_PreservesLayout(t *testing.T) {
	for _, in := range []string{"", "\n", "a\nb", "a\nb\n", "\n\nx\n\n", "no secrets here\nweka status\n"} {
		if got := string(redactSensitive([]byte(in))); got != in {
			t.Errorf("layout changed: %q -> %q", in, got)
		}
	}
	in := "l1\npassword: " + fakePW + "\nl3\n"
	if got := string(redactSensitive([]byte(in))); got != "l1\npassword: [REDACTED]\nl3\n" {
		t.Errorf("got %q", got)
	}
}

func TestExecutableTraceExtractor(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "te-0644")
	if err := os.WriteFile(plain, []byte("#!/bin/sh\n"), 0644); err != nil {
		t.Fatal(err)
	}
	p, cleanup, err := executableTraceExtractor(plain)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	orig, _ := os.Stat(plain)
	if p == plain || fi.Mode()&0111 == 0 || orig.Mode().Perm() != 0644 {
		t.Errorf("want an executable copy and the original untouched: path=%s mode=%v orig=%v", p, fi.Mode(), orig.Mode())
	}
	cleanup()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("cleanup did not remove %s", p)
	}

	exe := filepath.Join(dir, "te-0755")
	_ = os.WriteFile(exe, []byte("#!/bin/sh\n"), 0755)
	if p, _, err := executableTraceExtractor(exe); err != nil || p != exe {
		t.Errorf("executable file should be used as is: %s %v", p, err)
	}
}

func TestRemoteNodeArgs_TraceSkipReason(t *testing.T) {
	oldCT, oldPath := collectTraces, resolvedTraceExtractorPath
	collectTraces, resolvedTraceExtractorPath = true, "/x/trace_extractor"
	defer func() { collectTraces, resolvedTraceExtractorPath = oldCT, oldPath }()
	traceDeployFailed.Store("bad-host", "scp: write failed\nno space left")
	defer traceDeployFailed.Delete("bad-host")

	args := remoteNodeArgs("bad-host", time.Time{}, time.Time{}, nil)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--trace-skip-reason trace_extractor deploy failed: scp: write failed no space left") {
		t.Errorf("deploy-failed host should get a one-line --trace-skip-reason: %q", args)
	}
	if strings.Contains(joined, "--collect-traces") {
		t.Errorf("deploy-failed host must not get --collect-traces: %q", args)
	}
}

func TestRunTraceExtractor_Reasons(t *testing.T) {
	res, _ := runFakeExtractor(t, writeFakeExtractor(t, "verbose: /opt/weka/traces: 0 files match glob *.shard\nCollecting:\n  0 shards\n  0 histogram files\n", 0, 0), time.Minute)
	if res.Status != "no_shards" || res.Reason != "no shard files in the trace directory" {
		t.Errorf("empty dir: %+v", res)
	}
	res, _ = runFakeExtractor(t, writeFakeExtractor(t, "verbose: /opt/weka/traces: 3 files match glob *.shard\nverbose: /opt/weka/traces: 3 skipped (parse), 0 skipped (filter), 0 remaining\nCollecting:\n  0 shards\n", 0, 0), time.Minute)
	if res.Status != "no_shards" || !strings.Contains(res.Reason, "none of the 3 shard files") {
		t.Errorf("all unparsed: %+v", res)
	}
	res, _ = runFakeExtractor(t, writeFakeExtractor(t, sampleExtractorOutput, 30, 0), time.Second)
	if res.Status != "timeout" || res.Shards != 0 || !strings.Contains(res.Reason, "42 shards had been selected") {
		t.Errorf("timeout: %+v", res)
	}
	res, _ = runFakeExtractor(t, writeFakeExtractor(t, "Writing x ...\n", 0, 3), time.Minute)
	if res.Status != "failed" || !strings.HasPrefix(res.Reason, "exit status 3: Writing x") {
		t.Errorf("exit 3: %+v", res)
	}
}

func TestRunCommand_MinTimeout(t *testing.T) {
	r, out := runCommand(CommandSpec{Name: "slow", Cmd: "sleep 1; echo done", MinTimeout: 10 * time.Second}, 200*time.Millisecond)
	if r.Error != "" || !strings.Contains(string(out), "done") {
		t.Errorf("MinTimeout not applied: %+v %q", r, out)
	}
}

func TestBuildWindowedDefaultCmds_FutureStartAndTimeout(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	for _, c := range buildWindowedDefaultCmdsAt(now.Add(3*time.Hour), time.Time{}, now) {
		if strings.Contains(c.Cmd, "--start-time --") || strings.Contains(c.Cmd, "--start-time -0h") {
			t.Errorf("bad start offset: %q", c.Cmd)
		}
		if c.MinTimeout < eventsMinTimeout {
			t.Errorf("%s: MinTimeout %s", c.Name, c.MinTimeout)
		}
	}
}

func TestOneLine(t *testing.T) {
	if got := oneLine("a\n  b\tc ", 100); got != "a b c" {
		t.Errorf("got %q", got)
	}
	if got := oneLine("abcdef", 3); got != "abc" {
		t.Errorf("got %q", got)
	}
}

func TestRedactAssignments_NoLeaks(t *testing.T) {
	// Each of these must lose the secret (round-3 review: an earlier
	// structure-preserving heuristic let them through).
	for _, in := range []string{
		`bash -c "export PGPASSWORD='` + fakePW + `'"`,
		`"cmd": "export VAULT_TOKEN='` + fakePW + `'"`,
		`sh -c 'export DB_PASSWORD="` + fakePW + `"'`,
		`<user name="bob" password="` + fakePW + `"/>`,
		`login failed, password="` + fakePW + `".`,
		`login failed: password="` + fakePW + `": bad`,
		`Environment="DB_PASSWORD='` + fakePW + `'"`,
		`[{"env":"VAULT_TOKEN='` + fakePW + `'"}]`,
		"DB_PASSWORD=Xy)9k}Lm]" + fakePW,
		"export API_TOKEN=ab]" + fakePW,
		"client_secret=ab}" + fakePW,
		"password=)" + fakePW,
		"AWS_SECRET_ACCESS_KEY=/3kRtYbE9xQ+" + fakePW,
		"aws_secret_access_key = /3kRtYbE9xQ+" + fakePW,
		"WEKA_TOKEN=/opt/weka/" + fakePW,
	} {
		got := string(redactSensitive([]byte(in)))
		if strings.Contains(got, fakePW) {
			t.Errorf("secret leaked:\ninput: %q\ngot:   %q", in, got)
		}
	}
	// A duration-shaped value ("2024y") under a password name is still a
	// password. Built from parts so secret scanners do not flag the test.
	durationShaped := "DB_" + "PASSWORD=" + "2024" + "y"
	if got := string(redactSensitive([]byte(durationShaped))); got != "DB_PASSWORD=[REDACTED]" {
		t.Errorf("duration-shaped password kept: %q", got)
	}
	// Structure that must survive.
	for in, want := range map[string]string{
		`\"VAULT_TOKEN=\",\"PATH=/usr/bin\"`:        `\"VAULT_TOKEN=\",\"PATH=/usr/bin\"`,
		"(hostId=1, secret=" + fakePW + ")":         "(hostId=1, secret=[REDACTED])",
		"Config{user=bob, password=" + fakePW + "}": "Config{user=bob, password=[REDACTED]}",
		"[password=" + fakePW + "]":                 "[password=[REDACTED]]",
		`{"url":"https://h/api?token=","next":"v"}`: `{"url":"https://h/api?token=","next":"v"}`,
	} {
		if got := string(redactSensitive([]byte(in))); got != want {
			t.Errorf("got  %q\nwant %q", got, want)
		}
	}
}

func TestRedactSensitive_CLIValuelessFlagsAndCase(t *testing.T) {
	for in, want := range map[string]string{
		"weka smb domain join Administrator --debug " + fakePW:      "weka smb domain join Administrator --debug [REDACTED]",
		"weka nfs ldap setup-openldap s d cn=r --force " + fakePW:   "weka nfs ldap setup-openldap s d cn=r --force [REDACTED]",
		"Weka user login admin " + fakePW:                           "Weka user login admin [REDACTED]",
		"weka smb domain join Administrator " + fakePW + " --debug": "weka smb domain join Administrator [REDACTED] --debug",
	} {
		if got := string(redactSensitive([]byte(in))); got != want {
			t.Errorf("got  %q\nwant %q", got, want)
		}
	}
}

// refRedactAll is redactSensitive without any prefilter: every pass on every
// line. The fast path must give byte-identical output.
func refRedactAll(b []byte) []byte {
	isJSON := isJSONDocument(b)
	if looksLikeJSON(b) {
		b = redactSensitiveJSON(b)
	}
	lines := bytes.Split(b, []byte("\n"))
	for i, line := range lines {
		lines[i] = redactLine(line, nil, isJSON, false)
	}
	return redactSplitFlagValues(bytes.Join(lines, []byte("\n")))
}

func TestRedactSensitive_PrefilterEquivalence(t *testing.T) {
	src, err := os.ReadFile("main_test.go")
	if err != nil {
		t.Fatal(err)
	}
	extra := strings.Join([]string{
		"password\r: " + fakePW,
		"secret\f: " + fakePW,
		"to\u212aen: " + fakePW,
		"pa\u017f\u017fword=" + fakePW,
		"API_\u212aEY=" + fakePW,
		"plain line without anything",
	}, "\n")
	for _, in := range [][]byte{src, []byte(strings.ToUpper(string(src))), []byte(extra)} {
		fast, ref := redactSensitive(in), refRedactAll(in)
		if !bytes.Equal(fast, ref) {
			fl, rl := bytes.Split(fast, []byte("\n")), bytes.Split(ref, []byte("\n"))
			for i := range fl {
				if i < len(rl) && !bytes.Equal(fl[i], rl[i]) {
					t.Errorf("line %d differs:\nfast: %q\nref:  %q", i, fl[i], rl[i])
				}
			}
		}
	}
	got := string(redactSensitive([]byte(extra)))
	if strings.Count(got, fakePW) != 0 {
		t.Errorf("secret survived in folded/whitespace cases:\n%s", got)
	}
}

func TestRemoteFailure(t *testing.T) {
	log := "weka-log-collector 0.1.0\nProfile: default\n[WARN]  x\n[ERROR] Upload failed: no uploader\nCleanup done\n"
	if err := remoteFailure(1, log); err.Error() != "remote run failed (exit 1): Upload failed: no uploader" {
		t.Errorf("got %v", err)
	}
	if err := remoteFailure(255, "ssh: connect to host x port 22: Connection refused\n"); !strings.HasPrefix(err.Error(), "SSH failed (exit 255): ssh: connect") {
		t.Errorf("got %v", err)
	}
	if err := remoteFailure(2, "a\nlast line\n"); err.Error() != "remote run failed (exit 2): last line" {
		t.Errorf("got %v", err)
	}
}

func TestParseExtractorOutput_ShardVsHistogramParseFailures(t *testing.T) {
	out := "verbose: /opt/weka/traces: 5 files match glob *.shard\n" +
		"verbose: /opt/weka/traces/histograms: 4 skipped (parse), 0 skipped (filter), 0 remaining\n" +
		"verbose: /opt/weka/traces: 1 skipped (parse), 4 skipped (filter), 0 remaining\nCollecting:\n  0 shards\n"
	var r TraceResult
	seen, unparsed := parseExtractorOutput(out, &r)
	if seen != 5 || unparsed != 1 || r.UnparsedFiles != 5 {
		t.Errorf("seen=%d unparsed=%d total=%d", seen, unparsed, r.UnparsedFiles)
	}
}

func TestRedactAssignments_FinalCheckCases(t *testing.T) {
	// Separator-only "values" in compact JSON / argv arrays stay structure.
	for _, in := range []string{
		`["foo token=","-v"]`,
		`["sh","-c","export TOKEN=","--x"]`,
		`["export TOKEN=",""]`,
		`{"Env":["A=1 SECRET_TOKEN=","/opt/bin"]}`,
		`{"a":"x?token=","/b":1}`,
		`{\"args\":[\"export TOKEN=\",\"-v\"]}`,
		`{"a":"x?token=", "next": 1}`,
	} {
		if got := string(redactSensitive([]byte(in))); got != in {
			t.Errorf("structure changed:\ninput: %s\ngot:   %s", in, got)
		}
	}
	// Escaped quotes inside a double-quoted value are part of the value.
	for in, want := range map[string]string{
		`export PGPASSWORD="pa\"ss1" && psql`: `export PGPASSWORD=[REDACTED] && psql`,
		`PASSWORD="ab\"cd"`:                   `PASSWORD=[REDACTED]`,
	} {
		if got := string(redactSensitive([]byte(in))); got != want {
			t.Errorf("got  %s\nwant %s", got, want)
		}
	}
}

func TestRedactSensitive_CLIShortValuelessFlags(t *testing.T) {
	for in, want := range map[string]string{
		"weka smb domain leave -f Administrator '" + fakePW + "'": "weka smb domain leave -f Administrator [REDACTED]",
		"weka smb domain leave Administrator -f '" + fakePW + "'": "weka smb domain leave Administrator -f [REDACTED]",
		"weka user login -U admin " + fakePW:                      "weka user login -U admin [REDACTED]",
		"weka user add -R bob clusteradmin " + fakePW:             "weka user add -R bob clusteradmin [REDACTED]",
		"weka user login --without-agent admin " + fakePW:         "weka user login --without-agent admin [REDACTED]",
		"weka user login --UTC admin " + fakePW:                   "weka user login --UTC admin [REDACTED]",
	} {
		if got := string(redactSensitive([]byte(in))); got != want {
			t.Errorf("got  %q\nwant %q", got, want)
		}
	}
}

func TestRemoteErrorSummary(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plan\n[ERROR] Not enough free space on /opt/weka: only 150 MB available\n[ERROR] Tip: use --output /path\n[ERROR]      Or free up space on /opt/weka first.\n",
			"Not enough free space on /opt/weka: only 150 MB available"},
		{"[ERROR] Tip: use --output to write to a different location\n", "Tip: use --output to write to a different location"},
		{"log\npanic: runtime error: index out of range\n\ngoroutine 1 [running]:\nmain.main()\n\t/build/main.go:7011 +0x1c4\n", "panic: runtime error: index out of range"},
		{"a\nlast\n", "last"},
	}
	for _, c := range cases {
		if got := remoteErrorSummary(c.in); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}

func TestCopyExecutable_FailureLeavesNothing(t *testing.T) {
	src := filepath.Join(t.TempDir(), "te")
	_ = os.WriteFile(src, []byte("#!/bin/sh\n"), 0644)
	if _, err := copyExecutable(src, filepath.Join(t.TempDir(), "missing-dir")); err == nil {
		t.Errorf("expected an error for a missing directory")
	}
	dir := t.TempDir()
	p, err := copyExecutable(src, dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0755 || filepath.Dir(p) != dir {
		t.Errorf("copy %s mode %v", p, fi.Mode())
	}
}

// fakeKubectl puts a kubectl script on PATH that sleeps, then prints "ok".
func fakeKubectl(t *testing.T, sleepSecs int) {
	t.Helper()
	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\nsleep %d\necho ok\n", sleepSecs)
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestKubectlRunner_TimeoutIsDistinct(t *testing.T) {
	fakeKubectl(t, 1)
	kc := &kubectlRunner{timeout: 300 * time.Millisecond}
	start := time.Now()
	_, err := kc.execInPod("ns", "pod", "", "weka", "events")
	if !errors.Is(err, errKubectlTimeout) {
		t.Fatalf("want errKubectlTimeout, got %v", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("timeout not enforced: %s", d)
	}
	// A longer per-call timeout lets the same command finish.
	out, err := kc.execInPodTimeout(10*time.Second, "ns", "pod", "", "weka", "events")
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Errorf("execInPodTimeout: %q %v", out, err)
	}
}

func TestK8sEventsCommandHasMinTimeout(t *testing.T) {
	found := false
	for _, spec := range clusterWideCLICommands {
		if strings.Join(spec.cmd[:2], " ") == "weka events" {
			found = true
			if k8sCommandMinTimeout[spec.name] < eventsMinTimeout {
				t.Errorf("%s: min timeout %s, want at least %s", spec.name, k8sCommandMinTimeout[spec.name], eventsMinTimeout)
			}
		}
	}
	if !found {
		t.Errorf("no weka events command in clusterWideCLICommands")
	}
	for name := range k8sCommandMinTimeout {
		ok := false
		for _, spec := range clusterWideCLICommands {
			ok = ok || spec.name == name
		}
		if !ok {
			t.Errorf("k8sCommandMinTimeout names unknown command %s", name)
		}
	}
}

func TestRedactSplitFlagValues_DescribeArgs(t *testing.T) {
	in := "    Args:\n      --log-level\n      debug\n      --api-token\n      " + fakeBearer + "\n      --join-secret\n      --next-flag\n    Ready: True\n"
	want := "    Args:\n      --log-level\n      debug\n      --api-token\n      [REDACTED]\n      --join-secret\n      --next-flag\n    Ready: True\n"
	if got := string(redactSensitive([]byte(in))); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if got := string(redactSensitive([]byte("--password\n"))); got != "--password\n" {
		t.Errorf("flag with nothing after it changed: %q", got)
	}
}

func TestRedactSensitive_PrefixedPodLogsGetKeyPass(t *testing.T) {
	in := "[pod/cl-compute-1/weka-container] 2026-11-27 10:00:01 setup password: " + fakePW + "\n[pod/cl-compute-1/weka-container] ok\n"
	got := string(redactSensitive([]byte(in)))
	if strings.Contains(got, fakePW) {
		t.Errorf("prefixed pod log line not redacted:\n%s", got)
	}
	if isJSONDocument([]byte(in)) || isJSONDocument([]byte("[    0.000000] Linux version")) {
		t.Errorf("log text classified as a JSON document")
	}
	if !isJSONDocument([]byte(` {"a": 1, "join_secret": ["x"]}`)) || !isJSONDocument([]byte("[\n {\"a\": 1}\n]\n")) {
		t.Errorf("real JSON not classified as a JSON document")
	}
}

// JSON that does not parse (cut short by a command timeout, or followed by a
// trailer line) still gets the whole-document pass, the only one that
// redacts a multi-line array such as join_secret.
func TestRedactSensitive_InvalidJSONGetsArrayPass(t *testing.T) {
	doc := "{\n  \"name\": \"c1\",\n  \"join_secret\": [\n    \"" + fakePW + "\"\n  ],\n  \"other\": \"ok\""
	for name, in := range map[string]string{
		"truncated":       doc + ",\n  \"more\": [\n    \"x",
		"trailer":         doc + "\n}\nerror: command timed out\n",
		"array top level": "[\n {\"join_secret\": [\n   \"" + fakePW + "\"\n ]},\n {\"a\": ",
	} {
		if isJSONDocument([]byte(in)) {
			t.Fatalf("%s: test input parses as JSON", name)
		}
		got := string(redactSensitive([]byte(in)))
		if strings.Contains(got, fakePW) {
			t.Errorf("%s: join_secret array not redacted:\n%s", name, got)
		}
		if !strings.Contains(got, `"other": "ok"`) && name != "array top level" {
			t.Errorf("%s: unrelated key changed:\n%s", name, got)
		}
	}
}

func TestRedactSensitive_NoDoubleRedaction(t *testing.T) {
	for in, want := range map[string]string{
		"weka agent --token=" + fakeSRT:      "weka agent --token=[REDACTED]",
		"proc --join-secret=" + fakeBearer:   "proc --join-secret=[REDACTED]",
		"x --password=" + fakePW + " --next": "x --password=[REDACTED] --next",
	} {
		if got := string(redactSensitive([]byte(in))); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestPodsPreferring(t *testing.T) {
	pods := []string{"a", "b", "c"}
	if got := strings.Join(podsPreferring(pods, "b"), ","); got != "b,a,c" {
		t.Errorf("got %s", got)
	}
	if got := strings.Join(podsPreferring(pods, ""), ","); got != "a,b,c" {
		t.Errorf("got %s", got)
	}
	if got := strings.Join(podsPreferring(pods, "zz"), ","); got != "a,b,c" {
		t.Errorf("got %s", got)
	}
}

// runClusterWideWithFakeKubectl runs runK8sClusterWideCommands against a fake
// kubectl script and returns the archived command files and the call log.
func runClusterWideWithFakeKubectl(t *testing.T, script string, pods []string) (map[string]bool, string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	full := "#!/bin/sh\necho \"$*\" >> " + logPath + "\n" + script
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(full), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	saved := map[string]time.Duration{}
	for name, d := range k8sCommandMinTimeout {
		saved[name] = d
		k8sCommandMinTimeout[name] = time.Second
	}
	defer func() {
		for name, d := range saved {
			k8sCommandMinTimeout[name] = d
		}
	}()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	runK8sClusterWideCommands(tw, &kubectlRunner{timeout: 300 * time.Millisecond}, "root", "ns", pods, &k8sManifest{})
	tw.Close()
	files := map[string]bool{}
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		files[hdr.Name] = true
	}
	calls, _ := os.ReadFile(logPath)
	return files, string(calls)
}

func TestK8sClusterWide_HungFirstPodStillGetsEvents(t *testing.T) {
	// c-compute-0 never answers; c-compute-1 answers everything.
	script := "case \"$2\" in c-compute-0) exec sleep 30;; esac\necho ok\n"
	files, _ := runClusterWideWithFakeKubectl(t, script, []string{"c-compute-0", "c-compute-1"})
	for _, f := range []string{"root/weka-commands/weka_status.txt", "root/weka-commands/weka_events_major.txt", "root/weka-commands/weka_events_warning.txt"} {
		if !files[f] {
			t.Errorf("%s missing; got %v", f, files)
		}
	}
}

func TestK8sClusterWide_SlowEventsNotRetriedOnOtherPods(t *testing.T) {
	// Every pod answers quickly, but weka events itself is slow.
	script := "case \"$*\" in *events*) exec sleep 30;; esac\necho ok\n"
	start := time.Now()
	files, calls := runClusterWideWithFakeKubectl(t, script, []string{"c-compute-0", "c-compute-1", "c-compute-2"})
	if files["root/weka-commands/weka_events_major.txt"] {
		t.Errorf("events should have timed out")
	}
	// One call per events command (major, warning), never repeated on other pods.
	if n, want := strings.Count(calls, "events"), len(k8sCommandMinTimeout); n != want {
		t.Errorf("slow events queries ran %d times, want %d (no per-pod retry):\n%s", n, want, calls)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("took %s", d)
	}
}

func TestWindowIsEmpty(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		from, to time.Time
		want     bool
	}{
		{now.Add(time.Hour), time.Time{}, true},              // --local, future start, no end
		{now.Add(time.Hour), now, true},                      // cluster mode, end fixed at now
		{now.Add(-time.Hour), time.Time{}, false},            // normal --local
		{now.Add(-time.Hour), now.Add(-2 * time.Hour), true}, // end before start
		{time.Time{}, time.Time{}, false},
	}
	for i, c := range cases {
		if got := windowIsEmpty(c.from, c.to, now); got != c.want {
			t.Errorf("case %d: got %v, want %v", i, got, c.want)
		}
	}
}

func TestK8sHasBothEventsFiles(t *testing.T) {
	names := map[string]bool{}
	for _, spec := range clusterWideCLICommands {
		names[spec.name] = true
	}
	for _, n := range []string{"weka_events_major.txt", "weka_events_warning.txt"} {
		if !names[n] {
			t.Errorf("k8s clusterWideCLICommands lacks %s", n)
		}
	}
}

func TestRunTraceExtractor_LocalWindowEndFixed(t *testing.T) {
	// --local leaves "to" unset; the extractor must still get --to, set to
	// the time the 60 minute cap was checked, not "now" after log collection.
	end := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	old := traceWindowEnd
	traceWindowEnd = end
	defer func() { traceWindowEnd = old }()

	oldPath, oldTimeout := resolvedTraceExtractorPath, traceTimeout
	resolvedTraceExtractorPath, traceTimeout = writeFakeExtractor(t, sampleExtractorOutput, 0, 0), time.Minute
	defer func() { resolvedTraceExtractorPath, traceTimeout = oldPath, oldTimeout }()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	runTraceExtractor(tw, "root", "h1", end.Add(-time.Hour), time.Time{})
	tw.Close()
	tr := tar.NewReader(&buf)
	var log string
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if strings.HasSuffix(hdr.Name, "extractor.log") {
			b, _ := io.ReadAll(tr)
			log = string(b)
		}
	}
	if !strings.Contains(log, "--to "+end.Format(time.RFC3339)) {
		t.Errorf("extractor did not get the fixed window end:\n%s", log)
	}
}

func TestExitProcessRunsCleanups(t *testing.T) {
	if path := os.Getenv("WLC_TEST_EXIT_CLEANUP"); path != "" {
		// Child: register a cleanup that removes the file, then exit.
		addExitCleanup(func() { os.Remove(path) })
		exitProcess(3)
		return
	}
	path := filepath.Join(t.TempDir(), "copy")
	if err := os.WriteFile(path, []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestExitProcessRunsCleanups$")
	cmd.Env = append(os.Environ(), "WLC_TEST_EXIT_CLEANUP="+path)
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
		t.Fatalf("want exit code 3, got %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("cleanup did not run before exit: %s still exists", path)
	}
}

func TestRemoteNodeArgs_RunLevelTraceSkip(t *testing.T) {
	oldCT, oldReason := collectTraces, traceSkipReason
	collectTraces, traceSkipReason = false, "time window is 120 minutes (max: 60 minutes)"
	defer func() { collectTraces, traceSkipReason = oldCT, oldReason }()
	args := strings.Join(remoteNodeArgs("h", time.Time{}, time.Time{}, nil), " ")
	if !strings.Contains(args, "--trace-skip-reason time window is 120 minutes (max: 60 minutes)") || strings.Contains(args, "--collect-traces") {
		t.Errorf("run-level skip not forwarded: %s", args)
	}
}

func TestRemoteTraceLine(t *testing.T) {
	stderr := "Traces:   /opt/weka/weka-log-collector/trace_extractor-1  (filter: --all)\n" +
		"Traces:   ./te is not executable; running a copy (/tmp/x)\n" +
		"[traces] 42 shards, 7 histogram files in 3s\n\nCollection complete → x\n" +
		"  Commands: 80 total, 0 failed\n  Traces:   ok, 42 shards\n"
	if got := remoteTraceLine(stderr); got != "ok, 42 shards" {
		t.Errorf("got %q", got)
	}
	if got := remoteTraceLine("no traces here\n"); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestEarlySignalHandler(t *testing.T) {
	switch os.Getenv("WLC_TEST_EARLY_SIG") {
	case "handle", "handover":
		path := os.Getenv("WLC_TEST_EARLY_FILE")
		addExitCleanup(func() { os.Remove(path) })
		startEarlySignalHandler(false)
		if os.Getenv("WLC_TEST_EARLY_SIG") == "handover" {
			stopEarlySignalHandler()
		}
		_ = os.WriteFile(path+".ready", nil, 0644)
		time.Sleep(10 * time.Second)
		os.Exit(7) // not reached when the signal is handled
	}
	for _, mode := range []string{"handle", "handover"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "copy")
		_ = os.WriteFile(path, []byte("x"), 0755)
		cmd := exec.Command(os.Args[0], "-test.run=^TestEarlySignalHandler$")
		cmd.Env = append(os.Environ(), "WLC_TEST_EARLY_SIG="+mode, "WLC_TEST_EARLY_FILE="+path)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 100; i++ {
			if _, err := os.Stat(path + ".ready"); err == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		_ = cmd.Process.Signal(os.Interrupt)
		err := cmd.Wait()
		_, statErr := os.Stat(path)
		switch mode {
		case "handle":
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || !os.IsNotExist(statErr) {
				t.Errorf("handle: want exit 1 and copy removed, got err=%v copyErr=%v", err, statErr)
			}
		case "handover":
			// After stopEarlySignalHandler the early handler must not act:
			// the default SIGINT action ends the process, the file stays.
			if err == nil || statErr != nil {
				t.Errorf("handover: want default signal exit with the file kept, got err=%v copyErr=%v", err, statErr)
			}
		}
	}
}

func TestRunK8sMode_UploadFailureExitCode(t *testing.T) {
	if os.Getenv("WLC_TEST_K8S_UPLOAD") != "" {
		os.Exit(runK8sMode([]string{"--upload", "--cmd-timeout", "5s", "--output", os.Getenv("WLC_TEST_K8S_OUT")}))
	}
	dir := t.TempDir()
	// A kubectl that only answers "version"; everything else fails.
	script := "#!/bin/sh\ncase \"$1\" in version) echo 'Client Version: v1.29.0'; exit 0;; esac\necho 'error: not found' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunK8sMode_UploadFailureExitCode$")
	cmd.Env = append(os.Environ(), "WLC_TEST_K8S_UPLOAD=1", "WLC_TEST_K8S_OUT="+filepath.Join(dir, "b.tar.gz"),
		"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Errorf("want exit 1 after a failed k8s upload, got %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Upload failed") {
		t.Errorf("exit 1 did not come from the upload step:\n%s", out)
	}
}

func TestUploadSignalSetup_UnderClusterHandler(t *testing.T) {
	// Under the cluster handler the upload must not install its own handler
	// (it would exit before the remote collectors are killed); it registers
	// its cleanup for the cluster handler to run instead.
	clusterSignalHandler.Store(true)
	defer clusterSignalHandler.Store(false)
	exitCleanupsMu.Lock()
	before := len(exitCleanups)
	exitCleanupsMu.Unlock()
	ran := false
	undo := uploadSignalSetup(func() { ran = true })
	undo()
	exitCleanupsMu.Lock()
	added := exitCleanups[before:]
	exitCleanups = exitCleanups[:before]
	exitCleanupsMu.Unlock()
	if len(added) != 1 {
		t.Fatalf("want the cleanup registered once, got %d", len(added))
	}
	added[0]()
	if !ran {
		t.Errorf("registered cleanup is not the upload's")
	}
}

func TestUploadSignalSetup_OwnHandler(t *testing.T) {
	if path := os.Getenv("WLC_TEST_UPLOAD_SIG"); path != "" {
		undo := uploadSignalSetup(func() { os.Remove(path) })
		defer undo()
		_ = os.WriteFile(path+".ready", nil, 0644)
		time.Sleep(10 * time.Second)
		os.Exit(7)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "staged")
	_ = os.WriteFile(path, []byte("x"), 0644)
	cmd := exec.Command(os.Args[0], "-test.run=^TestUploadSignalSetup_OwnHandler$")
	cmd.Env = append(os.Environ(), "WLC_TEST_UPLOAD_SIG="+path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(path + ".ready"); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = cmd.Process.Signal(os.Interrupt)
	err := cmd.Wait()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Errorf("want exit 1 from the upload handler, got %v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("staged file not cleaned up")
	}
}
