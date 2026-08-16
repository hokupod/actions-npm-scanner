package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(t *testing.T) {
	workflowPath := writeWorkflowWithVulnerableAction(t)
	output, err := runScannerCommand(workflowPath)
	assertExitCode(t, err, 1, output)

	expectedStrings := []string{
		"Scanning workflow: " + workflowPath,
		"⚠️ Found vulnerabilities.",
		"Workflows scanned: 1",
		"Actions scanned: 1",
		"Vulnerabilities found: 1",
		"Errors: 0",
		"Vulnerability details:",
		workflowPath + " | some-user/some-action-with-vulnerable-dep@v1: Found vulnerable package @ctrl/tinycolor with version 4.1.1 in package.json",
	}

	for _, expected := range expectedStrings {
		assertContains(t, output, expected)
	}
	assertNotContains(t, output, "🔍 Scanning action")
	assertNotContains(t, output, "package-lock.json not found. Skipping.")
}

func TestMainVerboseIncludesDetailedOutputAndSummary(t *testing.T) {
	workflowPath := writeWorkflowWithVulnerableAction(t)
	output, err := runScannerCommand("--verbose", workflowPath)
	assertExitCode(t, err, 1, output)

	expectedStrings := []string{
		"🔍 Scanning action some-user/some-action-with-vulnerable-dep@v1...",
		"🔍 Scanning package.json...",
		"   package-lock.json not found. Skipping.",
		"   yarn.lock not found. Skipping.",
		"   pnpm-lock.yaml not found. Skipping.",
		"⚠️ Found vulnerabilities:",
		"-  Found vulnerable package @ctrl/tinycolor with version 4.1.1 in package.json",
		"Scan finished for action some-user/some-action-with-vulnerable-dep@v1.",
		"Vulnerabilities found: 1",
	}

	for _, expected := range expectedStrings {
		assertContains(t, output, expected)
	}
}

func TestWorkflowScanSkipsAlreadyScannedAction(t *testing.T) {
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "workflow.yml")
	writeTestFile(t, workflowPath, `
jobs:
  build:
    steps:
      - uses: some-user/some-action-with-vulnerable-dep@v1
      - uses: some-user/some-action-with-vulnerable-dep@v1
`)

	output, err := runScannerCommand("-v", workflowPath)
	assertExitCode(t, err, 1, output)

	downloadLog := "Downloading action some-user/some-action-with-vulnerable-dep@v1..."
	if count := strings.Count(output, downloadLog); count != 1 {
		t.Errorf("expected %q once, got %d.\nOutput:\n%s", downloadLog, count, output)
	}

	skipLog := "Skipping already scanned action some-user/some-action-with-vulnerable-dep@v1."
	if !strings.Contains(output, skipLog) {
		t.Errorf("expected output to contain %q.\nOutput:\n%s", skipLog, output)
	}
}

func TestLocalScanFileWithVulnerability(t *testing.T) {
	tmpDir := t.TempDir()
	packageJSONPath := filepath.Join(tmpDir, "package.json")
	writeTestFile(t, packageJSONPath, `{
	  "dependencies": {
	    "@ctrl/tinycolor": "4.1.1"
	  }
	}`)

	output, err := runScannerCommand("--local", packageJSONPath)
	assertExitCode(t, err, 1, output)

	expectedStrings := []string{
		"⚠️ Found vulnerabilities.",
		"Workflows scanned: 0",
		"Actions scanned: 0",
		"Vulnerabilities found: 1",
		"Errors: 0",
		"Vulnerability details:",
		"Found vulnerable package @ctrl/tinycolor with version 4.1.1 in package.json",
	}
	for _, expected := range expectedStrings {
		assertContains(t, output, expected)
	}
	assertNotContains(t, output, "🔍 Scanning local file:")
}

func TestLocalScanDirectoryWithVulnerability(t *testing.T) {
	tmpDir := t.TempDir()
	writeTestFile(t, filepath.Join(tmpDir, "package.json"), `{
	  "dependencies": {
	    "@ctrl/tinycolor": "4.1.1"
	  }
	}`)

	output, err := runScannerCommand("--local", tmpDir)
	assertExitCode(t, err, 1, output)

	expectedStrings := []string{
		"⚠️ Found vulnerabilities.",
		"Workflows scanned: 0",
		"Actions scanned: 0",
		"Vulnerabilities found: 1",
		"Found vulnerable package @ctrl/tinycolor with version 4.1.1 in package.json",
	}
	for _, expected := range expectedStrings {
		assertContains(t, output, expected)
	}
	assertNotContains(t, output, "Scanning local path:")
	assertNotContains(t, output, "🔍 Scanning package.json...")
}

// A pnpm v9 lockfile used to abort the whole directory scan, which silently
// dropped the findings of the package.json next to it.
func TestLocalScanDirectoryWithPnpmV9Lockfile(t *testing.T) {
	tmpDir := t.TempDir()
	writeTestFile(t, filepath.Join(tmpDir, "package.json"), `{
	  "dependencies": {
	    "@ctrl/tinycolor": "4.1.1"
	  }
	}`)
	writeTestFile(t, filepath.Join(tmpDir, "pnpm-lock.yaml"), `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      '@ctrl/tinycolor':
        specifier: ^4.1.1
        version: 4.1.1

packages:

  '@ctrl/tinycolor@4.1.1':
    resolution: {integrity: sha512-...}
`)

	output, err := runScannerCommand("--local", tmpDir)
	assertExitCode(t, err, 1, output)

	expectedStrings := []string{
		"Vulnerabilities found: 2",
		"Files failed: 0",
		"Errors: 0",
		"Found vulnerable package @ctrl/tinycolor with version 4.1.1 in package.json",
		"Found vulnerable package @ctrl/tinycolor with version 4.1.1 in pnpm-lock.yaml",
	}
	for _, expected := range expectedStrings {
		assertContains(t, output, expected)
	}
}

// One unparsable dependency file must not discard the findings of the others.
func TestLocalScanDirectoryKeepsFindingsWhenDependencyFileFails(t *testing.T) {
	tmpDir := t.TempDir()
	writeTestFile(t, filepath.Join(tmpDir, "package.json"), `{
	  "dependencies": {
	    "@ctrl/tinycolor": "4.1.1"
	  }
	}`)
	writeTestFile(t, filepath.Join(tmpDir, "pnpm-lock.yaml"), "packages: [\n")

	output, err := runScannerCommand("--local", tmpDir)
	assertExitCode(t, err, 1, output)

	expectedStrings := []string{
		"Found vulnerable package @ctrl/tinycolor with version 4.1.1 in package.json",
		"Vulnerabilities found: 1",
		"Files failed: 1",
		"Errors: 1",
	}
	for _, expected := range expectedStrings {
		assertContains(t, output, expected)
	}
}

func TestFailOnErrorExitsWithDedicatedCode(t *testing.T) {
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "workflow.yml")
	writeTestFile(t, workflowPath, "jobs:\n  build:\n    steps: [\n")

	output, err := runScannerBinary(t, "--fail-on-error", workflowPath)
	assertExitCode(t, err, 2, output)

	expectedStrings := []string{
		"✅ No vulnerabilities found.",
		"Files failed: 1",
		"Errors: 1",
		"Error details:",
	}
	for _, expected := range expectedStrings {
		assertContains(t, output, expected)
	}
}

// A top-level scan error (here: an unparsable single file) exits before a
// summary is produced, but --fail-on-error must still turn it into exit 2.
func TestFailOnErrorAppliesToTopLevelScanError(t *testing.T) {
	tmpDir := t.TempDir()
	packageJSONPath := filepath.Join(tmpDir, "package.json")
	writeTestFile(t, packageJSONPath, "{ not json")

	output, err := runScannerBinary(t, "--fail-on-error", "--local", packageJSONPath)
	assertExitCode(t, err, 2, output)
	assertContains(t, output, "Error:")

	// Without the flag the default exit code stays 1.
	output, err = runScannerBinary(t, "--local", packageJSONPath)
	assertExitCode(t, err, 1, output)
}

// When a scan both finds a vulnerability and fails on a file, --fail-on-error
// must report the incomplete scan (exit 2), not the finding (exit 1); an
// incomplete scan may hide further findings.
func TestFailOnErrorTakesPrecedenceOverVulnerabilityExit(t *testing.T) {
	tmpDir := t.TempDir()
	writeTestFile(t, filepath.Join(tmpDir, "package.json"), `{
	  "dependencies": {
	    "@ctrl/tinycolor": "4.1.1"
	  }
	}`)
	writeTestFile(t, filepath.Join(tmpDir, "pnpm-lock.yaml"), "packages: [\n")

	output, err := runScannerBinary(t, "--fail-on-error", "--local", tmpDir)
	assertExitCode(t, err, 2, output)

	expectedStrings := []string{
		"Vulnerabilities found: 1",
		"Files failed: 1",
		"Errors: 1",
	}
	for _, expected := range expectedStrings {
		assertContains(t, output, expected)
	}

	// Without the flag the default exit code stays 1 (vulnerability found).
	output, err = runScannerBinary(t, "--local", tmpDir)
	assertExitCode(t, err, 1, output)
}

// A dependency file that is a symlink to a missing target must be reported as
// a failed file, not silently skipped as "not found". Covers both the npm and
// the Python lockfile loop.
func TestBrokenSymlinkDependencyFileIsReportedAsError(t *testing.T) {
	tmpDir := t.TempDir()
	writeTestFile(t, filepath.Join(tmpDir, "package.json"), `{
	  "dependencies": {
	    "@ctrl/tinycolor": "4.1.1"
	  }
	}`)
	if err := os.Symlink(filepath.Join(tmpDir, "does-not-exist"), filepath.Join(tmpDir, "pnpm-lock.yaml")); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}
	if err := os.Symlink(filepath.Join(tmpDir, "does-not-exist"), filepath.Join(tmpDir, "Pipfile.lock")); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	output, err := runScannerCommand("--local", tmpDir)
	assertExitCode(t, err, 1, output)

	expectedStrings := []string{
		"Found vulnerable package @ctrl/tinycolor with version 4.1.1 in package.json",
		"Vulnerabilities found: 1",
		"Files failed: 2",
		"Errors: 2",
	}
	for _, expected := range expectedStrings {
		assertContains(t, output, expected)
	}
}

func TestLocalScanCleanFile(t *testing.T) {
	tmpDir := t.TempDir()
	packageJSONPath := filepath.Join(tmpDir, "package.json")
	writeTestFile(t, packageJSONPath, `{
	  "dependencies": {
	    "safe-package": "1.0.0"
	  }
	}`)

	output, err := runScannerCommand("--local", packageJSONPath)
	assertExitCode(t, err, 0, output)

	assertContains(t, output, "✅ No vulnerabilities found.")
	assertContains(t, output, "Workflows scanned: 0")
	assertContains(t, output, "Actions scanned: 0")
	assertContains(t, output, "Vulnerabilities found: 0")
	assertContains(t, output, "Errors: 0")
}

func TestWorkflowParseErrorAppearsInSummaryWithoutFailureExit(t *testing.T) {
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "workflow.yml")
	writeTestFile(t, workflowPath, "jobs:\n  build:\n    steps: [\n")

	output, err := runScannerCommand(workflowPath)
	assertExitCode(t, err, 0, output)

	assertContains(t, output, "✅ No vulnerabilities found.")
	assertContains(t, output, "Scanning workflow: "+workflowPath)
	assertContains(t, output, "Workflows scanned: 1")
	assertContains(t, output, "Actions scanned: 0")
	assertContains(t, output, "Vulnerabilities found: 0")
	assertContains(t, output, "Errors: 1")
	assertContains(t, output, "Error details:")
	assertContains(t, output, "Error parsing workflow")
}

func TestLocalScanUnsupportedFile(t *testing.T) {
	tmpDir := t.TempDir()
	unsupportedPath := filepath.Join(tmpDir, "go.mod")
	writeTestFile(t, unsupportedPath, "module example.com/test\n")

	output, err := runScannerCommand("--local", unsupportedPath)
	assertExitCode(t, err, 1, output)

	if !strings.Contains(output, "unsupported dependency file") {
		t.Errorf("expected unsupported file error, got:\n%s", output)
	}
}

func assertContains(t *testing.T, output, expected string) {
	t.Helper()
	if !strings.Contains(output, expected) {
		t.Errorf("expected output to contain %q, but it didn't.\nOutput:\n%s", expected, output)
	}
}

func assertNotContains(t *testing.T, output, unexpected string) {
	t.Helper()
	if strings.Contains(output, unexpected) {
		t.Errorf("expected output not to contain %q.\nOutput:\n%s", unexpected, output)
	}
}

func runScannerCommand(args ...string) (string, error) {
	cmdArgs := append([]string{"run", "."}, args...)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", cmdArgs...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// runScannerBinary runs a compiled binary instead of `go run`, which reports its
// own exit code 1 for any non-zero exit of the scanner. Use it whenever a test
// asserts on a specific exit code other than 0 or 1.
func runScannerBinary(t *testing.T, args ...string) (string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	binaryPath := filepath.Join(t.TempDir(), "actions-npm-scanner")
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", binaryPath, ".").CombinedOutput(); err != nil {
		t.Fatalf("failed to build scanner: %v\n%s", err, out)
	}

	out, err := exec.CommandContext(ctx, binaryPath, args...).CombinedOutput()
	return string(out), err
}

func assertExitCode(t *testing.T, err error, expected int, output string) {
	t.Helper()
	if expected == 0 {
		if err != nil {
			t.Fatalf("expected exit code 0, got %v, output: %s", err, output)
		}
		return
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected exit code %d, got %v, output: %s", expected, err, output)
	}
	if exitErr.ExitCode() != expected {
		t.Fatalf("expected exit code %d, got %d, output: %s", expected, exitErr.ExitCode(), output)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func writeWorkflowWithVulnerableAction(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "workflow.yml")
	writeTestFile(t, workflowPath, `
jobs:
  build:
    steps:
      - uses: some-user/some-action-with-vulnerable-dep@v1
`)
	return workflowPath
}
