package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(t *testing.T) {
	output, err := runScannerCommand("workflow.yml")
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
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("expected output to contain %q, but it didn't.\nOutput:\n%s", expected, output)
		}
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
		"🔍 Scanning local file:",
		"⚠️ Found vulnerabilities:",
		"Found vulnerable package @ctrl/tinycolor with version 4.1.1 in package.json",
	}
	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("expected output to contain %q, but it didn't.\nOutput:\n%s", expected, output)
		}
	}
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
		"Scanning local path:",
		"🔍 Scanning package.json...",
		"⚠️ Found vulnerabilities:",
		"Found vulnerable package @ctrl/tinycolor with version 4.1.1 in package.json",
	}
	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("expected output to contain %q, but it didn't.\nOutput:\n%s", expected, output)
		}
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

	if !strings.Contains(output, "✅ No vulnerabilities found.") {
		t.Errorf("expected clean output, got:\n%s", output)
	}
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

func runScannerCommand(args ...string) (string, error) {
	cmdArgs := append([]string{"run", "."}, args...)
	cmd := exec.Command("go", cmdArgs...)
	out, err := cmd.CombinedOutput()
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
