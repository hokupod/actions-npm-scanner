package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestMain(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "workflow.yml")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run main command: %v, output: %s", err, string(out))
	}

	output := string(out)

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
