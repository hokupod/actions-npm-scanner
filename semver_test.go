package main

import (
	"testing"
)

func TestIsVersionVulnerable(t *testing.T) {
	tests := []struct {
		name             string
		installedVersion string
		vulnerableVersions []string
		expected         bool
		description      string
	}{
		{
			name:             "Exact version match",
			installedVersion: "4.1.1",
			vulnerableVersions: []string{"4.1.1"},
			expected:         true,
			description:      "Should match exact version",
		},
		{
			name:             "Caret range match - vulnerable",
			installedVersion: "^4.1.0",
			vulnerableVersions: []string{"4.1.1"},
			expected:         true,
			description:      "^4.1.0 should be vulnerable to 4.1.1 (within caret range)",
		},
		{
			name:             "Caret range no match - safe",
			installedVersion: "^3.0.0",
			vulnerableVersions: []string{"4.1.1"},
			expected:         false,
			description:      "^3.0.0 should not match 4.1.1 (not in range)",
		},
		{
			name:             "Tilde range match - vulnerable",
			installedVersion: "~4.1.0",
			vulnerableVersions: []string{"4.1.1"},
			expected:         true,
			description:      "~4.1.0 should be vulnerable to 4.1.1 (within tilde range)",
		},
		{
			name:             "Tilde range no match - safe",
			installedVersion: "~4.0.0",
			vulnerableVersions: []string{"4.1.1"},
			expected:         false,
			description:      "~4.0.0 should not match 4.1.1 (not in tilde range)",
		},
		{
			name:             "Multiple vulnerable versions - match one",
			installedVersion: "4.1.2",
			vulnerableVersions: []string{"4.1.1", "4.1.2", "4.1.3"},
			expected:         true,
			description:      "Should match one of multiple vulnerable versions",
		},
		{
			name:             "Multiple vulnerable versions - no match",
			installedVersion: "4.2.0",
			vulnerableVersions: []string{"4.1.1", "4.1.2", "4.1.3"},
			expected:         false,
			description:      "Should not match any vulnerable version",
		},
		{
			name:             "Version with >=",
			installedVersion: ">=4.1.0",
			vulnerableVersions: []string{"4.1.1"},
			expected:         true,
			description:      ">=4.1.0 should be vulnerable to 4.1.1",
		},
		{
			name:             "Constraint-based vulnerable version",
			installedVersion: "4.1.5",
			vulnerableVersions: []string{">=4.1.1 <4.2.0"},
			expected:         true,
			description:      "4.1.5 should match constraint >=4.1.1 <4.2.0",
		},
		{
			name:             "Constraint-based safe version",
			installedVersion: "4.2.0",
			vulnerableVersions: []string{">=4.1.1 <4.2.0"},
			expected:         false,
			description:      "4.2.0 should not match constraint >=4.1.1 <4.2.0",
		},
		{
			name:             "Non-semantic version fallback",
			installedVersion: "latest",
			vulnerableVersions: []string{"latest"},
			expected:         true,
			description:      "Should fall back to exact string match for non-semantic versions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isVersionVulnerable(tt.installedVersion, tt.vulnerableVersions)
			if result != tt.expected {
				t.Errorf("isVersionVulnerable(%q, %v) = %v; expected %v. %s",
					tt.installedVersion, tt.vulnerableVersions, result, tt.expected, tt.description)
			}
		})
	}
}

func TestCleanVersionString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"^4.1.0", "4.1.0"},
		{"~4.1.0", "4.1.0"},
		{">=4.1.0", "4.1.0"},
		{"<=4.1.0", "4.1.0"},
		{">4.1.0", "4.1.0"},
		{"<4.1.0", "4.1.0"},
		{"=4.1.0", "4.1.0"},
		{"4.1.0", "4.1.0"},
		{" ^4.1.0 ", "4.1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := cleanVersionString(tt.input)
			if result != tt.expected {
				t.Errorf("cleanVersionString(%q) = %q; expected %q", tt.input, result, tt.expected)
			}
		})
	}
}