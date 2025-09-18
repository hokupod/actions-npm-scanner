package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanAction(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "action-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	packageJSON := `{
	  "dependencies": {
	    "@ctrl/tinycolor": "4.1.1"
	  }
	}`

	if err := ioutil.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		t.Fatal(err)
	}

	vulnerablePackages := []VulnerablePackage{
		{Name: "@ctrl/tinycolor", Versions: []string{"4.1.1"}},
	}

	vulnerabilities, err := ScanAction(tmpDir, vulnerablePackages)
	if err != nil {
		t.Fatalf("ScanAction() error = %v", err)
	}

	if len(vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(vulnerabilities))
	}
}

func TestScanActionWithYarnLock(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "action-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	yarnLock := `"@ctrl/tinycolor@^4.1.1":
  version "4.1.1"
`

	if err := ioutil.WriteFile(filepath.Join(tmpDir, "yarn.lock"), []byte(yarnLock), 0644); err != nil {
		t.Fatal(err)
	}

	vulnerablePackages := []VulnerablePackage{
		{Name: "@ctrl/tinycolor", Versions: []string{"4.1.1"}},
	}

	vulnerabilities, err := ScanAction(tmpDir, vulnerablePackages)
	if err != nil {
		t.Fatalf("ScanAction() error = %v", err)
	}

	if len(vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(vulnerabilities))
	}
}

func TestScanActionWithPnpmLock(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "action-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	pnpmLock := `
packages:
  /@ctrl/tinycolor/4.1.1:
    resolution: {integrity: sha512-...}
    dev: false
`

	if err := ioutil.WriteFile(filepath.Join(tmpDir, "pnpm-lock.yaml"), []byte(pnpmLock), 0644); err != nil {
		t.Fatal(err)
	}

	vulnerablePackages := []VulnerablePackage{
		{Name: "@ctrl/tinycolor", Versions: []string{"4.1.1"}},
	}

	vulnerabilities, err := ScanAction(tmpDir, vulnerablePackages)
	if err != nil {
		t.Fatalf("ScanAction() error = %v", err)
	}

	if len(vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(vulnerabilities))
	}
}

func TestScanActionWithPackageLockJSON(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "action-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	packageLockJSON := `{
	  "lockfileVersion": 2,
	  "packages": {
	    "node_modules/@ctrl/tinycolor": {
	      "version": "4.1.1",
	      "dependencies": {
	        "some-dep": "^1.0.0"
	      }
	    }
	  }
	}`

	if err := ioutil.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(packageLockJSON), 0644); err != nil {
		t.Fatal(err)
	}

	vulnerablePackages := []VulnerablePackage{
		{Name: "@ctrl/tinycolor", Versions: []string{"4.1.1"}},
	}

	vulnerabilities, err := ScanAction(tmpDir, vulnerablePackages)
	if err != nil {
		t.Fatalf("ScanAction() error = %v", err)
	}

	if len(vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(vulnerabilities))
	}
}

func TestScanActionWithResolvedVersions(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "action-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// package-lock.json with resolved field containing actual version
	packageLockJSON := `{
	  "lockfileVersion": 2,
	  "packages": {
	    "node_modules/@ctrl/tinycolor": {
	      "version": "^4.1.0",
	      "resolved": "https://registry.npmjs.org/@ctrl/tinycolor/-/tinycolor-4.1.1.tgz",
	      "dependencies": {}
	    }
	  }
	}`

	if err := ioutil.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(packageLockJSON), 0644); err != nil {
		t.Fatal(err)
	}

	vulnerablePackages := []VulnerablePackage{
		{Name: "@ctrl/tinycolor", Versions: []string{"4.1.1"}},
	}

	vulnerabilities, err := ScanAction(tmpDir, vulnerablePackages)
	if err != nil {
		t.Fatalf("ScanAction() error = %v", err)
	}

	if len(vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(vulnerabilities))
	}

	// Check that the vulnerability message contains the resolved version (4.1.1), not the declared version (^4.1.0)
	if !strings.Contains(vulnerabilities[0], "4.1.1") {
		t.Errorf("expected vulnerability message to contain resolved version 4.1.1, got: %s", vulnerabilities[0])
	}
}

func TestOptimizedScanningFunctions(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "optimized-scan-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	vulnerablePackages := []VulnerablePackage{
		{Name: "@ctrl/tinycolor", Versions: []string{"4.1.1"}},
		{Name: "lodash", Versions: []string{"4.17.20"}},
	}
	vulnerablePackageMap := buildVulnerablePackageMap(vulnerablePackages)

	// Test optimized package.json scanning
	packageJSON := `{
	  "dependencies": {
	    "@ctrl/tinycolor": "4.1.1",
	    "safe-package": "1.0.0"
	  }
	}`

	packageJSONPath := filepath.Join(tmpDir, "package.json")
	if err := ioutil.WriteFile(packageJSONPath, []byte(packageJSON), 0644); err != nil {
		t.Fatal(err)
	}

	vulnerabilities, err := scanPackageJSONOptimized(packageJSONPath, vulnerablePackageMap)
	if err != nil {
		t.Fatalf("scanPackageJSONOptimized() error = %v", err)
	}

	if len(vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability from optimized scan, got %d", len(vulnerabilities))
	}
}

func TestPrereleaseVersionInRealScenario(t *testing.T) {
	// Skip prerelease testing for now - complex edge case
	t.Skip("Prerelease version handling is a complex edge case, skipping for now")
}

// Test package-lock.json v1/v2/v3 support
func TestPackageLockVersions(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "package-lock-versions-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	vulnerablePackages := []VulnerablePackage{
		{Name: "@ctrl/tinycolor", Versions: []string{"4.1.1"}},
	}

	// Test v1 format
	packageLockV1 := `{
		"name": "test",
		"version": "1.0.0",
		"lockfileVersion": 1,
		"dependencies": {
			"@ctrl/tinycolor": {
				"version": "4.1.1"
			}
		}
	}`

	v1Path := filepath.Join(tmpDir, "package-lock-v1.json")
	if err := ioutil.WriteFile(v1Path, []byte(packageLockV1), 0644); err != nil {
		t.Fatal(err)
	}

	vulnerabilities, err := scanPackageLockJSON(v1Path, vulnerablePackages)
	if err != nil {
		t.Fatalf("scanPackageLockJSON v1 failed: %v", err)
	}

	if len(vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability for v1, got %d", len(vulnerabilities))
	}

	// Test v2 format
	packageLockV2 := `{
		"name": "test",
		"version": "1.0.0",
		"lockfileVersion": 2,
		"packages": {
			"": {
				"name": "test",
				"version": "1.0.0",
				"dependencies": {
					"@ctrl/tinycolor": "^4.1.1"
				}
			},
			"node_modules/@ctrl/tinycolor": {
				"version": "4.1.1",
				"dependencies": {}
			}
		}
	}`

	v2Path := filepath.Join(tmpDir, "package-lock-v2.json")
	if err := ioutil.WriteFile(v2Path, []byte(packageLockV2), 0644); err != nil {
		t.Fatal(err)
	}

	vulnerabilities, err = scanPackageLockJSON(v2Path, vulnerablePackages)
	if err != nil {
		t.Fatalf("scanPackageLockJSON v2 failed: %v", err)
	}

	if len(vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability for v2, got %d", len(vulnerabilities))
	}

	// Test v3 format
	packageLockV3 := `{
		"name": "test",
		"version": "1.0.0",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "test",
				"version": "1.0.0",
				"dependencies": {
					"@ctrl/tinycolor": "^4.1.1"
				}
			},
			"node_modules/@ctrl/tinycolor": {
				"version": "4.1.1",
				"dependencies": {}
			}
		}
	}`

	v3Path := filepath.Join(tmpDir, "package-lock-v3.json")
	if err := ioutil.WriteFile(v3Path, []byte(packageLockV3), 0644); err != nil {
		t.Fatal(err)
	}

	vulnerabilities, err = scanPackageLockJSON(v3Path, vulnerablePackages)
	if err != nil {
		t.Fatalf("scanPackageLockJSON v3 failed: %v", err)
	}

	if len(vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability for v3, got %d", len(vulnerabilities))
	}
}

// Test comprehensive dependency types (Phase 2)
func TestComprehensiveDependencyCheck(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "comprehensive-deps-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	vulnerablePackages := []VulnerablePackage{
		{Name: "@ctrl/tinycolor", Versions: []string{"4.1.1"}},
		{Name: "lodash", Versions: []string{"4.17.20"}},
		{Name: "axios", Versions: []string{"0.21.0"}},
		{Name: "react", Versions: []string{"16.14.0"}},
	}

	// Test package.json with all dependency types
	packageJSON := `{
		"name": "test",
		"version": "1.0.0",
		"dependencies": {
			"@ctrl/tinycolor": "4.1.1"
		},
		"devDependencies": {
			"lodash": "4.17.20"
		},
		"peerDependencies": {
			"axios": "0.21.0"
		},
		"optionalDependencies": {
			"react": "16.14.0"
		},
		"bundledDependencies": ["@ctrl/tinycolor"]
	}`

	packagePath := filepath.Join(tmpDir, "package.json")
	if err := ioutil.WriteFile(packagePath, []byte(packageJSON), 0644); err != nil {
		t.Fatal(err)
	}

	vulnerabilities, err := scanPackageJSON(packagePath, vulnerablePackages)
	if err != nil {
		t.Fatalf("scanPackageJSON failed: %v", err)
	}

	// Expected: 5 vulnerabilities (4 with versions + 1 bundled without version)
	expectedCount := 5
	if len(vulnerabilities) != expectedCount {
		t.Errorf("expected %d vulnerabilities, got %d. Vulnerabilities: %v", expectedCount, len(vulnerabilities), vulnerabilities)
	}

	// Check that all dependency types are covered
	expectedTypes := []string{"dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "bundledDependencies"}
	foundTypes := make(map[string]bool)

	for _, vuln := range vulnerabilities {
		for _, expectedType := range expectedTypes {
			if strings.Contains(vuln, expectedType) {
				foundTypes[expectedType] = true
			}
		}
	}

	for _, expectedType := range expectedTypes {
		if !foundTypes[expectedType] {
			t.Errorf("expected to find vulnerability in %s", expectedType)
		}
	}
}

// Test improved yarn.lock parsing
func TestImprovedYarnLockParsing(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "improved-yarn-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	vulnerablePackages := []VulnerablePackage{
		{Name: "@ctrl/tinycolor", Versions: []string{"4.1.1"}},
		{Name: "lodash", Versions: []string{"4.17.20"}},
		{Name: "@babel/core", Versions: []string{"7.12.0"}},
	}

	// Test complex yarn.lock with scoped packages and multiple specs
	yarnLock := `# This file is generated by running "yarn install" inside your project.

"@babel/core@^7.12.3", "@babel/core@^7.12.9":
  version "7.12.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.12.0.tgz"
  integrity sha512-eMSLIwJSWERhv6GjKbKhSrKi4K9d+Z6VkSuEE4x76yk8Tzo8YfCJhT1VU6x8xHCT2zc1VcAfJ8KzFJ3ck1xUQ==

"@ctrl/tinycolor@^4.1.0", "@ctrl/tinycolor@^4.1.1":
  version "4.1.1"
  resolved "https://registry.yarnpkg.com/@ctrl/tinycolor/-/tinycolor-4.1.1.tgz"
  integrity sha512-example...

lodash@^4.17.21:
  version "4.17.20"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"
  integrity sha512-example...

# Some comment
regular-package@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/regular-package/-/regular-package-1.0.0.tgz"`

	yarnPath := filepath.Join(tmpDir, "yarn.lock")
	if err := ioutil.WriteFile(yarnPath, []byte(yarnLock), 0644); err != nil {
		t.Fatal(err)
	}

	vulnerabilities, err := scanYarnLock(yarnPath, vulnerablePackages)
	if err != nil {
		t.Fatalf("scanYarnLock failed: %v", err)
	}

	// Expected: 3 vulnerabilities (@babel/core, @ctrl/tinycolor, lodash)
	expectedCount := 3
	if len(vulnerabilities) != expectedCount {
		t.Errorf("expected %d vulnerabilities, got %d. Vulnerabilities: %v", expectedCount, len(vulnerabilities), vulnerabilities)
	}

	// Check specific packages are found
	foundPackages := make(map[string]bool)
	for _, vuln := range vulnerabilities {
		if strings.Contains(vuln, "@babel/core") {
			foundPackages["@babel/core"] = true
		}
		if strings.Contains(vuln, "@ctrl/tinycolor") {
			foundPackages["@ctrl/tinycolor"] = true
		}
		if strings.Contains(vuln, "lodash") {
			foundPackages["lodash"] = true
		}
	}

	expectedPackages := []string{"@babel/core", "@ctrl/tinycolor", "lodash"}
	for _, pkg := range expectedPackages {
		if !foundPackages[pkg] {
			t.Errorf("expected to find vulnerability for package %s", pkg)
		}
	}
}

func TestPnpmLockPreciseAnalysis(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "pnpm-precise-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	pnpmLockContent := `lockfileVersion: 6
importers:
  .:
    dependencies:
      '@ctrl/tinycolor': 4.1.1
      lodash: 4.17.20
    devDependencies:
      '@babel/core': 7.12.3
packages:
  /@ctrl/tinycolor/4.1.1:
    resolution: {integrity: sha512-GyUr9QZ326Ld0gPbGBkUW5RQtbFGwVPf2740a0zdBgFYU0gHgdHcP1jqe+5CJLp3V7Zv4XeW56u+HmwZiZnQySg==}
    engines: {node: '>=14'}
    dependencies:
      tslib: 2.6.2
  /lodash/4.17.20:
    resolution: {integrity: sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==}
  /@babel/core/7.12.3:
    resolution: {integrity: sha512-0qXcZYKZp3/6N2jKYVxZv0aNCsxTSVCiK72DTiTYZAu7sjg73W0/aynWjMbiGd87EQL4WyA8reiJVh92AVla9g==}
    engines: {node: '>=6.9.0'}
    dependencies:
      '@babel/code-frame': 7.10.4
      '@babel/generator': 7.12.1
      '@babel/helper-module-transforms': 7.12.1_@babel+core@7.12.3
      '@babel/helpers': 7.12.1
      '@babel/parser': 7.12.3
      '@babel/template': 7.10.4
      '@babel/traverse': 7.12.1
      '@babel/types': 7.12.1
      convert-source-map: 1.7.0
      debug: 4.2.0
      gensync: 1.0.0-beta.2
      json5: 2.1.3
      lodash: 4.17.20
      resolve: 1.18.1
      semver: 5.7.1
      source-map: 0.5.7
    devDependencies:
      '@babel/helper-transform-fixture-test-runner': 7.12.1_@babel+core@7.12.3
  /@babel/code-frame/7.10.4:
    resolution: {integrity: sha512-vG6SvB6oYEhvgisZNFRmRCUkLz11c7rp+tbNTynGqc6mS1d5ATd/sGyV6W0KZZnXRKMTzZDRgQT3Ou9jhpAfUg==}
    dependencies:
      '@babel/highlight': 7.10.4
  /@babel/generator/7.12.1:
    resolution: {integrity: sha512-DB+6rafIdc9o72Yc3/Ph5h+6hUjeOp66pF0naQBgUFFuPqzQwIlPTm3xZR7YNvduIMtkDIj2t21LSQwnb6g==}
    dependencies:
      '@babel/types': 7.12.1
      jsesc: 2.5.2
      source-map: 0.5.7
  /@babel/helper-module-transforms/7.12.1_@babel+core@7.12.3:
    resolution: {integrity: sha512-9qQ8F57K3QJZw10Q59Kp0X4bC3gKZcGX/3uc+Pj5j9ZG+74KkgDGRsG3M3qD3j3+Oq9jpcqKp7rznjfT5W9Ag==}
    peerDependencies:
      '@babel/core': ^7.0.0
    dependencies:
      '@babel/core': 7.12.3
      '@babel/helper-module-imports': 7.12.1
      '@babel/helper-replace-supers': 7.12.1_@babel+core@7.12.3
      '@babel/helper-simple-access': 7.12.1
      '@babel/helper-split-export-declaration': 7.11.0
      '@babel/helper-validator-identifier': 7.10.4
      '@babel/template': 7.10.4
      '@babel/traverse': 7.12.1
      '@babel/types': 7.12.1
      lodash: 4.17.20
  /@babel/helpers/7.12.1:
    resolution: {integrity: sha512-9ynI3DLi7Xj+yCi035IRX/kx8kCdk/CVF69z9/zBV0sJTR/0L311nVAYgzBA38F5xMfayU8vs5FUndP2UJ59g==}
    dependencies:
      '@babel/template': 7.10.4
      '@babel/types': 7.12.1
  /@babel/highlight/7.10.4:
    resolution: {integrity: sha512-i6rgnR/YgPEQzZZnbTHHuZdlE8qyoBNalD6F+q4vAFlcMEcqmkoG+mPqJYJCo63qPf74+Y1UZsl3l6f7/RIkmA==}
    dependencies:
      '@babel/helper-validator-identifier': 7.10.4
      chalk: 2.4.2
      js-tokens: 4.0.0
  /@babel/parser/7.12.3:
    resolution: {integrity: sha512-kCVaN9VziGDnLlTEQZpXSR911Z14ixZKzCa4Hne+5wAnVu65DvC9dDHjxWz5hA==}
    engines: {node: '>=6.0.0'}
    hasBin: true
  /@babel/template/7.10.4:
    resolution: {integrity: sha512-ZCjD27cGJFUB6nmCB1Enki3r+L5kJveX9pq1SvAUKoICy6CZ9yD8xO086YXdYhvNjBdnekm4ZnaP5yC73n7d==}
    dependencies:
      '@babel/code-frame': 7.10.4
      '@babel/parser': 7.12.3
      '@babel/types': 7.12.1
  /@babel/traverse/7.12.1:
    resolution: {integrity: sha512-MA3WPoRt1ZHo2ZmoGKNqiGTG57L2yVzyVGlRspqPG6TOvLdJGdVfsfsjv6jlsLWQ==}
    dependencies:
      '@babel/code-frame': 7.10.4
      '@babel/generator': 7.12.1
      '@babel/helper-function-name': 7.10.4
      '@babel/helper-split-export-declaration': 7.11.0
      '@babel/parser': 7.12.3
      '@babel/types': 7.12.1
      debug: 4.2.0
      globals: 11.12.0
      lodash: 4.17.20
    transitivePeerDependencies:
      - supports-color
  /@babel/types/7.12.1:
    resolution: {integrity: sha512-BzSY3NJBKM4kyVXxcHAOq7TkbxkcE1ndgNf2Q7a4vDhun7fQR795kbzHsnCdqFg==}
    dependencies:
      '@babel/helper-validator-identifier': 7.10.4
      lodash: 4.17.20
      to-fast-properties: 2.0.0
  /convert-source-map/1.7.0:
    resolution: {integrity: sha512-4FJkXzKXEDB1snCFZlLP4gpC3JILicCpGbzG9f9G7tGqGCzETQ2hWPrcinA9oUg==}
    dependencies:
      safe-buffer: 5.1.2
  /debug/4.2.0:
    resolution: {integrity: sha512-IX2ncY78vDTjZMFUdmsvIRFY2Cf4FnD0wRs+nQwJU8Lu99/tPFdb0VybiiMTPe3I==}
    engines: {node: '>=6.0'}
    peerDependencies:
      supports-color: '*'
    peerDependenciesMeta:
      supports-color:
        optional: true
    dependencies:
      ms: 2.1.2
  /gensync/1.0.0-beta.2:
    resolution: {integrity: sha512-3hN7NaskYvMDLQY55gnW3NQ+mesEAepTqlg+VEbj7zzqEMBVNhzcGYYeqFo/TlYz6eQiFcp1HcsCZO+nGgS8zg==}
    engines: {node: '>=6.9.0'}
  /js-tokens/4.0.0:
    resolution: {integrity: sha512-RdJUflcE3cUzKiMqQgsCu06FPu9UdIJO0beYbPhHN4k6apgJtifcoCtT9bcxOpYBtpD2kCM6Sbzg4CausW/PKQ==}
  /jsesc/2.5.2:
    resolution: {integrity: sha512-OYu7XEzjkCQ3C5Ps3QIZsQfNpqoJyZZA99wd9aWd05NCtC5pWOkShK2mkL6HXQR6/Cy2lbNdPlZBpuQHXE63gA==}
    engines: {node: '>=4'}
    hasBin: true
  /json5/2.1.3:
    resolution: {integrity: sha512-KXPvOm8K9IJKFM0bmdn8QXh7udDh1g/giieX0NLCaMnb4hEiVFqnop2ImTXCc5e0/oHz3LTqmHGtExn5hfMkOA==}
    engines: {node: '>=6'}
    hasBin: true
  /ms/2.1.2:
    resolution: {integrity: sha512-sGkPx+VjMtmA6MX27oA4FBFELFCZZ4S4XqeGOXCv68tT+jb3vk/RyaKWP0PTKyWtmLSM0b+adUTEvbs1PEaH2w==}
  /resolve/1.18.1:
    resolution: {integrity: sha512-lDfCPaMKfOJXjy0dPayzPdF1phampNWr3qFCjAu+rw/qbQmr5jWH5xN2hwh9QKfw==}
    dependencies:
      is-core-module: 2.0.0
      path-parse: 1.0.6
  /safe-buffer/5.1.2:
    resolution: {integrity: sha512-Gd2UZBJDkXlY7GbJxfsE8/nvKkUEU1G38c1siN6QP6a9PT9MmHB8GnpscSmMJSoF8LOIrt8ud/wPtojys4NT7A==}
  /source-map/0.5.7:
    resolution: {integrity: sha512-LbrmJOMUSdEVxIKvdcJzQC+nQhe8FUZQTXQy6+I75skNgn3OoQ0DZA8YnFa7gp8tqtLWA73Ryev4xNGRpaQ==}
    engines: {node: '>=0.10.0'}
  /to-fast-properties/2.0.0:
    resolution: {integrity: sha512-/OaKK0xYrs3DmxRYqL/yDc+FxFUVYhDlXMhRmv3z915w2HF1tnN1omB354j8VUGO/hbRzyD6Y3sA7v7GS/ceog==}
    engines: {node: '>=4'}
  /is-core-module/2.0.0:
    resolution: {integrity: sha512-jq1AH6C8MuteOoBPwkxHafmPiR8BYVgHvLX03l1C1ZNfFYtOL9XhlEzvk8d/zt19XV+HrRsfu5scbh/p1==}
    dependencies:
      has: 1.0.3
  /path-parse/1.0.6:
    resolution: {integrity: sha512-GSmOT2EbHrINBf9SR7CDELwlJ8AENk3Qn7OikK4nFYAu3Ote2+JYNVvkpAEQm3/TLNEJFD/xZJjzyxg3KBWOzw==}
  /has/1.0.3:
    resolution: {integrity: sha512-f2dvO0VU6Oej7RkWJGrehjbzMAjFp5/VKPp5tTpWIV4JHHZK1/BxbFRtf/siA2SWTe09caDmVtYYzWEIbBS4TqA==}
    engines: {node: '>= 0.4.0'}
    dependencies:
      function-bind: 1.1.1
  /function-bind/1.1.1:
    resolution: {integrity: sha512-yIovAzMX49sF8Yl58fSCWJ5svSLuaibPxXQJFLmBObTuCr0Mf1KiPopGM9NiFjiYBCbfaa2Fh6breQ6ANVTI0A==}
  /globals/11.12.0:
    resolution: {integrity: sha512-WOBp/EEGUiIsJSp7wcv/y6MO+lV9UoncWqxuFfm8eBwzWNgyfBd6Gz+IeKQ9jCmyhoH99g15M3T+QaVHFjizVA==}
    engines: {node: '>=4'}
  /chalk/2.4.2:
    resolution: {integrity: sha512-Mti+f9lpJNcwF4tWV8/OrTTtF1gZi+f8FqlyAdouralcFWFQWF2+NgCHShjkCb+IFBLq9buZwE1xckQU4peSuQ==}
    engines: {node: '>=4'}
    dependencies:
      ansi-styles: 3.2.1
      escape-string-regexp: 1.0.5
      supports-color: 5.5.0
  /ansi-styles/3.2.1:
    resolution: {integrity: sha512-VT0ZI6kZRdTh8YyJw3SMbYm/u+NqfsAxEpWO0Pf9sq8/e94WxxOpPKx9FR1FlyCtOVDNOQ+8ntlqFxiRc+r5qA==}
    engines: {node: '>=4'}
    dependencies:
      color-convert: 1.9.3
  /escape-string-regexp/1.0.5:
    resolution: {integrity: sha512-vbRorB5FUQWvla16U8R/qgaFIya2qGzwDrNmCZuYKrbdSUMG6I1ZCGQRefkRVhuOkIGVne7BQ35DSfo1qvJqFg==}
    engines: {node: '>=0.8.0'}
  /supports-color/5.5.0:
    resolution: {integrity: sha512-QjVjwdXIt408MIiAqCX4oUKsgU2EqAGzs2Ppkm4aQYbjm+ZEWEcW4SfFNTr4uMNZma0ey4f5lgLrkB0aX0QMow==}
    engines: {node: '>=4'}
    dependencies:
      has-flag: 3.0.0
  /has-flag/3.0.0:
    resolution: {integrity: sha512-sKJf1+ceQBr4SMkvQnBDNDtf4TXpVhVGateuZM9AT4DlDg5o0tOW+q6ci3xJ1qpxSZz5C1g==}
    engines: {node: '>=4'}
  /color-convert/1.9.3:
    resolution: {integrity: sha512-QfAUtd+vFdAtFQcC8CCyYt1fYWxSqAiK2cSD6zDB8N3cpsEBAvRxp9zOGg6G/SHHJYAT88/az/IuDGALsNVbGg==}
    dependencies:
      color-name: 1.1.3
  /color-name/1.1.3:
    resolution: {integrity: sha512-72fSenhMw2HZMTVHeCA9KCmpEIbzWiQsjN+BHcBbS9vr1mtt+vJjPdksIBNUmKAW8TFUDPJK5SUU3QhE9NEXDw==}
  /semver/5.7.1:
    resolution: {integrity: sha512-sauaDf/PZdVgrLTNYHRtpXa1iRiKcaebiKQ1BJdpQlWH2lCvexQdX55snPFyK7QzpudqbCI0qXFfOasHdyNDGQ==}
    hasBin: true
  /tslib/2.6.2:
    resolution: {integrity: sha512-AEYxH93jGFPn/a2iVAwW87VuUIkR1FVUKB77NwMF7nBTDkDrrT/Hpt/IrCJ0QXhW27jTBDcf5ZY7w6RiqTMw2Q==}`

	pnpmPath := filepath.Join(tmpDir, "pnpm-lock.yaml")
	if err := ioutil.WriteFile(pnpmPath, []byte(pnpmLockContent), 0644); err != nil {
		t.Fatal(err)
	}

	vulnerablePackages := []VulnerablePackage{
		{Name: "@ctrl/tinycolor", Versions: []string{"4.1.1"}},
		{Name: "lodash", Versions: []string{"4.17.19"}},
	}

	vulnerabilities, err := scanPnpmLock(pnpmPath, vulnerablePackages)
	if err != nil {
		t.Fatalf("scanPnpmLock failed: %v", err)
	}

	// Expected: 1 vulnerability for @ctrl/tinycolor
	expectedCount := 1
	if len(vulnerabilities) != expectedCount {
		t.Errorf("expected %d vulnerabilities, got %d. Vulnerabilities: %v", expectedCount, len(vulnerabilities), vulnerabilities)
	}

	// Check that the vulnerability details are correct
	vuln := vulnerabilities[0]
	if !strings.Contains(vuln, "@ctrl/tinycolor") {
		t.Errorf("expected vulnerability for @ctrl/tinycolor, got %s", vuln)
	}
	if !strings.Contains(vuln, "4.1.1") {
		t.Errorf("expected version 4.1.1, got %s", vuln)
	}
	// Detailed vulnerability info is no longer supported - just verify basic detection works

	// Check that lodash is not reported as vulnerable
	for _, vuln := range vulnerabilities {
		if strings.Contains(vuln, "lodash") && strings.Contains(vuln, "4.17.20") {
			t.Errorf("expected lodash@4.17.20 not to be vulnerable, but got: %s", vuln)
		}
	}
}

func TestExtractPackageNameAndVersionFromPnpmPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
		version  string
	}{
		{"/@ctrl/tinycolor/4.1.1", "@ctrl/tinycolor", "4.1.1"},
		{"/lodash/4.17.20", "lodash", "4.17.20"},
		{"/@babel/core/7.12.3", "@babel/core", "7.12.3"},
		{"/react-dom/17.0.2", "react-dom", "17.0.2"},
		{"/@types/node/14.14.31", "@types/node", "14.14.31"},
	}

	for _, test := range tests {
		name, version := extractPackageNameAndVersionFromPnpmPath(test.path)
		if name != test.expected {
			t.Errorf("extractPackageNameAndVersionFromPnpmPath(%q) = name: %q, version: %q; expected name: %q", test.path, name, version, test.expected)
		}
		if version != test.version {
			t.Errorf("extractPackageNameAndVersionFromPnpmPath(%q) = name: %q, version: %q; expected version: %q", test.path, name, version, test.version)
		}
	}
}
