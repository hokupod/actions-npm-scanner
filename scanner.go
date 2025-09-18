package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"
)

// PackageJSON represents a package.json file
type PackageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	BundledDependencies  []string          `json:"bundledDependencies"`
}

// PackageLockJSON represents a package-lock.json file (v1-v3)
type PackageLockJSON struct {
	LockfileVersion int                               `json:"lockfileVersion,omitempty"`
	Packages        map[string]PackageLockPackageInfo `json:"packages,omitempty"`     // v2/v3
	Dependencies    map[string]PackageLockInfo        `json:"dependencies,omitempty"` // v1
}

// PackageLockPackageInfo represents package information in package-lock.json v2/v3 (flat structure)
type PackageLockPackageInfo struct {
	Version      string            `json:"version"`
	Resolved     string            `json:"resolved,omitempty"`     // Actual URL used to download the package
	Dependencies map[string]string `json:"dependencies,omitempty"` // v2/v3: dependencies are version strings
}

// PackageLockInfo represents package information in package-lock.json v1 (nested structure)
type PackageLockInfo struct {
	Version      string                     `json:"version"`
	Dependencies map[string]PackageLockInfo `json:"dependencies,omitempty"` // v1: dependencies are nested structures
}

// PnpmLock represents the structure of pnpm-lock.yaml
type PnpmLock struct {
	LockfileVersion int                        `yaml:"lockfileVersion"`
	Dependencies    map[string]string          `yaml:"dependencies,omitempty"`
	DevDependencies map[string]string          `yaml:"devDependencies,omitempty"`
	Packages        map[string]PnpmPackageInfo `yaml:"packages,omitempty"`
	Specifiers      map[string]string          `yaml:"specifiers,omitempty"`
}

// PnpmPackageInfo represents package information in pnpm-lock.yaml
type PnpmPackageInfo struct {
	Resolution   interface{}       `yaml:"resolution,omitempty"`
	Version      string            `yaml:"version,omitempty"`
	Dev          bool              `yaml:"dev,omitempty"`
	Dependencies map[string]string `yaml:"dependencies,omitempty"`
}

// extractVersionFromResolved extracts version from resolved URL
// Example: "https://registry.npmjs.org/@ctrl/tinycolor/-/tinycolor-4.1.1.tgz" -> "4.1.1"
func extractVersionFromResolved(resolved string) string {
	if resolved == "" {
		return ""
	}

	// Look for pattern like "/-/packagename-version.tgz"
	parts := strings.Split(resolved, "/-/")
	if len(parts) < 2 {
		return ""
	}

	// Extract the filename part
	filename := parts[len(parts)-1]

	// Remove .tgz extension
	filename = strings.TrimSuffix(filename, ".tgz")

	// For packages like "react-18.0.0-beta.0", we need to find where the package name ends
	// and the version starts. Package names don't typically start with numbers.

	// Split by dashes and find the first part that starts with a digit (likely the version)
	dashParts := strings.Split(filename, "-")
	if len(dashParts) < 2 {
		return ""
	}

	// Find the index where version starts (first part starting with digit)
	versionStartIdx := -1
	for i := 1; i < len(dashParts); i++ { // Skip first part (package name)
		if len(dashParts[i]) > 0 && (dashParts[i][0] >= '0' && dashParts[i][0] <= '9') {
			versionStartIdx = i
			break
		}
	}

	if versionStartIdx == -1 {
		return ""
	}

	// Join the version parts back together
	version := strings.Join(dashParts[versionStartIdx:], "-")
	return version
}

// getActualVersion returns the most accurate version available
// Prioritizes resolved version over declared version
func getActualVersion(declared, resolved string) string {
	if resolvedVersion := extractVersionFromResolved(resolved); resolvedVersion != "" {
		return resolvedVersion
	}
	return declared
}

// VulnerablePackageMap provides optimized lookups for vulnerable packages
type VulnerablePackageMap map[string]VulnerablePackage

// buildVulnerablePackageMap creates a hashmap for O(1) package lookups
func buildVulnerablePackageMap(vulnerablePackages []VulnerablePackage) VulnerablePackageMap {
	packageMap := make(VulnerablePackageMap, len(vulnerablePackages))
	for _, pkg := range vulnerablePackages {
		packageMap[pkg.Name] = pkg
	}
	return packageMap
}

// isVulnerable checks if a package is vulnerable using the optimized map
func (vpm VulnerablePackageMap) isVulnerable(packageName, version string) (bool, VulnerablePackage) {
	if vulnerablePackage, exists := vpm[packageName]; exists {
		if isVersionVulnerable(version, vulnerablePackage.Versions) {
			return true, vulnerablePackage
		}
	}
	return false, VulnerablePackage{}
}

// formatVulnerabilityMessage formats a vulnerability message
func formatVulnerabilityMessage(pkgName, version, filename string, vulnerablePackage VulnerablePackage) string {
	return fmt.Sprintf("Found vulnerable package %s with version %s in %s", pkgName, version, filename)
}

// ScanAction scans a downloaded action for vulnerable packages
func ScanAction(actionDir string, vulnerablePackages []VulnerablePackage) ([]string, error) {
	var foundVulnerabilities []string

	// Build optimized vulnerability map once
	vulnerablePackageMap := buildVulnerablePackageMap(vulnerablePackages)

	packageJSONPath := filepath.Join(actionDir, "package.json")
	packageLockJSONPath := filepath.Join(actionDir, "package-lock.json")
	yarnLockPath := filepath.Join(actionDir, "yarn.lock")
	pnpmLockPath := filepath.Join(actionDir, "pnpm-lock.yaml")

	// Scan package.json
	if _, err := os.Stat(packageJSONPath); err == nil {
		fmt.Println("    🔍 Scanning package.json...")
		vulnerabilities, err := scanPackageJSONOptimized(packageJSONPath, vulnerablePackageMap)
		if err != nil {
			return nil, err
		}
		foundVulnerabilities = append(foundVulnerabilities, vulnerabilities...)
	} else {
		fmt.Println("       package.json not found. Skipping.")
	}

	// Scan package-lock.json
	if _, err := os.Stat(packageLockJSONPath); err == nil {
		fmt.Println("    🔍 Scanning package-lock.json...")
		vulnerabilities, err := scanPackageLockJSONOptimized(packageLockJSONPath, vulnerablePackageMap)
		if err != nil {
			return nil, err
		}
		foundVulnerabilities = append(foundVulnerabilities, vulnerabilities...)
	} else {
		fmt.Println("       package-lock.json not found. Skipping.")
	}

	// Scan yarn.lock
	if _, err := os.Stat(yarnLockPath); err == nil {
		fmt.Println("    🔍 Scanning yarn.lock...")
		vulnerabilities, err := scanYarnLockOptimized(yarnLockPath, vulnerablePackageMap)
		if err != nil {
			return nil, err
		}
		foundVulnerabilities = append(foundVulnerabilities, vulnerabilities...)
	} else {
		fmt.Println("       yarn.lock not found. Skipping.")
	}

	// Scan pnpm-lock.yaml
	if _, err := os.Stat(pnpmLockPath); err == nil {
		fmt.Println("    🔍 Scanning pnpm-lock.yaml...")
		vulnerabilities, err := scanPnpmLockOptimized(pnpmLockPath, vulnerablePackageMap)
		if err != nil {
			return nil, err
		}
		foundVulnerabilities = append(foundVulnerabilities, vulnerabilities...)
	} else {
		fmt.Println("       pnpm-lock.yaml not found. Skipping.")
	}

	return foundVulnerabilities, nil
}

// Optimized scanning functions using VulnerablePackageMap

func scanPackageJSONOptimized(path string, vulnerablePackageMap VulnerablePackageMap) ([]string, error) {
	var foundVulnerabilities []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var packageJSON PackageJSON
	if err := json.Unmarshal(data, &packageJSON); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", path, err)
	}

	// Define all dependency types to check
	dependencyTypes := []struct {
		deps map[string]string
		name string
	}{
		{packageJSON.Dependencies, "dependencies"},
		{packageJSON.DevDependencies, "devDependencies"},
		{packageJSON.PeerDependencies, "peerDependencies"},
		{packageJSON.OptionalDependencies, "optionalDependencies"},
	}

	for _, depType := range dependencyTypes {
		if depType.deps == nil {
			continue
		}
		for pkgName, version := range depType.deps {
			if isVuln, vulnerablePackage := vulnerablePackageMap.isVulnerable(pkgName, version); isVuln {
				baseMsg := formatVulnerabilityMessage(pkgName, version, filepath.Base(path), vulnerablePackage)
				msgWithType := fmt.Sprintf("%s (%s)", baseMsg, depType.name)
				foundVulnerabilities = append(foundVulnerabilities, msgWithType)
			}
		}
	}

	// Check bundledDependencies (array of package names without versions)
	for _, bundledPkg := range packageJSON.BundledDependencies {
		if _, exists := vulnerablePackageMap[bundledPkg]; exists {
			foundVulnerabilities = append(foundVulnerabilities, fmt.Sprintf("Found vulnerable package %s in %s (bundledDependencies) - version unknown, check manually", bundledPkg, filepath.Base(path)))
		}
	}

	return foundVulnerabilities, nil
}

func scanPackageJSON(path string, vulnerablePackages []VulnerablePackage) ([]string, error) {
	var foundVulnerabilities []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var packageJSON PackageJSON
	if err := json.Unmarshal(data, &packageJSON); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", path, err)
	}

	// Define all dependency types to check
	dependencyTypes := []struct {
		deps map[string]string
		name string
	}{
		{packageJSON.Dependencies, "dependencies"},
		{packageJSON.DevDependencies, "devDependencies"},
		{packageJSON.PeerDependencies, "peerDependencies"},
		{packageJSON.OptionalDependencies, "optionalDependencies"},
	}

	for _, vulnerablePackage := range vulnerablePackages {
		// Check all dependency types
		for _, depType := range dependencyTypes {
			if depType.deps == nil {
				continue
			}
			if version, ok := depType.deps[vulnerablePackage.Name]; ok {
				if isVersionVulnerable(version, vulnerablePackage.Versions) {
					baseMsg := formatVulnerabilityMessage(vulnerablePackage.Name, version, filepath.Base(path), vulnerablePackage)
					msgWithType := fmt.Sprintf("%s (%s)", baseMsg, depType.name)
					foundVulnerabilities = append(foundVulnerabilities, msgWithType)
				}
			}
		}

		// Check bundledDependencies (array of package names without versions)
		for _, bundledPkg := range packageJSON.BundledDependencies {
			if bundledPkg == vulnerablePackage.Name {
				foundVulnerabilities = append(foundVulnerabilities, fmt.Sprintf("Found vulnerable package %s in %s (bundledDependencies) - version unknown, check manually", vulnerablePackage.Name, filepath.Base(path)))
			}
		}
	}

	return foundVulnerabilities, nil
}

// isVersionVulnerable checks if the installed version range could include any vulnerable versions
// Supports semantic versioning ranges, exact matches, and prerelease versions
func isVersionVulnerable(installedVersion string, vulnerableVersions []string) bool {
	// First try exact string match for non-semver cases
	for _, vulnVersion := range vulnerableVersions {
		if installedVersion == vulnVersion {
			return true
		}
	}

	// Try to parse installed version as a constraint (e.g., "^4.1.0", "~4.1.0", ">=4.1.0")
	// But skip if it's just a plain version number
	if isConstraintNotVersion(installedVersion) {
		if installedConstraint, err := semver.NewConstraint(installedVersion); err == nil {
			// Check if any vulnerable version satisfies the installed constraint
			for _, vulnVersion := range vulnerableVersions {
				// Try parsing vulnerable version as exact version first
				if vulnVer, err := semver.NewVersion(vulnVersion); err == nil {
					if installedConstraint.Check(vulnVer) {
						return true
					}
				}
			}
			return false // If we successfully parsed as constraint, don't continue to exact version parsing
		}
	}

	// If installed version is not a constraint, try parsing as exact version
	cleanVersion := cleanVersionString(installedVersion)
	if installedVer, err := semver.NewVersion(cleanVersion); err == nil {
		for _, vulnVersion := range vulnerableVersions {
			// Try parsing vulnerable version as constraint first (e.g., ">=4.1.1 <4.2.0")
			if constraint, err := semver.NewConstraint(vulnVersion); err == nil {
				if constraint.Check(installedVer) {
					return true
				}
				continue // If it parsed as constraint, don't try as version
			}
			// Try parsing vulnerable version as exact version for exact matches
			if vulnVer, err := semver.NewVersion(vulnVersion); err == nil {
				// Check for exact version match
				if installedVer.Equal(vulnVer) {
					return true
				}
				// Check for prerelease vulnerability: if installed version has same core version
				// but is a prerelease of a vulnerable version
				if installedVer.Prerelease() != "" && vulnVer.Prerelease() == "" {
					coreInstalled, err := semver.NewVersion(fmt.Sprintf("%d.%d.%d", installedVer.Major(), installedVer.Minor(), installedVer.Patch()))
					if err == nil && coreInstalled.Equal(vulnVer) {
						return true // Prerelease of vulnerable version is considered vulnerable
					}
				}
			}
		}
	} else {
		// If parsing as semver failed, check if it's because of different format
		// Try direct string parsing without cleaning first
		if directVer, err := semver.NewVersion(installedVersion); err == nil {
			for _, vulnVersion := range vulnerableVersions {
				if vulnVer, err := semver.NewVersion(vulnVersion); err == nil {
					// Check for exact version match
					if directVer.Equal(vulnVer) {
						return true
					}
					// Check for prerelease vulnerability
					if directVer.Prerelease() != "" && vulnVer.Prerelease() == "" {
						coreInstalled, err := semver.NewVersion(fmt.Sprintf("%d.%d.%d", directVer.Major(), directVer.Minor(), directVer.Patch()))
						if err == nil && coreInstalled.Equal(vulnVer) {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

// cleanVersionString removes version range indicators to get the actual version number
// Preserves prerelease and build metadata
func cleanVersionString(version string) string {
	version = strings.TrimSpace(version)
	// Remove common prefixes only from the beginning
	for _, prefix := range []string{"^", "~", ">=", "<=", ">", "<", "="} {
		if strings.HasPrefix(version, prefix) {
			version = strings.TrimSpace(version[len(prefix):])
			break // Only remove one prefix
		}
	}
	return version
}

// isConstraintNotVersion checks if a string is a constraint (not just a version number)
func isConstraintNotVersion(version string) bool {
	version = strings.TrimSpace(version)
	// Check for constraint operators
	constraintPrefixes := []string{"^", "~", ">=", "<=", ">", "<", "="}
	for _, prefix := range constraintPrefixes {
		if strings.HasPrefix(version, prefix) {
			return true
		}
	}
	// Check for range (space indicates multiple constraints)
	if strings.Contains(version, " ") {
		return true
	}
	// Check for comma-separated constraints
	if strings.Contains(version, ",") {
		return true
	}
	return false
}

func scanYarnLockOptimized(path string, vulnerablePackageMap VulnerablePackageMap) ([]string, error) {
	var foundVulnerabilities []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	lines := strings.Split(string(data), "\n")
	var currentPackageName string

	for i, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Package definition line (doesn't start with space and ends with :)
		if !strings.HasPrefix(lines[i], " ") && strings.HasSuffix(line, ":") {
			packageDef := strings.TrimSuffix(line, ":")

			// Handle multiple package specs separated by comma
			packageSpecs := strings.Split(packageDef, ",")

			for _, spec := range packageSpecs {
				spec = strings.TrimSpace(spec)
				spec = strings.Trim(spec, "\"'")

				// Extract package name from spec like "@ctrl/tinycolor@^4.1.0"
				packageName := extractPackageNameFromYarnSpec(spec)
				if packageName != "" {
					currentPackageName = packageName
					break // Use the first valid package name
				}
			}
		} else if strings.HasPrefix(lines[i], "  ") && strings.Contains(line, "version") {
			// Version line with proper indentation
			parts := strings.SplitN(line, "version", 2)
			if len(parts) == 2 {
				version := strings.TrimSpace(parts[1])
				version = strings.Trim(version, "\"'")

				// Check against vulnerable packages
				if isVuln, vulnerablePackage := vulnerablePackageMap.isVulnerable(currentPackageName, version); isVuln {
					foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(currentPackageName, version, filepath.Base(path), vulnerablePackage))
				}
			}
		}
	}

	return foundVulnerabilities, nil
}

func scanYarnLock(path string, vulnerablePackages []VulnerablePackage) ([]string, error) {
	var foundVulnerabilities []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	lines := strings.Split(string(data), "\n")
	var currentPackageName string

	for i, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Package definition line (doesn't start with space and ends with :)
		if !strings.HasPrefix(lines[i], " ") && strings.HasSuffix(line, ":") {
			packageDef := strings.TrimSuffix(line, ":")

			// Handle multiple package specs separated by comma
			packageSpecs := strings.Split(packageDef, ",")

			for _, spec := range packageSpecs {
				spec = strings.TrimSpace(spec)
				spec = strings.Trim(spec, "\"'")

				// Extract package name from spec like "@ctrl/tinycolor@^4.1.0"
				packageName := extractPackageNameFromYarnSpec(spec)
				if packageName != "" {
					currentPackageName = packageName
					break // Use the first valid package name
				}
			}
		} else if strings.HasPrefix(lines[i], "  ") && strings.Contains(line, "version") {
			// Version line with proper indentation
			parts := strings.SplitN(line, "version", 2)
			if len(parts) == 2 {
				version := strings.TrimSpace(parts[1])
				version = strings.Trim(version, "\"'")

				// Check against vulnerable packages
				for _, vulnerablePackage := range vulnerablePackages {
					if currentPackageName == vulnerablePackage.Name {
						if isVersionVulnerable(version, vulnerablePackage.Versions) {
							foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(vulnerablePackage.Name, version, filepath.Base(path), vulnerablePackage))
						}
					}
				}
			}
		}
	}

	return foundVulnerabilities, nil
}

// extractPackageNameFromYarnSpec extracts package name from yarn.lock package spec
// Examples:
//
//	"@ctrl/tinycolor@^4.1.0" -> "@ctrl/tinycolor"
//	"lodash@^4.17.21" -> "lodash"
//	"@babel/core@^7.12.3, @babel/core@^7.12.9" -> "@babel/core"
func extractPackageNameFromYarnSpec(spec string) string {
	spec = strings.TrimSpace(spec)

	// Handle scoped packages (@org/package@version)
	if strings.HasPrefix(spec, "@") {
		// Find the second @ which indicates the version separator
		firstSlash := strings.Index(spec, "/")
		if firstSlash == -1 {
			return ""
		}

		secondAt := strings.Index(spec[firstSlash:], "@")
		if secondAt == -1 {
			// No version spec, entire string is package name
			return spec
		}

		return spec[:firstSlash+secondAt]
	} else {
		// Regular package (package@version)
		atIndex := strings.Index(spec, "@")
		if atIndex == -1 {
			// No version spec
			return spec
		}
		return spec[:atIndex]
	}
}

func scanPnpmLockOptimized(path string, vulnerablePackageMap VulnerablePackageMap) ([]string, error) {
	var foundVulnerabilities []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var pnpmLock PnpmLock
	if err := yaml.Unmarshal(data, &pnpmLock); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", path, err)
	}

	// Process packages field
	if len(pnpmLock.Packages) > 0 {
		for pkgPath := range pnpmLock.Packages {
			// Skip empty paths and root path
			if pkgPath == "" || pkgPath == "/" {
				continue
			}

			// Extract package name and version from path
			pkgName, version := extractPackageNameAndVersionFromPnpmPath(pkgPath)
			if pkgName == "" || version == "" {
				continue
			}

			// Check against vulnerable packages
			if isVuln, vulnerablePackage := vulnerablePackageMap.isVulnerable(pkgName, version); isVuln {
				foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(pkgName, version, filepath.Base(path), vulnerablePackage))
			}
		}
	}

	// Process dependencies and devDependencies fields (for older pnpm lockfile versions)
	dependencyTypes := []struct {
		deps map[string]string
		name string
	}{
		{pnpmLock.Dependencies, "dependencies"},
		{pnpmLock.DevDependencies, "devDependencies"},
	}

	for _, depType := range dependencyTypes {
		if depType.deps == nil {
			continue
		}
		for pkgName, version := range depType.deps {
			if isVuln, vulnerablePackage := vulnerablePackageMap.isVulnerable(pkgName, version); isVuln {
				foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(pkgName, version, filepath.Base(path), vulnerablePackage))
			}
		}
	}

	return foundVulnerabilities, nil
}

func scanPnpmLock(path string, vulnerablePackages []VulnerablePackage) ([]string, error) {
	var foundVulnerabilities []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var pnpmLock PnpmLock
	if err := yaml.Unmarshal(data, &pnpmLock); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", path, err)
	}

	// Process packages field
	if len(pnpmLock.Packages) > 0 {
		for pkgPath := range pnpmLock.Packages {
			// Skip empty paths and root path
			if pkgPath == "" || pkgPath == "/" {
				continue
			}

			// Extract package name and version from path
			pkgName, version := extractPackageNameAndVersionFromPnpmPath(pkgPath)
			if pkgName == "" || version == "" {
				continue
			}

			// Check against vulnerable packages
			for _, vulnerablePackage := range vulnerablePackages {
				if pkgName == vulnerablePackage.Name {
					if isVersionVulnerable(version, vulnerablePackage.Versions) {
						foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(vulnerablePackage.Name, version, filepath.Base(path), vulnerablePackage))
					}
				}
			}
		}
	}

	// Process dependencies and devDependencies fields (for older pnpm lockfile versions)
	dependencyTypes := []struct {
		deps map[string]string
		name string
	}{
		{pnpmLock.Dependencies, "dependencies"},
		{pnpmLock.DevDependencies, "devDependencies"},
	}

	for _, depType := range dependencyTypes {
		if depType.deps == nil {
			continue
		}
		for pkgName, version := range depType.deps {
			for _, vulnerablePackage := range vulnerablePackages {
				if pkgName == vulnerablePackage.Name {
					if isVersionVulnerable(version, vulnerablePackage.Versions) {
						foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(vulnerablePackage.Name, version, filepath.Base(path), vulnerablePackage))
					}
				}
			}
		}
	}

	return foundVulnerabilities, nil
}

// extractPackageNameAndVersionFromPnpmPath extracts package name and version from pnpm lockfile package path
// Examples:
//
//	"/@ctrl/tinycolor/4.1.1" -> "@ctrl/tinycolor", "4.1.1"
//	"/lodash/4.17.21" -> "lodash", "4.17.21"
func extractPackageNameAndVersionFromPnpmPath(pkgPath string) (string, string) {
	// Remove leading slash
	pkgPath = strings.TrimPrefix(pkgPath, "/")

	// Split path into components
	components := strings.Split(pkgPath, "/")
	if len(components) < 2 {
		return "", ""
	}

	// Handle scoped packages (@org/package)
	if strings.HasPrefix(pkgPath, "@") {
		if len(components) < 3 {
			return "", ""
		}
		// For scoped packages, the name is @org/package and version is the last component
		pkgName := components[0] + "/" + components[1]
		version := components[2]
		return pkgName, version
	} else {
		// For regular packages, the name is the first component and version is the second
		pkgName := components[0]
		version := components[1]
		return pkgName, version
	}
}

func scanPackageLockJSONOptimized(path string, vulnerablePackageMap VulnerablePackageMap) ([]string, error) {
	var foundVulnerabilities []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var packageLockJSON PackageLockJSON
	if err := json.Unmarshal(data, &packageLockJSON); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", path, err)
	}

	// Determine lockfile version and scan accordingly
	if packageLockJSON.LockfileVersion >= 2 && len(packageLockJSON.Packages) > 0 {
		// v2/v3: use packages field
		foundVulnerabilities = append(foundVulnerabilities, scanPackageLockPackagesOptimized(packageLockJSON.Packages, vulnerablePackageMap, filepath.Base(path))...)
	} else if len(packageLockJSON.Dependencies) > 0 {
		// v1: use dependencies field
		foundVulnerabilities = append(foundVulnerabilities, scanPackageLockDependenciesOptimized(packageLockJSON.Dependencies, vulnerablePackageMap, filepath.Base(path))...)
	}

	return foundVulnerabilities, nil
}

func scanPackageLockJSON(path string, vulnerablePackages []VulnerablePackage) ([]string, error) {
	var foundVulnerabilities []string
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var packageLockJSON PackageLockJSON
	if err := json.Unmarshal(data, &packageLockJSON); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", path, err)
	}

	// Determine lockfile version and scan accordingly
	if packageLockJSON.LockfileVersion >= 2 && len(packageLockJSON.Packages) > 0 {
		// v2/v3: use packages field
		foundVulnerabilities = append(foundVulnerabilities, scanPackageLockPackages(packageLockJSON.Packages, vulnerablePackages, filepath.Base(path))...)
	} else if len(packageLockJSON.Dependencies) > 0 {
		// v1: use dependencies field
		foundVulnerabilities = append(foundVulnerabilities, scanPackageLockDependencies(packageLockJSON.Dependencies, vulnerablePackages, filepath.Base(path))...)
	}

	return foundVulnerabilities, nil
}

// scanPackageLockPackagesOptimized scans packages field (v2/v3) with optimized lookup
func scanPackageLockPackagesOptimized(packages map[string]PackageLockPackageInfo, vulnerablePackageMap VulnerablePackageMap, filename string) []string {
	var foundVulnerabilities []string
	for pkgPath, pkgInfo := range packages {
		// pkgPath is like "node_modules/@ctrl/tinycolor" or "" for root
		pkgName := strings.TrimPrefix(pkgPath, "node_modules/")
		if pkgName == "" || strings.Contains(pkgName, "/node_modules/") {
			continue // Skip root or nested node_modules
		}

		// Get the most accurate version available
		actualVersion := getActualVersion(pkgInfo.Version, pkgInfo.Resolved)

		if isVuln, vulnerablePackage := vulnerablePackageMap.isVulnerable(pkgName, actualVersion); isVuln {
			foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(pkgName, actualVersion, filename, vulnerablePackage))
		}
	}
	return foundVulnerabilities
}

// scanPackageLockPackages scans packages field (v2/v3)
func scanPackageLockPackages(packages map[string]PackageLockPackageInfo, vulnerablePackages []VulnerablePackage, filename string) []string {
	var foundVulnerabilities []string
	for pkgPath, pkgInfo := range packages {
		// pkgPath is like "node_modules/@ctrl/tinycolor" or "" for root
		pkgName := strings.TrimPrefix(pkgPath, "node_modules/")
		if pkgName == "" || strings.Contains(pkgName, "/node_modules/") {
			continue // Skip root or nested node_modules
		}

		// Get the most accurate version available
		actualVersion := getActualVersion(pkgInfo.Version, pkgInfo.Resolved)

		for _, vulnerablePackage := range vulnerablePackages {
			if pkgName == vulnerablePackage.Name {
				if isVersionVulnerable(actualVersion, vulnerablePackage.Versions) {
					foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(vulnerablePackage.Name, actualVersion, filename, vulnerablePackage))
				}
			}
		}
	}
	return foundVulnerabilities
}

// scanPackageLockDependenciesOptimized scans dependencies field recursively (v1) with optimized lookup
func scanPackageLockDependenciesOptimized(dependencies map[string]PackageLockInfo, vulnerablePackageMap VulnerablePackageMap, filename string) []string {
	var foundVulnerabilities []string
	for pkgName, pkgInfo := range dependencies {
		if isVuln, vulnerablePackage := vulnerablePackageMap.isVulnerable(pkgName, pkgInfo.Version); isVuln {
			foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(pkgName, pkgInfo.Version, filename, vulnerablePackage))
		}
		// Recursively scan nested dependencies
		if len(pkgInfo.Dependencies) > 0 {
			foundVulnerabilities = append(foundVulnerabilities, scanPackageLockDependenciesOptimized(pkgInfo.Dependencies, vulnerablePackageMap, filename)...)
		}
	}
	return foundVulnerabilities
}

// scanPackageLockDependencies scans dependencies field recursively (v1)
func scanPackageLockDependencies(dependencies map[string]PackageLockInfo, vulnerablePackages []VulnerablePackage, filename string) []string {
	var foundVulnerabilities []string
	for pkgName, pkgInfo := range dependencies {
		for _, vulnerablePackage := range vulnerablePackages {
			if pkgName == vulnerablePackage.Name {
				if isVersionVulnerable(pkgInfo.Version, vulnerablePackage.Versions) {
					foundVulnerabilities = append(foundVulnerabilities, formatVulnerabilityMessage(vulnerablePackage.Name, pkgInfo.Version, filename, vulnerablePackage))
				}
			}
		}
		// Recursively scan nested dependencies
		if len(pkgInfo.Dependencies) > 0 {
			foundVulnerabilities = append(foundVulnerabilities, scanPackageLockDependencies(pkgInfo.Dependencies, vulnerablePackages, filename)...)
		}
	}
	return foundVulnerabilities
}
