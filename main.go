package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// Action represents a GitHub Action
type Action struct {
	Owner   string
	Repo    string
	Version string
	Path    string
}

func main() {
	localMode := flag.Bool("local", false, "scan a local dependency file or directory")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Printf("Usage: %s [--local] <path>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	path := flag.Arg(0)
	vulnerabilityCatalog := GetVulnerabilityCatalog()

	var found bool
	var err error
	if *localMode {
		found, err = runLocalScan(path, vulnerabilityCatalog)
	} else {
		found, err = runWorkflowScan(path, vulnerabilityCatalog)
	}
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	if found {
		os.Exit(1)
	}
}

func runWorkflowScan(path string, vulnerabilityCatalog VulnerabilityCatalog) (bool, error) {
	files, err := getFiles(path)
	if err != nil {
		return false, err
	}

	foundAny := false
	for _, file := range files {
		fmt.Println("Scanning workflow:", file)

		workflow, err := ParseWorkflow(file)
		if err != nil {
			fmt.Println("Error parsing workflow:", err)
			continue
		}

		actions := ExtractActions(workflow)

		for _, action := range actions {
			if scanWorkflowAction(action, vulnerabilityCatalog) {
				foundAny = true
			}
		}
	}

	return foundAny, nil
}

func scanWorkflowAction(action Action, vulnerabilityCatalog VulnerabilityCatalog) bool {
	tmpDir, err := os.MkdirTemp("", "action-")
	if err != nil {
		fmt.Println("Error creating temp dir:", err)
		return false
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			fmt.Println("Error cleaning temp dir:", err)
		}
	}()

	fmt.Printf("  Downloading action %s/%s@%s...\n", action.Owner, action.Repo, action.Version)
	if err := DownloadAction(action, tmpDir); err != nil {
		fmt.Println("Error downloading action:", err)
		return false
	}

	fmt.Printf("  🔍 Scanning action %s/%s@%s...\n", action.Owner, action.Repo, action.Version)
	vulnerabilities, err := ScanAction(tmpDir, vulnerabilityCatalog)
	if err != nil {
		fmt.Println("Error scanning action:", err)
		return false
	}

	printVulnerabilityResult("    ", vulnerabilities)
	fmt.Printf("  Scan finished for action %s/%s@%s.\n", action.Owner, action.Repo, action.Version)

	return len(vulnerabilities) > 0
}

func runLocalScan(path string, vulnerabilityCatalog VulnerabilityCatalog) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	var vulnerabilities []string
	if fileInfo.IsDir() {
		fmt.Println("Scanning local path:", path)
		vulnerabilities, err = ScanAction(path, vulnerabilityCatalog)
	} else {
		fmt.Printf("🔍 Scanning local file: %s...\n", path)
		vulnerablePackageMap := buildVulnerablePackageMap(vulnerabilityCatalog.NpmPackages)
		pypiPackageMap := buildVulnerablePypiPackageMap(vulnerabilityCatalog.PypiPackages)
		vulnerabilities, err = scanDependencyFile(path, vulnerablePackageMap, pypiPackageMap)
	}
	if err != nil {
		return false, err
	}

	printVulnerabilityResult("  ", vulnerabilities)
	return len(vulnerabilities) > 0, nil
}

func printVulnerabilityResult(indent string, vulnerabilities []string) {
	if len(vulnerabilities) > 0 {
		fmt.Println(indent + "⚠️ Found vulnerabilities:")
		for _, vulnerability := range vulnerabilities {
			fmt.Println(indent+"  - ", vulnerability)
		}
	} else {
		fmt.Println(indent + "✅ No vulnerabilities found.")
	}
}

func getFiles(path string) ([]string, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if fileInfo.IsDir() {
		files, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}

		var yamlFiles []string
		for _, file := range files {
			if !file.IsDir() && (filepath.Ext(file.Name()) == ".yml" || filepath.Ext(file.Name()) == ".yaml") {
				yamlFiles = append(yamlFiles, filepath.Join(path, file.Name()))
			}
		}
		return yamlFiles, nil
	} else {
		return []string{path}, nil
	}
}
