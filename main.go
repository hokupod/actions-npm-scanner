package main

import (
	"flag"
	"fmt"
	"io/ioutil"
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
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Println("Usage: go run . <path>")
		os.Exit(1)
	}

	path := flag.Arg(0)

	files, err := getFiles(path)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	vulnerablePackages := GetVulnerablePackages()

	for _, file := range files {
		fmt.Println("Scanning workflow:", file)

		workflow, err := ParseWorkflow(file)
		if err != nil {
			fmt.Println("Error parsing workflow:", err)
			continue
		}

		actions := ExtractActions(workflow)

		for _, action := range actions {
			tmpDir, err := ioutil.TempDir("", "action-")
			if err != nil {
				fmt.Println("Error creating temp dir:", err)
				continue
			}
			defer os.RemoveAll(tmpDir)

			fmt.Printf("  Downloading action %s/%s@%s...\n", action.Owner, action.Repo, action.Version)
			if err := DownloadAction(action, tmpDir); err != nil {
				fmt.Println("Error downloading action:", err)
				continue
			}

			fmt.Printf("  🔍 Scanning action %s/%s@%s...\n", action.Owner, action.Repo, action.Version)
			vulnerabilities, err := ScanAction(tmpDir, vulnerablePackages)
			if err != nil {
				fmt.Println("Error scanning action:", err)
				continue
			}

			if len(vulnerabilities) > 0 {
				fmt.Println("    ⚠️ Found vulnerabilities:")
				for _, vulnerability := range vulnerabilities {
					fmt.Println("      - ", vulnerability)
				}
			} else {
				fmt.Println("    ✅ No vulnerabilities found.")
			}
			fmt.Printf("  Scan finished for action %s/%s@%s.\n", action.Owner, action.Repo, action.Version)
		}
	}
}

func getFiles(path string) ([]string, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if fileInfo.IsDir() {
		files, err := ioutil.ReadDir(path)
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
