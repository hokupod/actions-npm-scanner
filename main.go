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
	verboseShort := flag.Bool("v", false, "show detailed scan output")
	verboseLong := flag.Bool("verbose", false, "show detailed scan output")
	failOnError := flag.Bool("fail-on-error", false, "exit with code 2 when the scan reported any error")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Printf("Usage: %s [--local] [-v|--verbose] [--fail-on-error] <path>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	path := flag.Arg(0)
	verbose := *verboseShort || *verboseLong
	vulnerabilityCatalog := GetVulnerabilityCatalog()

	var summary ScanSummary
	var err error
	if *localMode {
		summary, err = runLocalScan(path, vulnerabilityCatalog, verbose)
	} else {
		summary, err = runWorkflowScan(path, vulnerabilityCatalog, verbose)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		if *failOnError {
			os.Exit(2)
		}
		os.Exit(1)
	}
	printScanSummary(summary)
	// Any error means the scan was incomplete, so the flag keys off the error
	// count rather than Files failed. An action that could not be downloaded
	// leaves Files failed at zero yet was never scanned at all. The error check
	// runs before the vulnerability check: an incomplete scan may hide further
	// findings, so exit 2 takes precedence over exit 1 when the flag is set.
	if *failOnError && summary.HasErrors() {
		os.Exit(2)
	}
	if summary.HasVulnerabilities() {
		os.Exit(1)
	}
}

type ScanSummary struct {
	WorkflowsScanned int
	ActionsScanned   int
	FilesFailed      int
	Vulnerabilities  []ScanFinding
	Errors           []string
}

func (summary ScanSummary) HasVulnerabilities() bool {
	return len(summary.Vulnerabilities) > 0
}

func (summary ScanSummary) HasErrors() bool {
	return len(summary.Errors) > 0
}

type ScanFinding struct {
	Workflow string
	Action   string
	Target   string
	Message  string
}

func runWorkflowScan(path string, vulnerabilityCatalog VulnerabilityCatalog, verbose bool) (ScanSummary, error) {
	files, err := getFiles(path)
	if err != nil {
		return ScanSummary{}, err
	}

	var summary ScanSummary
	scannedActions := make(map[string]bool)
	for _, file := range files {
		summary.WorkflowsScanned++
		fmt.Println("Scanning workflow:", file)

		workflow, err := ParseWorkflow(file)
		if err != nil {
			message := fmt.Sprintf("Error parsing workflow %s: %v", file, err)
			summary.Errors = append(summary.Errors, message)
			summary.FilesFailed++
			if verbose {
				fmt.Fprintln(os.Stderr, "Error parsing workflow:", err)
			}
			continue
		}

		actions := ExtractActions(workflow)

		for _, action := range actions {
			actionKey := actionScanKey(action)
			if scannedActions[actionKey] {
				if verbose {
					fmt.Printf("  Skipping already scanned action %s.\n", actionKey)
				}
				continue
			}

			result := scanWorkflowAction(action, vulnerabilityCatalog, verbose)
			summary.Errors = append(summary.Errors, result.Errors...)
			summary.FilesFailed += result.FilesFailed
			for _, vulnerability := range result.Vulnerabilities {
				summary.Vulnerabilities = append(summary.Vulnerabilities, ScanFinding{
					Workflow: file,
					Action:   actionKey,
					Message:  vulnerability,
				})
			}
			if result.Completed {
				summary.ActionsScanned++
				scannedActions[actionKey] = true
			}
		}
	}

	return summary, nil
}

func actionScanKey(action Action) string {
	return fmt.Sprintf("%s/%s@%s", action.Owner, action.Repo, action.Version)
}

type workflowActionScanResult struct {
	Vulnerabilities []string
	Errors          []string
	FilesFailed     int
	Completed       bool
}

func scanWorkflowAction(action Action, vulnerabilityCatalog VulnerabilityCatalog, verbose bool) workflowActionScanResult {
	actionKey := actionScanKey(action)
	tmpDir, err := os.MkdirTemp("", "action-")
	if err != nil {
		message := fmt.Sprintf("Error creating temp dir for action %s: %v", actionKey, err)
		if verbose {
			fmt.Println("Error creating temp dir:", err)
		}
		return workflowActionScanResult{Errors: []string{message}}
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			if verbose {
				fmt.Println("Error cleaning temp dir:", err)
			}
		}
	}()

	if verbose {
		fmt.Printf("  Downloading action %s...\n", actionKey)
	}
	if err := DownloadAction(action, tmpDir); err != nil {
		message := fmt.Sprintf("Error downloading action %s: %v", actionKey, err)
		if verbose {
			fmt.Println("Error downloading action:", err)
		}
		return workflowActionScanResult{Errors: []string{message}}
	}

	if verbose {
		fmt.Printf("  🔍 Scanning action %s...\n", actionKey)
	}
	scanResult := scanAction(tmpDir, vulnerabilityCatalog, verbose)

	if verbose {
		printVulnerabilityResult("    ", scanResult.Vulnerabilities)
		fmt.Printf("  Scan finished for action %s.\n", actionKey)
	}

	messages := make([]string, 0, len(scanResult.FileErrors))
	for _, fileError := range scanResult.FileErrors {
		messages = append(messages, fmt.Sprintf("Error scanning action %s: %s", actionKey, fileError))
	}

	return workflowActionScanResult{
		Vulnerabilities: scanResult.Vulnerabilities,
		Errors:          messages,
		FilesFailed:     len(scanResult.FileErrors),
		Completed:       true,
	}
}

func runLocalScan(path string, vulnerabilityCatalog VulnerabilityCatalog, verbose bool) (ScanSummary, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return ScanSummary{}, err
	}

	summary := ScanSummary{}
	var vulnerabilities []string
	if fileInfo.IsDir() {
		if verbose {
			fmt.Println("Scanning local path:", path)
		}
		scanResult := scanAction(path, vulnerabilityCatalog, verbose)
		vulnerabilities = scanResult.Vulnerabilities
		summary.Errors = append(summary.Errors, scanResult.FileErrors...)
		summary.FilesFailed = len(scanResult.FileErrors)
	} else {
		if verbose {
			fmt.Printf("🔍 Scanning local file: %s...\n", path)
		}
		vulnerablePackageMap := buildVulnerablePackageMap(vulnerabilityCatalog.NpmPackages)
		pypiPackageMap := buildVulnerablePypiPackageMap(vulnerabilityCatalog.PypiPackages)
		vulnerabilities, err = scanDependencyFile(path, vulnerablePackageMap, pypiPackageMap)
		if err != nil {
			return ScanSummary{}, err
		}
	}

	if verbose {
		printVulnerabilityResult("  ", vulnerabilities)
	}
	for _, vulnerability := range vulnerabilities {
		summary.Vulnerabilities = append(summary.Vulnerabilities, ScanFinding{
			Target:  path,
			Message: vulnerability,
		})
	}
	return summary, nil
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

func printScanSummary(summary ScanSummary) {
	if summary.HasVulnerabilities() {
		fmt.Println("⚠️ Found vulnerabilities.")
	} else {
		fmt.Println("✅ No vulnerabilities found.")
	}
	fmt.Printf("Workflows scanned: %d\n", summary.WorkflowsScanned)
	fmt.Printf("Actions scanned: %d\n", summary.ActionsScanned)
	fmt.Printf("Vulnerabilities found: %d\n", len(summary.Vulnerabilities))
	fmt.Printf("Files failed: %d\n", summary.FilesFailed)
	fmt.Printf("Errors: %d\n", len(summary.Errors))

	if len(summary.Vulnerabilities) > 0 {
		fmt.Println("Vulnerability details:")
		for _, finding := range summary.Vulnerabilities {
			fmt.Printf("  - %s\n", formatScanFinding(finding))
		}
	}

	// Errors go to stderr so that a pipeline grepping stdout cannot mistake a
	// partial scan for a clean one.
	if len(summary.Errors) > 0 {
		fmt.Fprintln(os.Stderr, "Error details:")
		for _, scanError := range summary.Errors {
			fmt.Fprintf(os.Stderr, "  - %s\n", scanError)
		}
	}
}

func formatScanFinding(finding ScanFinding) string {
	if finding.Workflow != "" && finding.Action != "" {
		return fmt.Sprintf("%s | %s: %s", finding.Workflow, finding.Action, finding.Message)
	}
	if finding.Target != "" {
		return fmt.Sprintf("%s: %s", finding.Target, finding.Message)
	}
	return finding.Message
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
