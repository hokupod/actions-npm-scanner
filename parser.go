package main

import (
	"fmt"
	"io/ioutil"
	"strings"

	"gopkg.in/yaml.v3"
)

// Workflow represents a GitHub Actions workflow
type Workflow struct {
	Jobs map[string]Job `yaml:"jobs"`
}

// Job represents a job in a workflow
type Job struct {
	Steps []Step `yaml:"steps"`
}

// Step represents a step in a job
type Step struct {
	Uses string `yaml:"uses"`
}

// ParseWorkflow parses a workflow file and returns a Workflow struct
func ParseWorkflow(path string) (*Workflow, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read workflow file: %w", err)
	}

	var workflow Workflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		return nil, fmt.Errorf("failed to unmarshal workflow file: %w", err)
	}

	return &workflow, nil
}

// ExtractActions extracts all actions from a workflow
func ExtractActions(workflow *Workflow) []Action {
	var actions []Action

	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Uses != "" {
				action := parseAction(step.Uses)
				if action != nil {
					actions = append(actions, *action)
				}
			}
		}
	}

	return actions
}

func parseAction(uses string) *Action {
	if strings.HasPrefix(uses, "./") {
		return nil
	}

	parts := strings.Split(uses, "@")
	if len(parts) != 2 {
		return nil
	}

	actionParts := strings.Split(parts[0], "/")
	if len(actionParts) < 2 {
		return nil
	}

	owner := actionParts[0]
	repo := actionParts[1]
	version := parts[1]

	path := ""
	if len(actionParts) > 2 {
		path = strings.Join(actionParts[2:], "/")
	}

	return &Action{
		Owner:   owner,
		Repo:    repo,
		Version: version,
		Path:    path,
	}
}
