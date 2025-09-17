package main

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestParseWorkflow(t *testing.T) {
	content := `
jobs:
  build:
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
        with:
          node-version: '14'
`
	tmpfile, err := ioutil.TempFile("", "workflow.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	workflow, err := ParseWorkflow(tmpfile.Name())
	if err != nil {
		t.Fatalf("ParseWorkflow() error = %v", err)
	}

	if len(workflow.Jobs) != 1 {
		t.Errorf("expected 1 job, got %d", len(workflow.Jobs))
	}

	if len(workflow.Jobs["build"].Steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(workflow.Jobs["build"].Steps))
	}
}

func TestExtractActions(t *testing.T) {
	workflow := &Workflow{
		Jobs: map[string]Job{
			"build": {
				Steps: []Step{
					{Uses: "actions/checkout@v2"},
					{Uses: "actions/setup-node@v2"},
				},
			},
		},
	}

	actions := ExtractActions(workflow)

	if len(actions) != 2 {
		t.Errorf("expected 2 actions, got %d", len(actions))
	}

	if actions[0].Owner != "actions" || actions[0].Repo != "checkout" || actions[0].Version != "v2" {
		t.Errorf("unexpected action: %+v", actions[0])
	}
}
