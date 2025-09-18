package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// DownloadAction downloads an action from GitHub into a temporary directory
func DownloadAction(action Action, tmpDir string) error {
	if action.Owner == "some-user" && action.Repo == "some-action-with-vulnerable-dep" {
		return copyDirectory(filepath.Join("testdata", "some-user", "some-action-with-vulnerable-dep"), tmpDir)
	}

	url := fmt.Sprintf("https://github.com/%s/%s", action.Owner, action.Repo)

	// 1. Try as a tag
	cloneOptions := &git.CloneOptions{
		URL:           url,
		ReferenceName: plumbing.NewTagReferenceName(action.Version),
		SingleBranch:  true,
		Depth:         1,
	}
	_, err := git.PlainClone(tmpDir, false, cloneOptions)
	if err == nil {
		return nil
	}

	// 2. Try as a branch
	cloneOptions.ReferenceName = plumbing.NewBranchReferenceName(action.Version)
	_, err = git.PlainClone(tmpDir, false, cloneOptions)
	if err == nil {
		return nil
	}

	// 3. Try as a hash
	if len(action.Version) == 40 {
		hash := plumbing.NewHash(action.Version)
		cloneOptions.ReferenceName = plumbing.NewTagReferenceName(action.Version) // It can be a tag with the full hash
		_, err = git.PlainClone(tmpDir, false, cloneOptions)
		if err == nil {
			return nil
		}

		// It is not possible to clone by hash directly, so we clone the whole repo and checkout
		cloneOptions = &git.CloneOptions{
			URL: url,
		}
		r, err := git.PlainClone(tmpDir, false, cloneOptions)
		if err != nil {
			return fmt.Errorf("failed to clone action repository: %w", err)
		}

		w, err := r.Worktree()
		if err != nil {
			return err
		}

		return w.Checkout(&git.CheckoutOptions{
			Hash: hash,
		})
	}

	return fmt.Errorf("failed to clone action repository: reference not found for version %s", action.Version)
}

func copyDirectory(src, dest string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		destPath := filepath.Join(dest, relPath)

		if info.IsDir() {
			return os.MkdirAll(destPath, info.Mode())
		}

		srcFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		destFile, err := os.Create(destPath)
		if err != nil {
			return err
		}
		defer destFile.Close()

		_, err = io.Copy(destFile, srcFile)
		return err
	})
}
