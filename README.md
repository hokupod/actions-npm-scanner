# GitHub Actions NPM Vulnerability Scanner

[![Go](https://github.com/hokupod/actions-npm-scanner/actions/workflows/go.yml/badge.svg)](https://github.com/hokupod/actions-npm-scanner/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/hokupod/actions-npm-scanner)](https://goreportcard.com/report/github.com/hokupod/actions-npm-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Go-based CLI tool that scans GitHub Actions workflows for vulnerable NPM packages, designed as a defense against NPM poisoning attacks.

## Background

NPM poisoning attacks have become a significant security concern affecting GitHub Actions. This tool helps identify potentially vulnerable NPM packages in your GitHub Actions workflows by scanning for known compromised packages.

## Features

- 🔍 **Comprehensive Scanning**: Scans GitHub Actions workflow files (.yml/.yaml)
- 🚨 **Vulnerability Detection**: Identifies vulnerable NPM packages in actions
- 📦 **Extensive Database**: Maintains a list of 330+ known vulnerable packages
- 📂 **Flexible Input**: Supports both single file and directory scanning
- ⚡ **Fast Performance**: Leverages Go concurrency for efficient scanning
- 🌐 **Git Integration**: Automatically clones and analyzes action repositories

## Installation

### From Source

```bash
git clone https://github.com/hokupod/actions-npm-scanner.git
cd actions-npm-scanner
go build
```

### Go Install

```bash
go install github.com/hokupod/actions-npm-scanner@latest
```

### Binary Releases

Binary releases will be available on the [releases page](https://github.com/hokupod/actions-npm-scanner/releases).

## Usage

### Scan a Single Workflow File

```bash
./actions-npm-scanner workflow.yml
```

### Scan All Workflows in a Directory

```bash
./actions-npm-scanner .github/workflows/
```

### From Source

```bash
# Scan single file
go run . workflow.yml

# Scan directory
go run . .github/workflows/
```

## Sample Output

### Clean Scan (No Vulnerabilities)
```
Scanning workflow: .github/workflows/ci.yml
✅ No vulnerable packages found in actions/checkout@v4
✅ No vulnerable packages found in actions/setup-node@v4
Scan completed: 0 vulnerabilities found
```

### Vulnerabilities Found
```
Scanning workflow: .github/workflows/ci.yml
❌ Vulnerable package found in some-user/vulnerable-action@v1:
   - Package: malicious-package@1.0.0
   - Risk: High - Known malicious package
✅ No vulnerable packages found in actions/checkout@v4
Scan completed: 1 vulnerability found
```

## How It Works

1. **YAML Parsing**: Parses GitHub Actions workflow files to extract action references
2. **Repository Cloning**: Downloads each referenced action repository using go-git
3. **Package Analysis**: Searches for package.json and package-lock.json files
4. **Vulnerability Matching**: Compares found packages against database of known vulnerable packages
5. **Reporting**: Provides detailed output on any vulnerabilities discovered

## Project Structure

- **main.go**: CLI entry point and workflow orchestration
- **parser.go**: YAML workflow parsing and action extraction
- **github.go**: GitHub repository downloading using go-git
- **scanner.go**: package.json vulnerability detection
- **vulnerable_packages.go**: Database of 330+ vulnerable NPM packages

## Development

### Building

```bash
go build
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./...

# Run specific test
go test -run TestName
```

### Dependencies

- `gopkg.in/yaml.v3`: YAML parsing
- `github.com/go-git/go-git/v5`: Git repository operations
- `github.com/Masterminds/semver/v3`: Semantic version handling

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

# 日本語 (Japanese)

## 概要

このツールは、NPM汚染攻撃に対する防御ツールとして開発された、GitHub Actionsワークフロー内の脆弱なNPMパッケージをスキャンするGo製のCLIツールです。

## 背景

NPM汚染攻撃はGitHub Actionsに影響する重要なセキュリティ懸念事項となっています。このツールは、既知の脆弱なパッケージをスキャンすることで、GitHub Actionsワークフロー内の潜在的に危険なNPMパッケージを特定するのに役立ちます。

## 主な機能

- 🔍 **包括的スキャン**: GitHub Actionsワークフローファイル(.yml/.yaml)をスキャン
- 🚨 **脆弱性検出**: アクション内の脆弱なNPMパッケージを特定
- 📦 **豊富なデータベース**: 330以上の既知の脆弱なパッケージのリストを維持
- 📂 **柔軟な入力**: 単一ファイルとディレクトリスキャンの両方をサポート
- ⚡ **高速パフォーマンス**: Goの並行処理を活用した効率的なスキャン
- 🌐 **Git統合**: アクションリポジトリの自動クローンと分析

## インストール

### ソースから

```bash
git clone https://github.com/hokupod/actions-npm-scanner.git
cd actions-npm-scanner
go build
```

### Go Install

```bash
go install github.com/hokupod/actions-npm-scanner@latest
```

## 使用方法

### 単一ワークフローファイルのスキャン

```bash
./actions-npm-scanner workflow.yml
```

### ディレクトリ内の全ワークフローのスキャン

```bash
./actions-npm-scanner .github/workflows/
```

### ソースから実行

```bash
# 単一ファイルをスキャン
go run . workflow.yml

# ディレクトリをスキャン
go run . .github/workflows/
```

## 動作原理

1. **YAML解析**: GitHub Actionsワークフローファイルを解析してアクション参照を抽出
2. **リポジトリクローン**: go-gitを使用して各参照されたアクションリポジトリをダウンロード
3. **パッケージ分析**: package.jsonとpackage-lock.jsonファイルを検索
4. **脆弱性マッチング**: 発見されたパッケージを既知の脆弱なパッケージのデータベースと比較
5. **レポート**: 発見された脆弱性について詳細な出力を提供

## 開発

### ビルド

```bash
go build
```

### テスト実行

```bash
# 全テストを実行
go test ./...

# 詳細出力で実行
go test -v ./...
```

## ライセンス

このプロジェクトはMITライセンスの下でライセンスされています - 詳細は[LICENSE](LICENSE)ファイルを参照してください。