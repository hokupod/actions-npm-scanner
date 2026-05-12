# GitHub Actions NPM Vulnerability Scanner

[![Go Report Card](https://goreportcard.com/badge/github.com/hokupod/actions-npm-scanner)](https://goreportcard.com/report/github.com/hokupod/actions-npm-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Go-based CLI tool that scans GitHub Actions workflows for vulnerable NPM packages, designed as a defense against NPM poisoning attacks.

## Background

This tool was developed in response to the [Shai-Hulud supply chain attack](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised) that compromised over 40 NPM packages in late 2024, including the widely-used `@ctrl/tinycolor` package (2+ million weekly downloads).

It also includes Mini Shai-Hulud indicators tracked by Socket as of May 12, 2026, covering 405 npm artifacts and the PyPI `lightning` package versions 2.6.2 and 2.6.3.

The attack demonstrated sophisticated techniques including:
- Self-propagating malware across maintainer packages
- Credential harvesting from AWS, GCP, Azure, and GitHub
- GitHub Actions backdoors for persistent access
- Exfiltration of secrets to public repositories

This scanner helps identify these specifically compromised packages in your GitHub Actions workflows, providing defense against this and similar NPM poisoning attacks that target CI/CD environments.

In late 2025, the "Second Coming" NPM contamination campaign was discovered, which is detailed in this [blog post](https://research.jfrog.com/post/shai-hulud-the-second-coming/).

## Features

- 🔍 **Comprehensive Scanning**: Scans GitHub Actions workflow files (.yml/.yaml)
- 🚨 **Vulnerability Detection**: Identifies vulnerable NPM and PyPI packages in actions
- 📦 **Curated Package List**: Contains 330+ Shai-Hulud packages plus Mini Shai-Hulud NPM/PyPI artifacts
- 🐍 **Python Lockfile Coverage**: Scans `requirements*.txt`, `Pipfile.lock`, `poetry.lock`, and `uv.lock`
- 📂 **Flexible Input**: Supports both single file and directory scanning
- 💻 **Local Dependency Scanning**: Scans local dependency files or directories with `--local`
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
actions-npm-scanner workflow.yml
```

### Scan All Workflows in a Directory

```bash
actions-npm-scanner .github/workflows/
```

### Scan a Local Dependency File or Directory

```bash
# Scan a single dependency file
actions-npm-scanner --local package.json

# Scan supported dependency files directly under a directory
actions-npm-scanner --local .
```

### From Source

```bash
# Scan single file
go run . workflow.yml

# Scan directory
go run . .github/workflows/

# Scan local dependency file or directory
go run . --local package.json
```

Add `-v` or `--verbose` to show detailed per-action and per-file scan output before the summary.

The command scans all requested targets before exiting. If any vulnerability is found, it exits with status code `1`; otherwise it exits with `0`.

## Sample Output

### Clean Scan (No Vulnerabilities)
```
✅ No vulnerabilities found.
Workflows scanned: 1
Actions scanned: 2
Vulnerabilities found: 0
Errors: 0
```

### Vulnerabilities Found
```
⚠️ Found vulnerabilities.
Workflows scanned: 1
Actions scanned: 2
Vulnerabilities found: 1
Errors: 0
Vulnerability details:
  - .github/workflows/ci.yml | some-user/vulnerable-action@v1: Found vulnerable package @ctrl/tinycolor with version 4.1.1 in package.json (dependencies)
```

### Verbose Output
```
Scanning workflow: .github/workflows/ci.yml
  Downloading action actions/checkout@v4...
  🔍 Scanning action actions/checkout@v4...
    🔍 Scanning package.json...
    🔍 Scanning package-lock.json...
       yarn.lock not found. Skipping.
       pnpm-lock.yaml not found. Skipping.
    ✅ No vulnerabilities found.
  Scan finished for action actions/checkout@v4.
  Downloading action some-user/vulnerable-action@v1...
  🔍 Scanning action some-user/vulnerable-action@v1...
    🔍 Scanning package.json...
       package-lock.json not found. Skipping.
       yarn.lock not found. Skipping.
       pnpm-lock.yaml not found. Skipping.
    ⚠️ Found vulnerabilities:
      -  Found vulnerable package @ctrl/tinycolor with version 4.1.1 in package.json (dependencies)
  Scan finished for action some-user/vulnerable-action@v1.
⚠️ Found vulnerabilities.
Workflows scanned: 1
Actions scanned: 2
Vulnerabilities found: 1
Errors: 0
Vulnerability details:
  - .github/workflows/ci.yml | some-user/vulnerable-action@v1: Found vulnerable package @ctrl/tinycolor with version 4.1.1 in package.json (dependencies)
```

## How It Works

1. **YAML Parsing**: Parses GitHub Actions workflow files to extract action references
2. **Repository Cloning**: Downloads each referenced action repository using go-git
3. **Package Analysis**: Searches for npm and Python dependency files
4. **Vulnerability Matching**: Compares found packages against static Shai-Hulud and Mini Shai-Hulud indicators
5. **Reporting**: Provides detailed output on any vulnerabilities discovered

Composer/Packagist indicators such as `intercom/intercom-php@5.0.2` are tracked as a follow-up area and are not scanned in the current implementation.

## Project Structure

- **main.go**: CLI entry point and workflow orchestration
- **parser.go**: YAML workflow parsing and action extraction
- **github.go**: GitHub repository downloading using go-git
- **scanner.go**: npm and Python dependency vulnerability detection
- **vulnerable_packages.go**: Static ecosystem-specific lists of compromised packages

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

このツールは、2024年後半に発生した[Shai-Hulud サプライチェーン攻撃](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)への対応として開発されました。この攻撃では、週間200万以上のダウンロード数を誇る`@ctrl/tinycolor`を含む40以上のNPMパッケージが侵害されました。

2026年5月12日時点でSocketが追跡しているMini Shai-HuludのNPM 405 artifactsと、PyPI `lightning` 2.6.2/2.6.3も検出対象に含めています。

この攻撃では以下のような高度な技術が使用されました：
- メンテナパッケージ間での自己増殖型マルウェア
- AWS、GCP、Azure、GitHubからの認証情報窃取
- 永続的アクセスのためのGitHub Actionsバックドア
- パブリックリポジトリへのシークレット情報の流出

このスキャナーは、GitHub Actionsワークフロー内でこれらの特定の侵害されたパッケージを識別し、CI/CD環境を標的とするNPM汚染攻撃に対する防御を提供します。

2025年後半には、「Second Coming」と呼ばれるNPM汚染キャンペーンが発見されました。詳細については、こちらの[ブログ記事](https://research.jfrog.com/post/shai-hulud-the-second-coming/)で解説されています。

## 主な機能

- 🔍 **包括的スキャン**: GitHub Actionsワークフローファイル(.yml/.yaml)をスキャン
- 🚨 **脆弱性検出**: アクション内の脆弱なNPM/PyPIパッケージを特定
- 📦 **厳選されたパッケージリスト**: Shai-Hulud攻撃の330以上のパッケージとMini Shai-HuludのNPM/PyPI artifactsを含む
- 🐍 **Pythonロックファイル対応**: `requirements*.txt`、`Pipfile.lock`、`poetry.lock`、`uv.lock`をスキャン
- 📂 **柔軟な入力**: 単一ファイルとディレクトリスキャンの両方をサポート
- 💻 **ローカル依存ファイルスキャン**: `--local`でローカルの依存ファイルまたはディレクトリをスキャン
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
actions-npm-scanner workflow.yml
```

### ディレクトリ内の全ワークフローのスキャン

```bash
actions-npm-scanner .github/workflows/
```

### ローカル依存ファイルまたはディレクトリのスキャン

```bash
# 単一の依存ファイルをスキャン
actions-npm-scanner --local package.json

# ディレクトリ直下の対応依存ファイルをスキャン
actions-npm-scanner --local .
```

### ソースから実行

```bash
# 単一ファイルをスキャン
go run . workflow.yml

# ディレクトリをスキャン
go run . .github/workflows/

# ローカル依存ファイルまたはディレクトリをスキャン
go run . --local package.json
```

コマンドは対象を最後までスキャンしてから終了します。脆弱性が1件以上見つかった場合は終了コード`1`、見つからない場合は`0`で終了します。

## 動作原理

1. **YAML解析**: GitHub Actionsワークフローファイルを解析してアクション参照を抽出
2. **リポジトリクローン**: go-gitを使用して各参照されたアクションリポジトリをダウンロード
3. **パッケージ分析**: npmとPythonの依存関係ファイルを検索
4. **脆弱性マッチング**: 発見されたパッケージをShai-Hulud/Mini Shai-Huludの静的IoCカタログと比較
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
