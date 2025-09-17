# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## プロジェクト概要

このプロジェクトはGitHub Actionsワークフロー内で使用されているNPMパッケージの脆弱性をチェックするGoベースのCLIツールです。NPM汚染攻撃に対する防御ツールとして開発されています。

## 主要コマンド

### ビルド・実行
```bash
go build                    # バイナリをビルド
go run . <path>            # ソースから直接実行（パスはワークフローファイルまたはディレクトリ）
```

### テスト
```bash
go test                    # 全テストを実行
go test -v                 # 詳細出力でテストを実行
go test ./...              # すべてのパッケージのテストを実行
go test -run TestName      # 特定のテストを実行
```

### 依存関係管理
```bash
go mod tidy               # 依存関係を整理
go mod download           # 依存関係をダウンロード
```

## アーキテクチャ

### 主要コンポーネント

- **main.go**: CLIエントリーポイント。コマンドライン引数を処理し、全体の処理を協調させる
- **parser.go**: GitHub Actionsワークフロー（YAML）の解析とアクション抽出
- **github.go**: GitHubからアクションリポジトリのダウンロード（go-git使用）
- **scanner.go**: ダウンロードしたアクション内のpackage.jsonファイルでの脆弱パッケージ検出
- **vulnerable_packages.go**: 脆弱なNPMパッケージのリスト（330以上のパッケージ）

### データフロー

1. YAMLワークフローファイルを解析してアクションを抽出
2. 各アクションのGitHubリポジトリを一時ディレクトリにクローン
3. package.json/package-lock.jsonファイルを検索
4. 脆弱パッケージリストと照合
5. 結果をコンソールに出力

### 主要な型定義

- `Action`: GitHubアクション（Owner, Repo, Version, Path）
- `VulnerablePackage`: 脆弱なNPMパッケージ（Name, Version）
- `Workflow`: GitHubワークフロー構造

## テストサンプル

プロジェクトには`workflow.yml`サンプルファイルが含まれており、テスト実行時の動作確認に使用できます。

## 依存関係

- `gopkg.in/yaml.v3`: YAMLパース
- `github.com/go-git/go-git/v5`: Gitリポジトリクローン

## 使用例

```bash
# 単一ワークフローファイルをスキャン
go run . workflow.yml

# ディレクトリ内の全YAMLファイルをスキャン
go run . .github/workflows/
```