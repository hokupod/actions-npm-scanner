# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## プロジェクト概要

このプロジェクトは、2024年後半に発生したShai-Hulud サプライチェーン攻撃（@ctrl/tinycolorを含む40以上のNPMパッケージが侵害）への対応として開発されたGoベースのCLIツールです。GitHub Actionsワークフロー内で使用されている、この攻撃で特定された脆弱なNPMパッケージをチェックします。

参考: https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised

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
- **scanner.go**: 複数のパッケージマネージャ（npm、yarn、pnpm）のロックファイルでの脆弱パッケージ検出。ハッシュマップ最適化とresolvedフィールドからの正確なバージョン抽出機能を含む
- **vulnerable_packages.go**: Shai-Hulud攻撃で侵害されたNPMパッケージの静的リスト（330以上のパッケージ）

### データフロー

1. YAMLワークフローファイルを解析してアクションを抽出
2. 各アクションのGitHubリポジトリを一時ディレクトリにクローン
3. 複数のパッケージマネージャファイルを検索：
   - package.json（npm）
   - package-lock.json（npm v1/v2/v3対応、resolvedフィールドからの正確なバージョン抽出）
   - yarn.lock（yarn）
   - pnpm-lock.yaml（pnpm）
4. ハッシュマップによる最適化された脆弱パッケージ検索
5. 結果をコンソールに出力

### 主要な型定義

- `Action`: GitHubアクション（Owner, Repo, Version, Path）
- `VulnerablePackage`: 脆弱なNPMパッケージ（Name, Versions）
- `VulnerablePackageMap`: パフォーマンス最適化のためのハッシュマップ型
- `Workflow`: GitHubワークフロー構造
- `PackageJSON`, `PackageLockJSON`, `PnpmLock`: 各パッケージマネージャのファイル構造

## テストサンプル

プロジェクトには`workflow.yml`サンプルファイルが含まれており、テスト実行時の動作確認に使用できます。

## 依存関係

- `gopkg.in/yaml.v3`: YAMLパース
- `github.com/go-git/go-git/v5`: Gitリポジトリクローン
- `github.com/Masterminds/semver/v3`: セマンティックバージョニング処理と範囲指定の解析

## 最近の改善点

### バージョンマッチング精度向上
- package-lock.jsonの`resolved`フィールドから実際にダウンロードされたバージョンを抽出
- セマンティックバージョン範囲指定（^, ~, >=等）の正確な処理
- プレリリース版のサポート向上

### パフォーマンス最適化
- 脆弱パッケージリストのハッシュマップ化（O(n*m) → O(n)の計算量改善）
- 各パッケージマネージャ向けの最適化されたスキャン関数

### 包括的なテストカバレッジ
- resolved版処理のテスト
- ハッシュマップ最適化のテスト
- 複数パッケージマネージャの統合テスト

## 使用例

```bash
# 単一ワークフローファイルをスキャン
go run . workflow.yml

# ディレクトリ内の全YAMLファイルをスキャン
go run . .github/workflows/
```