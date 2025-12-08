# Upstream同期手順

このリポジトリは[auth0-lab/mdl](https://github.com/auth0-lab/mdl)からforkされています。
このドキュメントでは、fork元（upstream）の最新変更を取り込む手順を説明します。

## 概要

- `main`ブランチ: 安定版（プロダクション用）
- `sync-upstream`ブランチ: upstream変更の取り込み専用ブランチ
- `upstream`リモート: auth0-lab/mdlを指す

## 定期的な更新手順

### 1. upstreamの最新変更を取得・マージ

```bash
# sync-upstreamブランチに切り替え
git checkout sync-upstream

# upstreamの最新変更を取得
git fetch upstream

# upstreamの変更をマージ
git merge upstream/main
```

### 2. コンフリクトの解決（発生した場合）

通常、`package-lock.json`は`.gitignore`に追加済みなのでコンフリクトは起きにくいですが、
もし発生した場合：

```bash
# package-lock.jsonのコンフリクトの場合（pnpm使用のため削除）
git rm package-lock.json

# その他のコンフリクトは手動で解決
# 解決後、マージをコミット
git commit
```

### 3. リモートにプッシュして変更を確認

```bash
# リモートにプッシュ
git push origin sync-upstream

# mainブランチとの差分を確認
git diff main..sync-upstream --stat
git log main..sync-upstream --oneline
```

### 4. mainブランチにマージ

変更内容を確認して問題なければ、mainブランチにマージします：

```bash
# mainブランチに切り替え
git checkout main

# sync-upstreamをマージ
git merge sync-upstream

# リモートにプッシュ
git push origin main
```

## 簡潔な手順（一連のコマンド）

```bash
# Step 1: upstreamの変更を取り込む
git checkout sync-upstream
git fetch upstream && git merge upstream/main
git push origin sync-upstream

# Step 2: 変更を確認
git diff main..sync-upstream

# Step 3: 問題なければmainにマージ
git checkout main
git merge sync-upstream
git push origin main
```

## 推奨頻度

- 月1回程度の定期的な確認を推奨
- auth0-lab/mdlで重要な修正やセキュリティアップデートがあった場合は随時

## 注意事項

- `main`ブランチは常に安定した状態を保つため、必ず`sync-upstream`ブランチで先に確認・テストを行う
- コンフリクトが発生した場合は慎重に解決する
- 大きな変更がある場合は、ローカルでビルドやテストを実行してから`main`にマージする

## リモート設定の確認

リモート設定を確認するには：

```bash
git remote -v
```

以下のように表示されるはずです：

```
origin    https://github.com/vess-id/mdl.git (fetch)
origin    https://github.com/vess-id/mdl.git (push)
upstream  https://github.com/auth0-lab/mdl.git (fetch)
upstream  https://github.com/auth0-lab/mdl.git (push)
```
