#!/usr/bin/env bash
#
# publish-github.sh — 初始化本地仓库、本地提交并推送到 GitHub
#
# 用法示例：
#   1) 指定已创建的仓库地址推送：
#        ./scripts/publish-github.sh -r https://github.com/<用户名>/<仓库名>.git
#
#   2) 用 Personal Access Token 自动在 GitHub 建库后推送：
#        GITHUB_TOKEN=ghp_xxx GITHUB_USER=flshw REPO_NAME=chatroom \
#          ./scripts/publish-github.sh --private
#
#   3) 仅做本地初始化与首次提交（不推送）：
#        ./scripts/publish-github.sh --no-push -u flshw -e flshw@126.com
#
#   4) 预览将要提交的文件（不提交、不推送）：
#        ./scripts/publish-github.sh --dry-run
#
# 选项：
#   -r, --repo URL        远程仓库地址（https 或 ssh）
#   -u, --user NAME       git 提交用户名（缺省读 git config / 环境变量 GIT_USER / 交互输入）
#   -e, --email EMAIL     git 提交邮箱（缺省读 git config / 环境变量 GIT_EMAIL / 交互输入）
#   -m, --message MSG     提交信息（缺省见下方 DEFAULT_MSG）
#   -b, --branch NAME     推送分支名（缺省 main）
#   -p, --private         通过 API 建库时设为私有（仅对 GITHUB_TOKEN 建库生效）
#       --no-push         只做本地初始化与提交，不推送
#       --dry-run         仅显示将要提交的文件，不做提交与推送
#   -h, --help            显示帮助
#
set -uo pipefail

# ── 默认值 ──
REPO_URL=""
GIT_USER="${GIT_USER:-}"
GIT_EMAIL="${GIT_EMAIL:-}"
COMMIT_MSG="Initial commit: 局域网端到端加密聊天室 (ChatRoom v5)"
BRANCH="main"
PRIVATE="false"
NO_PUSH="false"
DRY_RUN="false"
DESC="LAN end-to-end encrypted chat room — single-file HTML client, zero-trust server."

# ── 解析参数 ──
while [ $# -gt 0 ]; do
  case "$1" in
    -r|--repo)      REPO_URL="$2"; shift 2 ;;
    -u|--user)      GIT_USER="$2"; shift 2 ;;
    -e|--email)     GIT_EMAIL="$2"; shift 2 ;;
    -m|--message)   COMMIT_MSG="$2"; shift 2 ;;
    -b|--branch)    BRANCH="$2"; shift 2 ;;
    -p|--private)   PRIVATE="true"; shift ;;
    --no-push)      NO_PUSH="true"; shift ;;
    --dry-run)      DRY_RUN="true"; shift ;;
    -h|--help)      sed -n '3,40p' "$0"; exit 0 ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

cd "$(dirname "$0")/.." || { echo "无法切换到项目根目录"; exit 1; }
ROOT="$(pwd)"
echo "项目根目录: $ROOT"

# ── 安全检查：必须忽略 server/data（防止私钥/数据库入库） ──
if ! grep -qE 'server/data/' .gitignore 2>/dev/null; then
  echo "❌ 安全拦截：.gitignore 未忽略 server/data/（含服务器私钥与数据库），已中止。"
  echo "   请确认 .gitignore 包含 'server/data/' 后再发布。"
  exit 1
fi

# ── git 初始化 ──
if [ ! -d .git ]; then
  echo "→ 初始化 git 仓库（默认分支 $BRANCH）"
  git init -b "$BRANCH" 2>/dev/null || git init
  git branch -M "$BRANCH" 2>/dev/null || true
else
  echo "→ 已存在 git 仓库，跳过初始化"
fi

# ── 暂存 ──
echo "→ 暂存变更（遵循 .gitignore）"
git add -A

# ── dry-run：仅展示，不提交 ──
if [ "$DRY_RUN" = "true" ]; then
  echo "────────── dry-run：将要提交的文件 ──────────"
  git status --short
  echo "──────────────────────────────────────────────"
  echo "（未执行提交/推送）"
  exit 0
fi

# ── 设置 git 身份（仅本仓库，不污染全局） ──
if [ -z "$(git config user.name)" ]; then
  if [ -n "$GIT_USER" ]; then
    git config user.name "$GIT_USER"
  elif [ -t 0 ]; then
    printf "请输入 git 提交用户名: "; read -r GIT_USER
    [ -n "$GIT_USER" ] && git config user.name "$GIT_USER"
  fi
fi
if [ -z "$(git config user.email)" ]; then
  if [ -n "$GIT_EMAIL" ]; then
    git config user.email "$GIT_EMAIL"
  elif [ -t 0 ]; then
    printf "请输入 git 提交邮箱: "; read -r GIT_EMAIL
    [ -n "$GIT_EMAIL" ] && git config user.email "$GIT_EMAIL"
  fi
fi
if [ -z "$(git config user.name)" ] || [ -z "$(git config user.email)" ]; then
  echo "❌ 未配置 git 用户身份，无法提交。请通过 -u/-e、GIT_USER/GIT_EMAIL 环境变量，或在终端中交互输入提供。"
  exit 1
fi
echo "→ 提交身份: $(git config user.name) <$(git config user.email)>"

# ── 提交 ──
if git diff --cached --quiet; then
  echo "→ 没有需要提交的变更（工作区与已提交内容一致）"
else
  echo "→ 提交: $COMMIT_MSG"
  git commit -m "$COMMIT_MSG"
fi

# ── 推送 ──
if [ "$NO_PUSH" = "true" ]; then
  echo "→ 已按 --no-push 跳过推送。后续可运行："
  echo "   git remote add origin <仓库地址> && git push -u origin $BRANCH"
  exit 0
fi

# 确定远程地址
if [ -z "$REPO_URL" ]; then
  if [ -n "${GITHUB_TOKEN:-}" ] && [ -n "${GITHUB_USER:-}" ] && [ -n "${REPO_NAME:-}" ]; then
    echo "→ 通过 GitHub API 自动建库: $GITHUB_USER/$REPO_NAME (private=$PRIVATE)"
    RESP=$(curl -sSf -X POST "https://api.github.com/user/repos" \
      -H "Authorization: Bearer $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github+json" \
      -d "{\"name\":\"$REPO_NAME\",\"private\":$PRIVATE,\"description\":\"$DESC\",\"auto_init\":false}" \
      2>/dev/null) || { echo "❌ 建库失败，请检查 GITHUB_TOKEN 权限（需 repo 范围）"; exit 1; }
    REPO_URL=$(printf '%s' "$RESP" | grep -o '"clone_url":"[^"]*' | head -1 | sed 's/"clone_url":"//')
    [ -z "$REPO_URL" ] && { echo "❌ 无法解析建库返回的 clone_url"; exit 1; }
    echo "   新建仓库地址: $REPO_URL"
  else
    echo "⚠️  未提供远程仓库地址，跳过推送。"
    echo "   请先在 GitHub 创建仓库，然后："
    echo "     git remote add origin https://github.com/<用户名>/<仓库名>.git"
    echo "     git push -u origin $BRANCH"
    exit 0
  fi
fi

# 设置 remote
if git remote get-url origin >/dev/null 2>&1; then
  echo "→ 更新已存在的 remote origin -> $REPO_URL"
  git remote set-url origin "$REPO_URL"
else
  echo "→ 添加 remote origin -> $REPO_URL"
  git remote add origin "$REPO_URL"
fi

echo "→ 推送到 $BRANCH ..."
git push -u origin "$BRANCH" || {
  echo "❌ 推送失败。常见原因："
  echo "   - 仓库已存在且历史不一致：先 'git pull --rebase origin $BRANCH' 再推送"
  echo "   - 鉴权失败：使用 ssh 地址，或在 https 地址中嵌入 token："
  echo "     https://<TOKEN>@github.com/<用户名>/<仓库名>.git"
  exit 1
}

echo ""
echo "✅ 发布完成！"
echo "   仓库: $REPO_URL"
echo "   分支: $BRANCH"
