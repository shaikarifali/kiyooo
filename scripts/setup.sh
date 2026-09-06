#!/usr/bin/env bash
# kiyooo one-command environment setup.
#
# Installs everything this repo needs into user-local directories where
# possible (no root required): uv, Python deps, Node.js + the web UI's
# deps, Go + the 5 ProjectDiscovery recon binaries (subfinder/httpx/naabu/
# dnsx/tlsx). Docker and Ollama are checked, not silently installed — both
# either need root (Docker) or run their own installer with root-level
# side effects (Ollama's official script), and this script won't invoke
# something needing your password without you seeing it first.
#
# Safe to re-run — every step checks "is this already here" before doing
# anything. Run from the repo root:
#
#   bash scripts/setup.sh          # install everything possible
#   bash scripts/setup.sh --start  # also start the stack if Docker's up
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

LOCAL_BIN="$HOME/.local/bin"
LOCAL_NODE="$HOME/.local/node"
LOCAL_GO="$HOME/.local/go"
GOBIN="$HOME/go/bin"
mkdir -p "$LOCAL_BIN"

STARTMODE=0
[ "${1:-}" = "--start" ] && STARTMODE=1

info()  { echo -e "\033[1;34m==>\033[0m $*"; }
warn()  { echo -e "\033[1;33m!!\033[0m $*"; }
ok()    { echo -e "\033[1;32m✓\033[0m $*"; }

export PATH="$LOCAL_BIN:$LOCAL_NODE/bin:$LOCAL_GO/bin:$GOBIN:$PATH"

# --------------------------------------------------------------------- #
# 1. uv (Python package manager kiyooo is built on)
# --------------------------------------------------------------------- #
if ! command -v uv >/dev/null 2>&1; then
  info "installing uv..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
else
  ok "uv already installed ($(uv --version))"
fi

# --------------------------------------------------------------------- #
# 2. Python dependencies
# --------------------------------------------------------------------- #
info "installing Python dependencies (uv sync)..."
uv sync
ok "Python deps installed"

# --------------------------------------------------------------------- #
# 3. .env
# --------------------------------------------------------------------- #
if [ ! -f .env ]; then
  cp .env.example .env
  ok "created .env from .env.example — edit it if your Postgres/Redis/MinIO/LLM aren't on localhost defaults"
else
  ok ".env already exists"
fi

# --------------------------------------------------------------------- #
# 4. Node.js + web UI deps (portable tarball install, no root needed)
# --------------------------------------------------------------------- #
if ! command -v node >/dev/null 2>&1; then
  info "installing Node.js (user-local, no root)..."
  ARCH="$(uname -m)"; case "$ARCH" in x86_64) NODE_ARCH=x64 ;; aarch64|arm64) NODE_ARCH=arm64 ;; *) NODE_ARCH="" ;; esac
  if [ -z "$NODE_ARCH" ]; then
    warn "unrecognized architecture '$ARCH' — install Node.js 20+ yourself (https://nodejs.org) and re-run"
  else
    NODE_VERSION="v22.14.0"
    curl -fsSL "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" -o /tmp/node.tar.xz
    mkdir -p "$LOCAL_NODE"
    tar -xJf /tmp/node.tar.xz -C "$LOCAL_NODE" --strip-components=1
    rm -f /tmp/node.tar.xz
    ok "Node.js installed to $LOCAL_NODE ($("$LOCAL_NODE"/bin/node --version))"
  fi
else
  ok "Node.js already installed ($(node --version))"
fi

if command -v npm >/dev/null 2>&1; then
  info "installing web UI dependencies (npm install)..."
  (cd web && npm install)
  [ -f web/.env.local ] || cp web/.env.local.example web/.env.local
  ok "web UI deps installed"
else
  warn "npm not available — skipping web UI setup"
fi

# --------------------------------------------------------------------- #
# 5. Go + ProjectDiscovery recon binaries (subfinder/httpx/naabu/dnsx/tlsx)
# --------------------------------------------------------------------- #
if ! command -v go >/dev/null 2>&1; then
  info "installing Go (user-local, no root)..."
  ARCH="$(uname -m)"; case "$ARCH" in x86_64) GO_ARCH=amd64 ;; aarch64|arm64) GO_ARCH=arm64 ;; *) GO_ARCH="" ;; esac
  if [ -z "$GO_ARCH" ]; then
    warn "unrecognized architecture '$ARCH' — install Go 1.21+ yourself (https://go.dev/dl) and re-run"
  else
    GO_VERSION="1.23.4"
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz
    rm -rf "$LOCAL_GO"
    tar -xzf /tmp/go.tar.gz -C "$HOME/.local"
    rm -f /tmp/go.tar.gz
    ok "Go installed to $LOCAL_GO ($("$LOCAL_GO"/bin/go version))"
  fi
else
  ok "Go already installed ($(go version))"
fi

if command -v go >/dev/null 2>&1; then
  declare -A RECON_TOOLS=(
    [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    [naabu]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    [tlsx]="github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
  )
  for tool in "${!RECON_TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
      ok "$tool already installed ($(command -v "$tool"))"
    else
      info "installing $tool (go install)..."
      if go install "${RECON_TOOLS[$tool]}" 2>/tmp/kiyooo_setup_${tool}.log; then
        ok "$tool installed to $GOBIN"
      else
        warn "$tool failed to build — see /tmp/kiyooo_setup_${tool}.log (naabu needs libpcap-dev for full SYN-scan support; without it, connect-scan mode still works once built)"
      fi
    fi
  done
else
  warn "no Go toolchain available — subfinder/httpx/naabu/dnsx/tlsx not installed. kiyooo scan will report them missing (kiyooo doctor shows exactly which)."
fi

# --------------------------------------------------------------------- #
# 6. Docker — checked, never silently installed (needs root)
# --------------------------------------------------------------------- #
if command -v docker >/dev/null 2>&1; then
  ok "Docker found ($(docker --version))"
  HAVE_DOCKER=1
else
  warn "Docker not found. kiyooo needs Postgres/Redis/MinIO to actually run — install Docker"
  warn "  (https://docs.docker.com/engine/install/), then re-run: make dev"
  HAVE_DOCKER=0
fi

# --------------------------------------------------------------------- #
# 7. Ollama — checked, never silently installed (its installer uses sudo)
# --------------------------------------------------------------------- #
if command -v ollama >/dev/null 2>&1; then
  ok "Ollama found ($(ollama --version 2>&1 | head -1))"
  HAVE_OLLAMA=1
else
  warn "Ollama not found — kiyooo's bulk/escalation triage passes default to it."
  warn "  Install: curl -fsSL https://ollama.com/install.sh | sh   (then: ollama pull llama3.1:8b)"
  HAVE_OLLAMA=0
fi

# --------------------------------------------------------------------- #
# 8. Verify (fast, no live infra needed)
# --------------------------------------------------------------------- #
info "running ruff + mypy + pytest..."
uv run ruff check . && uv run mypy kiyooo && uv run pytest tests/ -q
uv run kiyooo categories lint
uv run kiyooo categories test
ok "all checks pass"

# --------------------------------------------------------------------- #
# 9. Optionally start the stack
# --------------------------------------------------------------------- #
if [ "$STARTMODE" -eq 1 ]; then
  if [ "$HAVE_DOCKER" -eq 1 ]; then
    info "starting Postgres/Redis/MinIO + migrations (make dev)..."
    make dev
    if [ "$HAVE_OLLAMA" -eq 1 ]; then
      info "pulling llama3.1:8b (skips if already present)..."
      ollama pull llama3.1:8b || warn "model pull failed — is 'ollama serve' running?"
    fi
    info "starting kiyooo API (background, :8000)..."
    nohup uv run kiyooo serve >/tmp/kiyooo-api.log 2>&1 &
    echo $! > /tmp/kiyooo-api.pid
    if command -v npm >/dev/null 2>&1; then
      info "starting web UI (background, :3000)..."
      (cd web && nohup npm run dev >/tmp/kiyooo-web.log 2>&1 &)
    fi
    ok "kiyooo is up: API http://localhost:8000  UI http://localhost:3000"
    echo "   logs: /tmp/kiyooo-api.log  /tmp/kiyooo-web.log"
    echo "   stop the API: kill \$(cat /tmp/kiyooo-api.pid)"
  else
    warn "--start requested but Docker isn't available — install it and re-run 'bash scripts/setup.sh --start'"
  fi
fi

echo
ok "setup done."
echo "Next: uv run kiyooo doctor"
echo "      make dev && uv run kiyooo scan --seeds <your-seeds-file> --profile passive"
echo "      uv run kiyooo serve   (API)      cd web && npm run dev   (UI)"
echo "      bash scripts/setup.sh --start    (does the above two for you, if Docker/Ollama are present)"
