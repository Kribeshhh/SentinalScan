#!/bin/zsh

cd "$(dirname "$0")" || exit 1

# Enable Semgrep and CodeQL
export SENTINELSCAN_SEMGREP_ENABLED=true
export SENTINELSCAN_CODEQL_ENABLED=true

export SENTINELSCAN_SEMGREP_BINARY=/opt/homebrew/bin/semgrep
export SENTINELSCAN_CODEQL_BINARY=/opt/homebrew/bin/codeql

# Trusted installed packs for this CodeQL 2.27.2 setup. Keep private subprocess HOME.
# Override with an OS-path-separated list of absolute installed pack directories.
export SENTINELSCAN_CODEQL_SEARCH_PATH="${SENTINELSCAN_CODEQL_SEARCH_PATH:-${HOME}/.codeql/packages/codeql/python-queries/1.8.12:${HOME}/.codeql/packages/codeql/javascript-queries/2.4.7}"

# Approved local recommendation model (override in the server environment if needed).
export SENTINELSCAN_LLM_ENABLED="${SENTINELSCAN_LLM_ENABLED:-true}"
export SENTINELSCAN_OLLAMA_BASE_URL="${SENTINELSCAN_OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
export SENTINELSCAN_OLLAMA_MODEL="${SENTINELSCAN_OLLAMA_MODEL:-qwen2.5-coder:3b}"

# Activate virtual environment
source .venv/bin/activate

# Start SentinelScan
python3 -u app.py
