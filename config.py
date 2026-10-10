"""Local-first configuration. Production deployments must enable HTTPS cookies."""
import os
import secrets
import stat
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def secret_key(data_dir):
    override = os.environ.get("SENTINELSCAN_SECRET_KEY")
    if override:
        if len(override) < 32:
            raise RuntimeError("SENTINELSCAN_SECRET_KEY must contain at least 32 characters")
        return override
    # Retain sessions across restarts without committing a secret to source control.
    path = data_dir / ".secret_key"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "r") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1024:
                raise RuntimeError("Invalid stored session key file")
            value = handle.read().strip()
            if len(value) < 32:
                raise RuntimeError("Stored session key is too short")
            os.fchmod(handle.fileno(), 0o600)
            return value
    with os.fdopen(fd, "w") as handle:
        value = secrets.token_hex(32)
        handle.write(value)
    return value


def settings():
    data_dir = Path(os.environ.get("SENTINELSCAN_DATA_DIR", BASE_DIR / "data"))
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    return dict(
        DATABASE=str(data_dir / "sentinelscan.sqlite3"),
        REPORTS_DIR=str(BASE_DIR / "reports_output"),
        SECRET_KEY=secret_key(data_dir),
        DEBUG=False,
        SEMGREP_ENABLED=os.environ.get("SENTINELSCAN_SEMGREP_ENABLED", "false").lower()=="true",
        SEMGREP_BINARY=os.environ.get("SENTINELSCAN_SEMGREP_BINARY", "semgrep"),
        CODEQL_ENABLED=os.environ.get("SENTINELSCAN_CODEQL_ENABLED", "false").lower()=="true",
        CODEQL_BINARY=os.environ.get("SENTINELSCAN_CODEQL_BINARY", "codeql"),
        CODEQL_SEARCH_PATH=os.environ.get("SENTINELSCAN_CODEQL_SEARCH_PATH", ""),
        LLM_ENABLED=os.environ.get("SENTINELSCAN_LLM_ENABLED", "false").lower() == "true",
        OLLAMA_BASE_URL=os.environ.get("SENTINELSCAN_OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
        OLLAMA_MODEL=os.environ.get("SENTINELSCAN_OLLAMA_MODEL", ""),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SENTINELSCAN_HTTPS") == "1",
        MAX_CONTENT_LENGTH=1024 * 1024,
        MAX_FORM_MEMORY_SIZE=600000,
        MAX_FORM_PARTS=32,
        TRUSTED_HOSTS=["localhost", "127.0.0.1", "[::1]"],
    )
