"""SQLite lifecycle and schema. Each request owns its connection."""
import sqlite3
from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS repositories (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    location TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    scan_type TEXT NOT NULL CHECK(scan_type IN ('Website','Repository')),
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Queued' CHECK(status IN ('Queued','Running','Completed','Failed')),
    repository_id INTEGER REFERENCES repositories(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    completed_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('Critical','High','Medium','Low','Informational')),
    confidence TEXT NOT NULL CHECK(confidence IN ('High','Medium','Low')),
    category TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('Website','Repository')),
    location TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT NOT NULL,
    impact TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open','Resolved','Ignored','False Positive')),
    fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(scan_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    format TEXT NOT NULL CHECK(format IN ('HTML','JSON','PDF')),
    file_path TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS scan_comparisons (
    id INTEGER PRIMARY KEY,
    baseline_scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    current_scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    summary_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    CHECK(baseline_scan_id != current_scan_id),
    UNIQUE(baseline_scan_id, current_scan_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at);
CREATE TABLE IF NOT EXISTS finding_context (
    finding_id INTEGER PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    path TEXT NOT NULL, commit_sha TEXT NOT NULL, start_line INTEGER NOT NULL,
    detected_line INTEGER NOT NULL, excerpt TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_files (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    path TEXT NOT NULL, content_hash TEXT NOT NULL,
    PRIMARY KEY(scan_id,path)
);
CREATE TABLE IF NOT EXISTS draft_checks (
    draft_id INTEGER NOT NULL REFERENCES remediation_drafts(id) ON DELETE CASCADE,
    version INTEGER NOT NULL, data_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY(draft_id,version)
);
CREATE TABLE IF NOT EXISTS pull_request_tracking (
    draft_id INTEGER PRIMARY KEY REFERENCES remediation_drafts(id) ON DELETE CASCADE,
    state TEXT NOT NULL, merge_commit TEXT,
    checked_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS remediation_verifications (
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    result TEXT NOT NULL, message TEXT NOT NULL, merge_commit TEXT,
    checked_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY(finding_id,scan_id)
);
CREATE TABLE IF NOT EXISTS remediation_drafts (
    id INTEGER PRIMARY KEY,
    finding_id INTEGER NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
    repository TEXT NOT NULL,
    path TEXT NOT NULL,
    base_branch TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    blob_sha TEXT NOT NULL,
    original TEXT NOT NULL,
    edited TEXT NOT NULL,
    head_branch TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL DEFAULT 'Draft' CHECK(state IN ('Draft','Publishing','Retry','Published')),
    version INTEGER NOT NULL DEFAULT 1,
    pr_url TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
    return g.db


def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        db = get_db()
        migrate(db)
        db.executescript(SCHEMA)
        columns = {r[1] for r in db.execute("PRAGMA table_info(scans)")}
        for name, definition in {
            "progress": "INTEGER NOT NULL DEFAULT 0",
            "risk_score": "INTEGER NOT NULL DEFAULT 0",
            "assessment_risk": "INTEGER",
            "error": "TEXT",
            "options_json": "TEXT NOT NULL DEFAULT '{}'",
            "started_at": "TEXT",
        }.items():
            if name not in columns:
                db.execute(f"ALTER TABLE scans ADD COLUMN {name} {definition}")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS scan_modules (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Queued',
                data_json TEXT NOT NULL DEFAULT '{}',
                error TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                UNIQUE(scan_id, name)
            );
            CREATE INDEX IF NOT EXISTS idx_scan_modules_scan ON scan_modules(scan_id);
            PRAGMA user_version = 4;
        """)
        repository_columns = {row[1] for row in db.execute("PRAGMA table_info(repositories)")}
        for name, definition in {
            "owner": "TEXT", "url": "TEXT", "branch": "TEXT", "commit_sha": "TEXT",
            "scan_id": "INTEGER REFERENCES scans(id)",
            "languages_json": "TEXT NOT NULL DEFAULT '{}'",
            "dependencies_json": "TEXT NOT NULL DEFAULT '[]'", "scanned_at": "TEXT",
        }.items():
            if name not in repository_columns:
                db.execute(f"ALTER TABLE repositories ADD COLUMN {name} {definition}")
        migrate_reports(db)
        # The local single-process server can recover interrupted publication on restart.
        db.execute("UPDATE remediation_drafts SET state='Retry' WHERE state='Publishing'")
        # Older completed scans can be reconstructed from all their detected findings.
        from analysis.risk_engine import calculate_risk
        for scan in db.execute("SELECT id FROM scans WHERE status IN ('Completed','Failed') AND assessment_risk IS NULL").fetchall():
            rows = [dict(row, status='Open') for row in db.execute('SELECT severity FROM findings WHERE scan_id=?',(scan['id'],))]
            db.execute('UPDATE scans SET assessment_risk=? WHERE id=?',(calculate_risk(rows),scan['id']))
        db.commit()


def migrate(db):
    """Rebuild only the scans table to extend its CHECK constraint, retaining IDs/FKs."""
    row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='scans'").fetchone()
    if not row or "'Pending'" not in row[0]:
        return
    db.commit()
    db.execute("PRAGMA foreign_keys = OFF")
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("""CREATE TABLE scans_v2 (
            id INTEGER PRIMARY KEY,
            scan_type TEXT NOT NULL CHECK(scan_type IN ('Website','Repository')),
            target TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Queued' CHECK(status IN ('Queued','Running','Completed','Failed')),
            repository_id INTEGER REFERENCES repositories(id),
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            completed_at TEXT
        )""")
        db.execute("""INSERT INTO scans_v2 SELECT id,scan_type,target,
            CASE WHEN status='Pending' THEN 'Queued' ELSE status END,
            repository_id,created_at,completed_at FROM scans""")
        db.execute("DROP TABLE scans")
        db.execute("ALTER TABLE scans_v2 RENAME TO scans")
        if db.execute("PRAGMA foreign_key_check").fetchall():
            raise RuntimeError("Migration foreign key validation failed")
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.execute("PRAGMA foreign_keys = ON")


def migrate_reports(db):
    row=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='reports'").fetchone()
    if not row or "'CSV'" in row[0]:
        return
    with db:
        db.execute("""CREATE TABLE reports_v4 (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            format TEXT NOT NULL CHECK(format IN ('HTML','JSON','CSV','PDF')),
            file_path TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )""")
        db.execute('INSERT INTO reports_v4 SELECT * FROM reports')
        db.execute('DROP TABLE reports')
        db.execute('ALTER TABLE reports_v4 RENAME TO reports')
