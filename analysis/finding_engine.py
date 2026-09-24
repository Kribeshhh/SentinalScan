"""Unified validated DAST/SAST finding contract; never renders raw evidence as HTML."""
from dataclasses import dataclass, replace
import hashlib
import json
from analysis.risk_engine import SEVERITY_WEIGHTS
from analysis.redaction import redact_text

STATUSES = ("Open", "Resolved", "Ignored", "False Positive")
SOURCES = ("Website", "Repository")


@dataclass(frozen=True)
class Finding:
    title: str
    severity: str
    confidence: str
    category: str
    source: str
    location: str
    description: str
    evidence: str
    impact: str
    recommendation: str
    status: str = "Open"

    def __post_init__(self):
        for name, value in vars(self).items():
            if not isinstance(value, str) or not value.strip() or len(value) > 20000:
                raise ValueError(f"Invalid finding field: {name}")
        if self.severity not in SEVERITY_WEIGHTS or self.confidence not in ("High", "Medium", "Low"):
            raise ValueError("Invalid severity or confidence")
        if self.source not in SOURCES or self.status not in STATUSES:
            raise ValueError("Invalid source or status")

    @property
    def fingerprint(self):
        identity = [self.source, self.category, self.title, self.location]
        return hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode()).hexdigest()


def save_finding(db, scan_id, finding):
    # Apply one persistence policy to both DAST and SAST findings.
    finding = replace(finding, **{key: redact_text(value) for key, value in vars(finding).items()})
    scan = db.execute("SELECT scan_type FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if scan is None or scan["scan_type"] != finding.source:
        raise ValueError("Finding source must match an existing scan")
    with db:
        result = db.execute(
            """INSERT INTO findings
            (scan_id,title,severity,confidence,category,source,location,description,
             evidence,impact,recommendation,status,fingerprint)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (scan_id, finding.title, finding.severity, finding.confidence, finding.category,
             finding.source, finding.location, finding.description, finding.evidence,
             finding.impact, finding.recommendation, finding.status, finding.fingerprint),
        )
    return result.lastrowid
