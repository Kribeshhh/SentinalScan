"""Integration tests use temporary databases, never the user's workspace data."""
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path
from app import create_app
from database import get_db
from analysis.finding_engine import Finding, save_finding
from analysis.risk_engine import calculate_risk


class FoundationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.config = {"TESTING": True, "DATABASE": str(Path(self.directory.name) / "test.sqlite3")}
        self.app = create_app(self.config)
        self.client = self.app.test_client()

    def tearDown(self):
        self.directory.cleanup()

    def seed(self):
        with self.app.app_context():
            db = get_db()
            scan_id = db.execute("INSERT INTO scans(scan_type,target,status) VALUES (?,?,?)", ("Website", "https://example.test", "Completed")).lastrowid
            db.commit()
            finding = Finding(title="<script>alert('test')</script>", severity="Critical", confidence="High", category="Headers", source="Website", location="https://example.test/", description="Test description", evidence="<img src=x onerror=alert(1)>", impact="Test impact", recommendation="Test recommendation")
            finding_id = save_finding(db, scan_id, finding)
            return scan_id, finding_id

    def token(self):
        self.client.get("/")
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def test_navigation_empty_database_and_headers(self):
        for path in ("/", "/website-scan", "/repository-scan", "/scans", "/findings", "/reports"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        home = self.client.get("/").get_data(as_text=True)
        self.assertIn("No scans recorded", home)
        self.assertIn("Awaiting assessment", home)
        for href in re.findall(r'href="([^"]+)"', home):
            if href.startswith("/"):
                with self.client.get(href.replace("&amp;", "&")) as linked:
                    self.assertEqual(linked.status_code, 200, href)
        with self.app.app_context():
            tables = {row[0] for row in get_db().execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertTrue({"scans", "findings", "repositories", "reports", "scan_comparisons"} <= tables)
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM scans").fetchone()[0], 0)

    def test_real_data_escaping_filter_and_risk(self):
        _, finding_id = self.seed()
        home = self.client.get("/").get_data(as_text=True)
        self.assertIn("https://example.test", home)
        self.assertIn("<strong>17<small>/ 100", home)
        response = self.client.get(f"/findings/{finding_id}").get_data(as_text=True)
        self.assertNotIn("<script>alert", response)
        self.assertNotIn("<img src=x", response)
        self.assertIn("&lt;img src=x", response)
        self.assertIn("No matching findings", self.client.get("/findings?severity=Low").get_data(as_text=True))
        self.assertIn("&lt;script&gt;", self.client.get("/findings?severity=Critical").get_data(as_text=True))

    def test_csrf_status_update_and_validation(self):
        _, finding_id = self.seed()
        path = f"/findings/{finding_id}/status"
        self.assertEqual(self.client.post(path, data={"status":"Resolved"}).status_code, 400)
        self.assertEqual(self.client.post(path, data={"status":"Resolved", "csrf_token":"é"}).status_code, 400)
        token = self.token()
        self.assertEqual(self.client.post(path, data={"status":"bad", "csrf_token":token}).status_code, 400)
        self.assertEqual(self.client.post(path, data={"status":"Resolved", "csrf_token":token}).status_code, 303)
        with self.app.app_context():
            row = get_db().execute("SELECT severity,status FROM findings WHERE id=?", (finding_id,)).fetchone()
            self.assertEqual(row["status"], "Resolved")
            self.assertEqual(calculate_risk([row]), 0)
        for path in ("/findings?status=bad", "/findings?severity=Critical%27%20OR%201=1--", "/scans?page=-1", "/reports?page=no", "/findings?page=1000001"):
            self.assertEqual(self.client.get(path).status_code, 400)
        self.assertEqual(self.client.get("/findings/9999").status_code, 404)
        self.assertEqual(self.client.get("/missing").status_code, 404)
        self.assertEqual(self.client.get("/", headers={"Host":"untrusted.test"}).status_code, 400)

    def test_persistence_new_app_instance(self):
        scan_id, finding_id = self.seed()
        restarted = create_app(self.config)
        with restarted.app_context():
            self.assertEqual(get_db().execute("SELECT target FROM scans WHERE id=?", (scan_id,)).fetchone()[0], "https://example.test")
            self.assertEqual(get_db().execute("SELECT severity FROM findings WHERE id=?", (finding_id,)).fetchone()[0], "Critical")
        self.assertEqual(restarted.test_client().get(f"/findings/{finding_id}").status_code, 200)

    def test_schema_constraints_and_fingerprint(self):
        scan_id, finding_id = self.seed()
        with self.app.app_context():
            db = get_db()
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE findings SET severity='Unknown' WHERE id=?", (finding_id,))
            db.rollback()
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE findings SET scan_id=999 WHERE id=?", (finding_id,))
            db.rollback()
            row = db.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
            fields = {key:row[key] for key in Finding.__dataclass_fields__}
            finding = Finding(**fields)
            self.assertEqual(finding.fingerprint, row["fingerprint"])
            with self.assertRaises(sqlite3.IntegrityError):
                save_finding(db, scan_id, finding)
            with self.assertRaises(ValueError):
                Finding(**dict(fields, confidence="Unknown"))
            with self.assertRaises(ValueError):
                save_finding(db, 999, finding)

    def test_risk_weights_and_bounds(self):
        self.assertEqual(calculate_risk([]), 0)
        self.assertEqual(calculate_risk([{"severity":"Critical", "status":"Open"}]), 17)
        for severity, weight in (("Critical",10), ("High",7), ("Medium",4), ("Low",1), ("Informational",0)):
            self.assertEqual(calculate_risk([{"severity":severity,"status":"Open"}]), round(100*weight/(weight+50)))
            self.assertEqual(calculate_risk([{"severity":severity,"status":"Ignored"}]), 0)
        self.assertLessEqual(calculate_risk([{"severity":"Critical", "status":"Open"}]*10000), 100)

    def test_pagination_and_report_records(self):
        with self.app.app_context():
            db = get_db()
            db.executemany("INSERT INTO scans(scan_type,target) VALUES (?,?)", [("Repository",f"test-project-{i}") for i in range(27)])
            db.execute("INSERT INTO reports(scan_id,format,file_path) VALUES (?,?,?)", (1,"JSON","private-report.json"))
            db.commit()
        page1 = self.client.get("/scans").get_data(as_text=True)
        self.assertIn("Next", page1)
        self.assertEqual(page1.count("SCAN-"), 25)
        page2 = self.client.get("/scans?page=2").get_data(as_text=True)
        self.assertIn("Previous", page2)
        self.assertEqual(page2.count("SCAN-"), 2)
        reports = self.client.get("/reports").get_data(as_text=True)
        self.assertIn("REPORT-1", reports)
        self.assertNotIn("private-report.json", reports)


if __name__ == "__main__":
    unittest.main()
