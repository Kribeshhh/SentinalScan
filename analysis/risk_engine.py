"""Bounded risk index of open findings; not a probability of compromise."""
SEVERITY_WEIGHTS = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Informational": 0}
RISK_NORMALIZATION_POINTS = 50


def calculate_risk(findings):
    points = sum(SEVERITY_WEIGHTS[f["severity"]] for f in findings if f["status"] == "Open")
    return round(100 * points / (points + RISK_NORMALIZATION_POINTS))
