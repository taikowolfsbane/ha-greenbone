"""Constants for the Greenbone Vulnerabilities integration."""

DOMAIN = "greenbone_vulnerabilities"

CONF_PORT = "port"
CONF_SCAN_INTERVAL_MINUTES = "scan_interval_minutes"

DEFAULT_PORT = 9391
DEFAULT_SCAN_INTERVAL_MINUTES = 60

SEVERITIES = ("critical", "high", "medium", "low")

# GVM reports a single CVSS float; these are the same critical/high/medium/low
# cut points Wazuh's dashboard uses, kept consistent across both integrations.
# GVM has no native "critical" bucket (its own UI only shows High/Medium/Low/Log),
# so critical is carved out of the top of the High range here.
SEVERITY_THRESHOLDS = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.1,
}
