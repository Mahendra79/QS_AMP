"""Default organization settings (configurable in Settings → Risk / Scanning / ...)."""
import copy

DEFAULT_SETTINGS = {
    "general": {"timezone": "UTC", "date_format": "YYYY-MM-DD", "default_environment": "production"},
    "risk": {
        # Weights are relative; the engine normalises them.
        "weights": {
            "quantum_vulnerability": 25,
            "algorithm_strength": 10,
            "business_criticality": 15,
            "data_sensitivity": 10,
            "internet_exposure": 10,
            "hndl_exposure": 10,
            "certificate_expiry": 5,
            "migration_complexity": 5,
            "asset_dependency": 10,
        },
        "thresholds": {"medium": 30, "high": 60, "critical": 80},
    },
    "scanning": {"default_frequency_hours": 24, "max_zip_mb": 50, "follow_subdomains": True},
    "notifications": {"email": True, "slack": False, "min_severity": "high", "digest": "daily"},
    "security": {"session_minutes": 30, "require_mfa": False, "ip_allowlist": []},
}


def default_settings():
    return copy.deepcopy(DEFAULT_SETTINGS)


def validate_settings(incoming, org):
    """Reject unknown keys, wrong types and inconsistent risk thresholds before they
    are stored - a bad value here would otherwise surface later as a crash in
    risk scoring (e.g. comparing a score with a string threshold)."""
    from .errors import ServiceError

    def fail(message):
        raise ServiceError("validation_error", message)

    for section, values in incoming.items():
        if section not in DEFAULT_SETTINGS:
            fail(f"Unknown settings section '{section}'.")
        if not isinstance(values, dict):
            fail(f"Settings section '{section}' must be an object.")
        for key, value in values.items():
            if key not in DEFAULT_SETTINGS[section]:
                fail(f"Unknown setting '{section}.{key}'.")
            expected = DEFAULT_SETTINGS[section][key]
            if isinstance(expected, bool):
                if not isinstance(value, bool):
                    fail(f"'{section}.{key}' must be true or false.")
            elif isinstance(expected, (int, float)):
                if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                    fail(f"'{section}.{key}' must be a non-negative number.")
            elif isinstance(expected, dict):
                if not isinstance(value, dict):
                    fail(f"'{section}.{key}' must be an object.")
                for sub_key, sub_value in value.items():
                    if sub_key not in expected:
                        fail(f"Unknown setting '{section}.{key}.{sub_key}'.")
                    if isinstance(sub_value, bool) or not isinstance(sub_value, (int, float)) or not 0 <= sub_value <= 100:
                        fail(f"'{section}.{key}.{sub_key}' must be a number from 0 to 100.")
            elif not isinstance(value, type(expected)):
                fail(f"'{section}.{key}' has the wrong type.")
    thresholds = {**merged_settings(org)["risk"]["thresholds"], **incoming.get("risk", {}).get("thresholds", {})}
    if not thresholds["medium"] < thresholds["high"] < thresholds["critical"]:
        fail("Risk thresholds must increase: medium < high < critical.")


def merged_settings(org):
    """Org settings deep-merged over defaults."""
    out = default_settings()
    for section, values in (org.settings or {}).items():
        if isinstance(values, dict) and isinstance(out.get(section), dict):
            for k, v in values.items():
                if isinstance(v, dict) and isinstance(out[section].get(k), dict):
                    out[section][k].update(v)
                else:
                    out[section][k] = v
        else:
            out[section] = values
    return out
