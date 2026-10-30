"""Hypothesis templates and the catalogue of safe validation checks.

Every catalogued check is passive and read-only, and applies only to targets that are
already in the assessment scope. The catalogue describes checks; it never runs them.
"""

HYPOTHESIS_TEMPLATES: dict[str, dict] = {
    "missing_security_header": {
        "category": "web",
        "description": "A scanner reports that a security response header is missing.",
        "hypotheses": [
            {
                "kind": "vulnerable",
                "statement": "The in-scope response really lacks the security header.",
                "requirements": [
                    {
                        "key": "header_present",
                        "question": "Is the header present in a normal response from the in-scope target?",
                        "supports_when": False,
                    }
                ],
            },
            {
                "kind": "false_positive",
                "statement": "The header is present; the scanner was wrong or saw a different response.",
                "requirements": [
                    {
                        "key": "header_present",
                        "question": "Is the header present in a normal response from the in-scope target?",
                        "supports_when": True,
                    }
                ],
            },
        ],
    },
    "outdated_service_banner": {
        "category": "network",
        "description": "A scanner infers a vulnerable version from a service banner.",
        "hypotheses": [
            {
                "kind": "vulnerable",
                "statement": "The service runs an affected version with no vendor backport fix.",
                "requirements": [
                    {
                        "key": "banner_version_in_affected_range",
                        "question": "Does the observed version fall inside the advisory's affected range?",
                        "supports_when": True,
                    },
                    {
                        "key": "backport_patched",
                        "question": "Has the vendor backported the fix into this package build?",
                        "supports_when": False,
                    },
                ],
            },
            {
                "kind": "false_positive",
                "statement": "The fix was backported, so the banner version misleads the scanner.",
                "requirements": [
                    {
                        "key": "backport_patched",
                        "question": "Has the vendor backported the fix into this package build?",
                        "supports_when": True,
                    }
                ],
            },
        ],
    },
}

CHECK_CATALOG: dict[str, dict] = {
    "header_present": {
        "name": "Inspect response headers",
        "safety": "passive_read_only",
        "instructions": (
            "Make one ordinary HEAD or GET request to the in-scope target and read its response "
            "headers. Record header_present=true/false as validated evidence, with the method used."
        ),
    },
    "banner_version_in_affected_range": {
        "name": "Compare version to advisory",
        "safety": "passive_read_only",
        "instructions": (
            "Compare the version you already observed with the affected range in the vendor advisory. "
            "No traffic to the target is needed."
        ),
    },
    "backport_patched": {
        "name": "Check vendor backport status",
        "safety": "passive_read_only",
        "instructions": (
            "Read the distribution's package changelog or security tracker for this exact build and "
            "see whether the fix was backported. Documentation lookup only."
        ),
    },
}
