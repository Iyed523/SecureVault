import pytest

from scripts.check_trivy_report import check_report


def report(severity: str = "HIGH", fixed: str = "", kind: str = "debian") -> dict:
    return {
        "Metadata": {"OS": {"Family": "debian", "Name": "13.7"}},
        "Results": [
            {"Type": "debian", "Vulnerabilities": []},
            {
                "Type": kind,
                "Vulnerabilities": [
                    {
                        "Severity": severity,
                        "FixedVersion": fixed,
                        "VulnerabilityID": "CVE-2026-76642",
                        "PkgName": "example",
                    }
                ],
            },
        ],
    }


@pytest.mark.parametrize(
    "severity,fixed,kind",
    [
        ("CRITICAL", "", "debian"),
        ("HIGH", "1.2.3", "debian"),
        ("HIGH", "", "python-pkg"),
    ],
)
def test_existing_exception_cannot_hide_escalation(
    severity: str, fixed: str, kind: str
) -> None:
    with pytest.raises(ValueError, match="Unacceptable finding"):
        check_report(report(severity, fixed, kind))


def test_unfixed_os_findings_are_left_to_native_trivy_gate() -> None:
    check_report(report())


def test_missing_scan_is_not_clean() -> None:
    data = report()
    data["Results"] = []
    with pytest.raises(ValueError, match="Missing OS scan"):
        check_report(data)
