"""Reject critical/fixable findings before the temporary Trivy ignore gate."""

import json
import sys
from pathlib import Path


def check_report(report: dict) -> None:
    os_metadata = report["Metadata"]["OS"]
    if os_metadata["Family"] != "debian" or os_metadata["Name"].split(".")[0] != "13":
        raise ValueError("Expected a Debian 13 image scan.")
    results = report["Results"]
    if not isinstance(results, list) or not any(r["Type"] == "debian" for r in results):
        raise ValueError("Missing OS scan results.")
    for result in results:
        for finding in result.get("Vulnerabilities") or []:
            severity = finding["Severity"]
            if severity not in {"HIGH", "CRITICAL"}:
                continue
            # A future reclassification or fix must not inherit an old acceptance.
            if (
                severity == "CRITICAL"
                or finding.get("FixedVersion")
                or result["Type"] != "debian"
            ):
                raise ValueError(
                    f"Unacceptable finding: {finding['VulnerabilityID']} "
                    f"in {finding['PkgName']} ({severity})."
                )


if __name__ == "__main__":
    report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
    # Keep the unfiltered inventory visible in CI logs.
    for result in report["Results"]:
        for finding in result.get("Vulnerabilities") or []:
            print(
                result["Type"],
                finding["PkgName"],
                finding["InstalledVersion"],
                finding["VulnerabilityID"],
                finding["Severity"],
                finding.get("FixedVersion", ""),
            )
    check_report(report)
