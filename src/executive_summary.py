from __future__ import annotations

"""Executive-summary generation helpers.

Extracted from changes_ai.py — do not import directly; use the re-exports in
changes_ai.py so that existing consumers keep working unchanged.
"""

import json
import os

try:
    from .cache import CacheMissError, SQLiteCache
    from .impact import LLMClient
    from .vulnerability import SEVERITY_RANK
except ImportError:  # pragma: no cover
    from src.cache import CacheMissError, SQLiteCache
    from src.impact import LLMClient
    from src.vulnerability import SEVERITY_RANK


def _summary_target_word_count(report: dict) -> int:
    packages = len(report.get("packages") or [])
    vulns = len(report.get("vulnerabilities") or [])
    impacts = len(report.get("impact_reports") or [])
    paths = len(report.get("remediation_paths") or [])
    unresolved = len((report.get("usage") or {}).get("unresolved") or [])
    complexity = packages + (vulns * 3) + (impacts * 4) + (paths * 6) + unresolved
    return max(100, min(300, 100 + complexity * 4))


def _build_executive_summary_prompt_data(report: dict) -> dict:
    vulns = report.get("vulnerabilities") or []
    impacts = report.get("impact_reports") or []
    paths = report.get("remediation_paths") or []
    currency = report.get("currency") or []
    usage = report.get("usage") or {}
    severity_counts: dict[str, int] = {}
    for vuln in vulns:
        severity = str(vuln.get("severity") or "UNKNOWN")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    top_vulnerabilities = sorted(
        vulns,
        key=lambda item: (
            -SEVERITY_RANK.get(str(item.get("severity") or "UNKNOWN"), 0),
            str(item.get("package") or ""),
            str(item.get("cve_id") or ""),
        ),
    )[:8]
    top_impacts = sorted(
        impacts,
        key=lambda item: (
            -float(item.get("breakage_score") or 0.0),
            str(item.get("package") or ""),
        ),
    )[:6]
    remediation_paths = sorted(
        paths,
        key=lambda item: (
            float(item.get("exposure_score") or 1.0),
            float(item.get("breakage_score") or 1.0),
        ),
    )[:3]
    noteworthy_currency = [
        {
            "package": item.get("package"),
            "installed_version": item.get("installed_version"),
            "latest_version": item.get("latest_version"),
            "signals": item.get("signals") or [],
        }
        for item in currency
        if item.get("signals")
    ][:6]
    unresolved_usage = [
        {
            "package": item.get("package"),
            "source_file": item.get("source_file"),
            "flag": item.get("flag"),
        }
        for item in (usage.get("unresolved") or [])
    ][:6]
    return {
        "run": report.get("run") or {},
        "package_count": len(report.get("packages") or []),
        "severity_counts": severity_counts,
        "top_vulnerabilities": [
            {
                "package": item.get("package"),
                "cve_id": item.get("cve_id"),
                "severity": item.get("severity"),
                "installed_version": item.get("installed_version"),
                "fixed_versions": item.get("fixed_versions") or [],
            }
            for item in top_vulnerabilities
        ],
        "top_impacts": [
            {
                "package": item.get("package"),
                "candidate_version": item.get("candidate_version"),
                "probable_breakage": item.get("probable_breakage"),
                "breakage_score": item.get("breakage_score"),
                "confidence": item.get("confidence"),
            }
            for item in top_impacts
        ],
        "remediation_paths": [
            {
                "path_type": item.get("path_type"),
                "upgrade_count": len(item.get("upgrades") or []),
                "resolved_cves": len(item.get("cves_resolved") or []),
                "open_cves": len(item.get("cves_unresolved") or []),
                "no_fix_cves": len(item.get("cves_no_fix") or []),
                "exposure_score": item.get("exposure_score"),
                "breakage_score": item.get("breakage_score"),
                "confidence": item.get("confidence"),
                "rationale": item.get("rationale"),
            }
            for item in remediation_paths
        ],
        "currency_signals": noteworthy_currency,
        "usage": {
            "record_count": len(usage.get("records") or []),
            "unresolved_count": len(usage.get("unresolved") or []),
            "unresolved_samples": unresolved_usage,
        },
    }


def _fallback_executive_summary_narrative(report: dict) -> str:
    run = report.get("run") or {}
    packages = report.get("packages") or []
    vulns = report.get("vulnerabilities") or []
    impacts = report.get("impact_reports") or []
    paths = report.get("remediation_paths") or []
    currency = report.get("currency") or []
    usage = report.get("usage") or {}
    unresolved = usage.get("unresolved") or []
    severity_counts: dict[str, int] = {}
    for vuln in vulns:
        severity = str(vuln.get("severity") or "UNKNOWN")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    severity_summary = (
        ", ".join(
            f"{count} {severity.lower()}"
            for severity, count in sorted(
                severity_counts.items(),
                key=lambda item: SEVERITY_RANK.get(item[0], 0),
                reverse=True,
            )
        )
        or "no known vulnerabilities"
    )
    return (
        f"Changes AI completed a dependency review for {run.get('locator') or 'the target project'} across {len(packages)} tracked packages. "
        f"The scan identified {len(vulns)} known vulnerabilities, made up of {severity_summary}, and collected currency signals for {len(currency)} packages to show how far behind each dependency is from the current release line. "
        f"Usage analysis {'found unresolved or dynamic references that lower certainty in the impact estimate' if unresolved else 'did not report unresolved source-usage flags, which improves confidence in the downstream impact estimate'}. "
        f"The impact stage produced {len(impacts)} upgrade assessments, and the remediation planner returned {len(paths)} ranked upgrade paths that balance exposure reduction against likely breakage. "
        "Overall, this run gives a concise picture of the present security exposure, the likely cost of fixing it, and the most credible path for reducing risk with the evidence available from the project and package metadata."
    )


def _generate_executive_summary_narrative(
    report: dict,
    *,
    api_key: str | None,
    model: str,
    api_base: str,
    cache: SQLiteCache,
    refresh: bool,
    offline: bool,
) -> str:
    fallback = _fallback_executive_summary_narrative(report)
    if not api_key:
        return fallback

    client = LLMClient(
        api_key=api_key,
        model=model,
        api_base=api_base,
        cache=cache,
        refresh=refresh,
        offline=offline,
    )
    target_words = _summary_target_word_count(report)
    prompt_data = _build_executive_summary_prompt_data(report)
    try:
        content = client.chat(
            [
                {
                    "role": "system",
                    "content": (
                        "You write concise executive summaries for software dependency risk reports. "
                        "Return plain prose only, with no bullets, no headings, and no markdown fences."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Write an executive summary narrative of about {target_words} words. "
                        "It must stay between 100 and 300 words, with length proportional to the complexity of the findings. "
                        "Summarize the overall exposure, the likely upgrade risk, and the most important remediation outcome if one exists. "
                        "Do not restate raw tables. Use clear prose only.\n\n"
                        f"<data>{json.dumps(prompt_data, indent=2, sort_keys=True)}</data>"
                    ),
                },
            ]
        )
    except CacheMissError:
        return fallback

    if not content:
        return fallback
    words = content.strip().split()
    if len(words) < 100:
        return fallback
    if len(words) > 300:
        return " ".join(words[:300]).rstrip(" ,;:") + "."
    return content.strip()


def _executive_summary_api_key(impact_analysis_enabled: bool) -> str | None:
    if not impact_analysis_enabled:
        return None
    return os.environ.get("OPENAI_API_KEY")
