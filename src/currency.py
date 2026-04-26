"""Package currency and deprecation signals for Phase 4 analysis enrichment."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

_STALE_THRESHOLD_DAYS = 548


@dataclass
class CurrencyRecord:
    package: str
    installed_version: str
    latest_version: str
    latest_release_date: str | None = None
    release_cadence_days: float | None = None
    is_stale: bool = False
    is_deprecated: bool = False
    major_version_lag: int = 0
    signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _extract_release_dates(info: dict) -> list[datetime]:
    versions = info.get("versions") or []
    dates: list[datetime] = []
    for item in versions:
        if not isinstance(item, dict):
            continue
        for key in ("published_at", "released_at", "created_at"):
            parsed = _parse_timestamp(item.get(key))
            if parsed is not None:
                dates.append(parsed)
                break
    return sorted({date.isoformat(): date for date in dates}.values(), reverse=True)


def _latest_release_date(info: dict) -> datetime | None:
    for key in (
        "latest_stable_release_published_at",
        "latest_release_published_at",
        "latest_release_date",
    ):
        parsed = _parse_timestamp(info.get(key))
        if parsed is not None:
            return parsed
    dates = _extract_release_dates(info)
    return dates[0] if dates else None


def _release_cadence_days(info: dict) -> float | None:
    dates = _extract_release_dates(info)
    if len(dates) < 2:
        return None
    intervals = [
        (older - newer).total_seconds() / 86400.0
        for newer, older in zip(dates[1:5], dates[0:4])
        if older > newer
    ]
    if not intervals:
        return None
    return round(sum(intervals) / len(intervals), 1)


def _major_version(version: str | None) -> int | None:
    if not version:
        return None
    match = re.match(r"^(\d+)", version.strip())
    if not match:
        return None
    return int(match.group(1))


def _is_deprecated(info: dict) -> bool:
    if info.get("deprecated"):
        return True
    if info.get("deprecation_reason"):
        return True
    status_fields = [
        str(info.get("status") or ""),
        str(info.get("repository_status") or ""),
        str(info.get("project_status") or ""),
    ]
    status = " ".join(status_fields).lower()
    return any(
        token in status
        for token in ("deprecated", "unmaintained", "abandoned", "archived")
    )


def analyse_currency(
    mapping: list[dict],
    libraries_client,
    *,
    now: datetime | None = None,
) -> list[dict]:
    """Return currency signals for the current package mapping."""
    now = now or datetime.now(timezone.utc)
    records: list[dict] = []

    for row in mapping:
        package = row.get("name") or ""
        installed_version = row.get("installed") or "(unknown)"
        latest_version = row.get("latest") or "(unknown)"
        info = libraries_client.get_package_info(package) or {}

        latest_release = _latest_release_date(info)
        cadence_days = _release_cadence_days(info)
        deprecated = _is_deprecated(info)

        installed_major = _major_version(installed_version)
        latest_major = _major_version(latest_version)
        major_version_lag = 0
        if (
            installed_major is not None
            and latest_major is not None
            and latest_major > installed_major
        ):
            major_version_lag = latest_major - installed_major

        stale = False
        if latest_release is not None:
            stale = (now - latest_release).days > _STALE_THRESHOLD_DAYS

        signals: list[str] = []
        if deprecated:
            signals.append("deprecated")
        if stale:
            signals.append("stale")
        if major_version_lag > 0:
            signals.append(f"major_version_lag:{major_version_lag}")
        if cadence_days is not None and cadence_days > 180:
            signals.append("slow_release_cadence")

        record = CurrencyRecord(
            package=package,
            installed_version=installed_version,
            latest_version=latest_version,
            latest_release_date=latest_release.isoformat().replace("+00:00", "Z")
            if latest_release
            else None,
            release_cadence_days=cadence_days,
            is_stale=stale,
            is_deprecated=deprecated,
            major_version_lag=major_version_lag,
            signals=signals,
        )
        records.append(record.to_dict())

    return records
