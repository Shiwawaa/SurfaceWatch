from models.schemas import DiffOut, FindingOut


def compute_scan_diff(
    *,
    current_scan_id: int | None,
    previous_scan_id: int | None,
    current_findings: list[FindingOut],
    previous_findings: list[FindingOut],
) -> DiffOut:
    current_map = {f.id: f for f in current_findings}
    previous_map = {f.id: f for f in previous_findings}

    new_items: list[FindingOut] = []
    unchanged_items: list[FindingOut] = []
    resolved_items: list[FindingOut] = []

    for fid, finding in current_map.items():
        if fid in previous_map:
            unchanged_items.append(finding)
        else:
            new_items.append(finding)

    for fid, finding in previous_map.items():
        if fid not in current_map:
            resolved_items.append(finding)

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    new_items.sort(key=lambda f: (severity_rank.get(f.severity, 9), f.host))
    resolved_items.sort(key=lambda f: (severity_rank.get(f.severity, 9), f.host))
    unchanged_items.sort(key=lambda f: (severity_rank.get(f.severity, 9), f.host))

    return DiffOut(
        current_scan_id=current_scan_id,
        previous_scan_id=previous_scan_id,
        new=new_items,
        resolved=resolved_items,
        unchanged=unchanged_items,
        counts={
            "new": len(new_items),
            "resolved": len(resolved_items),
            "unchanged": len(unchanged_items),
        },
    )
