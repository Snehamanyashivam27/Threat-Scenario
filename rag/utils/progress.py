from __future__ import annotations


def report_progress(label: str, current: int, total: int, *, steps: int = 20) -> None:
    """Print a flushed percent line about every 5% and always at 0% and 100%."""
    if total <= 0 or current < 0:
        return
    if current == 0:
        print(f"{label}: 0/{total} (0%)", flush=True)
        return
    every = max(1, total // max(1, steps))
    if current != total and current % every != 0:
        return
    percent = min(100, (100 * current) // total)
    print(f"{label}: {current}/{total} ({percent}%)", flush=True)
