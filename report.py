"""The approval message.

This string is the product. It is what a human reads at the moment they decide
whether to let a destructive command run, so it has to be short, true, and
specific enough to argue with.
"""

from __future__ import annotations

import os

from .classify import (
    ABSENT, AGENT_MADE, AGENT_TOUCHED, APP_STATE, MIXED, PROTECTED, UNKNOWN,
    USER_OWNED, Verdict,
)

MAX_LINES = 8
MARK = {
    AGENT_MADE: "+",
    AGENT_TOUCHED: "~",
    ABSENT: ".",
    MIXED: "!",
    USER_OWNED: "!",
    PROTECTED: "X",
    APP_STATE: "X",
    UNKNOWN: "?",
}


def human_count(n: int) -> str:
    return f"{n:,}"


def human_bytes(n: int) -> str:
    if not n:
        return "0 B"
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    value = float(n)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:,.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{n} B"


def shorten(path: str, env: dict[str, str], width: int = 34) -> str:
    home = env.get("HOME") or env.get("USERPROFILE")
    shown = path
    if home and path.startswith(home):
        shown = "~" + path[len(home):]
    if len(shown) > width:
        head = max(6, width - 12)
        shown = shown[:head] + "..." + shown[-(width - head - 3):]
    return shown


def verdict_line(v: Verdict, env: dict[str, str]) -> str:
    count = v.foreign or v.ours
    counter = f"{human_count(count)} files" if count else ""
    return "  %s  %-34s %-12s %s" % (
        MARK.get(v.custody, "?"),
        shorten(v.path, env),
        counter,
        v.reason,
    )


def format_report(verdicts: list[Verdict], blast, env: dict[str, str],
                  *, verb: str = "Delete", command: str = "") -> str:
    escalate = [v for v in verdicts if v.escalate]
    allowed = [v for v in verdicts if not v.escalate]

    head = "CUSTODY  %d target%s, %d outside this session" % (
        len(verdicts), "" if len(verdicts) == 1 else "s", len(escalate),
    )

    lines = [head, ""]

    shown = verdicts[:MAX_LINES]
    for v in shown:
        lines.append(verdict_line(v, env))
    if len(verdicts) > len(shown):
        lines.append(f"  ... and {len(verdicts) - len(shown)} more")

    files = blast.total_files
    size = blast.total_bytes
    if files:
        lines.append("")
        lines.append("  %s files, %s. %s" % (
            human_count(files), human_bytes(size), _recoverability(verdicts),
        ))

    for note in blast.notes[:2]:
        lines.append(f"  Why: {note}")

    if escalate:
        lines.append("")
        lines.append("  " + _closing(escalate))
    elif allowed:
        lines.append("")
        lines.append("  Everything here was created by this session.")

    return "\n".join(lines)


def _recoverability(verdicts: list[Verdict]) -> str:
    if any(v.custody == APP_STATE for v in verdicts):
        return "Unsaved work is not recoverable once a document is closed."
    return "No snapshot is taken before this runs."


def _closing(escalate: list[Verdict]) -> str:
    """One sentence that says why this is worth stopping for."""
    kinds = {v.custody for v in escalate}

    if APP_STATE in kinds:
        return "Approving lets the command act on a running app's documents."
    if PROTECTED in kinds:
        ranked = sorted(
            (v.reason for v in escalate if v.custody == PROTECTED),
            key=lambda r: 0 if "profile root" in r else 1,
        )
        return f"Approving deletes inside {ranked[0]}, which this session did not create."
    if MIXED in kinds:
        return "Approving deletes this session's files and the user's, in one command."
    if USER_OWNED in kinds:
        return "Every target here predates this session."
    return "Custody could not resolve these targets, so it cannot vouch for them."


def summarize(verdicts: list[Verdict]) -> str:
    if any(v.escalate for v in verdicts):
        return "escalate"
    return "allow"
