"""Custody classification.

Given a resolved target and the session ledger, decide who it belongs to.
The only question that matters: did this session make it?
"""

from __future__ import annotations

import os
from dataclasses import dataclass

AGENT_MADE = "agent-made"
AGENT_TOUCHED = "agent-touched"
MIXED = "mixed"
USER_OWNED = "user-owned"
PROTECTED = "protected"
APP_STATE = "app-state"
ABSENT = "absent"
UNKNOWN = "unknown"

# Roots where a deletion is never routine, whatever the provenance says.
# Deliberately excludes /var and /private: the per-user temp dir lives under
# /private/var/folders, and protecting it would cry wolf on every scratch file.
PROTECTED_POSIX = [
    "/System", "/Library", "/usr", "/bin", "/sbin", "/etc", "/private/etc",
    "/private/var/db", "/var/db", "/private/var/root", "/Applications",
    "/Volumes", "/opt", "/cores", "/private/var/vm",
]

PROTECTED_HOME = [
    ".ssh", ".gnupg", ".aws", ".kube", ".config", ".hermes", ".password-store",
    ".local/share/keyrings", "Library/Keychains", "Library/Mail",
    "Library/Messages", "Library/Application Support", "Library/Containers",
    "Library/Group Containers", "Documents", "Desktop", "Pictures", "Movies",
    "Music", "Downloads",
]

# Named so the approval prompt can say why, not just "blocked".
ROOT_REASONS = {
    "/System": "macOS system",
    "/Library": "system-wide library",
    "/usr": "unix system",
    "/bin": "unix system",
    "/sbin": "unix system",
    "/etc": "system configuration",
    "/var": "system state",
    "/private": "system state",
    "/Applications": "installed applications",
    "/Volumes": "mounted volumes",
    ".ssh": "SSH private keys",
    ".gnupg": "GPG keys",
    ".aws": "cloud credentials",
    ".kube": "cluster credentials",
    ".config": "app configuration",
    ".hermes": "Hermes' own state",
    ".password-store": "password store",
    "Library/Keychains": "the system keychain",
    "Library/Mail": "local mail",
    "Library/Messages": "message history",
    "Library/Application Support": "application state",
    "Library/Containers": "sandboxed app state",
    "Library/Group Containers": "sandboxed app state",
    "Documents": "user documents",
    "Desktop": "user files",
    "Pictures": "user media",
    "Movies": "user media",
    "Music": "user media",
    "Downloads": "downloaded files",
}

DRIVE_LETTER = len("C:\\") == 3  # named for readability; Windows paths are 3 chars


@dataclass
class Verdict:
    path: str
    custody: str
    reason: str
    ours: int = 0
    foreign: int = 0
    escalate: bool = True

    @property
    def label(self) -> str:
        return self.custody


def _is_windows_path(path: str) -> bool:
    return bool(path[1:3] == ":\\") or path.startswith("\\\\")


def protected_reason(path: str, env: dict[str, str], extra: tuple[str, ...] = ()) -> str | None:
    """Return why this path is protected, or None."""
    path = os.path.normpath(path)
    home = os.path.normpath(env.get("HOME") or env.get("USERPROFILE") or "") or None
    lowered = path.lower()

    for root in extra:
        if root and (path == root or path.startswith(root.rstrip(os.sep) + os.sep)):
            return "a path you marked protected"

    for root in PROTECTED_POSIX:
        if path == root or path.startswith(root + os.sep) or root.startswith(path + os.sep):
            return ROOT_REASONS.get(root, "system directory")

    if home:
        lowhome = home.lower()
        for rel in PROTECTED_HOME:
            full = os.path.normpath(os.path.join(home, rel))
            lowfull = full.lower()
            if lowered == lowfull or lowered.startswith(lowfull + os.sep):
                return ROOT_REASONS.get(rel, "protected user directory")
            if lowfull.startswith(lowered + os.sep) or lowered == lowhome:
                # the target is an ancestor of a protected directory, or home itself
                return "contains protected user data"

    if _is_windows_path(path):
        for var, label in (
            ("WINDIR", "the Windows directory"),
            ("PROGRAMFILES", "installed programs"),
            ("PROGRAMDATA", "system-wide application data"),
        ):
            value = env.get(var)
            if value and (lowered == value.lower() or lowered.startswith(value.lower() + "\\")):
                return label
        if len(path) <= 3 and path[1:3] == ":\\":
            return "a drive root"

    # Profile roots are checked by the env value, not by path style, so the
    # same rule holds when a Windows-shaped tree is inspected from another OS.
    for var, label in (
        ("USERPROFILE", "the user profile root"),
        ("APPDATA", "a roaming profile root"),
        ("LOCALAPPDATA", "a local profile root"),
    ):
        value = env.get(var)
        if value and value.strip() and os.path.normpath(value) != os.path.normpath(env.get("HOME", "/nonexistent")):
            norm = os.path.normpath(value)
            if path == norm or path.startswith(norm + os.sep):
                return label

    if path == os.path.abspath(os.sep):
        return "the filesystem root"

    return None


def classify_path(path: str, ledger, env: dict[str, str],
                  extra_protected: tuple[str, ...] = ()) -> Verdict:
    """Classify one resolved target."""
    reason = protected_reason(path, env, extra_protected)
    if reason:
        ours, foreign = ledger.count_under(path)
        return Verdict(path, PROTECTED, reason, ours=ours, foreign=foreign, escalate=True)

    if not os.path.exists(path):
        return Verdict(path, ABSENT, "nothing at this path", escalate=False)

    ours, foreign = ledger.count_under(path)

    if os.path.isdir(path) and not os.path.islink(path):
        if ours and not foreign:
            return Verdict(path, AGENT_MADE, "created this session", ours=ours, escalate=False)
        if foreign == 0 and ours == 0:
            prov = ledger.provenance(path)
            if prov.ours:
                return Verdict(path, AGENT_MADE, "created this session", escalate=False)
            return Verdict(path, UNKNOWN, "not in this session's index", escalate=True)
        if ours and foreign:
            return Verdict(
                path, MIXED, f"{ours} created here, {foreign} pre-existing",
                ours=ours, foreign=foreign, escalate=True,
            )
        return Verdict(path, USER_OWNED, "pre-existing directory", foreign=foreign, escalate=True)

    prov = ledger.provenance(path)
    if prov.origin in ("created", "touched"):
        return Verdict(path, AGENT_MADE if prov.origin == "created" else AGENT_TOUCHED,
                       "created this session", ours=1, escalate=False)
    if prov.origin == "unknown":
        return Verdict(path, UNKNOWN, "exists but predates this session", foreign=1, escalate=True)
    return Verdict(path, USER_OWNED, "pre-existing file", foreign=1, escalate=True)


def classify(blast, ledger, env: dict[str, str],
             extra_protected: tuple[str, ...] = ()) -> list[Verdict]:
    """Classify every target in a blast."""
    verdicts: list[Verdict] = []

    for label in blast.app_state:
        verdicts.append(
            Verdict(label, APP_STATE, "an app may be holding unsaved work here",
                    escalate=True)
        )

    for target in blast.targets:
        if not target.ok:
            verdicts.append(
                Verdict(target.raw, UNKNOWN, f"could not resolve: {target.unresolved}",
                        escalate=True)
            )
            continue
        v = classify_path(target.path, ledger, env, extra_protected)
        if target.truncated:
            v.reason += ", count capped"
        verdicts.append(v)

    return verdicts
