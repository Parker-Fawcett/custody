"""Custody - the agent may only destroy what it made.

Hermes approves the description of a command. The shell executes its
semantics. This plugin resolves the semantics first, attributes every target
to this session's provenance, and sends anything it did not create to a human.

Public surfaces only: pre_tool_call, post_tool_call, on_session_start,
register_tool, register_command.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from . import ledger as ledger_mod
from . import policy, schemas

logger = logging.getLogger(__name__)

_LEDGER = None
_SETTINGS = policy.Settings()

WRITE_TOOLS = {
    "write_file", "edit_file", "create_file", "patch", "apply_patch",
    "write", "edit", "multi_edit", "str_replace_editor",
}
PATH_KEYS = ("path", "file_path", "filename", "target_file")


def _load_settings(ctx) -> None:
    """Read operator options once, at registration."""
    global _SETTINGS
    try:
        mode = str(ctx.get_config("mode", default="enforce") or "enforce").lower()
        extra = ctx.get_config("extra_protected", default=[]) or []
        if isinstance(extra, str):
            extra = [extra]
        _SETTINGS = policy.Settings(
            observe=(mode == "observe"),
            extra_protected=tuple(str(e) for e in extra if e),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("custody: could not read settings (%s), using defaults", exc)


def _ledger():
    global _LEDGER
    if _LEDGER is None:
        _LEDGER = ledger_mod.open_ledger()
    return _LEDGER


# --------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------


def custody_explain(args: dict, **kwargs) -> str:
    """Resolve a command to its real targets without running it."""
    import json

    command = str(args.get("command") or "").strip()
    if not command:
        return json.dumps({"error": "No command supplied."})

    shell = str(args.get("shell") or "").strip().lower()
    if not shell:
        shell = "powershell" if os.name == "nt" else "posix"

    try:
        text = policy.explain(command, shell, _ledger(), dict(os.environ), os.getcwd(), _SETTINGS)
        return json.dumps({"command": command, "shell": shell, "report": text})
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"Could not resolve that command: {exc}"})


def custody_ledger(args: dict, **kwargs) -> str:
    """What this session has created, allowed, and stopped."""
    import json

    limit = int(args.get("limit") or 10)
    led = _ledger()
    summary = led.summary()
    recent = led.recent(limit)

    rows = [
        {
            "verdict": verdict,
            "verb": verb,
            "files": files,
            "bytes": size,
            "reason": reason,
        }
        for _ts, verdict, verb, files, size, reason in recent
    ]
    return json.dumps({"session_totals": summary, "recent": rows})


CUSTODY_COMMAND_HELP = "Show what this session created and what custody stopped."


def _slash(ctx, raw_args: str) -> str:
    led = _ledger()
    totals = led.summary()
    if not totals:
        return "Custody: nothing checked yet this session."

    parts = [f"{k}: {v}" for k, v in sorted(totals.items())]
    lines = ["Custody this session - " + ", ".join(parts), ""]

    for _ts, verdict, verb, files, size, reason in led.recent(5):
        lines.append(f"  {verdict:<8} {verb:<12} {files:>8,} files  {reason}")

    return "\n".join(lines)


# --------------------------------------------------------------------------
# Hooks
# --------------------------------------------------------------------------


def _on_session_start(session_id: str = "", **kwargs) -> None:
    try:
        led = _ledger()
        led.start_session(session_id)
        cwd = os.getcwd()
        count = led.baseline(cwd)
        logger.debug("custody: session %s baselined %d files under %s", session_id, count, cwd)
    except Exception as exc:  # noqa: BLE001
        logger.warning("custody: session start failed (%s)", exc)


def _on_post_tool_call(tool_name: str = "", args: dict | None = None, **kwargs) -> None:
    """Record anything this session wrote, so later deletes can be attributed."""
    try:
        if tool_name not in WRITE_TOOLS or not isinstance(args, dict):
            return
        led = _ledger()
        for key in PATH_KEYS:
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                target = value if os.path.isabs(value) else os.path.join(os.getcwd(), value)
                led.record_created(target)
                return
    except Exception as exc:  # noqa: BLE001
        logger.debug("custody: post_tool_call skipped (%s)", exc)


def _on_pre_tool_call(tool_name: str = "", args: dict | None = None, **kwargs):
    return policy.check_tool_call(tool_name, args or {}, _ledger(), settings=_SETTINGS)


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


def register(ctx) -> None:
    """Wire hooks, tools and the slash command."""
    _load_settings(ctx)

    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("post_tool_call", _on_post_tool_call)
    ctx.register_hook("on_session_start", _on_session_start)

    ctx.register_tool(
        name="custody_explain",
        toolset="custody",
        schema=schemas.CUSTODY_EXPLAIN,
        handler=custody_explain,
    )
    ctx.register_tool(
        name="custody_ledger",
        toolset="custody",
        schema=schemas.CUSTODY_LEDGER,
        handler=custody_ledger,
    )

    ctx.register_command(
        "custody",
        lambda raw: _slash(ctx, raw),
        description=CUSTODY_COMMAND_HELP,
    )

    skills_dir = Path(__file__).parent / "skills"
    if skills_dir.is_dir():
        for child in sorted(skills_dir.iterdir()):
            skill_md = child / "SKILL.md"
            if child.is_dir() and skill_md.exists():
                try:
                    ctx.register_skill(child.name, skill_md)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("custody: could not register skill %s (%s)", child.name, exc)

    logger.debug("custody: registered 2 tools, 3 hooks, 1 command")
