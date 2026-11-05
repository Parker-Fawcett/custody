"""Decision layer.

Turns a resolved blast radius into a directive for Hermes' approval gate.

The failure mode that matters: this runs on every tool call, so it must be
fast, silent when there is nothing to say, and incapable of wedging the agent.
Every path is wrapped. A resolver error degrades to "escalate if a destructive
verb is present", never to a crash.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from . import classify as C
from . import report as R
from . import resolver as Re

logger = logging.getLogger(__name__)

TERMINAL_TOOLS = {"terminal", "shell", "run_command", "bash", "exec", "execute_bash"}

# A rule key groups identical approvals in the session gate.
RULE_PREFIX = "custody"


@dataclass
class Settings:
    """Operator choices from plugin.yaml config_schema."""

    observe: bool = False
    extra_protected: tuple[str, ...] = field(default_factory=tuple)


def _command_from(args: dict) -> tuple[str, str]:
    """(command, shell) out of whatever a terminal tool was handed."""
    command = args.get("command") or args.get("cmd") or args.get("script") or ""
    if isinstance(command, list):
        command = " ".join(str(c) for c in command)

    shell = args.get("shell") or args.get("env_type") or ""
    if not shell:
        if os.name == "nt":
            shell = "powershell"
        else:
            shell = "posix"
    return str(command), str(shell)


def evaluate(command: str, shell: str, ledger, env: dict[str, str], cwd: str,
             settings: Settings | None = None):
    """Return (directive, blast, verdicts). directive is None when allowed."""
    settings = settings or Settings()

    blast = Re.analyze(command, shell=shell, env=env, cwd=cwd)
    if blast is None:
        return None, None, []

    verdicts = C.classify(blast, ledger, env, settings.extra_protected)
    if not verdicts:
        return None, blast, []

    message = R.format_report(verdicts, blast, env, verb=_verb(blast))
    rule_key = f"{RULE_PREFIX}:{blast.verb}"

    if settings.observe:
        ledger.record_decision(
            command=command, verb=blast.verb, verdict="observed",
            files=blast.total_files, bytes_=blast.total_bytes,
            reason=",".join(sorted({v.custody for v in verdicts if v.escalate})) or "session-owned",
        )
        return None, blast, verdicts

    if any(v.custody == C.APP_STATE for v in verdicts):
        ledger.record_decision(
            command=command, verb=blast.verb, verdict="block",
            files=blast.total_files, bytes_=blast.total_bytes,
            reason="app state",
        )
        return {"action": "block", "message": message}, blast, verdicts

    if any(v.escalate for v in verdicts):
        ledger.record_decision(
            command=command, verb=blast.verb, verdict="escalate",
            files=blast.total_files, bytes_=blast.total_bytes,
            reason=",".join(sorted({v.custody for v in verdicts if v.escalate})),
        )
        return {"action": "approve", "message": message, "rule_key": rule_key}, blast, verdicts

    ledger.record_decision(
        command=command, verb=blast.verb, verdict="allow",
        files=blast.total_files, bytes_=blast.total_bytes, reason="session-owned",
    )
    return None, blast, verdicts


def _verb(blast) -> str:
    return {
        "rm": "Delete", "rmdir": "Delete", "shred": "Shred", "unlink": "Delete",
        "find -delete": "Delete", "dd": "Overwrite", "redirect": "Overwrite",
        "truncate": "Truncate", "git clean": "Clean", "Remove-Item": "Remove",
        "Out-File": "Overwrite", "osascript": "Drive", "killall": "Kill",
        "pkill": "Kill", "taskkill": "Kill",
    }.get(blast.verb, "Run")


def check_tool_call(tool_name: str, args: dict, ledger, env: dict[str, str] | None = None,
                    cwd: str | None = None, settings: Settings | None = None):
    """The pre_tool_call entry point. Returns a directive or None."""
    try:
        if tool_name not in TERMINAL_TOOLS or not isinstance(args, dict):
            return None

        command, shell = _command_from(args)
        if not command.strip():
            return None

        return evaluate(
            command, shell, ledger,
            env if env is not None else dict(os.environ),
            cwd or args.get("workdir") or os.getcwd(),
            settings,
        )[0]

    except Exception as exc:  # never wedge a terminal call on a resolver bug
        logger.warning("custody: analysis failed (%s)", exc)
        try:
            if Re.detect(_command_from(args)[0], _command_from(args)[1]):
                return {
                    "action": "approve",
                    "message": (
                        "CUSTODY  could not resolve this command's targets "
                        f"({type(exc).__name__}). Nothing is known about what it touches, "
                        "so it needs a human decision."
                    ),
                    "rule_key": "custody:unresolved",
                }
        except Exception:
            logger.warning("custody: fallback detection also failed")
        return None


def explain(command: str, shell: str, ledger, env: dict[str, str],
            cwd: str, settings: Settings | None = None) -> str:
    """Resolve a command without running it. Used by the custody_explain tool."""
    blast = Re.analyze(command, shell=shell, env=env, cwd=cwd)
    if blast is None:
        return (
            "No destructive operation detected in this command. "
            "Custody only resolves deletes, overwrites, truncation and app control."
        )

    settings = settings or Settings()
    verdicts = C.classify(blast, ledger, env, settings.extra_protected)
    return R.format_report(verdicts, blast, env, verb=_verb(blast), command=command)
