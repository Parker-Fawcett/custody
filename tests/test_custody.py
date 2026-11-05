"""End-to-end scenarios. Every case is a real command shape from the two
open data-loss incidents, plus the safe cases that must stay silent.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from custody import classify as C          # noqa: E402
from custody import policy                 # noqa: E402
from custody.ledger import Ledger          # noqa: E402

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, str, str]] = []


def check(name: str, got, want) -> None:
    ok = got == want
    results.append((PASS if ok else FAIL, name, f"got={got!r} want={want!r}"))


def build_world(root: Path):
    """A fake home with a project, a profile, and a cache."""
    home = root / "home"
    project = home / "work" / "app"
    profile = home / "AppData" / "Local"
    cache = profile / "pip" / "cache"
    docs = home / "Documents"

    for d in (project / "src", cache, docs, profile):
        d.mkdir(parents=True, exist_ok=True)

    (project / "src" / "main.py").write_text("print('hi')\n")
    (project / "README.md").write_text("# app\n")
    for i in range(5):
        (cache / f"wheel{i}.whl").write_bytes(b"x" * 100)
    (docs / "thesis.pdf").write_bytes(b"y" * 500)

    env = {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "APPDATA": str(home / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(profile),
        "TEMP": str(home / "AppData" / "Local" / "Temp"),
        "TMPDIR": str(root / "tmp"),
    }
    return env, home, project, profile, cache, docs


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="custody-test-"))
    env, home, project, profile, cache, docs = build_world(root)

    conn = sqlite3.connect(":memory:")
    led = Ledger(conn)
    led.start_session("test-session")
    led.baseline(str(project))

    # the agent makes its own scratch space
    scratch = project / "scratch"
    scratch.mkdir()
    (scratch / "a.txt").write_text("a")
    (scratch / "b.txt").write_text("b")
    led.record_created(str(scratch / "a.txt"))
    led.record_created(str(scratch / "b.txt"))
    led.record_created(str(scratch))

    v = C.classify_path(str(scratch), led, env)
    check("agent scratch dir is ours", v.custody, C.AGENT_MADE)

    v = C.classify_path(str(project), led, env)
    check("project with prior files is mixed", v.custody, C.MIXED)

    v = C.classify_path(str(profile), led, env)
    check("profile root is protected", v.custody, C.PROTECTED)

    v = C.classify_path(str(docs / "thesis.pdf"), led, env)
    check("document is protected", v.custody, C.PROTECTED)

    # ---- directives -------------------------------------------------------
    led.record_created(str(scratch / "a.txt"))
    directive, blast, verdicts = policy.evaluate(
        f"rm -rf {scratch}", "posix", led, env, str(project))
    check("deleting our own scratch is allowed", directive, None)

    directive, blast, verdicts = policy.evaluate(
        f"rm -rf {project}", "posix", led, env, str(project))
    check("deleting the whole project escalates", directive and directive["action"], "approve")

    directive, blast, verdicts = policy.evaluate(
        f"rm -rf {profile}", "posix", led, env, str(project))
    check("deleting the profile root escalates", directive and directive["action"], "approve")

    directive, blast, verdicts = policy.evaluate(
        f"rm -f {docs / 'thesis.pdf'}", "posix", led, env, str(project))
    check("deleting a document escalates", directive and directive["action"], "approve")

    # incident #141346
    script = (
        'tell application "Microsoft PowerPoint" to close active presentation saving no'
    )
    directive, blast, verdicts = policy.evaluate(
        f'osascript -e {script!r}', "posix", led, env, str(project))
    check("osascript on a GUI app blocks", directive and directive["action"], "block")

    # incident #147373, the array-precedence trap
    ps = (
        "Remove-Item -Recurse -Force @('"
        + str(home / "AppData" / "Local" / "pip" / "cache")
        + "', $env:LOCALAPPDATA + '\\pip\\cache', $env:APPDATA + '\\x')"
    )
    blast = policy.Re.analyze(ps, shell="powershell", env=env, cwd=str(project))
    check("powershell array of 3 written paths expands", len(blast.targets), 5)
    check("precedence note is emitted", bool(blast.notes), True)

    directive, blast, verdicts = policy.evaluate(ps, "powershell", led, env, str(project))
    check("powershell widening escalates", directive and directive["action"], "approve")

    # ---- report shape -----------------------------------------------------
    directive, blast, verdicts = policy.evaluate(
        f"rm -rf {project} {profile}", "posix", led, env, str(project))
    text = directive["message"]
    check("report names CUSTODY", text.startswith("CUSTODY"), True)
    check("report counts targets", "2 targets" in text or "2 targets" in text, True)

    # the literal command shape from #147373: five written paths, eight targets
    incident = (
        "Remove-Item -Recurse -Force @('C:\\Windows\\Temp', $env:TEMP, "
        "$env:LOCALAPPDATA + '\\pip\\cache', $env:LOCALAPPDATA + '\\Temp', "
        "$env:APPDATA + '\\npm-cache')"
    )
    body = incident.split("@(", 1)[1].rstrip(")")
    expanded, note = policy.Re.expand_array_literal(body, env, str(project))
    check("incident #147373 expands 5 written paths to 8 elements", len(expanded), 8)
    check("incident note states the precedence trap", "5 written" in note and "8 array" in note, True)

    b = policy.Re.analyze(incident, shell="powershell", env=env, cwd=str(project))
    check("incident collapses to 7 unique paths", len(b.targets), 7)
    check("incident records both counts", any("8 array element(s)" in n for n in b.notes), True)

    profiles = [t for t in b.targets if t.path and "AppData" in t.path]
    check("incident exposes profile-root targets", len(profiles) >= 3, True)

    print(text)
    print()
    print("=" * 70)

    failures = [r for r in results if r[0] == FAIL]
    for status, name, detail in results:
        if status == FAIL:
            print(f"{status}  {name}  ({detail})")

    print(f"{len(results) - len(failures)}/{len(results)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
