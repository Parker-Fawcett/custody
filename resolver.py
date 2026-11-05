"""Command blast-radius resolver.

Turns a destructive shell command into the set of filesystem objects it will
actually touch, without executing it.

The point is not to prove a command is safe. The point is to give a human
something true to approve. A command's text and a shell's evaluation of that
text are different objects; this module computes the second one.
"""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Result types
# --------------------------------------------------------------------------


@dataclass
class Target:
    """One thing a command will touch."""

    raw: str
    path: str | None = None
    unresolved: str | None = None  # reason, when path is None
    exists: bool = False
    is_dir: bool = False
    file_count: int | None = None
    size_bytes: int | None = None
    truncated: bool = False
    note: str = ""

    @property
    def ok(self) -> bool:
        return self.path is not None


@dataclass
class Detected:
    """A destructive operation found in a command."""

    verb: str
    args: list[str]
    shell: str
    mode: str = "scalar"  # "scalar" | "array"
    notes: list[str] = field(default_factory=list)


@dataclass
class Blast:
    """Everything a command will touch, plus how confident we are."""

    command: str
    shell: str
    verb: str
    targets: list[Target] = field(default_factory=list)
    app_state: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def unresolved(self) -> list[str]:
        return [t.raw for t in self.targets if not t.ok]

    @property
    def total_files(self) -> int:
        return sum(t.file_count or 0 for t in self.targets if t.exists)

    @property
    def total_bytes(self) -> int:
        return sum(t.size_bytes or 0 for t in self.targets if t.exists)

    @property
    def truncated(self) -> bool:
        return any(t.truncated for t in self.targets)

    def resolved_paths(self) -> list[str]:
        return [t.path for t in self.targets if t.path]


# --------------------------------------------------------------------------
# Scanning budget
# --------------------------------------------------------------------------

MAX_ENTRIES = 120_000
MAX_DEPTH = 8
_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "site-packages",
    ".mypy_cache", ".pytest_cache", ".tox", "target", "build", "dist",
}


def probe(path: str, *, max_entries: int = MAX_ENTRIES, max_depth: int = MAX_DEPTH) -> tuple[int, int, bool]:
    """Count files and bytes under path. Returns (files, bytes, truncated).

    Bounded on purpose: this runs inside an approval hook and must never hang.
    """
    try:
        st = os.lstat(path)
    except OSError:
        return 0, 0, False

    if not os.path.isdir(path) or os.path.islink(path):
        return 1, st.st_size, False

    files = 0
    total = 0
    seen = 0
    stack = [(path, 0)]

    while stack:
        current, depth = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    seen += 1
                    if seen > max_entries:
                        return files, total, True
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if depth < max_depth and entry.name not in _SKIP_DIRS:
                                stack.append((entry.path, depth + 1))
                        elif entry.is_file(follow_symlinks=False):
                            files += 1
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue

    return files, total, False


# --------------------------------------------------------------------------
# Shell-aware splitting
# --------------------------------------------------------------------------


def split_simple_commands(command: str) -> list[str]:
    """Split on ; && || | and newlines, respecting quotes and $() nesting."""
    parts: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(command)
    quote: str | None = None
    depth = 0

    while i < n:
        ch = command[i]

        if quote:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(command[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue

        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue

        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(command[i + 1])
            i += 2
            continue

        if command.startswith("$(", i):
            depth += 1
            buf.append("$(")
            i += 2
            continue

        if ch == ")" and depth > 0:
            depth -= 1
            buf.append(ch)
            i += 1
            continue

        if depth == 0:
            if command.startswith("&&", i) or command.startswith("||", i):
                parts.append("".join(buf).strip())
                buf = []
                i += 2
                continue
            if ch in (";", "|", "\n"):
                parts.append("".join(buf).strip())
                buf = []
                i += 1
                continue

        buf.append(ch)
        i += 1

    parts.append("".join(buf).strip())
    return [p for p in parts if p]


def split_words(text: str) -> list[str]:
    """Whitespace split that respects quotes and strips them from the result."""
    words: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(text)
    quote: str | None = None

    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
                i += 1
                continue
            buf.append(ch)
            i += 1
            continue

        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue

        if ch == "\\" and i + 1 < n:
            buf.append(text[i + 1])
            i += 2
            continue

        if ch.isspace():
            if buf:
                words.append("".join(buf))
                buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    if buf:
        words.append("".join(buf))
    return words


def split_top_level(text: str, sep: str) -> list[str]:
    """Split on sep at nesting depth 0, respecting quotes."""
    parts: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(text)
    depth = 0
    quote: str | None = None

    while i < n:
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if depth == 0 and text.startswith(sep, i):
            parts.append("".join(buf).strip())
            buf = []
            i += len(sep)
            continue
        buf.append(ch)
        i += 1

    parts.append("".join(buf).strip())
    return parts


# --------------------------------------------------------------------------
# POSIX expansion
# --------------------------------------------------------------------------

SAFE_VARS = {"HOME", "TMPDIR", "TMP", "TEMP", "USER", "LOGNAME", "PWD", "OLDPWD"}

_UNRESOLVABLE = re.compile(r"\$\(|`|\$\{|\$\[")


def expand_posix(word: str, env: dict[str, str], cwd: str) -> tuple[str | None, str]:
    """Expand a POSIX word to a path. Returns (path, note). None means unknown."""
    if _UNRESOLVABLE.search(word):
        return None, "contains command or parameter substitution"

    if word.startswith("~") and word != "~" and not word.startswith("~/"):
        return None, "references another user's home"

    out = word
    if out == "~" or out.startswith("~/"):
        out = env.get("HOME", "") + out[1:]

    unsafe: list[str] = []

    def _var(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in SAFE_VARS:
            return env.get(name, "")
        unsafe.append(name)
        return ""

    out = re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)", _var, out)

    if unsafe:
        return None, f"reads ${unsafe[0]}, which is not on the safe list"

    if not os.path.isabs(out):
        out = os.path.join(cwd, out)

    out = os.path.normpath(out)

    if any(tok in out for tok in ("*", "?", "[")):
        return None, "glob target; the expanded set is not knowable without running it"

    return out, ""


# --------------------------------------------------------------------------
# PowerShell expansion
# --------------------------------------------------------------------------

_PS_VAR = re.compile(r"\$(?:env:)?([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
_PS_VAR_PREFIX = re.compile(
    r"(?i)^(?P<var>\$(?:env:)?[A-Za-z_][A-Za-z0-9_]*)(?P<rest>[^A-Za-z0-9_].*)$"
)
_PS_SAFE = {
    "env:temp", "env:tmp", "env:localappdata", "env:appdata", "env:userprofile",
    "env:username", "env:homepath", "env:programdata", "env:systemroot",
    "env:windir", "pwd", "home",
}


def split_ps_elements(body: str) -> list[str]:
    """Split an @( ) body into elements the way PowerShell parses it.

    Inside an array literal ',' binds tighter than '+', so a top-level '+'
    appends an element instead of concatenating two into one. That is the
    whole bug behind #147373: five written paths became eight elements.
    """
    parts: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(body)
    depth = 0
    quote: str | None = None

    while i < n:
        ch = body[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch in "([{":
            depth += 1
            buf.append(ch)
            i += 1
            continue
        if ch in ")]}":
            depth -= 1
            buf.append(ch)
            i += 1
            continue
        if depth == 0 and ch in ",+":
            parts.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1

    parts.append("".join(buf).strip())
    return [p for p in parts if p]


def expand_array_literal(body: str, env: dict[str, str], cwd: str) -> tuple[list[str | None], str]:
    """Expand an @( ) body. Returns (paths or None per element, note)."""
    written = len(split_top_level(body, ","))
    elements = split_ps_elements(body)

    out: list[str | None] = []
    for el in elements:
        path, _note = expand_ps_value(el, env, cwd)
        out.append(path)

    note = ""
    if len(elements) > written:
        note = (
            "',' binds tighter than '+': %d written path(s) became %d array element(s)"
            % (written, len(elements))
        )
    return out, note


def expand_ps_value(value: str, env: dict[str, str], cwd: str) -> tuple[str | None, str]:
    """Expand one PowerShell scalar to a path."""
    value = value.strip()
    if not value:
        return None, "empty"

    # parenthesised scalar concat: ($env:TEMP + '\x')
    if value.startswith("(") and value.endswith(")") and _balanced(value[1:-1]):
        return _ps_concat(value[1:-1], env, cwd)

    if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
        return _finish_ps_path(value[1:-1], cwd), ""

    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return _ps_concat(value[1:-1], env, cwd)

    if "+" in value and _has_top_level_plus(value):
        return _ps_concat(value, env, cwd)

    return _ps_scalar(value, env, cwd)


def _has_top_level_plus(text: str) -> bool:
    depth = 0
    quote: str | None = None
    for ch in text:
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "+" and depth == 0:
            return True
    return False


def _balanced(text: str) -> bool:
    depth = 0
    quote: str | None = None
    for ch in text:
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _ps_concat(expr: str, env: dict[str, str], cwd: str) -> tuple[str | None, str]:
    """Evaluate a literal-only '+' concatenation."""
    pieces = split_top_level(expr, "+")
    if len(pieces) < 2:
        return _ps_scalar(expr.strip(), env, cwd)

    acc = ""
    for piece in pieces:
        part, note = _ps_scalar(piece, env, cwd, finish=False)
        if part is None:
            return None, note
        acc += part
    return _finish_ps_path(acc, cwd), ""


def _ps_scalar(value: str, env: dict[str, str], cwd: str, *, finish: bool = True) -> tuple[str | None, str]:
    value = value.strip()
    if not value:
        return None, "empty"

    if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
        return (value[1:-1], "") if not finish else (_finish_ps_path(value[1:-1], cwd), "")

    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return _ps_expand_string(value[1:-1], env, cwd, finish=finish)

    m = _PS_VAR.fullmatch(value)
    if m:
        key = value.lower().lstrip("$")
        if key in _PS_SAFE:
            name = key.split(":", 1)[-1].upper()
            val = env.get(name)
            if val is None:
                return None, f"{value} is not set in this environment"
            return (val, "") if not finish else (_finish_ps_path(val, cwd), "")
        return None, f"{value} is not a variable this resolver expands"

    # argument mode concatenates a variable with the literal that follows it:
    # $env:LOCALAPPDATA\pip is one argument, not a variable and a suffix
    m = _PS_VAR_PREFIX.match(value)
    if m:
        key = m.group("var").lower().lstrip("$")
        rest = m.group("rest")
        if key in _PS_SAFE and rest[:1] not in (".", "[") and "$" not in rest:
            name = key.split(":", 1)[-1].upper()
            val = env.get(name)
            if val is None:
                return None, f"{m.group('var')} is not set in this environment"
            joined = val + rest
            return (joined, "") if not finish else (_finish_ps_path(joined, cwd), "")
        if key not in _PS_SAFE:
            return None, f"{m.group('var')} is not a variable this resolver expands"

    if any(ch in value for ch in "(){}|&;"):
        return None, "contains an expression this resolver does not evaluate"

    return (value, "") if not finish else (_finish_ps_path(value, cwd), "")


def _ps_expand_string(inner: str, env: dict[str, str], cwd: str, *, finish: bool = True) -> tuple[str | None, str]:
    bad: list[str] = []

    def _sub(match: re.Match[str]) -> str:
        key = match.group(0).lower().lstrip("$")
        if key in _PS_SAFE:
            name = key.split(":", 1)[-1].upper()
            return env.get(name, "")
        bad.append(match.group(0))
        return ""

    out = _PS_VAR.sub(_sub, inner)
    if bad:
        return None, f"expandable string reads {bad[0]}"
    return (out, "") if not finish else (_finish_ps_path(out, cwd), "")


def _finish_ps_path(value: str, cwd: str) -> str:
    if "%" in value:
        value = os.path.expandvars(value)
    if not os.path.isabs(value) and not re.match(r"^[A-Za-z]:[\\/]", value):
        value = os.path.join(cwd, value)
    return os.path.normpath(value)


# --------------------------------------------------------------------------
# Destructive verb detection
# --------------------------------------------------------------------------

POSIX_VERBS = {"rm", "rmdir", "shred", "unlink", "srm"}
PS_VERBS = {"remove-item", "ri", "del", "erase", "rd", "rmdir", "clear-content", "clc"}
APP_KILL_VERBS = {"killall", "pkill", "taskkill"}

_REDIRECT = re.compile(r"(?<![0-9&])>>?\s*([^\s;|&<>]+)")


PS_SHELLS = ("powershell", "pwsh", "windows", "cmd")

# A PowerShell command reaches a POSIX terminal tool in more than one shape: a
# wrapper (`pwsh -Command '...'` or `pwsh -EncodedCommand ...`), or PS syntax
# written straight into the call. Taken at face value the shell field says
# "posix", everything parses as POSIX, and a PS delete reads as harmless.
_PS_WRAPPER = re.compile(
    r"""(?ix)^\s*(?:pwsh|powershell)(?:\.exe)?\b
        (?:\s+-(?:noprofile|noninteractive|noexit|nologo|windowstyle
                  |workingdirectory|wd|executionpolicy|ep|inputformat
                  |outputformat)\s+\S+)*
        \s+-(?P<flag>encodedcommand|enc|command|c)\s+(?P<payload>.+)$"""
)
_PS_MARKERS = re.compile(
    r"(?i)(?:\$env:|\bRemove-Item\b|\bClear-Content\b|\bCopy-Item\b|\bMove-Item\b"
    r"|\bGet-ChildItem\b|\bOut-File\b|\bSet-Content\b|\bNew-Item\b|-LiteralPath\b"
    r"|-Recurse\b|\[System\.IO)"
)


def ps_payload(command: str) -> str | None:
    """The inner script when a call just wraps PowerShell. None when it does not."""
    m = _PS_WRAPPER.match(command.strip())
    if not m:
        return None
    payload = m.group("payload").strip()
    if m.group("flag").lower() in ("enc", "encodedcommand"):
        try:
            raw = base64.b64decode(payload.strip("'\""))
            return raw.decode("utf-16-le", "replace")
        except Exception:
            return None
    if len(payload) >= 2 and payload[0] == payload[-1] and payload[0] in "'\"":
        return payload[1:-1]
    return payload


def effective_shell(command: str, shell: str = "posix") -> str:
    """The shell that will read this command, not the one the call declared."""
    if shell.lower() in PS_SHELLS:
        return shell
    if ps_payload(command) is not None or _PS_MARKERS.search(command):
        return "powershell"
    return shell


def detect(command: str, shell: str = "posix") -> list[Detected]:
    """Find destructive operations in a command. Empty list means nothing to check."""
    if shell.lower() in PS_SHELLS:
        return _detect_powershell(ps_payload(command) or command)
    return _detect_posix(command)


def _detect_posix(command: str) -> list[Detected]:
    found: list[Detected] = []

    for simple in split_simple_commands(command):
        words = split_words(simple)
        if not words:
            continue

        while words and "=" in words[0] and not words[0].startswith("-"):
            words = words[1:]
        if words and words[0] == "sudo":
            words = words[1:]
        if not words:
            continue

        verb = os.path.basename(words[0])

        if verb in POSIX_VERBS:
            targets = [w for w in words[1:] if not w.startswith("-")]
            found.append(Detected(verb, targets, "posix"))

        elif verb == "find":
            if "-delete" in words or "-exec" in words:
                roots = [w for w in words[1:] if not w.startswith("-")]
                found.append(Detected("find -delete", [roots[0] if roots else "."], "posix"))

        elif verb == "dd":
            for w in words[1:]:
                if w.startswith("of="):
                    found.append(Detected("dd", [w[3:]], "posix"))

        elif verb in APP_KILL_VERBS:
            names = [w for w in words[1:] if not w.startswith("-")]
            found.append(Detected(verb, names, "posix"))

        elif verb == "osascript":
            found.append(Detected("osascript", [" ".join(words[1:])], "posix"))

        elif verb == "git" and len(words) > 1 and words[1] == "clean":
            found.append(Detected("git clean", ["."], "posix"))

        elif verb == "truncate":
            targets = [w for w in words[1:] if not w.startswith("-")]
            found.append(Detected("truncate", targets, "posix"))

        else:
            for m in _REDIRECT.finditer(simple):
                found.append(Detected("redirect", [m.group(1)], "posix"))

    return found


def _ps_array_groups(command: str) -> list[str]:
    """Extract the body of every @( ... ) group, balanced and quote-aware."""
    groups: list[str] = []
    i = 0
    while True:
        idx = command.find("@(", i)
        if idx < 0:
            break
        j = idx + 1
        depth = 0
        quote: str | None = None
        while j < len(command):
            ch = command[j]
            if quote:
                if ch == quote:
                    quote = None
            elif ch in ("'", '"'):
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    groups.append(command[idx + 2:j])
                    break
            j += 1
        i = idx + 2
    return groups


def split_ps_words(text: str) -> list[str]:
    """Split a PowerShell argument list.

    PowerShell is not POSIX: a backslash is a path separator, not an escape, so
    'C:\\Windows\\Temp' must survive splitting intact. Quotes are kept so the
    expander can tell a literal 'string' from an expandable "string".
    """
    words: list[str] = []
    buf: list[str] = []
    quote: str | None = None

    for ch in text:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            continue
        if ch.isspace():
            if buf:
                words.append("".join(buf))
                buf = []
            continue
        buf.append(ch)

    if buf:
        words.append("".join(buf))
    return words


def _detect_powershell(command: str) -> list[Detected]:
    found: list[Detected] = []

    for body in _ps_array_groups(command):
        found.append(Detected("Remove-Item", [body], "powershell", mode="array"))

    for simple in re.split(r"[;\n]|&&|\|\|", command):
        stripped = simple.strip()
        if not stripped:
            continue
        words = split_ps_words(stripped)
        if not words:
            continue
        head = words[0].lower()

        if head in PS_VERBS:
            # An @(...) group is resolved by the array branch above; splitting it
            # into scalar words would double-count every element.
            if "@(" in stripped:
                continue
            args: list[str] = []
            for w in words[1:]:
                if w.startswith("-"):
                    continue
                args.append(w.rstrip(","))  # 'A, B' is a two-element array in argument mode
            if args:
                found.append(Detected("Remove-Item", args, "powershell"))

        for m in _REDIRECT.finditer(stripped):
            found.append(Detected("redirect", [m.group(1)], "powershell"))

    for m in re.finditer(r"-FilePath\s+(\S+)", command, re.IGNORECASE):
        found.append(Detected("Out-File", [m.group(1).strip("'\"")], "powershell"))

    return found


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

APP_STATE_HINTS = {"osascript", "applescript", "system events", "saving no", "saving yes"}


def analyze(
    command: str,
    *,
    shell: str = "posix",
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    probe_fs: bool = True,
) -> Blast | None:
    """Resolve everything a command will touch. None when nothing is destructive."""
    shell = effective_shell(command, shell)
    ops = detect(command, shell)
    if not ops:
        return None

    env = dict(env if env is not None else os.environ)
    cwd = cwd or os.getcwd()

    blast = Blast(command=command, shell=shell, verb=ops[0].verb)

    for op in ops:
        if op.verb in APP_KILL_VERBS:
            for name in op.args:
                blast.app_state.append(f"process {name}")

        if op.verb == "osascript":
            script = op.args[0] if op.args else ""
            if any(h in script.lower() for h in APP_STATE_HINTS):
                blast.app_state.append(_osascript_target(script))
            continue

        for raw in op.args:
            if op.mode == "array":
                paths, note = expand_array_literal(raw, env, cwd)
                if note:
                    blast.notes.append(note)
                for p in paths:
                    blast.targets.append(_resolve_one(p, raw, probe_fs))
            else:
                if shell.lower() in PS_SHELLS:
                    path, why = expand_ps_value(raw, env, cwd)
                else:
                    path, why = expand_posix(raw, env, cwd)
                blast.targets.append(_resolve_one(path, raw, probe_fs, why))

    blast.notes = list(dict.fromkeys(blast.notes))

    # One line per object: the same path can arrive from two expressions.
    seen: set[str] = set()
    unique: list[Target] = []
    for t in blast.targets:
        key = t.path or ("unresolved:" + t.raw)
        if key in seen:
            continue
        seen.add(key)
        unique.append(t)

    if len(unique) < len(blast.targets):
        dup_note = "%d unique path(s)" % len(unique)
        for i, note in enumerate(blast.notes):
            if note.startswith("','"):
                blast.notes[i] = "%s, %s" % (note, dup_note)
                break
        else:
            blast.notes.append(dup_note)
    blast.targets = unique

    return blast


def _resolve_one(path: str | None, raw: str, probe_fs: bool, why: str = "") -> Target:
    if path is None:
        return Target(raw=raw, unresolved=why or "unresolved")

    t = Target(raw=raw, path=path)
    try:
        st = os.lstat(path)
        t.exists = True
        t.is_dir = os.path.isdir(path) and not os.path.islink(path)
    except OSError:
        t.exists = False
        return t

    if probe_fs and t.is_dir:
        files, size, truncated = probe(path)
        t.file_count = files
        t.size_bytes = size
        t.truncated = truncated
    elif not t.is_dir:
        try:
            t.file_count = 1
            t.size_bytes = st.st_size
        except OSError:
            pass

    return t


def _osascript_target(script: str) -> str:
    m = re.search(r"tell\s+application\s+\"([^\"]+)\"", script, re.IGNORECASE)
    app = m.group(1) if m else "an application"
    return f"{app} (GUI app state)"
