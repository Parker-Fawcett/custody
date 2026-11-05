# Custody

**The agent may only destroy what it made.**

Custody resolves what a destructive terminal command will actually touch, checks
each target against what this session created, and sends anything else to your
approval gate with the real numbers attached.

Hermes approves the description of a command. The shell executes its semantics.
Custody computes the semantics first.

```
CUSTODY  7 targets, 4 outside this session

  X  C:\Windows\Temp                       the Windows directory
  X  ~/AppData/Local/Temp                  a local profile root
  X  ~/AppData/Local                       a local profile root
  .  ~/work/app/\pip\cache                 nothing at this path
  X  ~/AppData/Roaming                     a roaming profile root

  8,264 files, 2.2 MiB. No snapshot is taken before this runs.
  Why: ',' binds tighter than '+': 5 written path(s) became 8 array element(s)

  Approving deletes inside a local profile root, which this session did not create.
```

## Why this exists

Two open incidents in `NousResearch/hermes-agent`, both caused by smart approval
reading a command as text while the shell ran it as an expression:

- **#147373** — a PowerShell cache cleanup. `,` binds tighter than `+`, so five
  written paths became eight array elements, three of them profile roots. 188,303
  delete records, 21.4 GiB, the user's Python install gone, no snapshot.
- **#141346** — an agent drove PowerPoint through `osascript` to render a deck.
  `close active presentation saving no` closed the user's own unsaved deck and
  wiped AutoRecovery.

Neither is a bypass. In both, approval behaved as implemented. The reviewer was
never told what the command would touch.

## What it does

1. **Detects** the destructive operations in a `terminal` call: `rm`, `rmdir`,
   `shred`, `find -delete`, `truncate`, `dd`, redirects, `git clean`,
   `Remove-Item`, `osascript`, `killall` / `pkill` / `taskkill`.
2. **Resolves** each target expression to concrete paths. Tilde, allowlisted
   variables, quoting, and PowerShell array precedence are modelled. Globs,
   command substitution and unknown variables resolve to *unknown*, which
   escalates. The command is never executed.
3. **Attributes** each path using a session ledger: files the agent wrote, plus a
   baseline snapshot of the working tree taken at session start. Anything that
   predates the session is the user's.
4. **Escalates** user-owned and protected targets to the human approval gate, and
   blocks GUI-app state outright.

## Install

```
hermes plugins install <owner>/custody
hermes plugins enable custody
```

Or from a local checkout:

```
hermes plugins validate ./custody --install-deps
hermes plugins doctor ./custody --ci
```

## Configuration

Declared in `plugin.yaml`, editable from **Settings → Plugins** in the desktop app.

| Key | Default | Meaning |
| --- | --- | --- |
| `mode` | `enforce` | `observe` records the same analysis without interrupting |
| `extra_protected` | `[]` | Extra absolute paths to treat as protected |

## Tools and commands

| Surface | What it does |
| --- | --- |
| `custody_explain` | Resolve a command to its targets without running it |
| `custody_ledger` | What this session created, what was allowed, what was stopped |
| `/custody` | The same ledger, in the session |

Bundled skill: `custody:blast-radius`, a pre-flight checklist the agent can load.

## What it will not do

- It never runs the command it inspects.
- It never approves anything on your behalf. It only adds a human step.
- It does not patch, wrap or rebind Hermes internals. Public hooks and
  `register_tool` only.

## Disclosure

What a reviewer or user should know before installing:

- **Filesystem reads outside the plugin's data directory.** Custody stats paths
  and counts directory entries to produce file and byte totals. Reads are
  metadata only (`os.scandir`, `os.stat`); file contents are never opened.
  Traversal is bounded per target (120,000 entries, depth 8) and skips
  `node_modules`, `.git`, virtualenvs and build output.
- **Local storage.** The session ledger, baseline snapshot and a decision log
  (command text, verb, verdict, counts) are written to a SQLite database under
  the profile's plugin data directory (`<HERMES_HOME>/plugin-data/custody/`).
  Command text is stored because `/custody` exists to answer "what did this
  session delete". Nothing is uploaded.
- **Network.** None. The plugin makes no network calls and has no dependencies.
- **Shell execution.** None. Commands are parsed, never spawned.
- **Processes and credentials.** No background processes, no credential reads, no
  environment access beyond `HOME`, `TMPDIR`, `TEMP`, `APPDATA`, `LOCALAPPDATA`,
  `USERPROFILE` and `WINDIR`, which are needed to expand paths.

## Limitations

Custody covers commands it can resolve. A command that shells out to a program
which deletes files internally (`npm cache clean`, a build script) is invisible to
it. It is a guard on the `terminal` tool, not a filesystem sandbox.

Unresolvable targets escalate rather than block, so a false positive costs one
approval prompt, never a wedged session.

## License

MIT
