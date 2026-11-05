---
name: blast-radius
description: Check what a destructive command will actually touch before proposing it. Use before any rm, find -delete, truncate, dd, redirect, git clean, Remove-Item or osascript command, and whenever a delete target is built from a variable, a glob, or a quoted path.
---

# Blast radius

A command's text and a shell's evaluation of that text are different objects.
Approving the first while executing the second is how an agent deletes 188,303
files by asking to clear a cache.

## Before you propose a destructive command

Run `custody_explain` on the exact command you intend to run, not a paraphrase:

```
custody_explain(command="rm -rf $BUILD_DIR/*")
```

Read the report. Every target comes back with one of these marks:

| Mark | Meaning | What to do |
| --- | --- | --- |
| `+` | Created by this session | Safe to proceed |
| `~` | Existed, modified by this session | Proceed, mention it |
| `!` | Mixed: session files and pre-existing files | Say so before acting |
| `X` | Protected root, or a GUI app's state | Ask first, explicitly |
| `?` | Could not resolve | Do not run it; ask |

If the report shows `X` or `?`, do not run the command. Show the person the
report and ask. Do not rephrase the command to get past the gate.

## Rules that prevent most incidents

1. **Never build a delete target out of a variable you did not set.** `$env:TEMP`,
   `$BUILD_DIR`, `%APPDATA%` are claims about an environment, not paths.
2. **In PowerShell, `,` binds tighter than `+`.** `@('a', $env:X + '\b')` is three
   elements, not two. Parenthesise: `@('a', ($env:X + '\b'))`.
3. **Quote nothing to yourself.** A quoted path in a script is still expanded by
   the shell that runs it.
4. **`osascript`, `killall` and `pkill` reach state your filesystem tools cannot
   see.** A GUI app can hold unsaved documents that closing destroys.
5. **Delete the directory you created, not the directory it lives in.**

## When a delete is refused

Say what was refused and why, in the terms the report used. Do not retry with a
different spelling of the same path. If the person wants it gone, they will
approve it at the gate.
