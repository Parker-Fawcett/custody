"""Tool schemas: what the model reads."""

CUSTODY_EXPLAIN = {
    "name": "custody_explain",
    "description": (
        "Resolve a destructive shell command to the exact filesystem targets it "
        "would delete, overwrite or truncate, WITHOUT running it. Returns each "
        "resolved path, its file count, and whether this session created it. "
        "Use this before proposing any rm, find -delete, truncate, dd, redirect, "
        "git clean, Remove-Item or osascript command that a person will approve, "
        "and whenever you are unsure which files a command actually reaches."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "The shell command to resolve, exactly as it would run.",
            },
            "shell": {
                "type": "string",
                "description": "posix (default) or powershell. Affects expansion rules.",
                "enum": ["posix", "powershell"],
            },
        },
        "required": ["command"],
    },
}

CUSTODY_LEDGER = {
    "name": "custody_ledger",
    "description": (
        "Report what this session has created, what custody allowed, and what it "
        "stopped at the approval gate. Use when the user asks what you changed, "
        "what you deleted, or whether something you removed was yours to remove."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "How many recent decisions to return. Default 10.",
            },
        },
    },
}
