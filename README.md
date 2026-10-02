# Advanced IPM Claude Code plugins

Plugin marketplace for Advanced IPM's Claude Code users. It is rolled out org-wide through server-managed settings, so users don't install anything themselves.

| Plugin | What it does |
|---|---|
| `aipm-compliance` | Every document, deck, PDF, spreadsheet or HTML page the AI creates carries the "CONFIDENTIAL – FOR INTERNAL USE ONLY" legend. Customer-facing material opts out. A guard blocks hand-off of unlabeled files. |

## Rollout (Owner, claude.ai → Admin Settings → Claude Code → Managed settings)

```json
{
  "extraKnownMarketplaces": {
    "aipm": { "source": { "source": "github", "repo": "Advanced-Integrated-Pest-Management/aipm-claude-plugins" } }
  },
  "enabledPlugins": { "aipm-compliance@aipm": true },
  "claudeMd": "Every Advanced IPM document, PDF, slide deck, spreadsheet or HTML page you create must follow the aipm-compliance:confidential-legend skill."
}
```

Users need `python3` on their machines, because the guard's checker uses it.

## Develop

```bash
claude plugin validate plugins/aipm-compliance
python3 plugins/aipm-compliance/bin/check_legend.py --selftest
claude --plugin-dir plugins/aipm-compliance
```
