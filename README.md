# JuicyFroot

![juicyfroot banner](images/juicyfroot.png)


`JuicyFroot` is a Python CLI for recursive file discovery and triage.

It scans a folder tree and produces:
- Unique file extensions
- Extension counts
- Categorized high-priority extension counts
- Keyword-based path hits
- Directory tree output
- Permission-denied path log (continues scanning)

## Features

- Recursive scan of files and folders
- One-line unique extension list (one extension per line)
- Extension-to-file listing on demand
- Security-focused extension categories (credentials/configs, keys, dumps, logs, etc.)
- Keyword hit report for likely sensitive paths
- Permission-safe traversal (logs errors, keeps going)
- Colorized summary output with markers:
  - `[+]` group has matches
  - `[!]` group has no matches

## Requirements

- Python 3.9+
- No third-party dependencies

## Quick Start

```bash
python3 juicyfroot.py scan /path/to/folder
```

Windows PowerShell:

```powershell
python .\juicyfroot.py scan C:\path\to\folder
```

## Commands

### 1) Scan (all reports in one run)

```bash
python3 juicyfroot.py scan /path/to/folder \
  --extensions-out extensions.txt \
  --counts-out extension_counts.txt \
  --categorized-out extension_categories.txt \
  --keyword-out keyword_hits.txt \
  --permission-errors-out permission_errors.txt \
  --tree-out tree.txt
```

Default output files:
- `extensions.txt`
- `extension_counts.txt`
- `extension_categories.txt`
- `keyword_hits.txt`
- `permission_errors.txt`
- `tree.txt`

### 2) List files by extension

```bash
python3 juicyfroot.py list-by-ext /path/to/folder .pdf --out pdf_files.txt
```

Accepted extension formats:
- `.pdf`
- `pdf`
- `[no_ext]` (files without extension)

### 3) Tree only

```bash
python3 juicyfroot.py tree /path/to/folder --out tree.txt
```

## Keyword Scanning

Built-in default keywords:

`password, passwd, pwd, creds, credential, secret, token, api, apikey, key, private, backup, dump, admin, domain, vpn, rdp, ssh, service, svc, prod, production, config, connection, database, db, sql, sa, ldap, bind`

Override keywords:

```bash
python3 juicyfroot.py scan /path/to/folder --keywords password token ldap
```

## Output Summary

At the end of `scan`, JuicyFroot prints:
- Total files scanned
- Keyword groups matched
- Permission/access error count
- Prioritized group totals (colorized with `[+]`/`[!]`)

## Notes

- The scan is path-name based for keyword detection (file/folder names and relative paths).
- Permission errors are expected on some targets; they are logged to `permission_errors.txt` and do not stop the run.

## License

Add your preferred license (MIT recommended for public repos).



