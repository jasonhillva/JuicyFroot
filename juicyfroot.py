#!/usr/bin/env python3
"""Recursive file discovery tool.

Features:
- Scan a directory and write unique file extensions to a file.
- Query files by extension from a fresh scan.
- Export a directory tree to a text file.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Dict, Iterable, List

DEFAULT_KEYWORDS: List[str] = [
    "password",
    "passwd",
    "pwd",
    "creds",
    "credential",
    "secret",
    "token",
    "api",
    "apikey",
    "key",
    "private",
    "backup",
    "dump",
    "admin",
    "domain",
    "vpn",
    "rdp",
    "ssh",
    "service",
    "svc",
    "prod",
    "production",
    "config",
    "connection",
    "database",
    "db",
    "sql",
    "sa",
    "ldap",
    "bind",
]

DEFAULT_CATEGORIES_FILE = "extension_categories.json"

DEFAULT_EXTENSION_CATEGORY_GROUPS: Dict[str, List[str]] = {
    "Credentials / configs": [
        ".kdbx",
        ".psafe3",
        ".ini",
        ".conf",
        ".config",
        ".cfg",
        ".env",
        ".yml",
        ".yaml",
        ".json",
        ".xml",
        ".properties",
        ".cnf",
    ],
    "Scripts that may contain creds": [
        ".ps1",
        ".bat",
        ".cmd",
        ".vbs",
        ".vbe",
        ".js",
        ".py",
        ".pl",
        ".sh",
        ".sql",
    ],
    "Database / data dumps": [
        ".sql",
        ".bak",
        ".backup",
        ".dump",
        ".dmp",
        ".mdb",
        ".accdb",
        ".sqlite",
        ".sqlite3",
        ".db",
        ".db3",
    ],
    "Keys / certificates": [
        ".pem",
        ".key",
        ".pfx",
        ".p12",
        ".cer",
        ".crt",
        ".der",
        ".ppk",
        ".pub",
        ".ssh",
    ],
    "Password managers / vaults": [
        ".kdbx",
        ".kdb",
        ".1pif",
        ".opvault",
        ".enpassdb",
        ".psafe3",
    ],
    "Office docs / notes": [
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".xlsm",
        ".ppt",
        ".pptx",
        ".pdf",
        ".txt",
        ".rtf",
        ".csv",
        ".one",
    ],
    "Remote/admin tooling": [".rdp", ".vnc", ".ovpn", ".wg", ".mobileconfig", ".reg"],
    "Logs": [".log", ".evtx", ".trace", ".out", ".err"],
    "Archives": [".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2"],
}

SUMMARY_LABELS: Dict[str, str] = {
    "Credentials / configs": "credential/config",
    "Scripts that may contain creds": "script",
    "Database / data dumps": "database/dump",
    "Keys / certificates": "key/certificate",
    "Password managers / vaults": "password-vault",
    "Office docs / notes": "office-doc/note",
    "Remote/admin tooling": "remote/admin-tooling",
    "Logs": "log",
    "Archives": "archive",
}

RESET = "\033[0m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"


def build_extension_category_map(category_groups: Dict[str, List[str]]) -> Dict[str, str]:
    ext_map: Dict[str, str] = {}
    for category, extensions in category_groups.items():
        for ext in extensions:
            normalized = ext.strip().lower()
            if normalized and not normalized.startswith("."):
                normalized = f".{normalized}"
            if normalized:
                ext_map[normalized] = category
    return ext_map


def load_extension_categories(config_path: Path) -> Dict[str, str]:
    try:
        if config_path.exists():
            with config_path.open("r", encoding="utf-8-sig") as f:
                groups = json.load(f)
            if not isinstance(groups, dict):
                raise ValueError("Category config must be a JSON object.")
            return build_extension_category_map(groups)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"{YELLOW}[!]{RESET} Failed to load {config_path}: {e}. Using built-in defaults.")
    return build_extension_category_map(DEFAULT_EXTENSION_CATEGORY_GROUPS)


def normalize_extension(path: Path) -> str:
    suffix = path.suffix.lower()
    return suffix if suffix else "[no_ext]"


def safe_walk(root: Path, denied_paths: List[Path]) -> Iterable[Path]:
    stack: List[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = list(it)
        except PermissionError:
            denied_paths.append(current)
            continue
        except OSError:
            denied_paths.append(current)
            continue

        for entry in entries:
            entry_path = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                stack.append(entry_path)
            else:
                yield entry_path


def build_extension_index(root: Path, denied_paths: List[Path]) -> Dict[str, List[Path]]:
    index: Dict[str, List[Path]] = {}
    for file_path in safe_walk(root, denied_paths):
        ext = normalize_extension(file_path)
        index.setdefault(ext, []).append(file_path)

    for ext in index:
        index[ext].sort()
    return dict(sorted(index.items(), key=lambda kv: kv[0]))


def build_keyword_hits(root: Path, keywords: List[str], denied_paths: List[Path]) -> Dict[str, List[Path]]:
    hits: Dict[str, List[Path]] = {}
    normalized_keywords = [k.strip().lower() for k in keywords if k.strip()]

    for p in safe_walk(root, denied_paths):
        rel = str(p.relative_to(root)).lower()
        for keyword in normalized_keywords:
            if keyword in rel:
                hits.setdefault(keyword, []).append(p)

    for keyword in hits:
        unique_sorted = sorted(set(hits[keyword]))
        hits[keyword] = unique_sorted

    return dict(sorted(hits.items(), key=lambda kv: kv[0]))


def write_extensions(index: Dict[str, List[Path]], out_file: Path) -> None:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as f:
        for ext in index.keys():
            f.write(f"{ext}\n")


def write_extension_counts(index: Dict[str, List[Path]], out_file: Path) -> None:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as f:
        for ext, paths in index.items():
            f.write(f"{ext}\t{len(paths)}\n")


def write_categorized_extensions(
    index: Dict[str, List[Path]], extension_categories: Dict[str, str], out_file: Path
) -> None:
    grouped: Dict[str, List[str]] = {}
    for ext, paths in index.items():
        category = extension_categories.get(ext, "Uncategorized")
        grouped.setdefault(category, []).append(f"{ext}\t{len(paths)}")

    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as f:
        for category in sorted(grouped.keys()):
            f.write(f"[{category}]\n")
            for line in sorted(grouped[category]):
                f.write(f"{line}\n")
            f.write("\n")


def write_juicy_paths(
    index: Dict[str, List[Path]], extension_categories: Dict[str, str], out_file: Path
) -> None:
    grouped_paths: Dict[str, List[Path]] = {}
    for ext, paths in index.items():
        category = extension_categories.get(ext)
        if not category:
            continue
        grouped_paths.setdefault(category, []).extend(paths)

    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as f:
        if not grouped_paths:
            f.write("No categorized extension matches found.\n")
            return

        for category in sorted(grouped_paths.keys()):
            unique_sorted_paths = sorted(set(grouped_paths[category]), key=lambda p: str(p).lower())
            f.write(f"[{category}] ({len(unique_sorted_paths)})\n")
            for p in unique_sorted_paths:
                f.write(f"{p}\n")
            f.write("\n")


def print_category_summary(index: Dict[str, List[Path]], extension_categories: Dict[str, str]) -> None:
    totals: Dict[str, int] = {}
    for ext, paths in index.items():
        category = extension_categories.get(ext)
        if not category:
            continue
        totals[category] = totals.get(category, 0) + len(paths)

    for category in sorted(SUMMARY_LABELS.keys()):
        count = totals.get(category, 0)
        label = SUMMARY_LABELS[category]
        marker = f"{GREEN}[+]{RESET}" if count > 0 else f"{YELLOW}[!]{RESET}"
        print(f"{marker} Found {CYAN}{count}{RESET} {label} file(s)")


def write_keyword_hits(hits: Dict[str, List[Path]], out_file: Path) -> None:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as f:
        if not hits:
            f.write("No keyword matches found.\n")
            return
        for keyword, paths in hits.items():
            f.write(f"[{keyword}] ({len(paths)})\n")
            for p in paths:
                f.write(f"{p}\n")
            f.write("\n")


def write_permission_errors(denied_paths: List[Path], out_file: Path) -> None:
    unique_sorted = sorted(set(denied_paths), key=lambda p: str(p).lower())
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as f:
        if not unique_sorted:
            f.write("No permission errors.\n")
            return
        for p in unique_sorted:
            f.write(f"{p}\n")


def write_tree(root: Path, out_file: Path, denied_paths: List[Path]) -> None:
    out_file.parent.mkdir(parents=True, exist_ok=True)

    with out_file.open("w", encoding="utf-8") as f:
        f.write(f"{root.resolve()}\n")

        def walk(dir_path: Path, prefix: str = "") -> None:
            try:
                entries = sorted(
                    dir_path.iterdir(), key=lambda p: (p.is_file(), p.name.lower())
                )
            except PermissionError:
                denied_paths.append(dir_path)
                f.write(f"{prefix}[permission denied] {dir_path.name}\n")
                return
            except OSError:
                denied_paths.append(dir_path)
                f.write(f"{prefix}[access error] {dir_path.name}\n")
                return
            for i, entry in enumerate(entries):
                is_last = i == len(entries) - 1
                branch = "└── " if is_last else "├── "
                f.write(f"{prefix}{branch}{entry.name}\n")
                if entry.is_dir():
                    extension = "    " if is_last else "│   "
                    walk(entry, prefix + extension)

        walk(root)


def scan_command(
    root: Path,
    extensions_out: Path,
    counts_out: Path | None,
    categorized_out: Path | None,
    juicy_out: Path | None,
    keyword_out: Path | None,
    permission_errors_out: Path | None,
    keywords: List[str],
    extension_categories: Dict[str, str],
    tree_out: Path | None,
) -> None:
    denied_paths: List[Path] = []
    index = build_extension_index(root, denied_paths)
    write_extensions(index, extensions_out)
    print(f"Wrote {len(index)} unique extensions to: {extensions_out}")
    print(f"Total files scanned: {sum(len(paths) for paths in index.values())}")

    if counts_out is not None:
        write_extension_counts(index, counts_out)
        print(f"Wrote extension counts to: {counts_out}")

    if categorized_out is not None:
        write_categorized_extensions(index, extension_categories, categorized_out)
        print(f"Wrote categorized extension report to: {categorized_out}")

    if juicy_out is not None:
        write_juicy_paths(index, extension_categories, juicy_out)
        print(f"Wrote categorized file paths to: {juicy_out}")

    if keyword_out is not None:
        hits = build_keyword_hits(root, keywords, denied_paths)
        write_keyword_hits(hits, keyword_out)
        print(f"Wrote keyword hit report to: {keyword_out}")
        print(f"Keywords with matches: {len(hits)}")

    if tree_out is not None:
        write_tree(root, tree_out, denied_paths)
        print(f"Wrote directory tree to: {tree_out}")

    if permission_errors_out is not None:
        write_permission_errors(denied_paths, permission_errors_out)
        print(f"Wrote permission error paths to: {permission_errors_out}")
        print(f"Permission/access errors: {len(set(denied_paths))}")

    print_category_summary(index, extension_categories)


def list_by_extension_command(root: Path, extension: str, out_file: Path | None) -> None:
    normalized = extension.strip().lower()
    if normalized and not normalized.startswith(".") and normalized != "[no_ext]":
        normalized = f".{normalized}"

    denied_paths: List[Path] = []
    index = build_extension_index(root, denied_paths)
    matches = index.get(normalized, [])

    lines = [str(p) for p in matches]

    if out_file:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with out_file.open("w", encoding="utf-8") as f:
            for line in lines:
                f.write(f"{line}\n")
        print(f"Wrote {len(lines)} file paths for {normalized} to: {out_file}")
    else:
        print(f"Found {len(lines)} file(s) for extension: {normalized}")
        for line in lines:
            print(line)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan directories, collect unique extensions, and export tree/file lists."
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan", help="Scan recursively and write unique extensions (and optional tree)."
    )
    scan_parser.add_argument("root", type=Path, help="Root directory to scan")
    scan_parser.add_argument(
        "--extensions-out",
        type=Path,
        default=Path("extensions.txt"),
        help="Output file for unique extensions (default: extensions.txt)",
    )
    scan_parser.add_argument(
        "--tree-out",
        type=Path,
        default=Path("tree.txt"),
        help="Output file for directory tree (default: tree.txt)",
    )
    scan_parser.add_argument(
        "--counts-out",
        type=Path,
        default=Path("extension_counts.txt"),
        help="Output file for extension counts (default: extension_counts.txt)",
    )
    scan_parser.add_argument(
        "--categorized-out",
        type=Path,
        default=Path("extension_categories.txt"),
        help="Output file for categorized extension counts (default: extension_categories.txt)",
    )
    scan_parser.add_argument(
        "--juicy-out",
        type=Path,
        default=Path("juicy.txt"),
        help="Output file with categorized matched file paths (default: juicy.txt)",
    )
    scan_parser.add_argument(
        "--keyword-out",
        type=Path,
        default=Path("keyword_hits.txt"),
        help="Output file for keyword path matches (default: keyword_hits.txt)",
    )
    scan_parser.add_argument(
        "--permission-errors-out",
        type=Path,
        default=Path("permission_errors.txt"),
        help="Output file for denied/inaccessible paths (default: permission_errors.txt)",
    )
    scan_parser.add_argument(
        "--keywords",
        nargs="*",
        default=DEFAULT_KEYWORDS,
        help="Optional keyword list override (default: built-in keyword set)",
    )
    scan_parser.add_argument(
        "--categories-file",
        type=Path,
        default=Path(__file__).resolve().parent / DEFAULT_CATEGORIES_FILE,
        help="JSON file mapping categories to extension arrays",
    )

    list_parser = subparsers.add_parser(
        "list-by-ext", help="List files that match a specific extension."
    )
    list_parser.add_argument("root", type=Path, help="Root directory to scan")
    list_parser.add_argument(
        "extension",
        help="Extension to filter by (e.g. .pdf, pdf, [no_ext])",
    )
    list_parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Optional output file for matching paths",
    )

    tree_parser = subparsers.add_parser(
        "tree", help="Write directory tree to a file."
    )
    tree_parser.add_argument("root", type=Path, help="Root directory to scan")
    tree_parser.add_argument(
        "--out",
        type=Path,
        default=Path("tree.txt"),
        help="Output file for directory tree (default: tree.txt)",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = args.root.resolve()

    if not root.exists() or not root.is_dir():
        raise SystemExit(f"Root path is not a directory: {root}")

    if args.command == "scan":
        extension_categories = load_extension_categories(args.categories_file)
        scan_command(
            root,
            args.extensions_out,
            args.counts_out,
            args.categorized_out,
            args.juicy_out,
            args.keyword_out,
            args.permission_errors_out,
            args.keywords,
            extension_categories,
            args.tree_out,
        )
    elif args.command == "list-by-ext":
        list_by_extension_command(root, args.extension, args.out)
    elif args.command == "tree":
        denied_paths: List[Path] = []
        write_tree(root, args.out, denied_paths)
        print(f"Wrote directory tree to: {args.out}")


if __name__ == "__main__":
    main()
