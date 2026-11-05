"""Closes open request issues whose classes and symbols are all available in LeviLamina.

Usage: close_implemented.py <LeviLamina checkout>
Needs the gh CLI authenticated with permission to close issues in GITHUB_REPOSITORY.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from check_request import PLATFORMS, HeaderIndex, build_index, check_class, check_symbol, field_lines, parse_issue


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def main() -> int:
    root = Path(sys.argv[1])
    repo = os.environ["GITHUB_REPOSITORY"]
    commit = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    issues = json.loads(gh("issue", "list", "--repo", repo, "--state", "open", "--limit", "1000", "--json", "number,body"))
    indexes: dict[str, HeaderIndex] = {}

    for issue in issues:
        fields = parse_issue(issue["body"] or "")
        if not PLATFORMS.get(fields.get("Platform", "")):
            continue
        items = [("Classes", line) for line in field_lines(fields.get("Classes", ""))]
        items += [("Symbols", line) for line in field_lines(fields.get("Symbols", ""))]
        if not items:
            continue
        platform = fields["Platform"]
        if platform not in indexes:
            indexes[platform] = build_index(root, platform)
        index = indexes[platform]

        done = []
        for kind, line in items:
            problem = check_class(line, index) if kind == "Classes" else check_symbol(line, index)
            if problem is None or not problem.implemented:
                break
            done.append(f"- {problem.message}")
        else:
            body = (
                f"### ✅ All requested items are now available in LeviLamina "
                f"([`{commit[:7]}`](https://github.com/LiteLDev/LeviLamina/commit/{commit}))\n\n" + "\n".join(done) + "\n"
            )
            num = str(issue["number"])
            gh("issue", "comment", num, "--repo", repo, "--body", body)
            gh("issue", "close", num, "--repo", repo, "--reason", "completed")
            print(f"Closed #{num}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
