"""Tidy symbols."""

import json
from typing import Dict, Iterable, List

ISSUE_PARSER_RESULT_FILE_PATH = "issue-parser-result.json"
SYMBOLS_FILE_PATH = "symbols.txt"
FILTERED_SYMBOLS = {"```", "```text"}


def tidy_items(items: Iterable[str]) -> List[str]:
    """Tidies a collection of items.

    Args:
        items: Collection of items to tidy.

    Returns:
        List of tidied items.
    """
    items = [item.strip() for item in items]
    items = [item for item in items if item and item not in FILTERED_SYMBOLS]
    items = sorted(set(items))
    return items


def main() -> None:
    """Main function."""

    with open(ISSUE_PARSER_RESULT_FILE_PATH, "r", encoding="utf-8") as f:
        issue_parser_result: Dict[str, str] = json.load(f)

    new_symbols_text = issue_parser_result.get("symbols", "")

    new_symbols = new_symbols_text.split()

    with open(SYMBOLS_FILE_PATH, "r", encoding="utf-8") as f:
        symbols = f.read().split()

    symbols.extend(new_symbols)

    symbols = tidy_items(symbols)

    with open(SYMBOLS_FILE_PATH, "w", encoding="utf-8") as f:
        for symbol in symbols:
            f.write(f"{symbol}\n")


if __name__ == "__main__":
    main()
