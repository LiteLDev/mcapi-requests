"""Tidy symbols."""

import json
from typing import Dict, Iterable, List

ISSUE_PARSER_RESULT_FILE_PATH = "issue-parser-result.json"
SYMBOLS_FILE_PATH = "symbols.txt"
FILTERED_SYMBOLS = {"```", "```text"}
IMPORT_PREFIX = "__imp_"


def tidy_items(items: Iterable[str]) -> List[str]:
    """Tidies a collection of items.

    Args:
        items: Collection of items to tidy.

    Returns:
        List of tidied items.
    """
    cleaned_items = []
    for item in items:
        item = item.strip()
        if not item or item in FILTERED_SYMBOLS:
            continue
        
        # Remove __imp_ prefix if present
        if item.startswith(IMPORT_PREFIX):
            item = item[len(IMPORT_PREFIX):]
        
        cleaned_items.append(item)
    
    return sorted(set(cleaned_items))


def main() -> None:
    """Main function."""

    with open(ISSUE_PARSER_RESULT_FILE_PATH, "r", encoding="utf-8") as f:
        issue_parser_result: Dict[str, str] = json.load(f)

    new_symbols_text = issue_parser_result.get("symbols", "")

    new_symbols = new_symbols_text.splitlines()

    with open(SYMBOLS_FILE_PATH, "r", encoding="utf-8") as f:
        symbols = [line.strip() for line in f.readlines()]

    symbols.extend(new_symbols)

    symbols = tidy_items(symbols)

    with open(SYMBOLS_FILE_PATH, "w", encoding="utf-8") as f:
        for symbol in symbols:
            f.write(f"{symbol}\n")


if __name__ == "__main__":
    main()
