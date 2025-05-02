"""Tidy symbols."""

from typing import Iterable, List

SYMBOLS_FILE_PATH = "symbols.txt"


def tidy_items(items: Iterable[str]) -> List[str]:
    """Tidies a collection of items.

    Args:
        lines: Collection of items to tidy.

    Returns:
        List of tidied items.
    """

    items = [item.strip() for item in items]

    items = [item for item in items if item]

    items = sorted(set(items))

    return items


def main() -> None:
    """Main function."""

    with open(SYMBOLS_FILE_PATH, "r", encoding="utf-8") as f:
        symbols = f.read().splitlines()

    symbols = tidy_items(symbols)

    with open(SYMBOLS_FILE_PATH, "w", encoding="utf-8") as f:
        for symbol in symbols:
            f.write(f"{symbol}\n")


if __name__ == "__main__":
    main()
