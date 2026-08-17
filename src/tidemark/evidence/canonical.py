"""One canonical JSON encoding shared by persisted and published evidence."""

import json


def canonical_json_text(value: object, *, trailing_newline: bool = False) -> str:
    """Encode with the repository's exact ASCII, ordering, and spacing rules."""

    if type(trailing_newline) is not bool:
        raise TypeError("trailing_newline requires bool")
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return encoded + ("\n" if trailing_newline else "")


def canonical_json_bytes(value: object, *, trailing_newline: bool = False) -> bytes:
    return canonical_json_text(
        value, trailing_newline=trailing_newline
    ).encode("utf-8")


__all__ = ("canonical_json_bytes", "canonical_json_text")
