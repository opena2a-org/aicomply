"""A literal every match of a pattern must contain, found from its source.

Python's ``re`` tries a pattern that starts with ``\\b`` or a group at every
position of the input, so a rule such as ``\\b(AKIA[0-9A-Z]{16})\\b`` costs a
full pass over a 20 MB input even when the text holds no ``AKIA``. ``str in``
is far cheaper than that pass. This module reads a pattern's source for the
literals that any match has to contain, so ``scan_patterns`` can skip a pattern
whose literals are all absent from the input.

The result is conservative: it is a set of literals of which at least one is in
every match, or None when the source gives no such set. A pattern that is run
only when a literal is present gives the same matches as one that is always run.
``tests/test_prefilter.py`` checks that against the pack and the shared corpus.
"""

from __future__ import annotations

__all__ = ["required_literals"]

#: Shortest literal worth a membership test; a one-letter literal is in almost
#: any text, so the test would only add a pass.
_MIN_LENGTH = 2

_QUANTIFIERS = "?*+{"
_SPECIAL = set("\\[](){}|.^$?*+")


class _Unsupported(Exception):
    pass


def _skip_class(source: str, i: int) -> int:
    """The index after the character class that opens at ``source[i]``."""
    i += 1
    if source[i : i + 1] == "^":
        i += 1
    if source[i : i + 1] == "]":
        i += 1
    while i < len(source):
        c = source[i]
        if c == "\\":
            i += 2
            continue
        if c == "]":
            return i + 1
        i += 1
    raise _Unsupported


def _skip_quantifier(source: str, i: int) -> tuple[int, bool]:
    """The index after the quantifier at ``source[i]`` and whether it is there."""
    start = i
    while i < len(source) and source[i] in _QUANTIFIERS:
        if source[i] == "{":
            end = source.find("}", i)
            if end == -1:
                raise _Unsupported
            i = end + 1
        else:
            i += 1
    return i, i != start


def _score(literals: frozenset[str]) -> tuple[int, int]:
    return (min(len(lit) for lit in literals), -len(literals))


def _parse_alternatives(source: str, i: int) -> tuple[frozenset[str] | None, int]:
    """Literals of the alternatives that start at ``i``, up to ``)`` or the end."""
    union: set[str] = set()
    complete = True
    while True:
        best, i = _parse_sequence(source, i)
        if best is None:
            complete = False
        else:
            union |= best
        if i < len(source) and source[i] == "|":
            i += 1
            continue
        return (frozenset(union) if complete else None), i


def _parse_sequence(source: str, i: int) -> tuple[frozenset[str] | None, int]:
    """The best literal set of one alternative, and the index of its ``|``, ``)`` or end."""
    pieces: list[frozenset[str]] = []
    run: list[str] = []

    def close_run() -> None:
        if run:
            pieces.append(frozenset(["".join(run)]))
            run.clear()

    n = len(source)
    while i < n:
        c = source[i]
        if c in "|)":
            break
        if c == "\\":
            close_run()
            i += 2
        elif c == "[":
            close_run()
            i = _skip_class(source, i)
        elif c == "(":
            close_run()
            i += 1
            if source[i : i + 1] == "?":
                if source[i : i + 2] != "?:":
                    raise _Unsupported
                i += 2
            inner, i = _parse_alternatives(source, i)
            if i >= n or source[i] != ")":
                raise _Unsupported
            i += 1
            end, quantified = _skip_quantifier(source, i)
            # A group that may be absent is not required; one at least once is.
            if inner is not None and not (quantified and source[i] in "?*{"):
                pieces.append(inner)
            i = end
        elif c in _QUANTIFIERS:
            # It binds the last character of the run, which is then optional.
            if run:
                run.pop()
            close_run()
            i, _ = _skip_quantifier(source, i)
        elif c in _SPECIAL or c.isspace() or not c.isascii() or not c.isprintable():
            close_run()
            i += 1
        else:
            run.append(c)
            i += 1
    close_run()
    if not pieces:
        return None, i
    return max(pieces, key=_score), i


def required_literals(source: str, ignore_case: bool) -> tuple[str, ...] | None:
    """Literals of which every match of ``source`` contains at least one.

    With ``ignore_case`` they are lower case, to be looked for in the input
    lowered; otherwise they are as the source spells them. None when the source
    gives no literal worth testing for.
    """
    try:
        found, end = _parse_alternatives(source, 0)
    except (_Unsupported, IndexError):
        return None
    if found is None or end != len(source):
        return None
    if ignore_case:
        found = frozenset(lit.lower() for lit in found)
    if min(len(lit) for lit in found) < _MIN_LENGTH:
        return None
    return tuple(sorted(found))
