"""Offset maps of the normalization stages (port of normalize/offset-map.ts).

Entry i of a stage's map is the index in the stage's input that character i
of its output came from. A map is held as an ``array('I')``, four bytes an
entry, and as a ``range`` where it is the identity, so a stage that leaves
every character at its own index allocates no map. A ``list[int]`` of the
same entries, such as ``normalize()`` returns, is ``list(offset_map)``.
"""

from __future__ import annotations

from array import array
from collections.abc import Sequence
from itertools import repeat

#: A stage's offset map: a ``range`` when it is the identity, else an ``array('I')``.
OffsetMap = Sequence[int]


class OffsetMapBuilder:
    """Builds the map of a stage as the stage appends to its output.

    Storage is allocated at the first character that did not come from its
    own index; until then the map is the identity.
    """

    __slots__ = ("_map", "_length")

    def __init__(self) -> None:
        self._map: array[int] | None = None
        self._length = 0

    def copy(self, start: int, count: int) -> None:
        """Appends ``count`` characters that came from input[start], input[start + 1] and so on."""
        if count == 0:
            return
        if self._map is None and start == self._length:
            self._length += count
            return
        self._storage().extend(range(start, start + count))
        self._length += count

    def repeat(self, start: int, count: int) -> None:
        """Appends ``count`` characters that all came from input[start]."""
        if count <= 1:
            self.copy(start, count)
            return
        self._storage().extend(repeat(start, count))
        self._length += count

    def finish(self) -> OffsetMap:
        """The map: a ``range`` when it is the identity, else the ``array('I')``."""
        return range(self._length) if self._map is None else self._map

    def _storage(self) -> array[int]:
        if self._map is None:
            self._map = array("I", range(self._length))
        return self._map


def compose_offset_maps(outer: OffsetMap, inner: OffsetMap, length: int) -> OffsetMap:
    """The map from ``outer``'s output, of ``length`` characters, to ``inner``'s input.

    Entry i is ``inner[outer[i]]``: ``outer`` maps into ``inner``'s output, so
    each of its entries is an index into ``inner``. An identity ``outer`` can
    be shorter than ``inner``, when its stage removed only characters at the end.
    """
    if isinstance(inner, range):
        return outer
    if isinstance(outer, range):
        return inner if len(inner) == length else inner[:length]
    return array("I", map(inner.__getitem__, outer))
