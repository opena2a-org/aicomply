"""Types for the pre-regex normalization layer (Python port of normalize/types.ts).

Normalization is additive and non-destructive: the original content is always
preserved alongside the canonical form. Offsets in this Python port are
*code-point* based (Python's native string indexing and ``re`` match positions),
whereas the TS implementation uses UTF-16 code-unit offsets. This is a benign
difference: the parity gate measures detected *types*, not offsets, and
code-point offsets are internally consistent with Python's ``re`` engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

NormalizationTransform = Literal[
    "nfkc", "strip-zero-width", "compact-whitespace", "decode-base64", "decode-url"
]
DecodedSource = Literal["compact", "decoded-base64", "decoded-url"]


@dataclass
class NormalizationStep:
    transform: NormalizationTransform
    count: int


@dataclass
class DecodedExtraction:
    decoded: str
    original_start: int
    original_end: int
    source: DecodedSource
    depth: int
    offset_map: list[int] | None = None


@dataclass
class NormalizationResult:
    original_content: str
    normalized_content: str
    offset_map: list[int]
    steps: list[NormalizationStep] = field(default_factory=list)
    decoded_extractions: list[DecodedExtraction] = field(default_factory=list)
