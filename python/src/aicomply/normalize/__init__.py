"""Pre-regex normalization pipeline (port of normalize/index.ts).

Runs NFKC + zero-width stripping to produce a canonical normalized stream,
generates a compact (whitespace-removed) view, and extracts bounded Base64/URL
payloads. The dual-layer classifier scans all of these views.
"""

from __future__ import annotations

from .encoded import extract_encoded
from .nfkc import normalize_nfkc
from .types import (
    DecodedExtraction,
    NormalizationResult,
    NormalizationStep,
)
from .whitespace import build_compact_form
from .zero_width import strip_zero_width

__all__ = [
    "normalize",
    "NormalizationResult",
    "NormalizationStep",
    "DecodedExtraction",
]


def _compose_offset_maps(outer: list[int], inner: list[int]) -> list[int]:
    """Compose outer (stage-N -> stage-N-1) with inner (stage-N-1 -> original)."""
    last = inner[-1] if inner else 0
    return [inner[mid] if mid < len(inner) else last for mid in outer]


def _identity_map(length: int) -> list[int]:
    return list(range(length))


def normalize(content: str) -> NormalizationResult:
    steps: list[NormalizationStep] = []

    # Stage 1: NFKC normalization.
    nfkc = normalize_nfkc(content)
    if nfkc.changed_count > 0:
        steps.append(NormalizationStep(transform="nfkc", count=nfkc.changed_count))

    # Stage 2: zero-width / bidi-control stripping.
    zw = strip_zero_width(nfkc.output)
    if zw.removed_count > 0:
        steps.append(
            NormalizationStep(transform="strip-zero-width", count=zw.removed_count)
        )

    if nfkc.changed_count == 0 and zw.removed_count == 0:
        normalized_to_original = _identity_map(len(content))
    else:
        normalized_to_original = _compose_offset_maps(zw.offset_map, nfkc.offset_map)

    normalized_content = zw.output
    decoded_extractions: list[DecodedExtraction] = []

    # Compact form: whitespace-removed view of the normalized stream.
    compact = build_compact_form(normalized_content)
    if compact.removed_count > 0 and len(compact.compact) > 0:
        steps.append(
            NormalizationStep(transform="compact-whitespace", count=compact.removed_count)
        )
        compact_to_original = [
            normalized_to_original[norm_idx]
            if norm_idx < len(normalized_to_original)
            else norm_idx
            for norm_idx in compact.offset_map
        ]
        compact_original_start = compact_to_original[0] if compact_to_original else 0
        compact_original_end = (
            compact_to_original[-1] if compact_to_original else len(content) - 1
        ) + 1
        decoded_extractions.append(
            DecodedExtraction(
                decoded=compact.compact,
                original_start=compact_original_start,
                original_end=min(compact_original_end, len(content)),
                source="compact",
                depth=1,
                offset_map=compact_to_original,
            )
        )

    # Base64 / URL decoded payloads from the original input.
    encoded = extract_encoded(content)
    base64_count = 0
    url_count = 0
    for ext in encoded:
        decoded_extractions.append(ext)
        if ext.source == "decoded-base64":
            base64_count += 1
        else:
            url_count += 1
    if base64_count > 0:
        steps.append(NormalizationStep(transform="decode-base64", count=base64_count))
    if url_count > 0:
        steps.append(NormalizationStep(transform="decode-url", count=url_count))

    return NormalizationResult(
        original_content=content,
        normalized_content=normalized_content,
        offset_map=normalized_to_original,
        steps=steps,
        decoded_extractions=decoded_extractions,
    )
