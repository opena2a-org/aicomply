"""Pre-regex normalization pipeline (port of normalize/index.ts).

Runs NFKC + zero-width stripping to produce a canonical normalized stream,
generates a compact (whitespace-removed) view, and extracts bounded Base64/URL
payloads. The dual-layer classifier scans all of these views.
"""

from __future__ import annotations

from .encoded import extract_encoded
from .nfkc import nfkc_stage
from .offset_map import compose_offset_maps
from .types import (
    DecodedExtraction,
    NormalizationResult,
    NormalizationStep,
    ScanExtraction,
    ScanNormalization,
)
from .whitespace import compact_stage
from .zero_width import zero_width_stage

__all__ = [
    "normalize",
    "normalize_for_scan",
    "NormalizationResult",
    "NormalizationStep",
    "DecodedExtraction",
    "ScanExtraction",
    "ScanNormalization",
]


def normalize(content: str) -> NormalizationResult:
    scan = normalize_for_scan(content)
    return NormalizationResult(
        original_content=scan.original_content,
        normalized_content=scan.normalized_content,
        offset_map=list(scan.offset_map),
        steps=scan.steps,
        decoded_extractions=[
            DecodedExtraction(
                decoded=ext.decoded,
                original_start=ext.original_start,
                original_end=ext.original_end,
                source=ext.source,
                depth=ext.depth,
                offset_map=None if ext.offset_map is None else list(ext.offset_map),
            )
            for ext in scan.decoded_extractions
        ],
    )


def normalize_for_scan(content: str) -> ScanNormalization:
    """The views normalize() returns, as the classifier scans them.

    Each offset map is an ``array('I')``, or a ``range`` where it is the
    identity: a stage allocates its map only once a character of its output
    comes from another index of its input (see ``.offset_map``).
    """
    steps: list[NormalizationStep] = []

    # Stage 1: NFKC normalization.
    nfkc = nfkc_stage(content)
    if nfkc.changed_count > 0:
        steps.append(NormalizationStep(transform="nfkc", count=nfkc.changed_count))

    # Stage 2: zero-width / bidi-control stripping.
    zw = zero_width_stage(nfkc.output)
    if zw.removed_count > 0:
        steps.append(
            NormalizationStep(transform="strip-zero-width", count=zw.removed_count)
        )

    # zw maps into nfkc.output positions; nfkc maps into the original. When
    # neither stage moved a character, the map is the identity.
    normalized_to_original = compose_offset_maps(
        zw.offset_map, nfkc.offset_map, len(zw.output)
    )

    normalized_content = zw.output
    decoded_extractions: list[ScanExtraction] = []

    # Compact form: whitespace-removed view of the normalized stream.
    compact = compact_stage(normalized_content)
    if compact.removed_count > 0 and len(compact.compact) > 0:
        steps.append(
            NormalizationStep(transform="compact-whitespace", count=compact.removed_count)
        )
        compact_to_original = compose_offset_maps(
            compact.offset_map, normalized_to_original, len(compact.compact)
        )
        compact_original_start = compact_to_original[0] if compact_to_original else 0
        compact_original_end = (
            compact_to_original[-1] if compact_to_original else len(content) - 1
        ) + 1
        decoded_extractions.append(
            ScanExtraction(
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
        decoded_extractions.append(
            ScanExtraction(
                decoded=ext.decoded,
                original_start=ext.original_start,
                original_end=ext.original_end,
                source=ext.source,
                depth=ext.depth,
                offset_map=ext.offset_map,
            )
        )
        if ext.source == "decoded-base64":
            base64_count += 1
        else:
            url_count += 1
    if base64_count > 0:
        steps.append(NormalizationStep(transform="decode-base64", count=base64_count))
    if url_count > 0:
        steps.append(NormalizationStep(transform="decode-url", count=url_count))

    return ScanNormalization(
        original_content=content,
        normalized_content=normalized_content,
        offset_map=normalized_to_original,
        steps=steps,
        decoded_extractions=decoded_extractions,
    )
