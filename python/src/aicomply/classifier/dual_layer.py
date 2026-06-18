"""Dual-layer classifier merge logic (port of classifier/dual-layer/index.ts).

Both the regex classifier and the Guard classifier must return CLEAN for content
to pass. If either flags a violation -> VIOLATION. If either returns DENY -> DENY
(highest severity wins).

Scope note ([CHIEF-CDS] 2026-06-18): this Python port covers the deterministic
detection layer (regex + normalization views + Guard merge + verdict). The TS-only
Registry-L2 / ARP-signature / policy-pack / session-vault layers are out of port
v1 scope - they carry no bench/corpus coverage and porting the crypto/registry
code before core parity is proven would be premature. ``comply`` therefore takes
no policy/registry args; those can be added later in lockstep with the TS side.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..normalize import NormalizationResult, normalize
from ..types import ClassifierResult, ComplyResult, NormalizationStep, Verdict, Violation
from .guard_client.nanomind_adapter import (
    NanoMindAdapterOptions,
    classify_with_nanomind_daemon,
)
from .regex import ScanViewOptions, classify_with_regex


@dataclass
class DualLayerOptions:
    use_guard: bool = True
    guard_options: NanoMindAdapterOptions | None = None


def _merge_verdicts(regex: ClassifierResult, guard: ClassifierResult | None) -> Verdict:
    verdicts = [regex.verdict]
    if guard is not None:
        verdicts.append(guard.verdict)
    if "DENY" in verdicts:
        return "DENY"
    if "VIOLATION" in verdicts:
        return "VIOLATION"
    return "CLEAN"


def _scan_all_views(norm: NormalizationResult) -> ClassifierResult:
    """Run the regex classifier across every content view, deduping by origin range."""
    normalized_scan = classify_with_regex(
        norm.normalized_content,
        ScanViewOptions(view="normalized", offset_map=norm.offset_map),
    )

    all_violations: list[Violation] = list(normalized_scan.violations)
    seen: set[str] = set()
    for v in all_violations:
        seen.add(f"{v.type}@{v.original_start}-{v.original_end}")

    for ext in norm.decoded_extractions:
        if ext.offset_map is not None:
            scan = classify_with_regex(
                ext.decoded, ScanViewOptions(view=ext.source, offset_map=ext.offset_map)
            )
        else:
            scan = classify_with_regex(
                ext.decoded,
                ScanViewOptions(
                    view=ext.source,
                    original_anchor=(ext.original_start, ext.original_end),
                ),
            )
        has_offset_map = ext.offset_map is not None
        for v in scan.violations:
            if has_offset_map:
                key = f"{v.type}@{v.original_start}-{v.original_end}"
            else:
                key = (
                    f"{v.type}@{v.original_start}-{v.original_end}"
                    f"#{v.view}:{v.start}-{v.end}"
                )
            if key in seen:
                continue
            seen.add(key)
            all_violations.append(v)

    return ClassifierResult(
        classifier="regex",
        verdict="CLEAN" if len(all_violations) == 0 else "VIOLATION",
        violations=all_violations,
    )


def classify_dual_layer(
    content: str, options: DualLayerOptions | None = None
) -> ComplyResult:
    opts = options or DualLayerOptions()

    # Pre-regex adversarial normalization (NFKC + zero-width strip produce the
    # normalized stream; compact form and any Base64/URL-decoded segments are
    # scanned in addition).
    norm = normalize(content)
    regex_result = _scan_all_views(norm)

    guard_result: ClassifierResult | None = None
    if opts.use_guard:
        guard_result = classify_with_nanomind_daemon(content, opts.guard_options)

    all_violations: list[Violation] = list(regex_result.violations)
    if guard_result is not None:
        all_violations.extend(guard_result.violations)

    classifier_results: dict[str, ClassifierResult] = {"regex": regex_result}
    if guard_result is not None:
        classifier_results["guard"] = guard_result

    verdict = _merge_verdicts(regex_result, guard_result)

    result = ComplyResult(
        verdict=verdict,
        violations=all_violations,
        classifier_results=classifier_results,
    )

    # Attach normalization audit metadata. On a DENY verdict we omit
    # original/normalized content (it has been flagged as harmful and may carry
    # attacker-controlled bytes); the structured step counts are always safe.
    steps: list[NormalizationStep] = [
        NormalizationStep(transform=s.transform, count=s.count) for s in norm.steps
    ]
    if verdict != "DENY":
        result.original_content = norm.original_content
        result.normalized_content = norm.normalized_content
    result.normalizations = steps

    return result
