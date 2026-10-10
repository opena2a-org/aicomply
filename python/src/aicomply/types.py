"""Core types for the AIComply compliance classifier (Python port).

Mirrors the TypeScript ``src/types.ts`` contract. JSON serialization uses
camelCase keys to stay wire-compatible with the npm package's ``--json`` output
(cross-language parity, per the org Registry-change-propagation discipline).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Verdict = Literal["CLEAN", "VIOLATION", "DENY"]
ClassifierName = Literal["regex", "guard"]
# A processing layer that ran on the content.
ComplyLayer = Literal["normalize", "regex", "guard"]
# 'normalized' is the canonical view; the others mirror DecodedExtraction.source.
ViolationView = Literal["normalized", "compact", "decoded-base64", "decoded-url"]


@dataclass
class Violation:
    type: str
    value: str
    start: int
    end: int
    confidence: float
    classifier: ClassifierName
    view: ViolationView | None = None
    original_start: int | None = None
    original_end: int | None = None

    def to_dict(self) -> dict:
        d: dict = {
            "type": self.type,
            "value": self.value,
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence,
            "classifier": self.classifier,
        }
        if self.view is not None:
            d["view"] = self.view
        if self.original_start is not None:
            d["originalStart"] = self.original_start
        if self.original_end is not None:
            d["originalEnd"] = self.original_end
        return d


@dataclass
class ClassifierResult:
    classifier: ClassifierName
    verdict: Verdict
    violations: list[Violation] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "classifier": self.classifier,
            "verdict": self.verdict,
            "violations": [v.to_dict() for v in self.violations],
        }


@dataclass
class NormalizationStep:
    transform: str
    count: int

    def to_dict(self) -> dict:
        return {"transform": self.transform, "count": self.count}


@dataclass
class PackIdentity:
    """The pattern pack the regex layer ran, as exported by PACK_VERSION and PACK_SHA256."""

    version: str
    sha256: str

    def to_dict(self) -> dict:
        return {"version": self.version, "sha256": self.sha256}


@dataclass
class ComplyResult:
    """Result of a ``comply()`` call: the verdict plus structured findings.

    Surfaced finding values (``Violation.value``) are masked. Note that
    ``original_content`` and ``normalized_content`` retain the **raw** input you
    passed in (they exist to map finding offsets back to the source) — so if you
    log or serialize a ``ComplyResult`` wholesale, those two fields carry the
    unmasked content. Log ``violations`` (or ``to_dict()`` selectively), not the
    whole result, when the input may contain secrets.

    ``pack`` names the pattern pack the regex layer ran. ``layers`` lists the
    layers that ran, in order; ``"guard"`` appears only when a Guard
    classification was accepted into ``classifier_results``, so a regex-only
    fallback never claims it, and the list is empty when there was no content.
    ``comply()`` always sets both.
    """

    verdict: Verdict
    violations: list[Violation]
    classifier_results: dict[str, ClassifierResult]
    original_content: str | None = None
    normalized_content: str | None = None
    normalizations: list[NormalizationStep] = field(default_factory=list)
    pack: PackIdentity | None = None
    layers: list[ComplyLayer] = field(default_factory=list)

    def to_dict(self) -> dict:
        cr: dict = {"regex": self.classifier_results["regex"].to_dict()}
        if "guard" in self.classifier_results:
            cr["guard"] = self.classifier_results["guard"].to_dict()
        d: dict = {
            "verdict": self.verdict,
            "violations": [v.to_dict() for v in self.violations],
            "classifierResults": cr,
            "normalizations": [s.to_dict() for s in self.normalizations],
        }
        if self.original_content is not None:
            d["originalContent"] = self.original_content
        if self.normalized_content is not None:
            d["normalizedContent"] = self.normalized_content
        if self.pack is not None:
            d["pack"] = self.pack.to_dict()
        d["layers"] = list(self.layers)
        return d
