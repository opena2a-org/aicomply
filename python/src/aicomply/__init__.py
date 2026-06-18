"""aicomply -- dual-layer compliance classifier for AI agent I/O (Python port).

Public API: ``comply()`` is the main entry point. Pass content and get back a
verdict with violations.

    from aicomply import comply

    result = comply("My SSN is 516-81-3086")
    if result.verdict != "CLEAN":
        ...  # block, redact, or log before this reaches an LLM
"""

from __future__ import annotations

from .classifier.dual_layer import DualLayerOptions, classify_dual_layer
from .classifier.guard_client import (
    DEFAULT_NANOMIND_DAEMON_URL,
    NanoMindAdapterOptions,
    classify_with_nanomind_daemon,
    is_nanomind_daemon_available,
)
from .classifier.regex import classify_with_regex, luhn_check, scan_patterns
from .normalize import normalize
from .types import (
    ClassifierResult,
    ComplyResult,
    NormalizationStep,
    Verdict,
    Violation,
    ViolationView,
)

__version__ = "0.2.0"

__all__ = [
    "comply",
    "ComplyResult",
    "Violation",
    "ClassifierResult",
    "Verdict",
    "ViolationView",
    "NormalizationStep",
    "DualLayerOptions",
    "normalize",
    "classify_with_regex",
    "classify_dual_layer",
    "scan_patterns",
    "luhn_check",
    "classify_with_nanomind_daemon",
    "is_nanomind_daemon_available",
    "NanoMindAdapterOptions",
    "DEFAULT_NANOMIND_DAEMON_URL",
    "guard_io",
    "guard_output",
    "ComplianceViolation",
    "__version__",
]


def comply(
    content: str,
    *,
    use_guard: bool = True,
    guard_options: NanoMindAdapterOptions | None = None,
) -> ComplyResult:
    """Run compliance classification on ``content``.

    Runs the dual-layer classifier (deterministic regex over normalized +
    decoded views, plus an optional semantic Guard when a local nanomind-daemon
    is reachable) and returns a verdict.

    :param content: The text to classify. Must be a ``str``. Empty string
        short-circuits to a CLEAN result with populated audit fields.
    :param use_guard: When True (default) attempt the Guard daemon, silently
        falling back to regex-only if it is unreachable.
    :param guard_options: Optional daemon connection overrides.
    :raises TypeError: if ``content`` is not a ``str``.
    """
    if not isinstance(content, str):
        raise TypeError(f"comply: content must be a string (got {type(content).__name__})")

    if not content:
        # Empty content: populate audit fields per the ComplyResult contract.
        return ComplyResult(
            verdict="CLEAN",
            violations=[],
            classifier_results={
                "regex": ClassifierResult(classifier="regex", verdict="CLEAN", violations=[])
            },
            original_content="",
            normalized_content="",
            normalizations=[],
        )

    return classify_dual_layer(
        content, DualLayerOptions(use_guard=use_guard, guard_options=guard_options)
    )


# Re-export the framework decorators at the top level so they are discoverable
# as `from aicomply import guard_io, guard_output` (matching how the package is
# advertised). Imported here, after `comply` is defined, because the decorator
# module imports `comply` from this package — a top-of-file import would be a
# circular import. `aicomply.integrations.decorator` pulls in no optional deps
# (the LangChain integration is imported separately and stays optional).
from .integrations import ComplianceViolation, guard_io, guard_output  # noqa: E402
