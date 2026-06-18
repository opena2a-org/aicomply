"""Framework ergonomics for Python agent developers.

* ``decorator`` -- a ``@guard_output`` / ``@guard_io`` decorator to wrap an
  agent function's I/O (mirrors the AIM Python SDK decorator pattern).
* ``langchain`` -- a callback handler that blocks PII egress in a LangChain
  agent (lazy-imports langchain so it stays an optional dependency).
"""

from .decorator import ComplianceViolation, guard_io, guard_output

__all__ = ["guard_output", "guard_io", "ComplianceViolation"]
