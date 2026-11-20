"""Integrations with Python's standard library logging."""

from __future__ import annotations

import logging
from typing import Literal

from .core import Redactor

__all__ = ["RedactingFilter", "RedactingFormatter"]


class RedactingFilter(logging.Filter):
    """Logging filter that redacts secrets from record messages.

    Attach it to a handler or logger::

        handler.addFilter(RedactingFilter())
    """

    def __init__(self, redactor: Redactor | None = None, name: str = "") -> None:
        super().__init__(name)
        self.redactor = redactor or Redactor()

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        redacted = self.redactor.redact(message)
        if redacted != message:
            record.msg = redacted
            record.args = None
        return True


class RedactingFormatter(logging.Formatter):
    """Formatter that redacts secrets from the final formatted line.

    Use this when you want the whole emitted line (including exception text
    and custom fields) to be scrubbed::

        handler.setFormatter(RedactingFormatter("%(asctime)s %(message)s"))
    """

    def __init__(
        self,
        fmt: str | None = None,
        datefmt: str | None = None,
        style: Literal["%", "{", "$"] = "%",
        validate: bool = True,
        *,
        redactor: Redactor | None = None,
    ) -> None:
        super().__init__(fmt, datefmt, style, validate)
        self.redactor = redactor or Redactor()

    def format(self, record: logging.LogRecord) -> str:
        return self.redactor.redact(super().format(record))
