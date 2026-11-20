"""Runnable demo of VaultScrub's main features.

Run with: python examples/demo.py

Note: this file intentionally contains fake secrets to demonstrate
redaction. It is excluded from the project's own secret scanning.
"""

import logging

from vaultscrub import RedactingFilter, Redactor, redact

TEXT = """\
2026-11-20 INFO starting worker
2026-11-20 INFO using key AKIAIOSFODNN7EXAMPLE for storage
2026-11-20 INFO contact admin@example.org for help
2026-11-20 INFO card charged 4242 4242 4242 4242
"""


def main() -> None:
    print("=== redact() ===")
    print(redact(TEXT))

    print("=== logging integration ===")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    logger = logging.getLogger("demo")
    logger.addFilter(RedactingFilter())
    logger.info("storage key AKIAIOSFODNN7EXAMPLE is active")

    print("=== custom Redactor ===")
    redactor = Redactor(replacement="[hidden]")
    print(redactor.redact("token ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s"))


if __name__ == "__main__":
    main()
