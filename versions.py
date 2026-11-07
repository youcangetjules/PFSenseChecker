"""NetCheck release identity.

SEMVER is major.minor.patch (https://semver.org).
SEQUENCE is the commit counter. Every git commit increments it by 1.

The product changelog stays in ``pfsense_checker/version.py`` and must use
the same SEMVER. ``full_version`` is ``<SEMVER>+<SEQUENCE>``.

``hooks/pre-commit`` performs the increment. Git does not run that file
until it is installed as ``.git/hooks/pre-commit`` (see ``hooks/install``).
Do not set ``core.hooksPath``.
"""

from __future__ import annotations

SEMVER = "1.3.71"
SEQUENCE = 3
def full_version() -> str:
    return f"{SEMVER}+{SEQUENCE}"
