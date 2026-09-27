"""Session guards.

Every route that can reach personal data goes through login_required. The staff
guard is separate because an internal report is a different privilege from an
account holder reading their own row.
"""

import logging
from functools import wraps

from flask import redirect, request, url_for
from flask import session as browser_session

from crypto_box import lookup_digest

logger = logging.getLogger("bharat_bazaar.auth")

STAFF_ROLE = "privacy_ops"
ACCOUNT_HOLDER_ROLE = "account_holder"

# The one internal login in this fixture. A deployment would read roles from a
# directory; keeping it here means the legacy report cannot be reached by an
# ordinary account even if the guard is mis-wired on a route.
STAFF_LOGIN = "privacy.ops@bharatbazaar.invalid"
STAFF_LOGIN_DIGEST = lookup_digest(STAFF_LOGIN)


def role_for_digest(stored_digest: str) -> str:
    """Map a stored lookup digest onto a role."""
    if stored_digest and stored_digest == STAFF_LOGIN_DIGEST:
        return STAFF_ROLE
    return ACCOUNT_HOLDER_ROLE


def current_principal_id() -> int | None:
    return browser_session.get("principal_id")


def current_minor_flag() -> bool:
    return bool(browser_session.get("minor_flag"))


def current_role() -> str | None:
    return browser_session.get("role")


def login_required(view):
    """Refuse an unauthenticated request before the handler body runs."""

    @wraps(view)
    def guarded(*args, **kwargs):
        if not current_principal_id():
            logger.info("unauthenticated request refused for path=%s", request.path)
            return redirect(url_for("login", next_path=request.path))
        return view(*args, **kwargs)

    return guarded


def staff_auth_required(view):
    """Second guard for internal reporting endpoints."""

    @wraps(view)
    def guarded(*args, **kwargs):
        if not current_principal_id():
            return redirect(url_for("login", next_path=request.path))
        if current_role() != STAFF_ROLE:
            return ("Not authorised for this report.", 403)
        return view(*args, **kwargs)

    return guarded
