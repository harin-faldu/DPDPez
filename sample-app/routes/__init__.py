"""Blueprints for the demo storefront.

WARNING: intentionally vulnerable demo fixture. Do not run on a public host.
See README.md.

This module holds only the shared session guard. Blueprints are imported
directly from their own modules by app.py so that the package import stays
free of cycles.
"""

from functools import wraps

from flask import redirect, session, url_for


def require_session(view):
    """Redirect to signup unless a session has been established.

    NEGATIVE CONTROL: one guarded route exists, so the scanner can show the
    difference between a route with an auth decorator and the PII endpoint in
    routes/account.py that has none.
    """

    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("signup.signup_form"))
        return view(*args, **kwargs)

    return wrapper
