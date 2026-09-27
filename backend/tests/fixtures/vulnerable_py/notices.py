"""Synthetic copy deck used only as scanner input. Not production code.

Every personal-data word in this file is prose or a plain string literal. None
of it is a field, and a scanner that reports any of it is pattern matching on
text rather than reading the syntax tree.
"""

# We collect an email_address and an aadhaar_number at signup.
NOTICE_BODY = "We store your email_address and your aadhaar_number."

CONSENT_PROMPT = "phone_number"
