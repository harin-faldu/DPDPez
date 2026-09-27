"""Synthetic outbound integration used only as scanner input. Not production code."""

import requests

PARTNER_ENDPOINT = "https://partner.example.invalid/v1/leads"


def forward_to_partner(email_address: str, phone_number: str) -> None:
    requests.post(
        PARTNER_ENDPOINT,
        json={"email_address": email_address, "phone_number": phone_number},
        timeout=5,
    )
