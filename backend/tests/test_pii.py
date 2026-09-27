"""Tests for the PII detection module.

Every identity number here is synthetic. Aadhaar and card samples are generated
by the checksum routines under test, and the PAN inside them uses a fourth
character that is not an allottable holder-type code, so none of these strings
can belong to a person.
"""

import pytest

from app.contracts import PIIFieldRef
from app.pii import taxonomy
from app.pii.field_classifier import build_field_ref, classify, normalise
from app.pii.indian_ids import (
    VALIDATORS,
    gstin_check_char,
    is_valid_aadhaar,
    is_valid_card_number,
    is_valid_gstin,
    is_valid_ifsc,
    is_valid_pan,
    is_valid_passport,
    is_valid_voter_id,
    luhn_check_digit,
    verhoeff_checksum,
    verhoeff_validate,
)

# Payloads are 11 digits; the twelfth is the generated check digit.
AADHAAR_PAYLOADS = [
    "22222222222",
    "34567890123",
    "98765432109",
    "56565656565",
    "77777777777",
    "29384756102",
]

# Fourth character Z or Q is not an allottable PAN holder-type code.
SYNTHETIC_PANS = ["ZZZZZ0000Z", "QQQQQ1111Q", "ABCZE9999Z"]


def synthetic_aadhaar(payload: str) -> str:
    return payload + str(verhoeff_checksum(payload))


def synthetic_gstin(state_code: str, pan: str, entity: str = "1") -> str:
    body = f"{state_code}{pan}{entity}Z"
    return body + gstin_check_char(body)


# ------------------------------------------------------------------- Verhoeff


@pytest.mark.parametrize("payload", AADHAAR_PAYLOADS)
def test_verhoeff_round_trip_produces_valid_aadhaar(payload):
    number = synthetic_aadhaar(payload)
    assert len(number) == 12
    assert verhoeff_validate(number)
    assert is_valid_aadhaar(number)


@pytest.mark.parametrize("payload", AADHAAR_PAYLOADS)
def test_verhoeff_catches_every_single_digit_corruption(payload):
    number = synthetic_aadhaar(payload)
    for position in range(len(number)):
        for replacement in "0123456789":
            if replacement == number[position]:
                continue
            corrupted = number[:position] + replacement + number[position + 1 :]
            assert not verhoeff_validate(corrupted)
            assert not is_valid_aadhaar(corrupted)


@pytest.mark.parametrize("payload", AADHAAR_PAYLOADS)
def test_verhoeff_catches_adjacent_transpositions(payload):
    # This is the property Luhn does not have, and the reason Aadhaar uses
    # Verhoeff: swapping two neighbouring digits is the commonest keying error.
    number = synthetic_aadhaar(payload)
    swapped_any = False
    for i in range(len(number) - 1):
        if number[i] == number[i + 1]:
            continue
        swapped_any = True
        swapped = number[:i] + number[i + 1] + number[i] + number[i + 2 :]
        assert not verhoeff_validate(swapped)
    if payload != payload[0] * len(payload):
        assert swapped_any


def test_verhoeff_differs_from_luhn():
    differing = [p for p in AADHAAR_PAYLOADS if verhoeff_checksum(p) != luhn_check_digit(p)]
    assert differing, "Verhoeff and Luhn must not agree on every payload"


def test_verhoeff_checksum_rejects_non_digits():
    with pytest.raises(ValueError):
        verhoeff_checksum("12345abc")


def test_verhoeff_validate_rejects_empty_and_garbage():
    assert not verhoeff_validate("")
    assert not verhoeff_validate("not-a-number")


# -------------------------------------------------------------------- Aadhaar


def test_aadhaar_rejects_leading_zero_and_one():
    # UIDAI does not issue numbers starting 0 or 1, whatever the checksum says.
    for lead in "01":
        payload = lead + "2345678901"[:10]
        number = synthetic_aadhaar(payload)
        assert verhoeff_validate(number)
        assert not is_valid_aadhaar(number)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "2345678901",
        "234567890123",
        "23456789012a",
        "abcdefghijkl",
        "2345 6789 012",
    ],
)
def test_aadhaar_rejects_wrong_shape(value):
    assert not is_valid_aadhaar(value)


def test_aadhaar_accepts_spaced_and_hyphenated_formatting():
    number = synthetic_aadhaar(AADHAAR_PAYLOADS[0])
    spaced = f"{number[:4]} {number[4:8]} {number[8:]}"
    hyphenated = f"{number[:4]}-{number[4:8]}-{number[8:]}"
    assert is_valid_aadhaar(spaced)
    assert is_valid_aadhaar(hyphenated)


# ------------------------------------------------------------------------ PAN


@pytest.mark.parametrize("pan", SYNTHETIC_PANS)
def test_pan_accepts_valid_format(pan):
    assert is_valid_pan(pan)


def test_pan_is_case_insensitive_on_input():
    assert is_valid_pan(SYNTHETIC_PANS[0].lower())


@pytest.mark.parametrize(
    "value",
    [
        "ZZZZ0000Z",
        "ZZZZZ0000",
        "ZZZZZ00000Z",
        "ZZZZZ000AZ",
        "ZZZ1ZZ000Z",
        "0ZZZZ0000Z",
        "ZZZZZ0000ZZ",
        "",
    ],
)
def test_pan_rejects_malformed(value):
    assert not is_valid_pan(value)


# ---------------------------------------------------------------------- GSTIN


@pytest.mark.parametrize("state_code", ["01", "09", "27", "38"])
def test_gstin_round_trip_over_valid_state_codes(state_code):
    gstin = synthetic_gstin(state_code, SYNTHETIC_PANS[0])
    assert len(gstin) == 15
    assert is_valid_gstin(gstin)


@pytest.mark.parametrize("state_code", ["00", "39", "99"])
def test_gstin_rejects_out_of_range_state_code(state_code):
    body = f"{state_code}{SYNTHETIC_PANS[0]}1Z"
    assert not is_valid_gstin(body + gstin_check_char(body))


def test_gstin_rejects_wrong_check_character():
    gstin = synthetic_gstin("27", SYNTHETIC_PANS[0])
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for candidate in alphabet:
        if candidate == gstin[14]:
            continue
        assert not is_valid_gstin(gstin[:14] + candidate)


def test_gstin_rejects_non_z_fourteenth_character():
    gstin = synthetic_gstin("27", SYNTHETIC_PANS[0])
    body = gstin[:13] + "A"
    assert not is_valid_gstin(body + gstin_check_char(body))


def test_gstin_rejects_bad_embedded_pan():
    body = "27" + "ZZZZZ00000" + "1Z"
    assert not is_valid_gstin(body + gstin_check_char(body))


@pytest.mark.parametrize("value", ["", "27ZZZZZ0000Z1Z", "27ZZZZZ0000Z1ZAA", "27ZZZZZ0000Z1Z!"])
def test_gstin_rejects_wrong_length_or_charset(value):
    assert not is_valid_gstin(value)


def test_gstin_check_char_rejects_wrong_input_length():
    with pytest.raises(ValueError):
        gstin_check_char("27ZZZZZ0000Z1")


# ------------------------------------------- IFSC, passport, voter id, cards


@pytest.mark.parametrize("value", ["ZZZZ0999999", "ZZZZ0ABC123"])
def test_ifsc_accepts_valid_format(value):
    assert is_valid_ifsc(value)


@pytest.mark.parametrize("value", ["ZZZZ1999999", "ZZZ0999999", "ZZZZ099999", "ZZZZ09999999", ""])
def test_ifsc_rejects_malformed(value):
    assert not is_valid_ifsc(value)


def test_passport_format():
    assert is_valid_passport("Z0000000")
    assert not is_valid_passport("ZZ000000")
    assert not is_valid_passport("Z000000")
    assert not is_valid_passport("Z00000000")
    assert not is_valid_passport("00000000")


def test_voter_id_format():
    assert is_valid_voter_id("ZZZ0000000")
    assert not is_valid_voter_id("ZZ00000000")
    assert not is_valid_voter_id("ZZZ000000")
    assert not is_valid_voter_id("ZZZZ000000")


def test_card_number_luhn_round_trip():
    # IIN 9 is unassigned by the card networks, so this cannot be a real card.
    for length in (12, 15, 18):
        payload = "9" * length
        number = payload + str(luhn_check_digit(payload))
        assert is_valid_card_number(number)
        assert is_valid_card_number(f"{number[:4]}-{number[4:]}")


def test_card_number_rejects_corrupted_and_out_of_range_lengths():
    payload = "9" * 15
    number = payload + str(luhn_check_digit(payload))
    corrupted = number[:-1] + str((int(number[-1]) + 1) % 10)
    assert not is_valid_card_number(corrupted)
    short = "9" * 11
    assert not is_valid_card_number(short + str(luhn_check_digit(short)))
    long_payload = "9" * 19
    assert not is_valid_card_number(long_payload + str(luhn_check_digit(long_payload)))
    assert not is_valid_card_number("")


# ------------------------------------------------------------ negative filters


@pytest.mark.parametrize(
    "field_name",
    [
        "email_template",
        "phone_format",
        "name_label",
        "address_placeholder",
        "email_regex",
        "emailTemplate",
        "EMAIL_TEMPLATE",
        "email-template",
        "email_templates",
        "phone_number_format",
        "aadhaar_regex",
        "pan_validation_pattern",
        "name_placeholder",
        "address_label",
        "sample_email",
        "dummy_phone_number",
        "test_aadhaar_number",
        "mock_pan_number",
        "email_column_name",
        "phone_field_name",
        "address_input_type",
        "password_hint_text",
        "email_subject",
        "card_number_mask_pattern",
        "phone_min_length",
        "email_validator",
        "address_form_config",
        "name_tooltip",
        "email_locale",
        "contact_email_default",
    ],
)
def test_negative_filters_reject_descriptive_fields(field_name):
    assert classify(field_name) is None


@pytest.mark.parametrize(
    ("field_name", "expected"),
    [
        ("user_email", "email"),
        ("mobile_number", "phone"),
        ("email", "email"),
        ("emailAddress", "email"),
        ("usr_email_addr", "email"),
        ("contact_phone", "phone"),
        ("aadhaar_number", "aadhaar"),
        ("AadhaarNumber", "aadhaar"),
        ("pan_card_number", "pan"),
        ("passport_no", "passport"),
        ("voter_id", "voter_id"),
        ("gstin", "gstin"),
        ("date_of_birth", "dob"),
        ("customer_dob", "dob"),
        ("billing_address", "address"),
        ("pin_code", "address"),
        ("ip_address", "ip_address"),
        ("x-forwarded-for", "ip_address"),
        ("card_number", "financial"),
        ("ifsc_code", "financial"),
        ("upi_id", "financial"),
        ("fingerprint_hash", "biometric"),
        ("blood_group", "health"),
        ("blood_type", "health"),
        ("medical_history", "health"),
        ("password_hash", "password"),
        ("confirm_password", "password"),
        ("full_name", "name"),
        ("customer_name", "name"),
        ("profile_name", "name"),
    ],
)
def test_real_pii_fields_still_classify(field_name, expected):
    assert classify(field_name) == expected


def test_token_run_matching_does_not_swallow_longer_words():
    # "file_name" is filtered, but "profile_name" merely contains those letters.
    assert classify("file_name") is None
    assert classify("profile_name") == "name"


def test_longest_alias_run_wins():
    # pin maps to password and pin_code to address; the longer run must win.
    assert classify("pin") == "password"
    assert classify("user_pin_code") == "address"
    assert classify("email_address") == "email"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("userEmail", "user_email"),
        ("USER_EMAIL", "user_email"),
        ("user-email", "user_email"),
        ("user.email", "user_email"),
        ("PANNumber", "pan_number"),
        ("  aadhaar__no  ", "aadhaar_no"),
    ],
)
def test_normalise_collapses_naming_conventions(raw, expected):
    assert normalise(raw) == expected


def test_classify_handles_empty_input():
    assert classify("") is None
    assert classify("___") is None


# ------------------------------------------------------- literal confirmation


def test_literal_establishes_category_when_name_is_silent():
    assert classify("id_value", nearby_literal=synthetic_aadhaar(AADHAAR_PAYLOADS[0])) == "aadhaar"
    assert classify("ref_code", nearby_literal=SYNTHETIC_PANS[0]) == "pan"
    assert classify("code_value", nearby_literal=synthetic_gstin("27", SYNTHETIC_PANS[0])) == "gstin"


def test_literal_overrides_another_document_category():
    # The name guesses at one document number and the literal proves another.
    assert classify("uid_number", nearby_literal=SYNTHETIC_PANS[0]) == "pan"


def test_literal_does_not_override_a_non_document_name():
    assert classify("customer_name", nearby_literal=SYNTHETIC_PANS[0]) == "name"


def test_unrecognised_literal_leaves_name_verdict_intact():
    assert classify("aadhaar_number", nearby_literal="not-an-id") == "aadhaar"
    assert classify("random_column", nearby_literal="123") is None


def test_negative_filter_beats_a_valid_literal():
    number = synthetic_aadhaar(AADHAAR_PAYLOADS[0])
    assert classify("aadhaar_example", nearby_literal=number) is None


def test_validator_table_only_names_known_categories():
    for category, validator in VALIDATORS:
        assert category in taxonomy.PII_TAXONOMY
        assert callable(validator)


# -------------------------------------------------------------------- taxonomy

REQUIRED_CATEGORIES = {
    "name",
    "email",
    "phone",
    "aadhaar",
    "pan",
    "passport",
    "voter_id",
    "gstin",
    "dob",
    "address",
    "ip_address",
    "financial",
    "biometric",
    "health",
    "password",
}

CRITICAL_CATEGORIES = {
    "aadhaar",
    "pan",
    "passport",
    "financial",
    "biometric",
    "health",
    "password",
}


def test_every_required_category_exists():
    assert REQUIRED_CATEGORIES <= set(taxonomy.PII_TAXONOMY)


def test_critical_tier_membership_is_exact():
    critical = {c for c in taxonomy.categories() if taxonomy.sensitivity_for(c) == "critical"}
    assert critical == CRITICAL_CATEGORIES


@pytest.mark.parametrize("category", sorted(REQUIRED_CATEGORIES))
def test_category_entries_are_well_formed(category):
    assert taxonomy.sensitivity_for(category) in {"critical", "high", "medium", "low"}
    sections = taxonomy.sections_for(category)
    assert sections
    for section in sections:
        assert section.startswith("s.")
    assert taxonomy.aliases_for(category)


def test_sections_are_returned_as_a_copy():
    sections = taxonomy.sections_for("aadhaar")
    sections.append("s.99")
    assert "s.99" not in taxonomy.sections_for("aadhaar")


def test_unknown_category_raises():
    with pytest.raises(KeyError):
        taxonomy.sensitivity_for("favourite_colour")
    with pytest.raises(KeyError):
        taxonomy.sections_for("favourite_colour")


def test_no_alias_is_shared_between_categories():
    seen: dict[str, str] = {}
    for category in taxonomy.categories():
        for alias in taxonomy.aliases_for(category):
            key = normalise(alias)
            assert key not in seen, f"{alias} claimed by {seen.get(key)} and {category}"
            seen[key] = category


def test_no_alias_is_killed_by_its_own_negative_filters():
    # The two constants have to stay consistent: a filter that rejects a
    # registered alias would silently delete a whole class of findings.
    for category in taxonomy.categories():
        for alias in taxonomy.aliases_for(category):
            assert classify(alias) == category, f"{alias} no longer classifies as {category}"


# -------------------------------------------------------------- build_field_ref


def test_build_field_ref_populates_the_contract():
    ref = build_field_ref(
        "aadhaar_number",
        file_path="app/models/user.py",
        line_number=42,
        location_kind="db_column",
        context="aadhaar_number = Column(String(12))",
    )
    assert isinstance(ref, PIIFieldRef)
    assert ref.field_name == "aadhaar_number"
    assert ref.pii_category == "aadhaar"
    assert ref.sensitivity == "critical"
    assert ref.file_path == "app/models/user.py"
    assert ref.line_number == 42
    assert ref.location_kind == "db_column"
    assert ref.context is not None


def test_build_field_ref_returns_none_for_filtered_fields():
    assert build_field_ref("email_template", file_path="ui/forms.py", line_number=7) is None
    assert build_field_ref("class_name") is None


def test_build_field_ref_uses_the_literal():
    ref = build_field_ref("id_value", nearby_literal=synthetic_aadhaar(AADHAAR_PAYLOADS[1]))
    assert ref is not None
    assert ref.pii_category == "aadhaar"
    assert ref.sensitivity == "critical"


def test_build_field_ref_sensitivity_tracks_taxonomy():
    for field_name, category in [("user_email", "email"), ("cvv", "financial"), ("city", "address")]:
        ref = build_field_ref(field_name)
        assert ref is not None
        assert ref.pii_category == category
        assert ref.sensitivity == taxonomy.sensitivity_for(category)
