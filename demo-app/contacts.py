"""The published contact points for data protection questions.

Rule 9 of the Digital Personal Data Protection Rules 2025 requires the contact
able to answer questions about processing to be published where a Data Principal
will find it. These functions are the single source for that: the footer of every
page, the notice page and the breach filing all read them, so the address a person
is told to write to cannot drift from the address the system uses.

Every value is invented and the domain ends in .invalid.
"""

DPO_ROLE = "Data Protection Officer"
GRIEVANCE_ROLE = "Grievance Officer"

REGISTERED_OFFICE = (
    "Bharat Bazaar Retail Private Limited, Ashram Road, Ahmedabad 380009, "
    "Gujarat, India"
)


def data_protection_officer() -> tuple[str, str, str]:
    """The appointed officer answerable for processing, based in India."""
    return (DPO_ROLE, "Ms A. Iyer", "dpo@bharatbazaar.invalid")


def grievance_officer() -> tuple[str, str, str]:
    """The officer who answers a section 13 grievance within thirty days."""
    return (GRIEVANCE_ROLE, "Mr R. Nair", "grievance-officer@bharatbazaar.invalid")


def published_contacts() -> tuple[tuple[str, str, str], ...]:
    """Both contacts, in the order the footer renders them."""
    return (data_protection_officer(), grievance_officer())


def escalation_note() -> str:
    """What to do if we do not resolve a complaint in time."""
    return (
        "If the Grievance Officer does not answer within thirty days, or the answer "
        "does not resolve the matter, the Data Principal may approach the Data "
        "Protection Board of India under section 13(3). Our permission is not needed "
        "and we do not have to be told first."
    )
