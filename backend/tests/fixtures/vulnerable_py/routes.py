"""Synthetic FastAPI surface used only as scanner input. Not production code."""

import logging

from fastapi import Depends, FastAPI

from models import Subscriber
from partners import forward_to_partner

app = FastAPI()
logger = logging.getLogger(__name__)


def get_current_user():
    return {"role": "operator"}


@app.post("/subscribers")
def register_subscriber(payload: dict, session=None):
    email_address = payload["email_address"]
    aadhaar_number = payload["aadhaar_number"]

    # PII straight into the log stream, with no auth on the endpoint either.
    logger.info(f"registering {email_address} with aadhaar {aadhaar_number}")

    subscriber = Subscriber()
    subscriber.email_address = email_address
    subscriber.aadhaar_number = aadhaar_number
    subscriber.set_password(payload["password"])
    session.add(subscriber)
    session.commit()

    forward_to_partner(email_address, payload["phone_number"])
    return {"status": "created"}


@app.get("/subscribers/{subscriber_id}")
def read_subscriber(
    subscriber_id: int, current_user=Depends(get_current_user), session=None
):
    return session.query(Subscriber).filter_by(id=subscriber_id).one_or_none()
