"""Synthetic Django model used only as scanner input. Not production code."""

from django.db import models
from django_cryptography.fields import encrypt


class Citizen(models.Model):
    email_address = models.EmailField(max_length=255)
    aadhaar_number = models.CharField(max_length=12)

    # The field is wrapped in a helper, so the column is one level down.
    pan_number = encrypt(models.CharField(max_length=20))

    session_expires_at = models.DateTimeField(null=True)

    class Meta:
        db_table = "django_citizens"
