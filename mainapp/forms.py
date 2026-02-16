from argparse import __all__
from django import forms
from .models import (
    Users,
    Signature,
    Document,
    ApiToken,
    UserCertificate,
    Signing_challenge,
    Subscription,
)
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.db import transaction
import secrets
import re
from datetime import datetime, timedelta


class UserForm(forms.Form):  # Use forms.Form, not ModelForm
    username = forms.CharField(max_length=150)
    fullname = forms.CharField(max_length=255)
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)
    contact = forms.CharField(max_length=20)

    # Add confirm_password if needed
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("password") != cleaned.get("confirm_password"):
            self.add_error("confirm_password", "Passwords don't match")
        return cleaned


class CertificateUploadForm(forms.ModelForm):
    class Meta:
        model = UserCertificate
        fields = ["pb7_file", "pb12_file", "passphrase"]
        widgets = {
            "pb7_file": forms.FileInput(
                attrs={"class": "form-control", "accept": ".pb7,.p7b,.cer,.crt"}
            ),
            "pb12_file": forms.FileInput(
                attrs={"class": "form-control", "accept": ".pb12,.p12,.pfx"}
            ),
            "passphrase": forms.PasswordInput(
                attrs={"class": "form-control", "placeholder": "Certificate Passphrase"}
            ),
        }


class DocumentSendForm(forms.Form):
    recipient_email = forms.EmailField(
        label=_("Recipient Email"),
        widget=forms.EmailInput(
            attrs={"class": "form-control", "placeholder": "recipient@example.com"}
        ),
    )
    message = forms.CharField(
        label=_("Message"),
        required=False,
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "placeholder": "Add a note to the recipient...",
                "rows": 3,
            }
        ),
    )


class DocumentUploadForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ["title", "file"]
        widgets = {
            "title": forms.TextInput(
                attrs={"class": "form-control", "placeholder": "Document Title"}
            ),
            "file": forms.FileInput(attrs={"class": "form-control"}),
        }


class TokenForm(forms.ModelForm):
    class Meta:
        model = ApiToken
        fields = ["token", "expiry_status", "organization"]
        widgets = {
            "token": forms.TextInput(attrs={"class": "form-control"}),
            "expiry_status": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "organization": forms.Select(attrs={"class": "form-select"}),
        }


class Signing_challengeForm(forms.ModelForm):
    class Meta:
        model = Signing_challenge
        fields = ["force_create", "max_content"]
        widgets = {
            "force_create": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "max_content": forms.NumberInput(attrs={"class": "form-control"}),
        }

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("max_content") < 1:
            self.add_error("max_content", "Max content must be at least 1")
        return cleaned


class SubscriptionForm(forms.ModelForm):
    class Meta:
        model = Subscription
        fields = ["plan", "end_date", "status", "card_details"]
        widgets = {
            "plan": forms.Select(attrs={"class": "form-select"}),
            "end_date": forms.DateInput(
                attrs={"class": "form-control", "type": "date"}
            ),
            "status": forms.Select(attrs={"class": "form-select"}),
            "card_details": forms.TextInput(attrs={"class": "form-control"}),
        }

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("end_date") and cleaned.get("end_date") < timezone.now():
            self.add_error("end_date", "End date must be after start date")
        return cleaned

    # def clean_card_details(self):
    #     card_details = self.cleaned_data.get("card_details")
    #     if not re.match(r"^\d{16}$", card_details):
    #         raise forms.ValidationError("Card details must be 16 digits")
    #     return card_details
