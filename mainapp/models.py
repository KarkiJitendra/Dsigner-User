import PIL.PngImagePlugin
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta


class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class Users(TimeStampedModel, AbstractUser):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    fullname = models.CharField(max_length=30, null=True, blank=True)
    contact = models.IntegerField(unique=True)
    password = models.CharField(max_length=128)
    confirm_password = models.CharField(max_length=128)

    def __str__(self):
        return self.email


class Organizations(TimeStampedModel):
    name = models.CharField(max_length=150, unique=True)


class Signature(TimeStampedModel):
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    image = models.ImageField(upload_to="signatures/", null=True, blank=True)

    def __str__(self):
        return f"{self.user.username}'s signature"


class Document(TimeStampedModel):
    STATUS_CHOICES = [
        ("draft", "Draft"),
        ("pending", "Pending Signature"),
        ("signed", "Signed"),
        ("verified", "Verified"),
        ("rejected", "Rejected"),
    ]

    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to="unsignatured_document/", null=False, blank=False)
    signed_file = models.FileField(
        upload_to="signatured_document/", null=True, blank=True
    )
    hash_value = models.CharField(max_length=64, blank=True, null=True)
    signature_data = models.TextField(blank=True, null=True)  # Cryptographic signature
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="draft")

    def __str__(self):
        return self.title


class UserCertificate(TimeStampedModel):
    user = models.OneToOneField(
        Users, on_delete=models.CASCADE, related_name="certificate"
    )
    pb7_file = models.FileField(upload_to="certificates/pb7/", null=True, blank=True)
    pb12_file = models.FileField(upload_to="certificates/pb12/", null=True, blank=True)
    passphrase = models.CharField(max_length=255, null=True, blank=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"Certificate for {self.user.username}"


class ApiToken(TimeStampedModel):
    user = models.OneToOneField(
        Users, on_delete=models.CASCADE, related_name="api_token"
    )
    token = models.CharField(max_length=255, unique=True)
    expires_at = models.DateTimeField(default=timezone.now() + timedelta(days=365))
    expiry_status = models.BooleanField(default=False)
    description = models.TextField(max_length=255)
    organization = models.ForeignKey(
        Organizations, on_delete=models.CASCADE, null=True, blank=True
    )
    allow_pdf_signing = models.BooleanField(default=False)
    allow_pdf_verification = models.BooleanField(default=False)
    allow_form_signing = models.BooleanField(default=False)
    allow_form_verification = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.token


class Signing_challenge(TimeStampedModel):
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    force_create = models.BooleanField(default=False)
    max_content = models.IntegerField(default=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Signing Challenge for {self.user.username}"


class Subscription(TimeStampedModel):
    PLAN_CHOICES = [
        ("basic", "Basic"),
        ("premium", "Premium"),
        ("enterprise", "Enterprise"),
    ]

    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    plan = models.CharField(max_length=255, choices=PLAN_CHOICES, default="basic")
    start_date = models.DateTimeField(auto_now_add=True)
    end_date = models.DateTimeField()
    status = models.CharField(
        max_length=20,
        choices=[("active", "Active"), ("inactive", "Inactive")],
        default="active",
    )
    card_details = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Subscription for {self.user.username}"
