from mainapp.forms import SubscriptionForm
from django.shortcuts import render, redirect, get_object_or_404
from django.http import FileResponse, Http404, JsonResponse
from django.contrib import messages
from mainapp.forms import (
    SubscriptionForm,
    DocumentSendForm,
    DocumentUploadForm,
    TokenForm,
    Signing_challengeForm,
    CertificateUploadForm,
)
from .models import *
from django.contrib.auth import login, logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from .utils import sign_pdf, verify_pdf, get_signature_details, get_signature_positions
import os
import requests
import base64
import json
from django.conf import settings
from core.settings import baseapi


# Create your views here.


def register(request):
    form = UserForm()

    if request.method == "POST":
        print(f"POST data: {request.POST}")
        form = UserForm(request.POST)
        r = requests.get(f"{baseapi}api/v1/register/")
        if form.is_valid():
            # Prepare payload from form data
            payload = {
                "username": form.cleaned_data.get("username"),
                "fullname": form.cleaned_data.get("fullname"),
                "email": form.cleaned_data.get("email"),
                "password": form.cleaned_data.get("password"),
                "confirm_password": form.cleaned_data.get("confirm_password"),
                "contact": form.cleaned_data.get("contact"),
            }
            print(f"Payload: {payload}")

            # Send to external API
            try:
                response = requests.post(
                    f"{baseapi}api/v1/register/",
                    json=payload,
                )
                print(f"Response status: {response.status_code}")  # ← BREAKPOINT 9
                print(f"Response data: {response.text}")

                if response.status_code == 201:
                    messages.success(request, "Registration successful! Please login.")
                    print("Registration successful, redirecting to login.")
                    try:
                        return redirect(reverse("login"))
                    except:
                        return redirect("login")
                else:
                    # API returned error - add to form
                    error_data = response.json()
                    for field, errors in error_data.items():
                        if isinstance(errors, list):
                            form.add_error(field, errors[0])
                        else:
                            form.add_error(field, str(errors))

            except requests.exceptions.RequestException:
                form.add_error(None, "Unable to connect to registration server.")

    return render(request, "users/register.html", {"form": form})


def login_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    form = AuthenticationForm()

    if request.method == "POST":
        email = request.POST.get(
            "username"
        )  # AuthenticationForm uses 'username' field for email
        password = request.POST.get("password")
        try:
            response = requests.post(
                f"{settings.EXTERNAL_API_BASE_URL}/login/",
                json={"email": email, "password": password},
            )

            if response.status_code == 200:
                data = response.json()

                # Get or create local user (Django needs this for session)
                user, created = Users.objects.get_or_create(
                    username=data.get("username", email),
                    defaults={
                        "email": email,
                        "first_name": data.get("fullname", ""),
                    },
                )
                login(request, user)
                messages.success(
                    request, f"Welcome back, {user.first_name or user.username}!"
                )
                return redirect("dashboard")

            else:
                messages.error(request, "Invalid email or password.")

        except requests.exceptions.RequestException:
            messages.error(request, "Unable to connect to server. Please try again.")

    return render(
        request, "users/login.html", {"form": form, "next": request.GET.get("next", "")}
    )


def logout_view(request):
    # This removes the user ID from the session and deletes the session cookie
    logout(request)

    # Add a success message to show on the login page
    messages.info(request, "You have successfully logged out.")

    # Redirect to the login page or home page
    return redirect("login")


@login_required
def dashboard(request):
    # Determine the active section from GET parameters (default to 'documents')
    active_section = request.GET.get("section", "documents")

    # Get user documents
    documents = Document.objects.filter(user=request.user).order_by("-updated_at")

    # Get user certificates if they exist
    user_cert = UserCertificate.objects.filter(user=request.user).first()

    # Initialize forms for different sections
    cert_form = CertificateUploadForm(instance=user_cert)
    token_form = TokenForm()
    send_form = DocumentSendForm()
    upload_form = DocumentUploadForm()
    subscription_form = SubscriptionForm()

    # Legacy flag (keeping just in case, though template uses user_cert now)
    try:
        has_keys = hasattr(request.user, "key_pair")
    except:
        has_keys = False

    context = {
        "documents": documents,
        "has_keys": has_keys,
        "active_section": active_section,
        "user_cert": user_cert,
        "cert_form": cert_form,
        "token_form": token_form,
        "send_form": send_form,
        "upload_form": upload_form,
        "subscription_form": subscription_form,
    }

    return render(request, "users/dashboard.html", context)


@login_required
def upload_certificate(request):
    if request.method == "POST":
        user_cert, created = UserCertificate.objects.get_or_create(user=request.user)
        form = CertificateUploadForm(request.POST, request.FILES, instance=user_cert)
        if form.is_valid():
            form.save()
            messages.success(request, "Certificate uploaded successfully.")
        else:
            messages.error(request, "Error uploading certificate.")
    return redirect(reverse("dashboard") + "?section=setup")


def view_certificates(request):
    user_cert = get_object_or_404(UserCertificate, user=request.user)
    return render(request, "users/view_certificates.html", {"user_cert": user_cert})


@login_required
def upload_token(request):
    user_token, created = ApiToken.objects.get_or_create(user=request.user)
    if request.method == "POST":
        form = TokenForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data["token"]
            user_token.token = token
            user_token.save()
            messages.success(request, "Token Uploaded Successfully")
        else:
            messages.error(request, "Error Uploading Token")
    else:
        messages.error(request, "Invalid Request Method")

    return redirect(reverse("dashboard") + "?section=setup")


def upload_document(request):
    if request.method == "POST":
        form = DocumentUploadForm(request.POST, request.FILES)
        if form.is_valid():
            document = form.save(commit=False)
            document.user = request.user
            document.status = "uploaded"
            document.save()
            messages.success(
                request, f'Document "{document.title}" uploaded successfully.'
            )
        else:
            messages.error(request, "Error uploading document.")
    return redirect(reverse("dashboard") + "?section=documents")


@login_required
def verify_document_view(request, document_id):
    user_token = getattr(request.user, "api_token", None)

    if not user_token:
        messages.error(request, "Please upload your token first.")
        return redirect(reverse("dashboard") + "?section=setup")

    headers = {"Authorization": f"Token {user_token.token}"}
    document = get_object_or_404(Document, id=document_id, user=request.user)
    payload = {"pdf_file": document}
    r = requests.post(
        f"{baseapi}api/v1/verify/pdf/", headers=headers, data=payload
    )
    data = r.json()
    print(data)
    # Use signed file if available, otherwise original
    file_to_verify = document.signed_file if document.signed_file else document.file

    if not file_to_verify:
        messages.warning(request, f'Document "{document.title}" has no file to verify.')
        return redirect(reverse("dashboard") + "?section=verify")

    try:
        is_valid, message = verify_pdf(file_to_verify.path)

        if is_valid:
            document.status = "verified"
            document.save()
            messages.success(request, f'Document "{document.title}" {message}')
        else:
            messages.error(request, f'Document "{document.title}" {message}')

    except Exception as e:
        messages.error(request, f"Verification error: {str(e)}")

    return redirect(reverse("dashboard") + "?section=verify")


@login_required
def sign_document(request, document_id):
    user_token = getattr(request.user, "api_token", None)

    if not user_token:
        messages.error(request, "Please upload your token first.")
        return redirect(reverse("dashboard") + "?section=setup")

    headers = {"Authorization": f"Token {user_token.token}"}

    # 1. Create signing session
    try:
        challenge_response = requests.post(
            f"{baseapi}api/v1/signing-challenge/",
            headers=headers,
            json={
                "force_create": True,
                "requested_max_content": 100,
            },
            timeout=20,
        )
        # print("STATUS:", challenge_response.status_code)
        # print("HEADERS:", challenge_response.headers)
        # print("RAW TEXT:", challenge_response.text)

        if challenge_response.ok:
            data = challenge_response.json()
            signing_session = data.get("signing_session_id")
            if not signing_session:
                messages.error(request, "Signing session not returned by API.")
                return redirect("dashboard")
            print(data)
        else:
            messages.error(request, "Failed to create signing challenge.")
            return redirect("dashboard")

    except requests.exceptions.RequestException as e:
        messages.error(request, f"Signing service error: {str(e)}")
        return redirect("dashboard")

    # 2. Get document
    document = get_object_or_404(Document, id=document_id, user=request.user)

    if not document.file:
        messages.error(request, "No file found for this document.")
        return redirect("dashboard")

    try:
        # Parse page numbers
        page_input = request.POST.get("page_numbers", "1")
        pages_to_sign = set()

        for part in page_input.split(","):
            if "-" in part:
                try:
                    start, end = map(int, part.split("-"))
                    pages_to_sign.update(range(start, end + 1))
                except ValueError:
                    pass
            else:
                try:
                    pages_to_sign.add(int(part.strip()))
                except ValueError:
                    pass

        sorted_pages = sorted(list(pages_to_sign)) if pages_to_sign else [1]

        # Coordinates
        x1 = float(request.POST.get("x1", 100))
        y1 = float(request.POST.get("y1", 100))
        x2 = float(request.POST.get("x2", 200))
        y2 = float(request.POST.get("y2", 200))

        # Stamp logic
        sign_method = request.POST.get("sign_method", "sign")
        stamp_image_content = None
        stamp_filename = "stamp.png"
        stamp_content_type = "image/png"

        if sign_method == "stamp":
            stamp_source = request.POST.get("stamp_source")

            if stamp_source == "upload" and request.FILES.get("stamp_file"):
                image_file = request.FILES["stamp_file"]
                stamp_image_content = image_file.read()
                stamp_filename = image_file.name
                stamp_content_type = image_file.content_type

                new_sig = Signature(user=request.user, image=image_file)
                new_sig.save()

            elif stamp_source == "existing":
                sig_id = request.POST.get("selected_signature_id")
                if sig_id:
                    sig = Signature.objects.filter(id=sig_id, user=request.user).first()
                    if sig and sig.image:
                        stamp_filename = os.path.basename(sig.image.name)
                        stamp_content_type, _ = mimetypes.guess_type(
                            sig.image.path
                        ) or ("image/png", None)
                        with open(sig.image.path, "rb") as f:
                            stamp_image_content = f.read()

        # Read original PDF
        with open(document.file.path, "rb") as f:
            current_pdf_content = f.read()

        final_signed_content = None

        # 3. Sign each page
        for page_num in sorted_pages:

            files_payload = {
                "pdf_files": ("document.pdf", current_pdf_content, "application/pdf")
            }

            if sign_method == "stamp" and stamp_image_content:
                files_payload["signature_stamp"] = (
                    stamp_filename,
                    stamp_image_content,
                    stamp_content_type,
                )

            payload = {
                "signing_session_id": signing_session,
                "signature_box": f"{int(x1)},{int(y1)},{int(x2)},{int(y2)}",
                "signature_page": str(page_num),
                "location": "Kathmandu",
                "apply_stamp": "true" if sign_method == "stamp" else "false",
                "field_name": f"Signature_{page_num}",  # Creates interactive signature field
                "create_signature_field": "true",  # Enables clickable signature annotation
            }

            sign_response = requests.post(
                f"{baseapi}api/v1/sign/pdf",
                headers=headers,
                data=payload,
                files=files_payload,
                timeout=60,
            )
            # print("STATUS:", sign_response.status_code)
            # print("HEADERS:", sign_response.headers)
            # print("RAW TEXT:", sign_response.text)

            if sign_response.status_code != 200:
                messages.error(request, f"Error signing page {page_num}")
                print(sign_response.text)
                return redirect("dashboard")

            content_type = sign_response.headers.get("Content-Type", "")
            # print(content_type)

            if "application/json" in content_type:
                data = sign_response.json()

                try:
                    pdf_base64 = data["results"][0]["signature"]
                    pdf_content = base64.b64decode(pdf_base64)

                    current_pdf_content = pdf_content
                    final_signed_content = pdf_content

                    print("Signed PDF extracted successfully, size:", len(pdf_content))

                except (KeyError, IndexError, TypeError) as e:
                    print("Unexpected API response:", data)
                    messages.error(request, "Unexpected API response format")
                    return redirect("dashboard")

        # 5. Save signed PDF
        if final_signed_content:
            if not final_signed_content.startswith(b"%PDF"):
                raise ValueError("Returned file is not a valid PDF")

            signed_filename = f"signed_{os.path.basename(document.file.name)}"
            relative_signed_path = os.path.join("signatured_document", signed_filename)
            output_path = os.path.join(settings.MEDIA_ROOT, relative_signed_path)

            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            with open(output_path, "wb") as f:
                f.write(final_signed_content)

            document.signed_file = relative_signed_path
            document.status = "signed"
            document.save()

            messages.success(
                request, f'Document "{document.title}" signed successfully.'
            )

    except Exception as e:
        messages.error(request, f"Error processing document: {str(e)}")
        print(e)

    return redirect(reverse("dashboard") + "?section=documents")


@login_required
def sign_form(request):
    user_token = getattr(request.user, "api_token", None)
    if not user_token:
        messages.error(request, "Please upload your token first.")
        return redirect(reverse("dashboard") + "?section=setup")

    headers = {"Authorization": f"Token {user_token.token}"}
    # 1. Create signing session
    if request.method == "POST":
        form = SubscriptionForm(request.POST)
        if form.is_valid():
            form_string = f"plan={form.cleaned_data['plan']}&end_date={form.cleaned_data['end_date']}&status={form.cleaned_data['status']}&card_details={form.cleaned_data['card_details']}&user={request.user.id}"
            try:
                challenge_response = requests.post(
                    f"{baseapi}api/v1/signing-challenge/",
                    headers=headers,
                    json={
                        "force_create": True,
                        "requested_max_content": 5,
                    },
                    timeout=20,
                )

                if challenge_response.ok:
                    data = challenge_response.json()
                    signing_session = data.get("signing_session_id")
                    if not signing_session:
                        messages.error(request, "Signing session not returned by API.")
                        return redirect("dashboard")
                else:
                    messages.error(request, "Failed to create signing challenge.")
                    return redirect("dashboard")

            except requests.exceptions.RequestException as e:
                messages.error(request, f"Signing service error: {str(e)}")
                return redirect("dashboard")

            sign_response = requests.post(
                f"{baseapi}api/v1/sign/text",
                headers=headers,
                json={"signing_session_id": signing_session, "text": [form_string]},
            )
            if sign_response.ok:
                result = sign_response.json()
                signature = result.get("signature")

                data_to_store = {
                    "form_data": form_string,
                    "signature": signature,
                }
                print(data_to_store)

                filename = f"subscription_{request.user.id}.json"
                relative_path = os.path.join("signed_subscriptions", filename)
                full_path = os.path.join(settings.MEDIA_ROOT, relative_path)

                os.makedirs(os.path.dirname(full_path), exist_ok=True)

                with open(full_path, "w", encoding="utf-8") as f:
                    json.dump(data_to_store, f, indent=4)

                # Save the subscription with the user
                subscription = form.save(commit=False)
                subscription.user = request.user
                subscription.save()
                messages.success(request, "Subscription plan updated successfully.")
                return redirect("dashboard")

        else:
            messages.error(request, "Invalid form data.")
            return redirect("dashboard")

    return redirect(reverse("dashboard"))


@login_required
def signature_info(request, document_id):
    document = get_object_or_404(Document, id=document_id, user=request.user)
    file_path = (
        document.signed_file.path if document.signed_file else document.file.path
    )
    details = get_signature_details(file_path)
    return JsonResponse({"signatures": details})


def send_document(request, document_id):
    document = get_object_or_404(Document, id=document_id, user=request.user)
    if request.method == "POST":
        form = DocumentSendForm(request.POST)
        if form.is_valid():
            # Logic to "send" the document (e.g., email notification)
            recipient = form.cleaned_data["recipient_email"]
            document.status = "pending"
            document.save()
            messages.success(
                request, f'Document "{document.title}" sent to {recipient}.'
            )
        else:
            messages.error(request, "Invalid form data.")


@login_required
def download_document(request, document_id):
    document = get_object_or_404(Document, id=document_id, user=request.user)
    file_type = request.GET.get("type", "original")

    if file_type == "signed" and document.signed_file:
        file_path = document.signed_file.path
    elif document.file:
        file_path = document.file.path
    else:
        raise Http404("File not found")

    if not os.path.exists(file_path):
        raise Http404("File does not exist on server")

    return FileResponse(open(file_path, "rb"), as_attachment=True)


@login_required
def document_preview(request, document_id):
    document = get_object_or_404(Document, id=document_id, user=request.user)
    file_to_preview = document.signed_file if document.signed_file else document.file

    if not file_to_preview:
        messages.error(request, "File not found.")
        return redirect("dashboard")

    # Get signature positions for clickable overlays
    positions = get_signature_positions(file_to_preview.path)

    context = {
        "document": document,
        "file_url": file_to_preview.url,
        "positions": json.dumps(positions),
    }
    return render(request, "users/preview.html", context)


@login_required
def prepare_sign(request, document_id):
    document = get_object_or_404(Document, id=document_id, user=request.user)

    # Ensure document exists and is valid
    if not document.file:
        messages.error(request, "No file found to sign.")
        return redirect("dashboard")

    context = {
        "document": document,
        "file_url": document.file.url,
    }
    return render(request, "users/prepare_signing.html", context)
