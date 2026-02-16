from django.urls import path
from django.contrib.auth import views as auth_views
from . import views


urlpatterns = [
    path("", views.register, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("upload_document/", views.upload_document, name="upload_document"),
    path("Upload_certificate/", views.upload_certificate, name="upload_certificate"),
    path("view_certificate/", views.view_certificates, name="view_certificate"),
    path("upload_token/", views.upload_token, name="upload_token"),
    path("subscription/", views.sign_form, name="subscription"),
    path(
        "verify_document/<int:document_id>/",
        views.verify_document_view,
        name="verify_document",
    ),
    path("send_document/<int:document_id>/", views.send_document, name="send_document"),
    path("prepare_sign/<int:document_id>/", views.prepare_sign, name="prepare_sign"),
    path("sign_document/<int:document_id>/", views.sign_document, name="sign_document"),
    path(
        "download_document/<int:document_id>/",
        views.download_document,
        name="download_document",
    ),
    path(
        "signature_info/<int:document_id>/", views.signature_info, name="signature_info"
    ),
    path("preview/<int:document_id>/", views.document_preview, name="document_preview"),
]
