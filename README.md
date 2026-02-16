# CustDigi (DigiSigner)

CustDigi is a Django-based digital signing application for uploading documents, signing PDFs, verifying signatures, and managing signed subscription data.

## Features

- User registration and login flow (integrated with an external API)
- Dashboard-driven workflow for document upload, token/certificate setup, and signing preparation
- PDF signing with page/coordinate placement options
- Signature verification and signature detail inspection
- Previewing and downloading original/signed files
- Subscription form signing and local JSON signature storage

## Tech Stack

- Python + Django (`core` project, `mainapp` application)
- SQLite (`db.sqlite3`)
- External signing/verification API via `requests`
- `pyHanko` for signature verification/detail extraction
- `django-environ` for `.env` loading
- Static assets under `static/`, templates under `templates/`

## Prerequisites

- Python 3.10+
- Pip
- Access to the external API base URL used by this project

## Environment Variables

Create a `.env` file in the project root:

```env
EXTERNAL_API_BASE_URL= external api
```

## Local Setup

1. Create and activate a virtual environment.

```powershell
python -m venv venv
.\venv\Scripts\activate
```

2. Install dependencies.

```powershell
pip install django django-environ requests pyHanko Pillow
```

3. Run migrations.

```powershell
python manage.py migrate
```

4. (Optional) Create an admin user.

```powershell
python manage.py createsuperuser
```

5. Start the development server.

```powershell
python manage.py runserver
```

## Key URLs

- `/` - Register
- `/login/` - Login
- `/dashboard/` - Main dashboard
- `/admin/` - Django admin

## Project Structure

```text
core/        Django settings, URL config, ASGI/WSGI
mainapp/     Models, forms, views, app URLs, utilities
templates/   HTML templates (users/*)
static/      CSS and JavaScript assets
media/       Uploaded/signed files and generated artifacts
manage.py    Django management entry point
```

## Notes

- `AUTH_USER_MODEL` is configured as `mainapp.Users`.
- Media files are served in development when `DEBUG=True`.
- Signing and verification flows depend on a valid API token and reachable external API.