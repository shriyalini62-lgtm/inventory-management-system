# Inventory Management System — Review 3

Flask web app backed by the existing Oracle Database 21c XE schema (`INVENTORY_APP`, service `localhost:1521/XEPDB1`). Authentication accounts are stored separately in a local SQLite file (`inventory_auth.db`) so the existing Oracle inventory tables and records are not recreated or altered.

## Features

- Dashboard totals, stock valuation, low-stock alerts, and recent purchase/sale history.
- Product add/update/delete for administrators.
- Purchase and sale entry for administrators and staff, including stock checks.
- Product search by code/name/category/supplier, category filtering, and low-stock-only filter.
- Date-filtered purchase and sales reports.
- Login/logout and roles: `admin`, `staff`, `viewer`.
- Password hashes (PBKDF2-HMAC-SHA256), CSRF tokens for POST forms, HTTP-only/Lax session cookies, login lockout after repeated failures, and role checks on backend routes.
- Oracle credentials are read from environment variables. SQL values use bind parameters.

## Windows PowerShell setup

Run these commands from this folder. Use your actual Oracle password when prompted; it is not echoed by PowerShell's secure prompt only if you use `Read-Host -AsSecureString`, but this app expects a normal environment variable. To avoid putting the password in command history, use the snippet below:

```powershell
$secure = Read-Host "Oracle INVENTORY_APP password" -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try { $env:ORACLE_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
$env:ORACLE_USER = "INVENTORY_APP"
$env:ORACLE_DSN = "localhost:1521/XEPDB1"
```

Create the initial admin account on first run (password must be at least 12 characters):

```powershell
$env:ADMIN_USERNAME = "admin"
$secureAdmin = Read-Host "Create initial admin password (12+ characters)" -AsSecureString
$ptrAdmin = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAdmin)
try { $env:ADMIN_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptrAdmin) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptrAdmin) }
```

Install and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m py_compile app.py
python app.py
```

Open http://127.0.0.1:5000/login. On the first start, `inventory_auth.db` is created. The admin environment variables are used only to create the initial administrator if that username does not already exist. After creating the admin, remove `ADMIN_PASSWORD` from the current session with `Remove-Item Env:ADMIN_PASSWORD`.

If PowerShell blocks virtual-environment activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` for that terminal, then activate again.

## Roles

- **Admin:** dashboard, products CRUD, purchases, sales, reports, and user creation.
- **Staff:** dashboard, purchases, sales, search/filter, reports; no product CRUD or user management.
- **Viewer:** dashboard, search/filter, and reports only.

An admin creates additional users at **Users**. User accounts are stored in `inventory_auth.db`; back up this file securely. Do not share it publicly.

## Security notes

- Keep `ORACLE_PASSWORD`, `ADMIN_PASSWORD`, and `FLASK_SECRET_KEY` out of source control and screenshots.
- The app uses a random session secret if `FLASK_SECRET_KEY` is not set; set a long random value in the environment for sessions that should persist across restarts.
- This app binds to `127.0.0.1` by default and debug mode is off. Do not expose it publicly without HTTPS, production deployment hardening, and review.
- CSRF protection is enabled for HTML POST forms. API access to `GET /products` requires an authenticated session.
- Existing Oracle tables are not dropped or recreated.

## Review 3 demo checklist

1. Sign in as admin.
2. Search products by name/code; filter by category and low stock.
3. Add a test product if suitable, update its price, then delete it only if it has no transaction history.
4. Record a purchase and show stock increasing.
5. Record a sale and show stock decreasing; attempt to sell more than available and show rejection.
6. Open Reports and filter by dates.
7. Create a viewer user, sign in as viewer, and confirm product-changing and transaction POST routes are denied.
8. Sign back in as admin and show user management.

## Known limitations to disclose honestly

- Authentication users are stored in local SQLite, separate from the Oracle business schema.
- Purchase and sale forms currently record one product line per transaction (not a multi-line cart).
- This is a local college-demo application, not a hardened public production deployment.
- The project should be tested against the actual Oracle instance after any code changes.

## Category and supplier management

Administrators can add, edit, and delete categories and suppliers from the **Categories** and **Suppliers** pages. Staff and viewers can view those lists but cannot modify them. Oracle foreign-key/unique constraints remain authoritative; for example, a category used by products cannot be deleted.

## Set a persistent Flask session key (recommended)

In PowerShell, set a random key for the current terminal session before starting the app:

```powershell
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:FLASK_SECRET_KEY = [Convert]::ToBase64String($bytes)
```

Keep this value private. If it changes, users will need to sign in again.
