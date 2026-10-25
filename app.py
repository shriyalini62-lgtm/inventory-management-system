import os
import hmac
import hashlib
import secrets
import sqlite3
from contextlib import contextmanager
from functools import wraps
from datetime import datetime
from decimal import Decimal, InvalidOperation
import oracledb
from flask import Flask, request, jsonify, redirect, url_for, render_template_string, session, abort

app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=3600,
)
AUTH_DB = os.getenv("AUTH_DB_PATH", os.path.join(os.path.dirname(__file__), "inventory_auth.db"))
ROLES = {"admin", "staff", "viewer"}


@contextmanager
def auth_db():
    conn = sqlite3.connect(AUTH_DB, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return salt.hex() + "$" + digest.hex()


def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 310_000).hex()
        return hmac.compare_digest(actual, digest_hex)
    except (ValueError, TypeError):
        return False


def init_auth_db():
    with auth_db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS app_users (
            username TEXT PRIMARY KEY COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','staff','viewer')),
            active INTEGER NOT NULL DEFAULT 1,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        # Bootstrap an initial administrator only when environment variables are supplied.
        # Never ship a hard-coded default password.
        username = os.getenv("ADMIN_USERNAME", "").strip()
        password = os.getenv("ADMIN_PASSWORD", "")
        if username and password and len(password) >= 12:
            exists = conn.execute("SELECT 1 FROM app_users WHERE username=?", (username,)).fetchone()
            if not exists:
                conn.execute("INSERT INTO app_users(username,password_hash,role) VALUES(?,?, 'admin')",
                             (username, hash_password(password)))


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def inject_template_helpers():
    return {"csrf_token": csrf_token, "current_username": session.get("username"), "current_role": session.get("role")}


@app.after_request
def set_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'same-origin')
    response.headers.setdefault('Content-Security-Policy', "default-src 'self' 'unsafe-inline'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'")
    return response


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("_csrf_token", "")
        if not sent or not expected or not hmac.compare_digest(sent, expected):
            abort(400, description="The form expired or failed its security check. Refresh the page and try again.")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def roles_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("username"):
                return redirect(url_for("login", next=request.path))
            if session.get("role") not in allowed_roles:
                abort(403, description="Your account does not have permission to perform this action.")
            return view(*args, **kwargs)
        return wrapped
    return decorator


LOGIN_PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in · Inventory Management</title><style>body{font-family:Arial,sans-serif;background:#f1f5f9;display:grid;place-items:center;min-height:100vh;margin:0;color:#172033}.box{background:white;padding:30px;border-radius:14px;box-shadow:0 8px 30px #0f172a14;width:min(390px,calc(100% - 36px))}h1{font-size:23px;margin-top:0}p{color:#64748b;font-size:14px}label{display:block;margin-top:16px;font-size:13px}input{box-sizing:border-box;width:100%;padding:11px;margin-top:6px;border:1px solid #cbd5e1;border-radius:7px}button{width:100%;padding:12px;margin-top:20px;border:0;border-radius:7px;background:#2563eb;color:white;font-weight:bold;cursor:pointer}.error{padding:10px;background:#fee2e2;color:#991b1b;border-radius:7px;font-size:13px}.hint{font-size:12px;line-height:1.5}</style></head><body><main class="box"><h1>Inventory Management System</h1><p>Sign in to continue.</p>{% if error %}<div class="error">{{ error }}</div>{% endif %}<form method="post" action="{{ url_for('login') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="next" value="{{ next_url }}"><label>Username<input name="username" autocomplete="username" required maxlength="80" autofocus></label><label>Password<input type="password" name="password" autocomplete="current-password" required></label><button type="submit">Sign in</button></form><p class="hint">Initial admin setup: configure ADMIN_USERNAME and ADMIN_PASSWORD in PowerShell before the first launch. Use a password of at least 12 characters.</p></main></body></html>'''

REPORT_PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Reports · Inventory Management</title><style>body{font-family:Arial,sans-serif;margin:0;background:#f3f5f9;color:#202b3c}header{background:#172554;color:white;padding:20px max(18px,calc((100% - 1100px)/2));display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}nav{background:white;padding:14px max(18px,calc((100% - 1100px)/2));display:flex;gap:18px;flex-wrap:wrap}a{color:#2563eb;text-decoration:none;font-weight:bold}.container{max-width:1100px;margin:24px auto;padding:0 18px}.panel{background:white;padding:20px;border-radius:12px;margin-bottom:20px;overflow:auto}label{font-size:13px}input{padding:9px;border:1px solid #cbd5e1;border-radius:6px;margin:0 10px 10px 5px}button{padding:10px 14px;background:#2563eb;color:white;border:0;border-radius:6px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;font-size:13px}.muted{color:#64748b}.error{background:#fee2e2;color:#991b1b;padding:10px;border-radius:6px}</style></head><body><header><div><b>Inventory Management System</b><div style="font-size:13px;margin-top:5px">Reports · Signed in as {{current_username}} ({{current_role}})</div></div><form method="post" action="{{url_for('logout')}}"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><button>Log out</button></form></header><nav><a href="{{url_for('home')}}">Dashboard</a><a href="{{url_for('categories')}}">Categories</a><a href="{{url_for('suppliers')}}">Suppliers</a>{% if current_role=='admin' %}<a href="{{url_for('users')}}">User management</a>{% endif %}<a href="{{url_for('reports')}}">Reports</a></nav><main class="container"><h1>Purchase & Sales Reports</h1><section class="panel"><form method="get"><label>From <input type="date" name="start" value="{{start}}"></label><label>To <input type="date" name="end" value="{{end}}"></label><button>Apply date filter</button> <a href="{{url_for('reports')}}">Clear</a></form><p class="muted">Dates are inclusive. Leave either date blank to omit that boundary.</p>{% if report_error %}<div class="error">{{report_error}}</div>{% endif %}</section><section class="panel"><h2>Sales</h2><p><b>Transactions:</b> {{sales|length}} &nbsp; <b>Total:</b> ₹{{'%.2f'|format(sales_total)}}</p><table><thead><tr><th>Sale ID</th><th>Date</th><th>Total</th></tr></thead><tbody>{% for r in sales %}<tr><td>{{r[0]}}</td><td>{{r[1]}}</td><td>₹{{'%.2f'|format(r[2] or 0)}}</td></tr>{% else %}<tr><td colspan="3">No sales for this period.</td></tr>{% endfor %}</tbody></table></section><section class="panel"><h2>Purchases</h2><p><b>Transactions:</b> {{purchases|length}} &nbsp; <b>Total:</b> ₹{{'%.2f'|format(purchases_total)}}</p><table><thead><tr><th>Purchase ID</th><th>Date</th><th>Supplier</th><th>Total</th></tr></thead><tbody>{% for r in purchases %}<tr><td>{{r[0]}}</td><td>{{r[1]}}</td><td>{{r[2] or '—'}}</td><td>₹{{'%.2f'|format(r[3] or 0)}}</td></tr>{% else %}<tr><td colspan="4">No purchases for this period.</td></tr>{% endfor %}</tbody></table></section></main></body></html>'''

USERS_PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>User management</title><style>body{font-family:Arial,sans-serif;margin:0;background:#f3f5f9;color:#202b3c}header{background:#172554;color:white;padding:20px max(18px,calc((100% - 1000px)/2));display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}nav{background:white;padding:14px max(18px,calc((100% - 1000px)/2));display:flex;gap:18px}a{color:#2563eb;text-decoration:none;font-weight:bold}.container{max-width:1000px;margin:24px auto;padding:0 18px}.panel{background:white;padding:20px;border-radius:12px;margin-bottom:20px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}label{font-size:13px}input,select{box-sizing:border-box;width:100%;padding:10px;margin-top:6px;border:1px solid #cbd5e1;border-radius:6px}button{padding:10px 14px;background:#2563eb;color:white;border:0;border-radius:6px;margin-top:12px}.message{padding:10px;background:#dcfce7;color:#166534;border-radius:6px}.error{padding:10px;background:#fee2e2;color:#991b1b;border-radius:6px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid #e2e8f0}</style></head><body><header><div><b>Inventory Management System</b><div style="font-size:13px;margin-top:5px">User management · Signed in as {{current_username}}</div></div><form method="post" action="{{url_for('logout')}}"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><button>Log out</button></form></header><nav><a href="{{url_for('home')}}">Dashboard</a><a href="{{url_for('categories')}}">Categories</a><a href="{{url_for('suppliers')}}">Suppliers</a><a href="{{url_for('reports')}}">Reports</a><a href="{{url_for('users')}}">User management</a></nav><main class="container"><h1>User management</h1>{% if message %}<p class="{{'error' if is_error else 'message'}}">{{message}}</p>{% endif %}<section class="panel"><h2>Create user</h2><p>Create staff or read-only viewer accounts. Use a password with at least 12 characters.</p><form method="post" action="{{url_for('create_user')}}"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><div class="grid"><label>Username<input name="username" required minlength="3" maxlength="80" autocomplete="off"></label><label>Temporary password<input name="password" type="password" required minlength="12" autocomplete="new-password"></label><label>Role<select name="role"><option value="staff">Staff</option><option value="viewer">Viewer (read-only)</option><option value="admin">Admin</option></select></label></div><button>Create user</button></form></section><section class="panel"><h2>Existing users</h2><table><thead><tr><th>Username</th><th>Role</th><th>Active</th><th>Created</th></tr></thead><tbody>{% for u in users_list %}<tr><td>{{u['username']}}</td><td>{{u['role']}}</td><td>{{'Yes' if u['active'] else 'No'}}</td><td>{{u['created_at']}}</td></tr>{% endfor %}</tbody></table></section></main></body></html>'''



def get_connection():
    password = os.getenv("ORACLE_PASSWORD")
    if not password:
        raise RuntimeError('Set your Oracle password in PowerShell first: $env:ORACLE_PASSWORD = "YOUR_PASSWORD"')
    return oracledb.connect(
        user=os.getenv("ORACLE_USER", "inventory_app"),
        password=password,
        dsn=os.getenv("ORACLE_DSN", "localhost:1521/XEPDB1"),
    )


def next_id(cur, table, column):
    # Serialize ID allocation until transaction commit to avoid concurrent MAX(id)+1 collisions.
    allowed = {"INVENTORY": "InventoryID", "PURCHASE": "PurchaseID", "SALE": "SaleID"}
    if allowed.get(table) != column:
        raise ValueError("Unsupported ID allocation request.")
    cur.execute(f"LOCK TABLE {table} IN EXCLUSIVE MODE")
    cur.execute(f"SELECT NVL(MAX({column}), 0) + 1 FROM {table}")
    return int(cur.fetchone()[0])


def whole_number(value, label, minimum=0):
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a whole number.")
    if n < minimum:
        raise ValueError(f"{label} must be at least {minimum}.")
    return n


def money(value, label):
    try:
        n = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        raise ValueError(f"{label} must be a valid number.")
    if not n.is_finite() or n < 0:
        raise ValueError(f"{label} cannot be negative.")
    return n


def flash(message, error=False):
    return redirect(url_for("home", message=message, error="1" if error else "0"))



MASTER_PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{title}} · Inventory Management</title><style>body{font-family:Arial,sans-serif;margin:0;background:#f3f5f9;color:#202b3c}header{background:#172554;color:white;padding:20px max(18px,calc((100% - 1100px)/2));display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}nav{background:white;padding:14px max(18px,calc((100% - 1100px)/2));display:flex;gap:16px;flex-wrap:wrap}a{color:#2563eb;text-decoration:none;font-weight:bold}.container{max-width:1100px;margin:24px auto;padding:0 18px}.panel{background:white;padding:20px;border-radius:12px;margin-bottom:20px;overflow:auto}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}label{font-size:13px}input{box-sizing:border-box;width:100%;padding:9px;margin-top:5px;border:1px solid #cbd5e1;border-radius:6px}button{padding:9px 12px;background:#2563eb;color:white;border:0;border-radius:6px;margin-top:8px;cursor:pointer}.danger{background:#fee2e2;color:#991b1b}.message{padding:10px;background:#dcfce7;color:#166534;border-radius:6px}.error{padding:10px;background:#fee2e2;color:#991b1b;border-radius:6px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid #e2e8f0;vertical-align:top;font-size:13px}.muted{color:#64748b;font-size:13px}details form{min-width:200px;margin:8px 0}details input{margin:3px 0}summary{cursor:pointer;color:#2563eb;font-weight:bold}</style></head><body><header><div><b>Inventory Management System</b><div style="font-size:13px;margin-top:5px">{{title}} · {{current_username}} ({{current_role}})</div></div><form method="post" action="{{url_for('logout')}}"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><button>Log out</button></form></header><nav><a href="{{url_for('home')}}">Dashboard</a><a href="{{url_for('categories')}}">Categories</a><a href="{{url_for('suppliers')}}">Suppliers</a><a href="{{url_for('reports')}}">Reports</a>{% if current_role=='admin' %}<a href="{{url_for('users')}}">Users</a>{% endif %}</nav><main class="container"><h1>{{title}}</h1>{% if message %}<p class="{{'error' if is_error else 'message'}}">{{message}}</p>{% endif %}{% if current_role=='admin' %}<section class="panel"><h2>Add {{singular}}</h2><form method="post" action="{{add_url}}"><input type="hidden" name="csrf_token" value="{{csrf_token()}}">{% if entity=='categories' %}<div class="grid"><label>Category ID<input type="number" name="CategoryID" min="1" required></label><label>Category name<input name="CategoryName" maxlength="100" required></label><label>Description<input name="Description" maxlength="500"></label></div>{% else %}<div class="grid"><label>Supplier ID<input type="number" name="SupplierID" min="1" required></label><label>Supplier name<input name="SupplierName" maxlength="200" required></label><label>Email<input type="email" name="Email" maxlength="254"></label><label>Phone number<input name="PhoneNumber" maxlength="40"></label><label>Address<input name="Address" maxlength="500"></label></div>{% endif %}<button>Create {{singular}}</button></form></section>{% endif %}<section class="panel"><h2>Existing {{title|lower}}</h2><div style="overflow:auto"><table><thead>{% if entity=='categories' %}<tr><th>ID</th><th>Name</th><th>Description</th>{% if current_role=='admin' %}<th>Actions</th>{% endif %}</tr>{% else %}<tr><th>ID</th><th>Name</th><th>Email</th><th>Phone</th><th>Address</th>{% if current_role=='admin' %}<th>Actions</th>{% endif %}</tr>{% endif %}</thead><tbody>{% for r in rows %}{% if entity=='categories' %}<tr><td>{{r[0]}}</td><td>{{r[1]}}</td><td>{{r[2] or '—'}}</td>{% if current_role=='admin' %}<td><details><summary>Edit</summary><form method="post" action="{{url_for('update_category',item_id=r[0])}}"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><label>Category name<input name="CategoryName" value="{{r[1] or ''}}" required maxlength="100"></label><label>Description<input name="Description" value="{{r[2] or ''}}" maxlength="500"></label><button>Save changes</button></form></details><form method="post" action="{{url_for('delete_category',item_id=r[0])}}" onsubmit="return confirm('Delete this category? Products may prevent deletion.')"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><button class="danger">Delete</button></form></td>{% endif %}</tr>{% else %}<tr><td>{{r[0]}}</td><td>{{r[1]}}</td><td>{{r[2] or '—'}}</td><td>{{r[3] or '—'}}</td><td>{{r[4] or '—'}}</td>{% if current_role=='admin' %}<td><details><summary>Edit</summary><form method="post" action="{{url_for('update_supplier',item_id=r[0])}}"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><label>Supplier name<input name="SupplierName" value="{{r[1] or ''}}" required maxlength="200"></label><label>Email<input type="email" name="Email" value="{{r[2] or ''}}" maxlength="254"></label><label>Phone number<input name="PhoneNumber" value="{{r[3] or ''}}" maxlength="40"></label><label>Address<input name="Address" value="{{r[4] or ''}}" maxlength="500"></label><button>Save changes</button></form></details><form method="post" action="{{url_for('delete_supplier',item_id=r[0])}}" onsubmit="return confirm('Delete this supplier? Products or purchases may prevent deletion.')"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><button class="danger">Delete</button></form></td>{% endif %}</tr>{% endif %}{% else %}<tr><td colspan="6">No records found.</td></tr>{% endfor %}</tbody></table></div><p class="muted">Database constraints may prevent deleting categories or suppliers already used by products or transactions.</p></section></main></body></html>'''
PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Inventory Management System</title><style>
*{box-sizing:border-box}body{margin:0;font-family:Arial,sans-serif;background:#f3f5f9;color:#202b3c}header{background:#172554;color:white;padding:22px max(20px,calc((100% - 1200px)/2));display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}header h1{margin:0;font-size:24px}header p{margin:6px 0 0;color:#cbd5e1}nav{background:white;padding:0 max(20px,calc((100% - 1200px)/2));display:flex;flex-wrap:wrap;border-bottom:1px solid #e2e8f0}nav a{padding:14px 12px;color:#334155;text-decoration:none;font-weight:bold;font-size:13px}nav a:hover{background:#eff6ff;color:#2563eb}.container{max-width:1200px;margin:26px auto;padding:0 18px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:14px}.card,.panel{background:white;border-radius:12px;padding:20px;box-shadow:0 3px 12px #0f172a0c;margin-bottom:20px}.stat-label{color:#64748b;font-size:13px}.stat-value{font-size:28px;font-weight:bold;margin-top:8px}h2{font-size:19px;margin:0 0 14px}h3{font-size:15px;margin:0 0 12px}.muted{color:#64748b;font-size:13px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px}label{font-size:12px;color:#475569;display:block}input,select{width:100%;padding:10px;border:1px solid #cbd5e1;border-radius:7px;margin-top:6px;background:white}button{border:0;border-radius:7px;padding:10px 13px;cursor:pointer;font-weight:bold;margin-top:11px}.primary{background:#2563eb;color:white}.danger{background:#fee2e2;color:#991b1b}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;min-width:650px}th,td{text-align:left;padding:12px;border-bottom:1px solid #e2e8f0;font-size:13px}th{background:#f8fafc;color:#64748b;font-size:11px;text-transform:uppercase}.tag{display:inline-block;background:#dbeafe;color:#1d4ed8;padding:4px 8px;border-radius:20px}.low{background:#fee2e2;color:#991b1b}.message,.error{padding:12px;border-radius:8px;margin-bottom:16px}.message{background:#dcfce7;color:#166534}.error{background:#fee2e2;color:#991b1b}.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:18px}.inline{display:flex;gap:5px;align-items:center}.inline input{width:95px;margin:0}.inline button{margin:0}footer{text-align:center;color:#64748b;padding:20px;font-size:12px}@media(max-width:600px){.container{padding:0 10px}.card,.panel{padding:15px}}
</style></head><body>
<header><div><h1>Inventory Management System</h1><p>Small Business · Inventory, purchases and sales</p></div><span>● Oracle Database</span></header>
<nav><a href="#dashboard">Dashboard</a><a href="#products">Products</a><a href="#alerts">Low-stock Alerts</a><a href="{{url_for('categories')}}">Categories</a><a href="{{url_for('suppliers')}}">Suppliers</a><a href="{{url_for('reports')}}">Reports</a>{% if current_role == 'admin' %}<a href="{{url_for('users')}}">Users</a>{% endif %}<span style="margin-left:auto;padding:12px 0;font-size:12px">{{current_username}} · {{current_role}}</span><form method="post" action="{{url_for('logout')}}" style="margin:0"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><button style="margin:5px 0;background:#fee2e2;color:#991b1b">Log out</button></form></nav>
<div class="container">{% if message %}<div class="{{ 'error' if is_error else 'message' }}">{{ message }}</div>{% endif %}
{% if db_error %}<div class="error"><b>Database error:</b> {{ db_error }}<br>Confirm Oracle is running, the password is configured, and all eight tables exist.</div>{% else %}
<section id="dashboard" class="stats"><div class="card"><div class="stat-label">Total Products</div><div class="stat-value">{{ products|length }}</div></div><div class="card"><div class="stat-label">Units in Stock</div><div class="stat-value">{{ total_stock }}</div></div><div class="card"><div class="stat-label">Stock Value (selling price)</div><div class="stat-value">₹{{ '%.2f'|format(total_value) }}</div></div><div class="card"><div class="stat-label">Low-stock Products</div><div class="stat-value">{{ low_stock|length }}</div></div><div class="card"><div class="stat-label">Purchases</div><div class="stat-value">{{ purchase_count }}</div></div><div class="card"><div class="stat-label">Sales</div><div class="stat-value">{{ sale_count }}</div></div></section>
<div class="two">{% if current_role in ['admin','staff'] %}<section id="purchase" class="panel"><h2>＋ Record Purchase / Restock</h2><p class="muted">Records a purchase and increases stock.</p><form method="post" action="{{ url_for('ui_purchase') }}"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><div class="grid"><div><label>Supplier</label><select name="SupplierID" required>{% for s in suppliers %}<option value="{{s[0]}}">{{s[0]}} — {{s[1]}}</option>{% endfor %}</select></div><div><label>Product</label><select name="ProductID" required>{% for p in products %}<option value="{{p[0]}}">{{p[2]}} (stock {{p[7]}})</option>{% endfor %}</select></div><div><label>Quantity</label><input name="Quantity" type="number" min="1" step="1" required></div><div><label>Unit Cost (₹)</label><input name="UnitCost" type="number" min="0" step="0.01" required></div></div><button class="primary">Save Purchase & Add Stock</button></form></section>
<section id="sale" class="panel"><h2>− Record Sale</h2><p class="muted">Records a sale and reduces stock only if enough units are available.</p><form method="post" action="{{ url_for('ui_sale') }}"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><div class="grid"><div><label>Product</label><select id="saleProduct" name="ProductID" required>{% for p in products %}<option value="{{p[0]}}" data-price="{{p[3]}}">{{p[2]}} (stock {{p[7]}})</option>{% endfor %}</select></div><div><label>Quantity</label><input name="Quantity" type="number" min="1" step="1" required></div><div><label>Unit Selling Price (₹)</label><input id="salePrice" name="UnitPrice" type="number" min="0" step="0.01" required></div></div><button class="primary">Save Sale & Reduce Stock</button></form></section></div>{% endif %}
<section id="products" class="panel"><h2>Product Inventory</h2><form method="get" action="{{url_for('home')}}" class="grid" style="margin-bottom:18px"><div><label>Search name, code, category or supplier</label><input name="q" value="{{q}}" placeholder="Search products..."></div><div><label>Category</label><select name="category"><option value="">All categories</option>{% for c in categories %}<option value="{{c[0]}}" {{'selected' if category_filter == (c[0]|string) else ''}}>{{c[1]}}</option>{% endfor %}</select></div><div style="display:flex;align-items:end;gap:8px"><label style="display:flex;align-items:center;gap:6px"><input type="checkbox" name="low" value="1" style="width:auto;margin:0" {{'checked' if low_only else ''}}> Low stock only</label><button class="primary" type="submit">Search / Filter</button><a href="{{url_for('home')}}" style="align-self:center">Clear</a></div></form>{% if current_role == 'admin' %}<h3>Add New Product</h3><form method="post" action="{{url_for('ui_add')}}"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><div class="grid"><div><label>Product ID</label><input name="ProductID" type="number" min="1" required></div><div><label>Product Code</label><input name="ProductCode" required></div><div><label>Product Name</label><input name="ProductName" required></div><div><label>Unit Price (₹)</label><input name="UnitPrice" type="number" min="0" step="0.01" required></div><div><label>Reorder Level</label><input name="ReorderLevel" type="number" min="0" value="10" required></div><div><label>Category</label><select name="CategoryID" required>{% for c in categories %}<option value="{{c[0]}}">{{c[0]}} — {{c[1]}}</option>{% endfor %}</select></div><div><label>Supplier</label><select name="SupplierID" required>{% for s in suppliers %}<option value="{{s[0]}}">{{s[0]}} — {{s[1]}}</option>{% endfor %}</select></div></div><button class="primary">Add Product</button></form>{% endif %}<hr style="border:0;border-top:1px solid #e2e8f0;margin:22px 0"><div class="table-wrap"><table><thead><tr><th>ID</th><th>Code</th><th>Product</th><th>Price</th><th>Stock</th><th>Reorder Level</th><th>Category</th><th>Supplier</th>{% if current_role == 'admin' %}<th>Actions</th>{% endif %}</tr></thead><tbody>{% for p in display_products %}<tr><td>{{p[0]}}</td><td><span class="tag">{{p[1]}}</span></td><td><b>{{p[2]}}</b></td><td>₹{{'%.2f'|format(p[3])}}</td><td><span class="tag {{'low' if p[7] <= p[4] else ''}}">{{p[7]}}</span></td><td>{{p[4]}}</td><td>{{p[5]}}</td><td>{{p[6]}}</td>{% if current_role == 'admin' %}<td><form class="inline" method="post" action="{{url_for('ui_update',product_id=p[0])}}"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input name="UnitPrice" type="number" min="0" step="0.01" value="{{p[3]}}" required aria-label="New price"><button class="primary">Update</button></form><form method="post" action="{{url_for('ui_delete',product_id=p[0])}}" onsubmit="return confirm('Delete this product? Products with purchase or sale history cannot be deleted.')"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><button class="danger">Delete</button></form></td>{% endif %}</tr>{% else %}<tr><td colspan="9">No products match these filters.</td></tr>{% endfor %}</tbody></table></div></section>
<div class="two"><section id="alerts" class="panel"><h2>⚠ Low-stock Alerts</h2><div class="table-wrap"><table><thead><tr><th>Product</th><th>Stock</th><th>Reorder Level</th></tr></thead><tbody>{% for p in low_stock %}<tr><td>{{p[2]}}</td><td><span class="tag low">{{p[7]}}</span></td><td>{{p[4]}}</td></tr>{% else %}<tr><td colspan="3">No low-stock products.</td></tr>{% endfor %}</tbody></table></div></section>
<section class="panel"><h2>Recent Purchases</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>Date</th><th>Supplier</th><th>Total</th></tr></thead><tbody>{% for r in purchases %}<tr><td>{{r[0]}}</td><td>{{r[1]}}</td><td>{{r[2]}}</td><td>₹{{'%.2f'|format(r[3])}}</td></tr>{% else %}<tr><td colspan="4">No purchases yet.</td></tr>{% endfor %}</tbody></table></div></section></div>
<section class="panel"><h2>Recent Sales</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>Date</th><th>Total</th></tr></thead><tbody>{% for r in sales %}<tr><td>{{r[0]}}</td><td>{{r[1]}}</td><td>₹{{'%.2f'|format(r[2])}}</td></tr>{% else %}<tr><td colspan="3">No sales yet.</td></tr>{% endfor %}</tbody></table></div></section>{% endif %}</div><footer>Inventory Management System · Flask + Python + Oracle Database 21c XE</footer>
<script>const ps=document.getElementById('saleProduct'),pr=document.getElementById('salePrice');function price(){if(ps&&pr){pr.value=ps.options[ps.selectedIndex]?.dataset.price||''}}if(ps){ps.addEventListener('change',price);price()}</script></body></html>'''


def dashboard_data():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT p.ProductID,p.ProductCode,p.ProductName,p.UnitPrice,NVL(p.ReorderLevel,10),c.CategoryName,s.SupplierName,NVL(i.QuantityInStock,0) FROM PRODUCT p LEFT JOIN CATEGORY c ON c.CategoryID=p.CategoryID LEFT JOIN SUPPLIER s ON s.SupplierID=p.SupplierID LEFT JOIN INVENTORY i ON i.ProductID=p.ProductID ORDER BY p.ProductID""")
            products = cur.fetchall()
            cur.execute("SELECT CategoryID,CategoryName FROM CATEGORY ORDER BY CategoryName")
            categories = cur.fetchall()
            cur.execute("SELECT SupplierID,SupplierName FROM SUPPLIER ORDER BY SupplierName")
            suppliers = cur.fetchall()
            cur.execute("SELECT COUNT(*) FROM PURCHASE")
            purchase_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM SALE")
            sale_count = cur.fetchone()[0]
            cur.execute("""SELECT p.PurchaseID,TO_CHAR(p.PurchaseDate,'YYYY-MM-DD'),s.SupplierName,p.TotalAmount FROM PURCHASE p LEFT JOIN SUPPLIER s ON s.SupplierID=p.SupplierID ORDER BY p.PurchaseDate DESC,p.PurchaseID DESC FETCH FIRST 5 ROWS ONLY""")
            purchases = cur.fetchall()
            cur.execute("SELECT SaleID,TO_CHAR(SaleDate,'YYYY-MM-DD'),TotalAmount FROM SALE ORDER BY SaleDate DESC,SaleID DESC FETCH FIRST 5 ROWS ONLY")
            sales = cur.fetchall()
    low = [p for p in products if int(p[7] or 0) <= int(p[4] or 0)]
    return dict(products=products,categories=categories,suppliers=suppliers,low_stock=low,
                total_stock=sum(int(p[7] or 0) for p in products),
                total_value=sum(float(p[3] or 0)*int(p[7] or 0) for p in products),
                purchase_count=purchase_count,sale_count=sale_count,purchases=purchases,sales=sales)


@app.route('/')
@login_required
def home():
    msg = request.args.get('message', '')
    err = request.args.get('error') == '1'
    try:
        data = dashboard_data()
        q = request.args.get('q', '').strip().casefold()
        category_filter = request.args.get('category', '').strip()
        low_only = request.args.get('low') == '1'
        display_products = data['products']
        if q:
            display_products = [p for p in display_products if q in ' '.join(str(v or '') for v in (p[1], p[2], p[5], p[6])).casefold()]
        # Category filtering uses the category name from the joined product rows.
        if category_filter:
            if not category_filter.isdigit() or int(category_filter) < 1:
                display_products = []
            else:
                with get_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute('SELECT CategoryName FROM CATEGORY WHERE CategoryID=:1', (int(category_filter),))
                        catrow = cur.fetchone()
                category_name = catrow[0] if catrow else None
                display_products = [p for p in display_products if p[5] == category_name]
        if low_only:
            display_products = [p for p in display_products if int(p[7] or 0) <= int(p[4] or 0)]
        return render_template_string(PAGE, **data, display_products=display_products, q=q,
                                      category_filter=category_filter, low_only=low_only,
                                      message=msg, is_error=err)
    except Exception:
        app.logger.exception('Dashboard failed')
        return 'The dashboard could not be loaded. Check the application log and Oracle connection settings.', 500
@app.route('/ui/add',methods=['POST'])
@login_required
@roles_required('admin')
def ui_add():
    try:
        f=request.form
        pid=whole_number(f.get('ProductID'),'Product ID',1); price=money(f.get('UnitPrice'),'Unit price')
        reorder=whole_number(f.get('ReorderLevel'),'Reorder level',0); cat=whole_number(f.get('CategoryID'),'Category',1); sup=whole_number(f.get('SupplierID'),'Supplier',1)
        code=f.get('ProductCode','').strip(); name=f.get('ProductName','').strip()
        if not code or not name: raise ValueError('Product code and product name are required.')
        if len(code) > 50 or len(name) > 200: raise ValueError('Product code must be at most 50 characters and product name at most 200 characters.')
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO PRODUCT (ProductID,ProductCode,ProductName,UnitPrice,ReorderLevel,CategoryID,SupplierID) VALUES (:1,:2,:3,:4,:5,:6,:7)",(pid,code,name,price,reorder,cat,sup))
                cur.execute("INSERT INTO INVENTORY (InventoryID,ProductID,QuantityInStock,LastUpdated) VALUES (:1,:2,0,SYSDATE)",(next_id(cur,'INVENTORY','InventoryID'),pid))
            conn.commit()
        return flash('Product added. Initial stock is 0; record a purchase to restock.')
    except ValueError as exc: return flash(str(exc), True)
    except Exception:
        app.logger.exception('Product creation failed')
        return flash('Could not add product. Check that the product code and ID are unique and the selected category/supplier exist.', True)


@app.route('/ui/update/<int:product_id>',methods=['POST'])
@login_required
@roles_required('admin')
def ui_update(product_id):
    try:
        price=money(request.form.get('UnitPrice'),'Unit price')
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('UPDATE PRODUCT SET UnitPrice=:1 WHERE ProductID=:2',(price,product_id))
                if cur.rowcount==0: conn.rollback(); return flash('Product not found.',True)
            conn.commit()
        return flash('Product price updated.')
    except ValueError as exc: return flash(str(exc), True)
    except Exception:
        app.logger.exception('Product update failed')
        return flash('Product update failed. Please verify the product and try again.', True)


@app.route('/ui/delete/<int:product_id>',methods=['POST'])
@login_required
@roles_required('admin')
def ui_delete(product_id):
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('DELETE FROM INVENTORY WHERE ProductID=:1',(product_id,))
                cur.execute('DELETE FROM PRODUCT WHERE ProductID=:1',(product_id,))
                if cur.rowcount==0: conn.rollback(); return flash('Product not found.',True)
            conn.commit()
        return flash('Product deleted.')
    except Exception:
        app.logger.exception('Product deletion failed')
        return flash('Could not delete product. It may have purchase or sale history.', True)


@app.route('/ui/purchase',methods=['POST'])
@login_required
@roles_required('admin', 'staff')
def ui_purchase():
    try:
        f=request.form; supplier=whole_number(f.get('SupplierID'),'Supplier',1); product=whole_number(f.get('ProductID'),'Product',1); qty=whole_number(f.get('Quantity'),'Quantity',1); cost=money(f.get('UnitCost'),'Unit cost'); total=cost*qty
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT ProductID FROM PRODUCT WHERE ProductID=:1',(product,))
                if not cur.fetchone(): raise ValueError('Product does not exist.')
                cur.execute('SELECT SupplierID FROM SUPPLIER WHERE SupplierID=:1',(supplier,))
                if not cur.fetchone(): raise ValueError('Supplier does not exist.')
                purchase_id=next_id(cur,'PURCHASE','PurchaseID')
                cur.execute('INSERT INTO PURCHASE (PurchaseID,SupplierID,PurchaseDate,TotalAmount) VALUES (:1,:2,SYSDATE,:3)',(purchase_id,supplier,total))
                cur.execute('INSERT INTO PURCHASE_ITEM (PurchaseID,ProductID,Quantity,UnitCost) VALUES (:1,:2,:3,:4)',(purchase_id,product,qty,cost))
                cur.execute('SELECT InventoryID FROM INVENTORY WHERE ProductID=:1 FOR UPDATE',(product,)); inv=cur.fetchone()
                if inv: cur.execute('UPDATE INVENTORY SET QuantityInStock=QuantityInStock+:1,LastUpdated=SYSDATE WHERE ProductID=:2',(qty,product))
                else: cur.execute('INSERT INTO INVENTORY (InventoryID,ProductID,QuantityInStock,LastUpdated) VALUES (:1,:2,:3,SYSDATE)',(next_id(cur,'INVENTORY','InventoryID'),product,qty))
            conn.commit()
        return flash(f'Purchase #{purchase_id} recorded; added {qty} unit(s) to stock.')
    except ValueError as exc: return flash(str(exc), True)
    except Exception:
        app.logger.exception('Purchase transaction failed')
        return flash('Purchase failed. Verify the product, supplier and database connection.', True)


@app.route('/ui/sale',methods=['POST'])
@login_required
@roles_required('admin', 'staff')
def ui_sale():
    try:
        f=request.form; product=whole_number(f.get('ProductID'),'Product',1); qty=whole_number(f.get('Quantity'),'Quantity',1); price=money(f.get('UnitPrice'),'Selling price'); total=price*qty
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT ProductName FROM PRODUCT WHERE ProductID=:1',(product,)); p=cur.fetchone()
                if not p: raise ValueError('Product does not exist.')
                cur.execute('SELECT QuantityInStock FROM INVENTORY WHERE ProductID=:1 FOR UPDATE',(product,)); row=cur.fetchone(); stock=int(row[0]) if row else 0
                if qty>stock: raise ValueError(f'Insufficient stock for {p[0]}. Available: {stock}; requested: {qty}.')
                sale_id=next_id(cur,'SALE','SaleID')
                cur.execute('INSERT INTO SALE (SaleID,SaleDate,TotalAmount) VALUES (:1,SYSDATE,:2)',(sale_id,total))
                cur.execute('INSERT INTO SALE_ITEM (SaleID,ProductID,Quantity,UnitPrice) VALUES (:1,:2,:3,:4)',(sale_id,product,qty,price))
                cur.execute('UPDATE INVENTORY SET QuantityInStock=QuantityInStock-:1,LastUpdated=SYSDATE WHERE ProductID=:2',(qty,product))
            conn.commit()
        return flash(f'Sale #{sale_id} recorded; removed {qty} unit(s) from stock.')
    except ValueError as exc: return flash(str(exc), True)
    except Exception:
        app.logger.exception('Sale transaction failed')
        return flash('Sale failed. Verify available stock and the database connection.', True)



@app.route('/products', methods=['GET'])
@login_required
def get_products():
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT p.ProductID, p.ProductCode, p.ProductName,
                           p.UnitPrice, p.ReorderLevel, p.CategoryID,
                           p.SupplierID, NVL(i.QuantityInStock, 0)
                    FROM PRODUCT p
                    LEFT JOIN INVENTORY i ON i.ProductID = p.ProductID
                    ORDER BY p.ProductID
                """)
                rows = cur.fetchall()

        products = [
            {
                'ProductID': r[0],
                'ProductCode': r[1],
                'ProductName': r[2],
                'UnitPrice': float(r[3]),
                'ReorderLevel': r[4],
                'CategoryID': r[5],
                'SupplierID': r[6],
                'QuantityInStock': r[7]
            }
            for r in rows
        ]
        return jsonify(products)

    except Exception as exc:
        return jsonify({'error': str(exc)}), 500
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('username'):
        return redirect(url_for('home'))
    error = ''
    next_url = request.args.get('next', '') if request.method == 'GET' else request.form.get('next', '')
    # Only allow local relative redirects to prevent open redirects.
    if not next_url.startswith('/') or next_url.startswith('//'):
        next_url = url_for('home')
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        now = int(datetime.now().timestamp())
        with auth_db() as conn:
            user = conn.execute('SELECT * FROM app_users WHERE username=? COLLATE NOCASE', (username,)).fetchone()
            if user and user['active'] and user['locked_until'] > now:
                error = 'Sign-in temporarily unavailable. Try again later.'
            elif user and user['active'] and verify_password(password, user['password_hash']):
                conn.execute('UPDATE app_users SET failed_attempts=0, locked_until=0 WHERE username=?', (user['username'],))
                session.clear()
                session['username'] = user['username']
                session['role'] = user['role']
                session.permanent = True
                csrf_token()
                return redirect(next_url)
            else:
                if user:
                    attempts = int(user['failed_attempts']) + 1
                    locked_until = now + 300 if attempts >= 5 else 0
                    conn.execute('UPDATE app_users SET failed_attempts=?, locked_until=? WHERE username=?',
                                 (0 if locked_until else attempts, locked_until, user['username']))
                error = 'Invalid username or password.'
    return render_template_string(LOGIN_PAGE, error=error, next_url=next_url)


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/reports')
@login_required
def reports():
    start = request.args.get('start', '').strip()
    end = request.args.get('end', '').strip()
    report_error = ''
    sales, purchases = [], []
    sales_total = purchases_total = 0.0
    try:
        for label, value in (('Start date', start), ('End date', end)):
            if value:
                datetime.strptime(value, '%Y-%m-%d')
        if start and end and start > end:
            raise ValueError('Start date must be on or before end date.')
        with get_connection() as conn:
            with conn.cursor() as cur:
                sql = "SELECT SaleID,TO_CHAR(SaleDate,'YYYY-MM-DD'),TotalAmount FROM SALE WHERE 1=1"
                params = []
                if start:
                    params.append(start)
                    sql += f" AND TRUNC(SaleDate) >= TO_DATE(:{len(params)},'YYYY-MM-DD')"
                if end:
                    params.append(end)
                    sql += f" AND TRUNC(SaleDate) <= TO_DATE(:{len(params)},'YYYY-MM-DD')"
                sql += " ORDER BY SaleDate DESC, SaleID DESC"
                cur.execute(sql, params)
                sales = cur.fetchall()
                sql = "SELECT p.PurchaseID,TO_CHAR(p.PurchaseDate,'YYYY-MM-DD'),s.SupplierName,p.TotalAmount FROM PURCHASE p LEFT JOIN SUPPLIER s ON s.SupplierID=p.SupplierID WHERE 1=1"
                params = []
                if start:
                    params.append(start)
                    sql += f" AND TRUNC(p.PurchaseDate) >= TO_DATE(:{len(params)},'YYYY-MM-DD')"
                if end:
                    params.append(end)
                    sql += f" AND TRUNC(p.PurchaseDate) <= TO_DATE(:{len(params)},'YYYY-MM-DD')"
                sql += " ORDER BY p.PurchaseDate DESC, p.PurchaseID DESC"
                cur.execute(sql, params)
                purchases = cur.fetchall()
        sales_total = sum(float(r[2] or 0) for r in sales)
        purchases_total = sum(float(r[3] or 0) for r in purchases)
    except ValueError as exc:
        report_error = str(exc)
    except Exception:
        app.logger.exception('Report query failed')
        report_error = 'The report could not be loaded. Check the database connection and application log.'
    return render_template_string(REPORT_PAGE, start=start, end=end, report_error=report_error,
                                  sales=sales, purchases=purchases, sales_total=sales_total,
                                  purchases_total=purchases_total)


@app.route('/users')
@login_required
@roles_required('admin')
def users():
    message = request.args.get('message', '')
    is_error = request.args.get('error') == '1'
    with auth_db() as conn:
        users_list = conn.execute('SELECT username, role, active, created_at FROM app_users ORDER BY username').fetchall()
    return render_template_string(USERS_PAGE, users_list=users_list, message=message, is_error=is_error)


@app.route('/users/create', methods=['POST'])
@login_required
@roles_required('admin')
def create_user():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'viewer').strip().lower()
    if len(username) < 3 or len(username) > 80:
        return redirect(url_for('users', message='Username must contain 3–80 characters.', error='1'))
    if len(password) < 12:
        return redirect(url_for('users', message='Password must contain at least 12 characters.', error='1'))
    if role not in ROLES:
        return redirect(url_for('users', message='Choose a valid role.', error='1'))
    try:
        with auth_db() as conn:
            conn.execute('INSERT INTO app_users(username,password_hash,role) VALUES(?,?,?)',
                         (username, hash_password(password), role))
        return redirect(url_for('users', message='User created successfully.'))
    except sqlite3.IntegrityError:
        return redirect(url_for('users', message='That username already exists.', error='1'))


@app.route('/categories')
@login_required
def categories():
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT CategoryID, CategoryName, Description FROM CATEGORY ORDER BY CategoryName')
                rows = cur.fetchall()
        return render_template_string(MASTER_PAGE, title='Categories', singular='category', entity='categories',
                                      rows=rows, add_url=url_for('add_category'), message=request.args.get('message',''),
                                      is_error=request.args.get('error')=='1')
    except Exception:
        app.logger.exception('Categories page failed')
        return 'Could not load categories. Check the Oracle connection.', 500


@app.route('/suppliers')
@login_required
def suppliers():
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT SupplierID, SupplierName, Email, PhoneNumber, Address FROM SUPPLIER ORDER BY SupplierName')
                rows = cur.fetchall()
        return render_template_string(MASTER_PAGE, title='Suppliers', singular='supplier', entity='suppliers',
                                      rows=rows, add_url=url_for('add_supplier'), message=request.args.get('message',''),
                                      is_error=request.args.get('error')=='1')
    except Exception:
        app.logger.exception('Suppliers page failed')
        return 'Could not load suppliers. Check the Oracle connection.', 500


@app.route('/categories/add', methods=['POST'])
@login_required
@roles_required('admin')
def add_category():
    try:
        item_id = whole_number(request.form.get('CategoryID'), 'Category ID', 1)
        name = request.form.get('CategoryName','').strip()
        description = request.form.get('Description','').strip() or None
        if not name or len(name)>100: raise ValueError('Category name is required and must be at most 100 characters.')
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('INSERT INTO CATEGORY(CategoryID,CategoryName,Description) VALUES(:1,:2,:3)', (item_id,name,description))
            conn.commit()
        return redirect(url_for('categories', message='Category created.'))
    except ValueError as exc: return redirect(url_for('categories', message=str(exc), error='1'))
    except Exception:
        app.logger.exception('Category creation failed')
        return redirect(url_for('categories', message='Could not create category. Check that the ID/name is unique.', error='1'))


@app.route('/categories/<int:item_id>/update', methods=['POST'])
@login_required
@roles_required('admin')
def update_category(item_id):
    name=request.form.get('CategoryName','').strip(); description=request.form.get('Description','').strip() or None
    if not name or len(name)>100: return redirect(url_for('categories',message='Category name is required and must be at most 100 characters.',error='1'))
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('UPDATE CATEGORY SET CategoryName=:1, Description=:2 WHERE CategoryID=:3',(name,description,item_id))
                if cur.rowcount==0: conn.rollback(); return redirect(url_for('categories',message='Category not found.',error='1'))
            conn.commit()
        return redirect(url_for('categories',message='Category updated.'))
    except Exception:
        app.logger.exception('Category update failed')
        return redirect(url_for('categories',message='Could not update category. The name may already be in use.',error='1'))


@app.route('/categories/<int:item_id>/delete', methods=['POST'])
@login_required
@roles_required('admin')
def delete_category(item_id):
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('DELETE FROM CATEGORY WHERE CategoryID=:1',(item_id,))
                if cur.rowcount==0: conn.rollback(); return redirect(url_for('categories',message='Category not found.',error='1'))
            conn.commit()
        return redirect(url_for('categories',message='Category deleted.'))
    except Exception:
        app.logger.exception('Category deletion failed')
        return redirect(url_for('categories',message='Could not delete category because it may be used by products.',error='1'))


@app.route('/suppliers/add', methods=['POST'])
@login_required
@roles_required('admin')
def add_supplier():
    try:
        item_id=whole_number(request.form.get('SupplierID'),'Supplier ID',1)
        name=request.form.get('SupplierName','').strip(); email=request.form.get('Email','').strip() or None
        phone=request.form.get('PhoneNumber','').strip() or None; address=request.form.get('Address','').strip() or None
        if not name or len(name)>200: raise ValueError('Supplier name is required and must be at most 200 characters.')
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('INSERT INTO SUPPLIER(SupplierID,SupplierName,Email,PhoneNumber,Address) VALUES(:1,:2,:3,:4,:5)',(item_id,name,email,phone,address))
            conn.commit()
        return redirect(url_for('suppliers',message='Supplier created.'))
    except ValueError as exc: return redirect(url_for('suppliers',message=str(exc),error='1'))
    except Exception:
        app.logger.exception('Supplier creation failed')
        return redirect(url_for('suppliers',message='Could not create supplier. Check that the ID/email is unique.',error='1'))


@app.route('/suppliers/<int:item_id>/update', methods=['POST'])
@login_required
@roles_required('admin')
def update_supplier(item_id):
    name=request.form.get('SupplierName','').strip(); email=request.form.get('Email','').strip() or None
    phone=request.form.get('PhoneNumber','').strip() or None; address=request.form.get('Address','').strip() or None
    if not name or len(name)>200: return redirect(url_for('suppliers',message='Supplier name is required and must be at most 200 characters.',error='1'))
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('UPDATE SUPPLIER SET SupplierName=:1,Email=:2,PhoneNumber=:3,Address=:4 WHERE SupplierID=:5',(name,email,phone,address,item_id))
                if cur.rowcount==0: conn.rollback(); return redirect(url_for('suppliers',message='Supplier not found.',error='1'))
            conn.commit()
        return redirect(url_for('suppliers',message='Supplier updated.'))
    except Exception:
        app.logger.exception('Supplier update failed')
        return redirect(url_for('suppliers',message='Could not update supplier. The email may already be in use.',error='1'))


@app.route('/suppliers/<int:item_id>/delete', methods=['POST'])
@login_required
@roles_required('admin')
def delete_supplier(item_id):
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('DELETE FROM SUPPLIER WHERE SupplierID=:1',(item_id,))
                if cur.rowcount==0: conn.rollback(); return redirect(url_for('suppliers',message='Supplier not found.',error='1'))
            conn.commit()
        return redirect(url_for('suppliers',message='Supplier deleted.'))
    except Exception:
        app.logger.exception('Supplier deletion failed')
        return redirect(url_for('suppliers',message='Could not delete supplier because it may be used by products or purchases.',error='1'))


@app.errorhandler(403)
def forbidden(error):
    return 'Access denied: your account does not have permission to perform this action.', 403


@app.errorhandler(400)
def bad_request(error):
    return 'Request rejected. Refresh the page and try again. ' + (error.description if getattr(error, 'description', None) else ''), 400


init_auth_db()


if __name__ == '__main__':
    # Debug mode is disabled by default; enable only for local development if needed.
    app.run(debug=os.getenv('FLASK_DEBUG', '0') == '1', host='127.0.0.1', port=int(os.getenv('PORT', '5000')))

