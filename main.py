import os
import sqlite3
from datetime import datetime

from flask import (
    Flask, render_template, redirect, url_for,
    session, request, flash
)
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
import csv




app = Flask(__name__)
app.secret_key = "SUPER_SECRET_KEY_CHANGE_THIS"

# ============================================================
# HARD-CODED GOOGLE OAUTH CONFIG
# ============================================================

GOOGLE_CLIENT_ID = "970893101025-tfcddrq6204md1vlvms9q5624ucfl1a5.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
ADMIN_PASSWORD = "bstadmin"
REDIRECT_URI = "https://bstannouncements.onrender.com"

# Initialize LoginManager


ALLOWED_EMAIL = "sammydennehy2011@gmail.com"

oauth = OAuth(app)

oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile"
    }
)


# ============================================================
# DATABASE
# ============================================================

DB_PATH = os.path.join(os.path.dirname(__file__), "portal.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# DATABASE
# ============================================================

def init_db():
    conn = get_db()

    # USERS TABLE
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            google_email TEXT NOT NULL,
            name TEXT NOT NULL,
            pin_hash TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # Make sure roles column exists
    columns = [col["name"] for col in conn.execute("PRAGMA table_info(users)")]
    if "roles" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN roles TEXT DEFAULT ''")

    # ANNOUNCEMENTS TABLE
    conn.execute("""
        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            program TEXT,
            tag TEXT,
            created_at TEXT NOT NULL,
            author TEXT NOT NULL,
            is_draft INTEGER DEFAULT 0,
            is_hidden INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()
    
# ============================================================
# SENDING BULK EMAILS 
# ============================================================

def send_bulk_email(subject, html_content, recipients):
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail
    import os

    sg = SendGridAPIClient(os.environ.get("SENDGRID_API_KEY"))

    for email in recipients:
        message = Mail(
            from_email="sammydennehy2011@gmail.com",
            to_emails=email,
            subject=subject,
            html_content=html_content
        )
        sg.send(message)


# ============================================================
# USER FUNCTIONS
# ============================================================

def get_user(email, name):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM users WHERE google_email = ? AND name = ?",
        (email, name),
    ).fetchone()
    conn.close()
    return row



def create_user(email, name, role):
    now = datetime.utcnow().isoformat()
    conn = get_db()
    conn.execute(
        """
        INSERT INTO users (google_email, name, role, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (email, name, role, now),
    )
    conn.commit()
    user_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    conn.close()
    return user_id






def set_pin(user_id, pin_plain):
    pin_hash = generate_password_hash(pin_plain)
    conn = get_db()
    conn.execute("UPDATE users SET pin_hash = ? WHERE id = ?", (pin_hash, user_id))
    conn.commit()
    conn.close()


def verify_pin(user_id, pin_plain):
    conn = get_db()
    row = conn.execute("SELECT pin_hash FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if not row or not row["pin_hash"]:
        return False
    return check_password_hash(row["pin_hash"], pin_plain)


def get_user_by_id(user_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row

# ------------------ Manage Team Functions ------------------ #

def get_all_users():
    conn = get_db()
    rows = conn.execute("SELECT * FROM users ORDER BY name").fetchall()
    conn.close()
    return rows

def update_user_roles(user_id, roles_list):
    roles_str = ",".join(roles_list)
    conn = get_db()
    conn.execute("UPDATE users SET roles = ? WHERE id = ?", (roles_str, user_id))
    conn.commit()
    conn.close()

def reset_user_pin(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET pin_hash = NULL WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def remove_user(name):
    global STAFF_NAMES, ADMIN_NAMES
    STAFF_NAMES = [n for n in STAFF_NAMES if n != name]
    ADMIN_NAMES.discard(name)

    conn = get_db()
    conn.execute("DELETE FROM users WHERE name = ?", (name,))
    conn.commit()
    conn.close()


# ============================================================
# ANNOUNCEMENTS FUNCTIONS (KEEPING YOUR SYSTEM)
# ============================================================

def format_date(date_str):
    dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M")
    day = dt.day
    if 4 <= day <= 20 or 24 <= day <= 30:
        suffix = "th"
    else:
        suffix = ["st", "nd", "rd"][day % 10 - 1]
    return dt.strftime(f"%A, %B {day}{suffix}, %Y")


def get_published_announcements():
    conn = get_db()
    rows = conn.execute(
        """
        SELECT * FROM announcements
        WHERE is_draft = 0 AND is_hidden = 0
        ORDER BY datetime(created_at) DESC
        """
    ).fetchall()
    conn.close()
    return [
        dict(row, formatted_date=format_date(row["created_at"]))
        for row in rows
    ]


def get_drafts():
    conn = get_db()
    rows = conn.execute(
        """
        SELECT * FROM announcements
        WHERE is_draft = 1
        ORDER BY datetime(created_at) DESC
        """
    ).fetchall()
    conn.close()
    return [
        dict(row, formatted_date=format_date(row["created_at"]))
        for row in rows
    ]


def get_admin_published():
    conn = get_db()
    rows = conn.execute(
        """
        SELECT * FROM announcements
        WHERE is_draft = 0
        ORDER BY datetime(created_at) DESC
        """
    ).fetchall()
    conn.close()
    return [
        dict(row, formatted_date=format_date(row["created_at"]))
        for row in rows
    ]


def get_announcement(aid):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM announcements WHERE id = ?", (aid,)
    ).fetchone()
    conn.close()
    return row


def save_announcement(title, body, program, tag=None, is_draft=False, existing_id=None):
    conn = get_db()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Pull author from session
    author = session.get("user_name") or session.get("google_email")
    if not author:
        author = "Unknown"

    if existing_id:
        # UPDATE existing announcement
        conn.execute(
            """
            UPDATE announcements
            SET title = ?, body = ?, program = ?, tag = ?, is_draft = ?, created_at = ?, author = ?
            WHERE id = ?
            """,
            (title, body, program, tag, int(is_draft), now, author, existing_id),
        )
    else:
        # INSERT new announcement
        conn.execute(
            """
            INSERT INTO announcements (title, body, program, tag, created_at, author, is_draft)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (title, body, program, tag, now, author, int(is_draft)),
        )

    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template('homepage/home.html')  # Renders your homepage

@app.route('/history')
def history():
    return render_template('dashboard/history.html')  # Renders your homepage

# Generic error handler for all HTTP exceptions and other errors
import traceback

@app.errorhandler(Exception)
def handle_all_errors(e):
    code = 500
    # Default message
    message = "Something went wrong. Please try again later."
    error_detail = ""

    # If it's an HTTPException, we can use its code and description
    if isinstance(e, HTTPException):
        code = e.code
        message = e.description
    else:
        # For non-HTTP exceptions, include the error type and message
        error_detail = f"{type(e).__name__}: {str(e)}\n\n{traceback.format_exc()}"

    return render_template(
        "misc/error.html",
        code=code,
        message=message,
        error_detail=error_detail
    ), code

# ============================================================
# ADMIN ANNOUNCEMENTS PANEL (UNCHANGED)
# ============================================================

# ============================================================
# MANAGE TEAM ROUTE
# ============================================================

@app.route("/manage-team", methods=["GET", "POST"])
def manage_team():
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    # All possible staff
    STAFF_NAMES_LIST = [
        "Rainer", "Elaine", "Evan", "Edwin", "Nylah",
        "Sam", "Conor", "Ethan", "Jasmine", "Tiana"
    ]
    ADMIN_NAMES_SET = {"Rainer", "Elaine", "Evan"}

    ROLE_OPTIONS = [
        "Volunteer", "Sound/Tech Support", "Production Staff",
        "Head of A/V", "Production Manager", "Executive Manager", "Director"
    ]

    users_in_db = {u["name"]: u for u in get_all_users()}

    # Ensure all staff are represented
    users = []
    for name in STAFF_NAMES_LIST:
        if name in users_in_db:
            users.append(users_in_db[name])
        else:
            # Placeholder user for people not yet in DB
            users.append({
                "id": 0,  # 0 means not yet in DB
                "name": name,
                "roles": "",
                "last_login": None
            })

    if request.method == "POST":
        action = request.form.get("action")
        user_id = request.form.get("user_id")
        user_name = request.form.get("new_name")  # match input field name


        if action == "add_user" and user_name:
            if user_name not in users_in_db:
                role = "admin" if user_name in ADMIN_NAMES_SET else "standard"
                new_id = create_user(session.get("google_email"), user_name, role)
                flash(f"{user_name} added to the team.", "success")
            return redirect(url_for("manage_team"))

        elif action == "reset_pin" and user_id:
            reset_user_pin(user_id)
            flash("PIN has been reset.", "success")

        elif action == "remove" and user_id:
            user = get_user_by_id(user_id)
            remove_user(user["name"])
            flash(f"{user['name']} removed.", "success")



        elif action == "save_all":
            # Update roles for all users in DB
            for u in users:
                if u["id"] == 0:
                    continue  # skip placeholders
                selected_roles = request.form.get(f"roles_{u['id']}", "")
                # Convert to list, ignore empty strings
                roles_list = [r.strip() for r in selected_roles.split(",") if r.strip()]
                update_user_roles(u["id"], roles_list)

            flash("All roles updated successfully.", "success")

        return redirect(url_for("manage_team"))

    return render_template(
        "dashboard/manage-team.html",
        users=users,
        ROLE_OPTIONS=ROLE_OPTIONS
    )


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not session.get("logged_in"):
        return redirect(url_for("admin_login"))

    draft_id = request.args.get("draft_id")
    editing_draft = None

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        program = request.form.get("program", "").strip()
        submit_type = request.form.get("submit_type")
        existing_id = request.form.get("announcement_id") or None

        if title and body:
            if submit_type == "draft":
                save_announcement(title, body, program, is_draft=True, existing_id=existing_id)
            else:
                save_announcement(title, body, program, is_draft=False, existing_id=existing_id)
            return redirect(url_for("admin"))

    if draft_id:
        editing_draft = get_announcement(draft_id)

    drafts = get_drafts()
    announcements = get_admin_published()
    return render_template(
        "announcements/admin.html",
        drafts=drafts,
        announcements=announcements,
        editing_draft=editing_draft,
        login_only=False,
        error=None,
    )


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == ADMIN_PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("admin"))
        return render_template("announcements/admin.html", login_only=True, error="Incorrect password")

    return render_template("announcements/admin.html", login_only=True, error=None)


@app.route("/admin/logout")
def admin_logout():
    session.pop("logged_in", None)
    return redirect(url_for("home"))


@app.route("/admin/hide/<int:aid>")
def hide_announcement(aid):
    if not session.get("logged_in"):
        return redirect(url_for("admin_login"))
    conn = get_db()
    conn.execute("UPDATE announcements SET is_hidden = 1 WHERE id = ?", (aid,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin"))


@app.route("/admin/delete/<int:aid>")
def delete_announcement(aid):
    if not session.get("logged_in"):
        return redirect(url_for("admin_login"))
    conn = get_db()
    conn.execute("DELETE FROM announcements WHERE id = ?", (aid,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin"))


# ============================================================
# STAFF CONFIG
# ============================================================

STAFF_NAMES = [
    "Rainer", "Elaine", "Evan", "Edwin", "Nylah",
    "Sam", "Conor", "Ethan", "Jasmine", "Tiana"
]

ADMIN_NAMES = {"Rainer", "Elaine", "Evan"}


# ============================================================
# ROUTES
# ============================================================

@app.route("/admin/send-announcement", methods=["GET", "POST"])
def send_announcement_email():
    if not session.get("logged_in"):
        return redirect(url_for("admin_login"))

    if request.method == "POST":
        csv_file = request.files.get("csv")
        subject = request.form.get("subject", "").strip()
        body = request.form.get("body", "").strip()

        if not csv_file or not subject or not body:
            flash("CSV, subject, and body are required.", "error")
            return redirect(request.url)

        recipients = []

        try:
            stream = csv_file.stream.read().decode("utf-8").splitlines()
            reader = csv.reader(stream)

            for row in reader:
                if row and "@" in row[0]:
                    recipients.append(row[0].strip())

        except Exception as e:
            flash("Invalid CSV file.", "error")
            return redirect(request.url)

        if not recipients:
            flash("No valid emails found.", "error")
            return redirect(request.url)

        send_bulk_email(subject, body, recipients)

        flash(f"Announcement sent to {len(recipients)} recipients.", "success")
        return redirect(url_for("admin"))

    return render_template("announcements/send_email.html")


@app.route("/announcements")
def announcements():
    # This will display real announcements
    published = get_published_announcements()
    return render_template("announcements/announcements.html", announcements=published)


# ---------------- LOGIN WIZARD ---------------- #

@app.route("/login")
def login_page():
    step = request.args.get("step", "start")

    return render_template(
        "homepage/login.html",
        step=step,
        google_email=session.get("google_email"),
        google_picture=session.get("google_picture"),
        staff_names=STAFF_NAMES,
        name=session.get("pending_name"),
        first_time=session.get("first_time", False),
    )


@app.route("/login/google")
def login_google():
    redirect_uri = url_for("auth_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)



@app.route("/auth/callback")
def auth_callback():
    token = oauth.google.authorize_access_token()
    userinfo = token["userinfo"]

    email = userinfo.get("email")

    if email != ALLOWED_EMAIL:
        return "Not authorized", 403

    session["google_email"] = email
    session["google_picture"] = userinfo.get("picture")

    return redirect(url_for("login_page", step="name"))



@app.route("/select-name", methods=["POST"])
def select_name():
    name = request.form.get("name")
    email = session.get("google_email")

    if not email or name not in STAFF_NAMES:
        return redirect(url_for("login_page"))

    user = get_user(email, name)

    if not user:
        role = "admin" if name in ADMIN_NAMES else "standard"
        user_id = create_user(email, name, role)
        session["first_time"] = True
    else:
        user_id = user["id"]
        session["first_time"] = False  # clear after first PIN

    session["pending_user_id"] = user_id
    session["pending_name"] = name

    return redirect(url_for("login_page", step="pin"))


@app.route("/login/pin", methods=["POST"])
def login_pin():
    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("login_page"))

    action = request.form.get("action")

    # FIRST TIME: SET PIN
    if action == "set_pin":
        new_pin = request.form.get("new_pin")
        confirm_pin = request.form.get("confirm_pin")

        if not new_pin or new_pin != confirm_pin or not new_pin.isdigit() or not (4 <= len(new_pin) <= 6):
            flash("PIN must be 4–6 digits and match confirmation.", "error")
            return redirect(url_for("login_page", step="pin"))

        set_pin(user_id, new_pin)
        session["first_time"] = False
        flash("PIN created successfully. Enter it to continue.", "success")
        return redirect(url_for("login_page", step="pin"))

    # RETURNING USER: VERIFY PIN
    pin = request.form.get("pin")  # <-- ADD THIS

    if not pin:
        flash("Please enter your PIN.", "error")
        return redirect(url_for("login_page", step="pin"))

    if verify_pin(user_id, pin):
        user = get_user_by_id(user_id)

        session["user_id"] = user["id"]
        session["user_name"] = user["name"]

        # Use roles from DB, fallback if empty
        session["user_role"] = user["roles"] if user["roles"] else "Production Staff"

        session.pop("pending_user_id", None)
        session.pop("pending_name", None)
        session.pop("first_time", None)

        return redirect(url_for("dashboard"))

    # WRONG PIN
    flash("Incorrect PIN.", "error")
    return redirect(url_for("login_page", step="pin"))



# ---------------- DASHBOARD ---------------- #

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    return render_template(
        "dashboard/dashboard.html",
        name=session.get("user_name"),
        role=session.get("user_role"),
        picture=session.get("google_picture"),
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/dashboard/create-season", methods=["GET", "POST"])
def create_season():
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    if request.method == "POST":
        action = request.form.get("action")  # "draft" or "deploy"

        season_title = request.form.get("season_title", "").strip()
        season_year = request.form.get("season_year", "").strip()

        if not season_title or not season_year:
            flash("Please complete all required fields before saving.", "error")
            return redirect(url_for("create_season"))

        if action == "draft":
            flash("Season saved as draft successfully.", "success")
            return redirect(url_for("create_season"))

        if action == "deploy":
            flash("Season deployed successfully.", "success")
            return redirect(url_for("create_season"))

        flash("Invalid action.", "error")
        return redirect(url_for("create_season"))

    return render_template("dashboard/create_season.html", active="create_season")



# ============================================================
# INIT
# ============================================================

init_db()

if __name__ == "__main__":
    app.run(debug=True)








