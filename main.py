from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)

# CHANGE THESE IN REAL USE
app.secret_key = "change_this_secret_key"
ADMIN_PASSWORD = "bstadmin"

DB_PATH = os.path.join(os.path.dirname(__file__), "announcements.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            program TEXT,
            created_at TEXT NOT NULL,
            is_draft INTEGER NOT NULL DEFAULT 0,
            is_hidden INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


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


def save_announcement(title, body, program, is_draft, existing_id=None):
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    conn = get_db()
    if existing_id:
        conn.execute(
            """
            UPDATE announcements
            SET title = ?, body = ?, program = ?, is_draft = ?, created_at = ?
            WHERE id = ?
            """,
            (title, body, program, 1 if is_draft else 0, now, existing_id),
        )
    else:
        conn.execute(
            """
            INSERT INTO announcements (title, body, program, created_at, is_draft)
            VALUES (?, ?, ?, ?, ?)
            """,
            (title, body, program, now, 1 if is_draft else 0),
        )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    announcements = get_published_announcements()
    return render_template("index.html", announcements=announcements)


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
        "admin.html",
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
        return render_template("admin.html", login_only=True, error="Incorrect password")

    return render_template("admin.html", login_only=True, error=None)


@app.route("/admin/logout")
def admin_logout():
    session.pop("logged_in", None)
    return redirect(url_for("index"))


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


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
