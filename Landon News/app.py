from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from pathlib import Path
import secrets
import os
import smtplib
from email.message import EmailMessage


def generate_api_key():
    return secrets.token_urlsafe(32)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "app.db"

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-to-something-random")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
        """
    )
    conn.commit()

    # Add api_key column if it doesn't exist (safe to run repeatedly)
    try:
        cur.execute("ALTER TABLE users ADD COLUMN api_key TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        # column probably exists already
        pass

    # Create admin user Bears with provided password if not exists
    admin_username = "Matcha"
    admin_password = "gwcba6Bj"
    cur.execute("SELECT * FROM users WHERE username = ?", (admin_username,))
    if not cur.fetchone():
        pw_hash = generate_password_hash(admin_password)
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
            (admin_username, pw_hash),
        )
        conn.commit()
        # generate and store an API key for the new admin
        api_key = generate_api_key()
        cur.execute("UPDATE users SET api_key = ? WHERE username = ?", (api_key, admin_username))
        conn.commit()
    else:
        # ensure existing admin users have an api_key
        cur.execute("SELECT id, username, role, api_key FROM users WHERE role = 'admin'")
        for row in cur.fetchall():
            if not row['api_key']:
                key = generate_api_key()
                cur.execute("UPDATE users SET api_key = ? WHERE id = ?", (key, row['id']))
        conn.commit()
    conn.close()

    # submissions table for student-submitted items
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()

    # articles table for editorial content
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT,
            status TEXT NOT NULL DEFAULT 'draft', -- draft, submitted, published
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()

    # pages table for editable site sections (announcements, clubs, sports, etc.)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            content TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()

    # audit logs for API actions
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            endpoint TEXT,
            method TEXT,
            action TEXT,
            target TEXT,
            data TEXT,
            ip TEXT,
            payload_size INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    # Add missing columns safely if running against older DB
    try:
        cur.execute("ALTER TABLE users ADD COLUMN email TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute("ALTER TABLE audit_logs ADD COLUMN ip TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute("ALTER TABLE audit_logs ADD COLUMN payload_size INTEGER")
    except sqlite3.OperationalError:
        pass
    conn.commit()

    # seed default pages if missing
    # default pages seeded with empty content so admins can add real content
    defaults = [
        ('announcements', 'Announcements', ''),
        ('clubs', 'Clubs', ''),
        ('sports', 'Sports', ''),
        ('voices', 'Student Voices', ''),
        ('highlights', 'Highlights of the Week', ''),
        ('home', 'Home', '')
    ]
    for slug, title, content in defaults:
        cur.execute('SELECT id FROM pages WHERE slug = ?', (slug,))
        if not cur.fetchone():
            cur.execute('INSERT INTO pages (slug, title, content) VALUES (?, ?, ?)', (slug, title, content))
    conn.commit()
    conn.close()


# Flask 3 removed `before_first_request`; initialize DB at import time instead
init_db()


@app.route("/")
def index():
    user = session.get("user")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, title, content, author, created_at FROM articles WHERE status = 'published' ORDER BY created_at DESC LIMIT 6")
    articles = cur.fetchall()
    conn.close()
    return render_template("home.html", user=user, articles=articles)


def generate_api_key():
    return secrets.token_urlsafe(32)


def get_user_by_api_key(key):
    if not key:
        return None
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, username, role FROM users WHERE api_key = ?', (key,))
    row = cur.fetchone()
    conn.close()
    return row


def log_api_action(user_id, username, endpoint, method, action, target, data, ip=None, payload_size=None, key_fingerprint=None):
    # sanitize data: remove any api_key fields and replace with fingerprint
    try:
        stored = None
        if isinstance(data, dict):
            d = dict(data)
            if 'api_key' in d:
                d.pop('api_key')
            if key_fingerprint:
                d['api_key_fingerprint'] = key_fingerprint
            stored = str(d)
        else:
            stored = str(data)
    except Exception:
        stored = str(data)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('INSERT INTO audit_logs (user_id, username, endpoint, method, action, target, data, ip, payload_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (user_id, username, endpoint, method, action, target, stored, ip, payload_size))
    conn.commit()
    conn.close()


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form.get("email")
        password = request.form["password"]
        if not username or not password:
            flash("Username and password required")
            return redirect(url_for("signup"))

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, 'user', ?)",
                (username, generate_password_hash(password), email),
            )
            conn.commit()
            flash("Account created. Please log in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already taken")
            return redirect(url_for("signup"))
        finally:
            conn.close()

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()
        if row and check_password_hash(row["password_hash"], password):
            session["user"] = {"id": row["id"], "username": row["username"], "role": row["role"]}
            flash("Logged in successfully")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out")
    return redirect(url_for("index"))


def requires_admin(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = session.get("user")
        if not user or user.get("role") != "admin":
            flash("Administrator access required")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)

    return wrapper


@app.route("/admin", methods=["GET", "POST"])
@requires_admin
def admin():
    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == "POST":
        # Change user role
        user_id = request.form.get("user_id")
        new_role = request.form.get("role")
        if user_id and new_role:
            cur.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
            conn.commit()

    cur.execute("SELECT id, username, role FROM users ORDER BY id ASC")
    users = cur.fetchall()
    # fetch current admin api_key to show them their key
    current_key = None
    user = session.get('user')
    if user and user.get('role') == 'admin':
        cur.execute('SELECT api_key FROM users WHERE id = ?', (user.get('id'),))
        r = cur.fetchone()
        if r:
            current_key = r['api_key']

    # show any recently generated key (one-time) to the admin who generated it
    last_generated = session.pop('last_generated_key', None)
    conn.close()
    return render_template("admin.html", users=users, api_key=current_key, last_generated=last_generated)


def requires_roles(*roles):
    from functools import wraps

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = session.get("user")
            if not user or user.get("role") not in roles:
                flash("Insufficient permissions")
                return redirect(url_for("login"))
            return fn(*args, **kwargs)

        return wrapper

    return decorator


@app.route('/editor', methods=['GET', 'POST'])
@requires_roles('editor', 'admin')
def editor():
    user = session.get('user')
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        action = request.form.get('action', 'save')
        if not title or not content:
            flash('Title and content are required')
            return redirect(url_for('editor'))
        status = 'draft'
        if action == 'submit':
            status = 'submitted'
        elif action == 'publish' and user.get('role') == 'admin':
            status = 'published'

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO articles (title, content, author, status) VALUES (?, ?, ?, ?)', (title, content, user.get('username'), status))
        conn.commit()
        conn.close()
        flash('Article saved')
        return redirect(url_for('editor'))

    # show user's articles
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, title, status, created_at FROM articles WHERE author = ? ORDER BY created_at DESC', (user.get('username'),))
    my_articles = cur.fetchall()
    conn.close()
    return render_template('editor.html', user=user, my_articles=my_articles)


@app.route('/articles')
def articles():
    # public listing shows published only; admins see all
    user = session.get('user')
    conn = get_db_connection()
    cur = conn.cursor()
    if user and user.get('role') == 'admin':
        cur.execute('SELECT id, title, author, status, created_at FROM articles ORDER BY created_at DESC')
    elif user and user.get('role') == 'editor':
        cur.execute("SELECT id, title, author, status, created_at FROM articles WHERE status = 'published' OR author = ? ORDER BY created_at DESC", (user.get('username'),))
    else:
        cur.execute("SELECT id, title, author, status, created_at FROM articles WHERE status = 'published' ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return render_template('articles.html', articles=rows, user=user)


@app.route('/article/<int:article_id>/edit', methods=['GET', 'POST'])
@requires_roles('editor', 'admin')
def edit_article(article_id):
    user = session.get('user')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM articles WHERE id = ?', (article_id,))
    art = cur.fetchone()
    if not art:
        conn.close()
        flash('Article not found')
        return redirect(url_for('articles'))
    # only author (editor) or admin can edit
    if user.get('role') != 'admin' and art['author'] != user.get('username'):
        conn.close()
        flash('Permission denied')
        return redirect(url_for('articles'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        action = request.form.get('action', 'save')
        new_status = art['status']
        if action == 'submit':
            new_status = 'submitted'
        if action == 'publish' and user.get('role') == 'admin':
            new_status = 'published'
        cur.execute('UPDATE articles SET title = ?, content = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', (title, content, new_status, article_id))
        conn.commit()
        conn.close()
        flash('Article updated')
        return redirect(url_for('articles'))

    conn.close()
    return render_template('article_edit.html', article=art, user=user)


@app.route('/article/<int:article_id>/publish', methods=['POST'])
@requires_roles('admin')
def publish_article(article_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('UPDATE articles SET status = "published", updated_at = CURRENT_TIMESTAMP WHERE id = ?', (article_id,))
    conn.commit()
    conn.close()
    flash('Article published')
    return redirect(url_for('articles'))


@app.route('/article/<int:article_id>')
def view_article(article_id):
    user = session.get('user')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM articles WHERE id = ?', (article_id,))
    art = cur.fetchone()
    conn.close()
    if not art:
        flash('Article not found')
        return redirect(url_for('articles'))
    # only show if published unless author or admin
    if art['status'] != 'published':
        if not user or (user.get('role') != 'admin' and user.get('username') != art['author']):
            flash('Article not available')
            return redirect(url_for('articles'))
    return render_template('article_view.html', article=art, user=user)


@app.route('/announcements')
def announcements():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT title, content FROM pages WHERE slug = ?', ('announcements',))
    p = cur.fetchone()
    conn.close()
    if p:
        return render_template('page.html', title=p['title'], content=p['content'])
    return render_template('announcements.html')


@app.route('/clubs')
def clubs():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT title, content FROM pages WHERE slug = ?', ('clubs',))
    p = cur.fetchone()
    conn.close()
    if p:
        return render_template('page.html', title=p['title'], content=p['content'])
    return render_template('clubs.html')


@app.route('/sports')
def sports():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT title, content FROM pages WHERE slug = ?', ('sports',))
    p = cur.fetchone()
    conn.close()
    if p:
        return render_template('page.html', title=p['title'], content=p['content'])
    return render_template('sports.html')


@app.route('/voices')
def voices():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT title, content FROM pages WHERE slug = ?', ('voices',))
    p = cur.fetchone()
    conn.close()
    if p:
        return render_template('page.html', title=p['title'], content=p['content'])
    return render_template('voices.html')


@app.route('/highlights')
def highlights():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT title, content FROM pages WHERE slug = ?', ('highlights',))
    p = cur.fetchone()
    conn.close()
    if p:
        return render_template('page.html', title=p['title'], content=p['content'])
    return render_template('page.html', title='Highlights of the Week', content='')


@app.route('/admin/pages')
@requires_admin
def admin_pages():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT slug, title, updated_at FROM pages ORDER BY id ASC')
    pages = cur.fetchall()
    conn.close()
    return render_template('admin_pages.html', pages=pages)


@app.route('/editor/pages')
@requires_roles('editor', 'admin')
def editor_pages():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT slug, title, updated_at FROM pages ORDER BY id ASC')
    pages = cur.fetchall()
    conn.close()
    return render_template('editor_pages.html', pages=pages)


@app.route('/admin/pages/<slug>/edit', methods=['GET', 'POST'])
@requires_admin
def admin_edit_page(slug):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM pages WHERE slug = ?', (slug,))
    page = cur.fetchone()
    if not page:
        conn.close()
        flash('Page not found')
        return redirect(url_for('admin_pages'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        if not title:
            flash('Title required')
            return redirect(url_for('admin_edit_page', slug=slug))
        cur.execute('UPDATE pages SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE slug = ?', (title, content, slug))
        conn.commit()
        conn.close()
        flash('Page updated')
        return redirect(url_for('admin_pages'))

    conn.close()
    return render_template('admin_edit_page.html', page=page)


@app.route('/editor/pages/<slug>/edit', methods=['GET', 'POST'])
@requires_roles('editor', 'admin')
def editor_edit_page(slug):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM pages WHERE slug = ?', (slug,))
    page = cur.fetchone()
    if not page:
        conn.close()
        flash('Page not found')
        return redirect(url_for('editor_pages'))

    if request.method == 'POST':
        # editors may edit content but not change the slug; allow title change as well
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        if not title:
            flash('Title required')
            return redirect(url_for('editor_edit_page', slug=slug))
        cur.execute('UPDATE pages SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE slug = ?', (title, content, slug))
        conn.commit()
        conn.close()
        flash('Page updated')
        return redirect(url_for('editor_pages'))

    conn.close()
    return render_template('admin_edit_page.html', page=page)


@app.route('/admin/users/<int:user_id>/generate_key', methods=['POST'])
@requires_admin
def admin_generate_user_key(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, username FROM users WHERE id = ?', (user_id,))
    u = cur.fetchone()
    if not u:
        conn.close()
        flash('User not found')
        return redirect(url_for('admin'))
    new_key = generate_api_key()
    cur.execute('UPDATE users SET api_key = ? WHERE id = ?', (new_key, user_id))
    conn.commit()
    conn.close()
    # try to email the key if SMTP configured and user has email
    sent = False
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT email FROM users WHERE id = ?', (user_id,))
    row = cur.fetchone()
    user_email = row['email'] if row else None
    smtp_host = os.environ.get('SMTP_HOST')
    smtp_port = int(os.environ.get('SMTP_PORT', '0')) if os.environ.get('SMTP_PORT') else None
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')
    smtp_from = os.environ.get('SMTP_FROM') or smtp_user
    conn.close()
    if user_email and smtp_host and smtp_port and smtp_user and smtp_pass:
        try:
            msg = EmailMessage()
            msg['Subject'] = 'Your API key'
            msg['From'] = smtp_from
            msg['To'] = user_email
            msg.set_content(f'Hello {u["username"]},\n\nYour API key: {new_key}\nKeep it secret.')
            with smtplib.SMTP_SSL(smtp_host, smtp_port) as s:
                s.login(smtp_user, smtp_pass)
                s.send_message(msg)
            sent = True
        except Exception as e:
            flash(f'Could not send email: {e}')

    if sent:
        flash(f'API key generated for {u["username"]} and emailed to {user_email}')
    else:
        flash(f'API key generated for {u["username"]}')
    # store the generated key in session for one-time display with guidance
    session['last_generated_key'] = { 'user_id': user_id, 'username': u['username'], 'key': new_key }
    return redirect(url_for('admin'))


@app.route('/admin/users/<int:user_id>/reveal_key', methods=['POST'])
@requires_admin
def admin_reveal_user_key(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT username, api_key FROM users WHERE id = ?', (user_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        flash('User not found')
        return redirect(url_for('admin'))
    if not row['api_key']:
        flash('User has no API key')
        return redirect(url_for('admin'))
    flash(f"API key for {row['username']} revealed")
    # if AJAX JSON request, return key in JSON
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
        return {'ok': True, 'key': row['api_key']}
    return redirect(url_for('admin'))


@app.route('/admin/users/<int:user_id>/reveal_key_json', methods=['POST'])
@requires_admin
def admin_reveal_user_key_json(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT username, api_key FROM users WHERE id = ?', (user_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return {'ok': False, 'error': 'User not found'}
    if not row['api_key']:
        return {'ok': False, 'error': 'User has no API key'}
    return {'ok': True, 'key': row['api_key']}


@app.route('/admin/users/<int:user_id>/revoke_key', methods=['POST'])
@requires_admin
def admin_revoke_user_key(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    u = cur.fetchone()
    if not u:
        conn.close()
        flash('User not found')
        return redirect(url_for('admin'))
    cur.execute('UPDATE users SET api_key = NULL WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash(f'API key revoked for {u["username"]}')
    return redirect(url_for('admin'))


@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@requires_admin
def admin_edit_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, username, email, role, api_key FROM users WHERE id = ?', (user_id,))
    u = cur.fetchone()
    if not u:
        conn.close()
        flash('User not found')
        return redirect(url_for('admin'))
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email')
        role = request.form.get('role')
        if not username:
            flash('Username required')
            return redirect(url_for('admin_edit_user', user_id=user_id))
        cur.execute('UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?', (username, email, role, user_id))
        conn.commit()
        conn.close()
        flash('User updated')
        return redirect(url_for('admin'))

    conn.close()
    return render_template('admin_user_edit.html', user=u)


@app.route('/admin/clear_content', methods=['POST'])
@requires_admin
def admin_clear_content():
    """Delete all articles and submissions and clear pages content. Admin-only destructive action."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM articles')
    cur.execute('DELETE FROM submissions')
    cur.execute('UPDATE pages SET content = "", updated_at = CURRENT_TIMESTAMP')
    conn.commit()
    conn.close()
    flash('All articles and submissions removed; pages cleared.')
    return redirect(url_for('admin'))


@app.route('/admin/seed_content', methods=['POST'])
@requires_admin
def admin_seed_content():
    """Insert example pages and a few sample published articles to make the site feel real."""
    conn = get_db_connection()
    cur = conn.cursor()
    # example pages
    cur.execute("UPDATE pages SET content = ? WHERE slug = 'announcements'", ("<h3>Welcome Back to School</h3><p>Welcome to the new year of Landon Middle News — check here for all important announcements.</p>",))
    cur.execute("UPDATE pages SET content = ? WHERE slug = 'clubs'", ("<h3>Clubs Directory</h3><ul><li>Robotics Club — Wednesdays</li><li>Art Club — Thursdays</li><li>Yearbook — Fridays</li></ul>",))
    cur.execute("UPDATE pages SET content = ? WHERE slug = 'sports'", ("<h3>Sports Highlights</h3><p>Girls soccer won 3-1; upcoming basketball tryouts next Monday.</p>",))
    cur.execute("UPDATE pages SET content = ? WHERE slug = 'voices'", ("<h3>Student Voices</h3><p>Student-submitted stories, interviews, and opinion pieces.</p>",))
    cur.execute("UPDATE pages SET content = ? WHERE slug = 'home'", ("<p>Welcome to Landon Middle News — your source for student stories, announcements, and highlights.</p>",))
    cur.execute("UPDATE pages SET content = ? WHERE slug = 'highlights'", ("<h3>Highlights of the Week</h3><ul><li>Outstanding student achievements</li><li>Top sports moments</li><li>Upcoming events</li></ul>",))

    # sample articles
    cur.execute("INSERT INTO articles (title, content, author, status) VALUES (?, ?, ?, 'published')", (
        'School Play Opens This Friday', '<p>The spring play opens Friday in the auditorium. Tickets available at lunch.</p>', 'DramaClub',
    ))
    cur.execute("INSERT INTO articles (title, content, author, status) VALUES (?, ?, ?, 'published')", (
        'Robotics Club Wins Regional Match', '<p>The robotics team placed first at the regional competition. Congratulations to the team!</p>', 'Robotics',
    ))
    cur.execute("INSERT INTO articles (title, content, author, status) VALUES (?, ?, ?, 'published')", (
        'Science Fair Winners Announced', '<p>Outstanding projects from sixth to eighth grade were recognized at the fair.</p>', 'ScienceDept',
    ))

    conn.commit()
    conn.close()
    flash('Example content seeded.')
    return redirect(url_for('admin'))


@app.route('/admin/logs')
@requires_admin
def admin_logs():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, user_id, username, endpoint, method, action, target, data, created_at FROM audit_logs ORDER BY id DESC LIMIT 200')
    logs = cur.fetchall()
    conn.close()
    return render_template('admin_logs.html', logs=logs)


@app.route('/admin/regenerate_key', methods=['POST'])
@requires_admin
def admin_regenerate_key():
    user = session.get('user')
    if not user:
        flash('No user')
        return redirect(url_for('admin'))
    new_key = generate_api_key()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('UPDATE users SET api_key = ? WHERE id = ?', (new_key, user.get('id')))
    conn.commit()
    conn.close()
    flash('API key regenerated')
    # update session not necessary since api_key not stored there; redirect to admin to show new key
    return redirect(url_for('admin'))


@app.route('/api/pages/<slug>', methods=['POST'])
def api_update_page(slug):
    key = request.headers.get('X-API-Key') or request.args.get('api_key')
    u = get_user_by_api_key(key)
    if not u or u['role'] != 'admin':
        return { 'error': 'unauthorized' }, 401
    data = request.get_json() or {}
    title = data.get('title')
    content = data.get('content')
    if not title and content is None:
        return { 'error': 'title or content required' }, 400
    conn = get_db_connection()
    cur = conn.cursor()
    if title:
        cur.execute('UPDATE pages SET title = ? WHERE slug = ?', (title, slug))
    if content is not None:
        cur.execute('UPDATE pages SET content = ?, updated_at = CURRENT_TIMESTAMP WHERE slug = ?', (content, slug))
    conn.commit()
    conn.close()
    # log the API action with IP and payload size
    payload = request.get_data() or b''
    ip = request.remote_addr
    key_fp = key[:8] if key else None
    log_api_action(u['id'], u['username'], request.path, request.method, 'update_page', slug, data, ip=ip, payload_size=len(payload), key_fingerprint=key_fp)
    return { 'ok': True }


@app.route('/api/articles', methods=['POST'])
def api_create_article():
    key = request.headers.get('X-API-Key') or request.args.get('api_key')
    u = get_user_by_api_key(key)
    if not u or u['role'] != 'admin':
        return { 'error': 'unauthorized' }, 401
    data = request.get_json() or {}
    title = data.get('title')
    content = data.get('content')
    author = data.get('author') or u['username']
    status = data.get('status') or 'draft'
    if not title or content is None:
        return { 'error': 'title and content required' }, 400
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('INSERT INTO articles (title, content, author, status) VALUES (?, ?, ?, ?)', (title, content, author, status))
    conn.commit()
    art_id = cur.lastrowid
    conn.close()
    payload = request.get_data() or b''
    ip = request.remote_addr
    key_fp = key[:8] if key else None
    log_api_action(u['id'], u['username'], request.path, request.method, 'create_article', art_id, data, ip=ip, payload_size=len(payload), key_fingerprint=key_fp)
    return { 'ok': True, 'id': art_id }


@app.route('/api/articles/<int:article_id>', methods=['PUT'])
def api_update_article(article_id):
    key = request.headers.get('X-API-Key') or request.args.get('api_key')
    u = get_user_by_api_key(key)
    if not u or u['role'] != 'admin':
        return { 'error': 'unauthorized' }, 401
    data = request.get_json() or {}
    title = data.get('title')
    content = data.get('content')
    status = data.get('status')
    if title is None and content is None and status is None:
        return { 'error': 'nothing to update' }, 400
    conn = get_db_connection()
    cur = conn.cursor()
    if title is not None:
        cur.execute('UPDATE articles SET title = ? WHERE id = ?', (title, article_id))
    if content is not None:
        cur.execute('UPDATE articles SET content = ? WHERE id = ?', (content, article_id))
    if status is not None:
        cur.execute('UPDATE articles SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', (status, article_id))
    conn.commit()
    conn.close()
    payload = request.get_data() or b''
    ip = request.remote_addr
    key_fp = key[:8] if key else None
    log_api_action(u['id'], u['username'], request.path, request.method, 'update_article', article_id, data, ip=ip, payload_size=len(payload), key_fingerprint=key_fp)
    return { 'ok': True }


@app.route('/submit', methods=['GET', 'POST'])
def submit():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        category = request.form.get('category', 'General')
        content = request.form.get('content', '').strip()
        author = session.get('user', {}).get('username') if session.get('user') else request.form.get('author', 'Anonymous')
        if not title or not content:
            flash('Title and content are required')
            return redirect(url_for('submit'))
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO submissions (title, category, content, author) VALUES (?, ?, ?, ?)', (title, category, content, author))
        conn.commit()
        conn.close()
        flash('Submission received — an admin will review it.')
        return redirect(url_for('index'))
    return render_template('submit.html')


if __name__ == "__main__":
    app.run(debug=True)
