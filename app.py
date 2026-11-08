import hmac
import os
import secrets
from pathlib import Path, PurePosixPath
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import RequestEntityTooLarge


# ==========================================
# APPLICATION CONFIGURATION
# ==========================================

app = Flask(__name__)

BASE_DIR = Path.home()
NAS_STORAGE = (BASE_DIR / "NAS").resolve()
ANDROID_STORAGE = (BASE_DIR / "storage" / "shared").resolve()

NAS_STORAGE.mkdir(parents=True, exist_ok=True)

# Keep the Flask signing key stable between server restarts.
SECRET_FILE = BASE_DIR / ".nas_secret"

if SECRET_FILE.exists():
    SECRET_KEY = SECRET_FILE.read_text(encoding="utf-8").strip()
    if len(SECRET_KEY) < 32:
        raise RuntimeError(
            f"{SECRET_FILE} is invalid. Remove it and restart to generate a new key."
        )
else:
    SECRET_KEY = secrets.token_hex(32)
    SECRET_FILE.write_text(SECRET_KEY, encoding="utf-8")
    SECRET_FILE.chmod(0o600)

app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024 * 1024,  # 2 GiB per request
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # The NAS uses HTTP on the trusted home LAN. Secure=True requires HTTPS.
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=8 * 60 * 60,  # 8 hours
)

# Protect every POST request, including login and file-management actions.
csrf = CSRFProtect(app)


# ==========================================
# ADMINISTRATOR CONFIGURATION
# ==========================================

ADMIN_USERNAME = os.environ.get("NAS_USER", "admin")
ADMIN_PASSWORD = os.environ.get("NAS_PASSWORD")

if not ADMIN_PASSWORD:
    raise RuntimeError(
        "NAS_PASSWORD is not set. Set it in Termux before starting the server."
    )


# ==========================================
# AUTHENTICATION
# ==========================================

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return function(*args, **kwargs)

    return wrapper


@app.route("/", methods=["GET"])
def index():
    if session.get("authenticated"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        valid_username = hmac.compare_digest(username, ADMIN_USERNAME)
        valid_password = hmac.compare_digest(password, ADMIN_PASSWORD)

        if valid_username and valid_password:
            session.clear()
            session.permanent = True
            session["authenticated"] = True
            session["username"] = ADMIN_USERNAME
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


# ==========================================
# STORAGE MANAGEMENT
# ==========================================

STORAGE_ROOTS = {
    "nas": NAS_STORAGE,
    "android": ANDROID_STORAGE,
}


def get_root(storage):
    if storage not in STORAGE_ROOTS:
        abort(404)

    root = STORAGE_ROOTS[storage]

    if not root.is_dir():
        abort(404)

    return root.resolve()


def safe_path(storage, relative_path=""):
    """Resolve a user-supplied path and prevent traversal outside its root."""
    root = get_root(storage)

    # Treat the supplied path as a relative POSIX-style path.
    cleaned_path = str(relative_path or "").replace("\\", "/").lstrip("/")
    target = (root / cleaned_path).resolve()

    try:
        target.relative_to(root)
    except ValueError:
        abort(403)

    return target


def get_storage_info(path):
    stat = os.statvfs(path)

    total = stat.f_blocks * stat.f_frsize
    free = stat.f_bavail * stat.f_frsize
    used = total - free

    return {
        "total": total,
        "used": used,
        "free": free,
    }


def format_size(size):
    units = ["B", "KB", "MB", "GB", "TB"]

    for unit in units:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024

    return f"{size:.2f} PB"


def clean_filename(filename):
    """Keep only a filename, not any client-supplied directory components."""
    normalized = str(filename or "").replace("\\", "/")
    name = PurePosixPath(normalized).name

    if name in ("", ".", "..") or "\x00" in name:
        return None

    return name


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    nas_info = get_storage_info(NAS_STORAGE)

    android_info = None
    if ANDROID_STORAGE.is_dir():
        android_info = get_storage_info(ANDROID_STORAGE)

    return render_template(
        "dashboard.html",
        nas=nas_info,
        android=android_info,
        format_size=format_size,
    )


# ==========================================
# FILE MANAGER
# ==========================================

@app.route("/files/<storage>", methods=["GET"])
@login_required
def files(storage):
    root = get_root(storage)
    relative_path = request.args.get("path", "")
    current = safe_path(storage, relative_path)

    if not current.is_dir():
        abort(404)

    # Pass a normalized relative path to the template.
    normalized_relative_path = current.relative_to(root).as_posix()
    if normalized_relative_path == ".":
        normalized_relative_path = ""

    entries = []

    for item in sorted(
        current.iterdir(),
        key=lambda entry: (not entry.is_dir(), entry.name.lower()),
    ):
        try:
            entries.append(
                {
                    "name": item.name,
                    "is_dir": item.is_dir(),
                    "size": (
                        format_size(item.stat().st_size)
                        if item.is_file()
                        else "-"
                    ),
                }
            )
        except OSError:
            continue

    parent_path = PurePosixPath(normalized_relative_path).parent
    parent_path = "" if str(parent_path) == "." else str(parent_path)

    return render_template(
        "files.html",
        storage=storage,
        current_path=normalized_relative_path,
        parent_path=parent_path,
        entries=entries,
    )


# ==========================================
# FILE DOWNLOAD
# ==========================================

@app.route("/download/<storage>", methods=["GET"])
@login_required
def download(storage):
    relative_path = request.args.get("path", "")
    target = safe_path(storage, relative_path)

    if not target.is_file():
        abort(404)

    return send_file(target, as_attachment=True)


# ==========================================
# FILE UPLOAD
# ==========================================

@app.route("/upload/<storage>", methods=["POST"])
@login_required
def upload(storage):
    relative_path = request.form.get("path", "")
    destination = safe_path(storage, relative_path)

    if not destination.is_dir():
        abort(404)

    uploaded_files = request.files.getlist("files")
    uploaded_count = 0

    for uploaded in uploaded_files:
        if not uploaded or not uploaded.filename:
            continue

        filename = clean_filename(uploaded.filename)
        if not filename:
            flash("Skipped a file with an invalid filename.")
            continue

        target = safe_path(
            storage,
            str(PurePosixPath(relative_path.replace("\\", "/")) / filename),
        )

        if target.exists():
            flash(f"{filename} already exists; it was not overwritten.")
            continue

        try:
            uploaded.save(target)
            uploaded_count += 1
        except OSError:
            flash(f"Could not save {filename}. Check available storage space.")
            continue

    flash(f"Upload completed: {uploaded_count} file(s) saved.")

    return redirect(
        url_for("files", storage=storage, path=relative_path)
    )


# ==========================================
# CREATE FOLDER
# ==========================================

@app.route("/mkdir/<storage>", methods=["POST"])
@login_required
def mkdir(storage):
    relative_path = request.form.get("path", "")
    folder_name = request.form.get("folder_name", "").strip()

    if (
        not folder_name
        or folder_name in (".", "..")
        or "/" in folder_name
        or "\\" in folder_name
        or "\x00" in folder_name
    ):
        abort(400)

    parent = safe_path(storage, relative_path)

    if not parent.is_dir():
        abort(404)

    target = safe_path(
        storage,
        str(PurePosixPath(relative_path.replace("\\", "/")) / folder_name),
    )

    try:
        target.mkdir(exist_ok=False)
    except FileExistsError:
        flash("A file or folder with that name already exists.")
    except OSError:
        flash("Could not create the folder.")

    return redirect(
        url_for("files", storage=storage, path=relative_path)
    )


# ==========================================
# RENAME FILE OR FOLDER
# ==========================================

@app.route("/rename/<storage>", methods=["POST"])
@login_required
def rename(storage):
    relative_path = request.form.get("path", "")
    new_name = request.form.get("new_name", "").strip()

    if (
        not new_name
        or new_name in (".", "..")
        or "/" in new_name
        or "\\" in new_name
        or "\x00" in new_name
    ):
        abort(400)

    target = safe_path(storage, relative_path)

    if not target.exists():
        abort(404)

    if target == get_root(storage):
        abort(403)

    parent_relative = PurePosixPath(
        relative_path.replace("\\", "/")
    ).parent

    new_relative_path = str(parent_relative / new_name)
    new_target = safe_path(storage, new_relative_path)

    if new_target.exists():
        flash("A file or folder with that name already exists.")
        return redirect(
            url_for(
                "files",
                storage=storage,
                path=str(parent_relative) if str(parent_relative) != "." else "",
            )
        )

    try:
        target.rename(new_target)
        flash("Renamed successfully.")
    except OSError:
        flash("Could not rename this item.")

    parent_path = str(parent_relative)
    if parent_path == ".":
        parent_path = ""

    return redirect(
        url_for("files", storage=storage, path=parent_path)
    )


# ==========================================
# DELETE FILE OR EMPTY FOLDER
# ==========================================

@app.route("/delete/<storage>", methods=["POST"])
@login_required
def delete(storage):
    relative_path = request.form.get("path", "")
    target = safe_path(storage, relative_path)
    root = get_root(storage)

    if not target.exists():
        abort(404)

    # Never allow deletion of the NAS or Android storage root.
    if target == root:
        abort(403)

    try:
        if target.is_dir():
            # Deliberately refuse non-empty folders. No recursive deletion.
            target.rmdir()
        else:
            target.unlink()
        flash("Deleted successfully.")
    except OSError:
        flash("Could not delete this item. Folders must be empty before deletion.")

    parent = PurePosixPath(relative_path.replace("\\", "/")).parent
    parent_path = "" if str(parent) == "." else str(parent)

    return redirect(
        url_for("files", storage=storage, path=parent_path)
    )


# ==========================================
# ERROR HANDLING
# ==========================================

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    return (
        "Upload rejected: the total request size exceeds the 2 GiB limit.",
        413,
    )


# ==========================================
# SERVER
# ==========================================

if __name__ == "__main__":
    from waitress import serve

    print("================================")
    print("       VIVO Y28 HOME NAS")
    print("================================")
    print("Listening on: http://0.0.0.0:8080")
    print("Storage: NAS + Android shared storage")
    print("Maximum upload request: 2 GiB")
    print("================================")
    print("Use only on a trusted LAN. Do not configure router port forwarding.")

    serve(
        app,
        host="0.0.0.0",
        port=8080,
        threads=8,
    )
