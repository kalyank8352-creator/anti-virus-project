"""
=====================================================================
 BASIC HASH-BASED ANTIVIRUS SCANNER  (Diploma CSE/CME mini project)
=====================================================================

 What this program does
 ----------------------
 1. The user selects one OR many files on the Scan page.
 2. Flask saves every file safely inside the "uploads" folder.
 3. For every file we calculate a SHA-256 hash (a unique fingerprint).
 4. That hash is compared with a list of KNOWN malicious hashes.
 5. Each file gets a result: Safe / Suspicious / Malicious.
 6. Every result is stored in the SQLite database (scan_history).

 IMPORTANT (be honest in your viva):
 This is a BASIC hash-based scanner. It can only recognise malware
 whose exact hash is already in our list. A file marked "Safe" only
 means "no known-malicious hash matched" - not "guaranteed virus free".

 Run with:  python app.py
=====================================================================
"""

import hashlib
import mimetypes
import os
import sqlite3

from flask import Flask, jsonify, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------
# BASIC CONFIGURATION
# ---------------------------------------------------------------

# Absolute path of the folder that contains this file (app.py).
# Using absolute paths avoids "file not found" problems.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
DATABASE = os.path.join(BASE_DIR, "database.db")

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Maximum total upload size. Big installers (.exe, .iso) can easily be
# 100-200 KB, so the limit is set to 3000 KB. Change MAX_UPLOAD_KB if you
# need more or less.
MAX_UPLOAD_KB = 3000
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_KB * 1024 

# Make sure the uploads folder exists before we try to save anything.
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------------------------------------------------------
# 1) KNOWN MALICIOUS HASH DATABASE
# ---------------------------------------------------------------
# >>> ADD YOUR KNOWN MALICIOUS SHA-256 HASHES HERE <<<
#
# Rules:
#   * one hash per line, inside quotes, followed by a comma
#   * lowercase, 64 characters long
#   * a file is marked "Malicious" ONLY if its hash is in this list
#
# The hash below belongs to a harmless TEST file you can create
# yourself (see the README) so you can demo a "Malicious" result
# without using real malware.
MALICIOUS_HASHES = [
    "bcf199184beffeb49d5cf8c4d39eec065b51f37ef4cc32978321e80fc5b9d3b8",  # demo test file
    # "paste_another_known_malicious_sha256_here",
]

# Optional: you can also keep hashes in a plain text file called
# "malicious_hashes.txt" (one hash per line). If that file exists,
# its hashes are added to the list above. This makes the list easy
# to expand later without editing app.py.
EXTRA_HASH_FILE = os.path.join(BASE_DIR, "malicious_hashes.txt")


def load_malicious_hashes():
    """Return a set of all known malicious hashes (list + optional text file)."""
    hashes = set(h.strip().lower() for h in MALICIOUS_HASHES if h.strip())

    if os.path.exists(EXTRA_HASH_FILE):
        with open(EXTRA_HASH_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                # skip empty lines and comment lines starting with #
                if line and not line.startswith("#"):
                    hashes.add(line)

    return hashes


# ---------------------------------------------------------------
# 2) FILE TYPE DETECTION TABLE
# ---------------------------------------------------------------
# Extension -> friendly name shown in the UI.
FILE_TYPES = {
    ".pdf": "PDF",
    ".doc": "Microsoft Word Document",
    ".docx": "Microsoft Word Document",
    ".xls": "Microsoft Excel Spreadsheet",
    ".xlsx": "Microsoft Excel Spreadsheet",
    ".ppt": "Microsoft PowerPoint Presentation",
    ".pptx": "Microsoft PowerPoint Presentation",
    ".jpg": "JPEG Image",
    ".jpeg": "JPEG Image",
    ".png": "PNG Image",
    ".gif": "GIF Image",
    ".bmp": "Bitmap Image",
    ".txt": "Text File",
    ".csv": "CSV Data File",
    ".zip": "ZIP Archive",
    ".rar": "RAR Archive",
    ".7z": "7-Zip Archive",
    ".exe": "Windows Executable",
    ".msi": "Windows Installer",
    ".bat": "Windows Batch Script",
    ".cmd": "Windows Command Script",
    ".vbs": "VBScript File",
    ".scr": "Windows Screensaver (Executable)",
    ".apk": "Android Application",
    ".py": "Python Source File",
    ".java": "Java Source File",
    ".c": "C Source File",
    ".cpp": "C++ Source File",
    ".html": "HTML File",
    ".htm": "HTML File",
    ".css": "CSS File",
    ".js": "JavaScript File",
    ".json": "JSON Data File",
    ".mp3": "MP3 Audio",
    ".mp4": "MP4 Video",
}

# Extensions that can run code on a computer. We do NOT run them -
# we only warn the user, because such files need extra care.
RISKY_EXTENSIONS = [".exe", ".msi", ".bat", ".cmd", ".vbs", ".scr", ".js", ".jar", ".ps1"]


def detect_file_type(filename):
    """
    Detect the type of a file from its name.

    Step 1: look the extension up in our FILE_TYPES table.
    Step 2: if it is not in the table, ask Python's mimetypes module.
    Step 3: if even that fails, show the extension itself.
    """
    extension = os.path.splitext(filename)[1].lower()

    if extension in FILE_TYPES:
        return FILE_TYPES[extension]

    # mimetypes guesses something like "image/webp" from the file name
    guessed_type, _ = mimetypes.guess_type(filename)
    if guessed_type and guessed_type != "application/octet-stream":
        return guessed_type

    if extension:
        return extension.replace(".", "").upper() + " File"

    return "Unknown"


# ---------------------------------------------------------------
# 3) SHA-256 HASH CALCULATION  (existing logic - unchanged idea)
# ---------------------------------------------------------------
def calculate_sha256(filepath):
    """
    Read the file in small 4096-byte pieces and build its SHA-256 hash.
    Reading in pieces means even a very large file does not fill the RAM.
    NOTE: the file is only READ here. It is never executed.
    """
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as file:
        while True:
            data = file.read(4096)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


# ---------------------------------------------------------------
# 4) DATABASE SETUP AND SAFE UPGRADE
# ---------------------------------------------------------------
def get_connection():
    """Open a connection to the SQLite database."""
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row  # lets us use row["filename"]
    return connection


def init_db():
    """
    Create the scan_history table if it does not exist, and add the new
    'file_type' column to OLD databases without deleting existing rows.
    """
    connection = get_connection()
    cursor = connection.cursor()

    # Original table (kept exactly as before)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            file_hash TEXT,
            result TEXT
        )
    """)

    # --- Safe upgrade -------------------------------------------------
    # PRAGMA table_info gives the list of columns that already exist.
    cursor.execute("PRAGMA table_info(scan_history)")
    existing_columns = [column["name"] for column in cursor.fetchall()]

    if "file_type" not in existing_columns:
        # ALTER TABLE only ADDS a column; old scan history is not lost.
        cursor.execute("ALTER TABLE scan_history ADD COLUMN file_type TEXT")

    if "scan_time" not in existing_columns:
        cursor.execute("ALTER TABLE scan_history ADD COLUMN scan_time TEXT")

    connection.commit()
    connection.close()


def save_scan_result(filename, file_type, file_hash, result):
    """Insert one scanned file into the scan_history table."""
    connection = get_connection()
    connection.execute(
        """INSERT INTO scan_history (filename, file_type, file_hash, result, scan_time)
           VALUES (?, ?, ?, ?, datetime('now', 'localtime'))""",
        (filename, file_type, file_hash, result),
    )
    connection.commit()
    connection.close()


# ---------------------------------------------------------------
# 5) SAVING UPLOADED FILES SAFELY
# ---------------------------------------------------------------
def build_safe_path(original_filename):
    """
    Turn the uploaded filename into a safe filename and make sure the
    final path stays inside the uploads folder.

    * secure_filename() removes dangerous characters such as "../"
      so nobody can write outside our folder (path traversal attack).
    * If a file with the same name already exists we add _1, _2, ...
      so an old file is never overwritten.
    """
    safe_name = secure_filename(original_filename)

    if not safe_name:  # e.g. the user sent only "../../"
        safe_name = "unnamed_file"

    name, extension = os.path.splitext(safe_name)
    final_name = safe_name
    counter = 1

    while os.path.exists(os.path.join(UPLOAD_FOLDER, final_name)):
        final_name = f"{name}_{counter}{extension}"
        counter += 1

    full_path = os.path.join(UPLOAD_FOLDER, final_name)

    # Extra safety check: the path must really be inside uploads/
    if not os.path.abspath(full_path).startswith(os.path.abspath(UPLOAD_FOLDER)):
        raise ValueError("Unsafe file path detected")

    return final_name, full_path


# ---------------------------------------------------------------
# 6) THE SCANNING LOGIC
# ---------------------------------------------------------------
def looks_suspicious(filename):
    """
    Very simple extra rules (NOT real antivirus detection).
    A file is 'Suspicious' when:
      * it can run code on the computer (.exe, .bat, .vbs ...), or
      * it uses a double extension to hide, e.g. invoice.pdf.exe
    """
    lower_name = filename.lower()
    extension = os.path.splitext(lower_name)[1]

    if extension in RISKY_EXTENSIONS:
        # double extension like "photo.jpg.exe" is a classic trick
        name_without_ext = os.path.splitext(lower_name)[0]
        if os.path.splitext(name_without_ext)[1]:
            return True, "Hidden double extension"
        return True, "File can run code on your computer"

    return False, ""


def scan_one_file(uploaded_file, malicious_hashes):
    """
    Save one uploaded file, hash it, detect its type and decide the result.
    Returns a dictionary describing the scan of that single file.
    """
    saved_name, saved_path = build_safe_path(uploaded_file.filename)
    uploaded_file.save(saved_path)

    file_hash = calculate_sha256(saved_path)
    file_type = detect_file_type(saved_name)
    file_size = os.path.getsize(saved_path)

    # ---- the actual decision -------------------------------------
    if file_hash in malicious_hashes:
        result = "Malicious"
        reason = "Hash matches a known malicious file"
    else:
        suspicious, why = looks_suspicious(saved_name)
        if suspicious:
            result = "Suspicious"
            reason = why
        else:
            result = "Safe"
            reason = "No known-malicious hash matched"

    return {
        "filename": saved_name,
        "original_name": uploaded_file.filename,
        "file_type": file_type,
        "file_hash": file_hash,
        "file_size": file_size,
        "result": result,
        "reason": reason,
    }


def scan_uploaded_files(file_list):
    """
    Scan EVERY uploaded file, one after another.
    Scanning never stops when a malicious file is found - the loop
    simply continues with the next file.
    """
    malicious_hashes = load_malicious_hashes()
    results = []

    for uploaded_file in file_list:
        # Skip empty inputs (user pressed Scan without choosing a file)
        if uploaded_file is None or uploaded_file.filename.strip() == "":
            continue

        try:
            single_result = scan_one_file(uploaded_file, malicious_hashes)
        except Exception as error:
            # An invalid upload must not crash the whole scan.
            single_result = {
                "filename": uploaded_file.filename or "unknown",
                "original_name": uploaded_file.filename or "unknown",
                "file_type": "Unknown",
                "file_hash": "-",
                "file_size": 0,
                "result": "Error",
                "reason": f"Could not scan this file ({error})",
            }

        results.append(single_result)

        # Save every file separately in the history table
        if single_result["result"] != "Error":
            save_scan_result(
                single_result["filename"],
                single_result["file_type"],
                single_result["file_hash"],
                single_result["result"],
            )

    return results


def build_summary(results):
    """Count how many files are Safe / Suspicious / Malicious."""
    return {
        "total": len(results),
        "safe": sum(1 for r in results if r["result"] == "Safe"),
        "suspicious": sum(1 for r in results if r["result"] == "Suspicious"),
        "malicious": sum(1 for r in results if r["result"] == "Malicious"),
        "errors": sum(1 for r in results if r["result"] == "Error"),
        "malicious_files": [r["filename"] for r in results if r["result"] == "Malicious"],
        "suspicious_files": [r["filename"] for r in results if r["result"] == "Suspicious"],
    }


# ---------------------------------------------------------------
# 7) FLASK ROUTES (web pages)
# ---------------------------------------------------------------
@app.context_processor
def inject_upload_limit():
    """Makes max_upload_kb available inside every HTML template."""
    return {"max_upload_kb": MAX_UPLOAD_KB}


@app.route("/")
def index():
    """Home page."""
    connection = get_connection()
    row = connection.execute("SELECT COUNT(*) AS total FROM scan_history").fetchone()
    connection.close()
    return render_template(
        "index.html",
        total_scanned=row["total"],
        known_hashes=len(load_malicious_hashes()),
    )


@app.route("/scan", methods=["GET", "POST"])
def scan():
    """
    GET  -> show the scan page
    POST -> scan all uploaded files

    If the browser asks for JSON (our JavaScript does), we answer with
    JSON so the results appear without reloading the page.
    Otherwise we render the normal result page - so the project still
    works even if JavaScript is turned off.
    """
    if request.method == "GET":
        return render_template("scan.html")

    # request.files.getlist("files") gives ALL selected files
    uploaded_files = request.files.getlist("files")

    wants_json = request.headers.get("X-Requested-With") == "fetch"

    # Handle empty file selection
    real_files = [f for f in uploaded_files if f and f.filename.strip() != ""]
    if not real_files:
        message = "No file selected. Please choose at least one file to scan."
        if wants_json:
            return jsonify({"error": message}), 400
        return render_template("scan.html", error=message)

    results = scan_uploaded_files(real_files)
    summary = build_summary(results)

    if wants_json:
        return jsonify({"results": results, "summary": summary})

    return render_template("result.html", results=results, summary=summary)


def build_chart_data(rows):
    """
    Turn the scan history rows into numbers the charts can draw.

    We do the small amount of maths here in Python so the HTML page can
    simply print the values. No chart library is needed - the charts are
    plain SVG shapes.
    """
    # --- 1. Count how many Safe / Suspicious / Malicious files there are ---
    result_counts = {"Safe": 0, "Suspicious": 0, "Malicious": 0, "Error": 0}
    type_counts = {}

    for row in rows:
        result = row["result"] or "Error"
        result_counts[result] = result_counts.get(result, 0) + 1

        file_type = row["file_type"] or "Unknown"
        type_counts[file_type] = type_counts.get(file_type, 0) + 1

    total = len(rows)

    # --- 2. Donut chart segments -------------------------------------
    # A circle of radius 70 has a circumference of 2 * pi * 70 = 439.8.
    # Each segment is drawn as a dash of that circle: its length is
    # (count / total) * circumference, and each new segment starts where
    # the previous one ended.
    circumference = 439.8
    donut = []
    start = 0.0

    for label in ["Safe", "Suspicious", "Malicious", "Error"]:
        count = result_counts.get(label, 0)
        if count == 0:
            continue

        share = count / total if total else 0
        donut.append({
            "label": label,
            "count": count,
            "percent": round(share * 100),
            "dash": round(share * circumference, 2),
            "gap": round(circumference - share * circumference, 2),
            "offset": round(-start * circumference, 2),
        })
        start += share

    # --- 3. Bar chart of the most common file types ------------------
    ordered_types = sorted(type_counts.items(), key=lambda item: item[1], reverse=True)
    biggest = ordered_types[0][1] if ordered_types else 1

    bars = [
        {
            "label": name,
            "count": count,
            "width": round(count / biggest * 100),  # bar width in percent
        }
        for name, count in ordered_types[:6]
    ]

    return {
        "total": total,
        "counts": result_counts,
        "donut": donut,
        "bars": bars,
        "clean_percent": round(result_counts["Safe"] / total * 100) if total else 0,
    }


@app.route("/history")
def history():
    """Show every scanned file, newest scan at the top, plus charts."""
    connection = get_connection()
    rows = connection.execute(
        "SELECT * FROM scan_history ORDER BY id DESC"
    ).fetchall()
    connection.close()

    charts = build_chart_data(rows)
    return render_template("history.html", rows=rows, charts=charts)


@app.route("/clear-history", methods=["POST"])
def clear_history():
    """Delete all rows from scan_history (useful while testing)."""
    connection = get_connection()
    connection.execute("DELETE FROM scan_history")
    connection.commit()
    connection.close()
    return redirect(url_for("history"))
@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    conn = sqlite3.connect(DATABASE)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            feedback TEXT
        )
    """)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        feedback_text = request.form.get("feedback", "").strip()

        conn.execute(
            "INSERT INTO feedback (name, feedback) VALUES (?, ?)",
            (name, feedback_text)
        )
        conn.commit()

        conn.close()

        return redirect(url_for("feedback"))

    feedbacks = conn.execute(
        "SELECT * FROM feedback ORDER BY id DESC"
    ).fetchall()

    conn.close()

    return render_template("feedback.html", feedbacks=feedbacks)
@app.errorhandler(413)
def file_too_large(error):
    """
    Shown when the user selects more than MAX_UPLOAD_KB in one go.
    We answer with JSON for our JavaScript and with HTML for a normal
    form post, so the user always sees a clear message instead of a
    confusing "server not reachable" error.
    """
    message = (
        f"Upload is too large. The total size of all selected files must stay "
        f"under {MAX_UPLOAD_KB} KB. Scan the very big files one at a time, or "
        f"increase MAX_UPLOAD_KB in app.py."
    )

    if request.headers.get("X-Requested-With") == "fetch":
        return jsonify({"error": message}), 413

    return render_template("scan.html", error=message), 413


# ---------------------------------------------------------------
# 8) START THE APPLICATION
# ---------------------------------------------------------------
if __name__ == "__main__":
    init_db()  # create / upgrade the database before the server starts
    app.run(debug=True)
