# Basic Hash-Based Antivirus Scanner

Diploma CSE/CME mini project — Python, Flask, SQLite, SHA-256.

Upgraded with three new features: multiple file scanning, malicious file
notification, and file type detection.

---

## 1. Project structure

```
antivirus_project/
├── app.py                  main Flask application
├── database.db             created automatically on first run
├── malicious_hashes.txt    optional extra hash list
├── requirements.txt
├── uploads/                uploaded files are stored here
├── templates/
│   ├── index.html
│   ├── scan.html
│   ├── result.html
│   └── history.html
└── static/
    ├── style.css
    └── script.js
```

## 2. Installation

```bash
pip install flask
```

(or `pip install -r requirements.txt`)

Nothing else is needed. `hashlib`, `sqlite3`, `os` and `mimetypes` are part
of the Python standard library.

## 3. How to run

```bash
cd antivirus_project
python app.py
```

Open **http://127.0.0.1:5000/** in your browser.

- Home page → project summary
- Scan files → select many files and scan them
- History → charts plus every scanned file, newest first

The database and its tables are created automatically the first time you run
the app, so you do not have to create `database.db` yourself.

## 4. How to demo a "Malicious" result safely

Never use real malware. Instead create a harmless test file whose hash is
already in the list:

**Windows (Notepad):** create `test_malicious.txt` containing exactly this one
line (press Enter at the end):

```
This is a test malicious file for the antivirus project.
```

**Linux / macOS:**

```bash
printf 'This is a test malicious file for the antivirus project.\n' > test_malicious.txt
```

Its SHA-256 is
`bcf199184beffeb49d5cf8c4d39eec065b51f37ef4cc32978321e80fc5b9d3b8`,
which is already inside `MALICIOUS_HASHES`, so the scanner will report
**Malicious** for it. Rename it to `test.exe` if you want the demo to look
like the example in your report.

## 5. Where to add known malicious SHA-256 hashes

Two places, both easy:

**Option A — inside `app.py`** (around line 60), in the `MALICIOUS_HASHES` list:

```python
MALICIOUS_HASHES = [
    "bcf199184beffeb49d5cf8c4d39eec065b51f37ef4cc32978321e80fc5b9d3b8",
    "paste_your_new_64_character_hash_here",
]
```

**Option B — inside `malicious_hashes.txt`**, one hash per line. `app.py`
reads this file automatically if it exists, so you can keep adding hashes
without touching the Python code.

Rules: lowercase, exactly 64 characters, one hash per entry. A file is marked
Malicious **only** when its hash matches an entry here — nothing is ever
labelled malicious at random.

## 6. Database schema

```sql
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    file_hash TEXT,
    result TEXT
);

-- added automatically by init_db() if they are missing:
ALTER TABLE scan_history ADD COLUMN file_type TEXT;
ALTER TABLE scan_history ADD COLUMN scan_time TEXT;
```

`init_db()` checks the existing columns with `PRAGMA table_info(scan_history)`
and only adds what is missing, so **an old database keeps all its rows**. Old
rows simply show "Unknown" in the File Type column.

## 6b. Charts on the history page

The history page opens with two charts, both drawn as plain SVG and CSS -
**no chart library, no internet connection needed**:

- a **donut chart** of Safe / Suspicious / Malicious, with the percentage of
  clean files in the middle;
- a **bar chart** of the most frequently scanned file types.

`build_chart_data()` in app.py counts the rows and works out each slice. A
circle of radius 70 has a circumference of about 439.8, so a slice covering
20% of the files is drawn as a dash of 0.20 x 439.8 = 87.96 using the SVG
attribute `stroke-dasharray`, and `stroke-dashoffset` pushes each new slice to
start where the previous one ended. The bars are simply `<div>` elements whose
width percentage comes from `count / biggest count`.

## 7. How the three features work (simple English)

**Feature 1 — Multiple file scanning.**
The file input on the scan page has the `multiple` attribute, so the user can
pick many files at once. In Flask, `request.files.getlist("files")` returns
the whole list instead of a single file. A `for` loop walks through the list:
each file is saved with a safe name, hashed with SHA-256, checked against the
malicious hash list and added to the results list. The loop never stops when a
malicious file is found — it just records the result and moves to the next
file. At the end the counts (total / safe / suspicious / malicious) are
calculated and shown along with a table of every file.

**Feature 2 — Malicious file notification.**
After the scan, the summary contains a list of all malicious filenames. If
that list is not empty, JavaScript builds a red notification box at the top of
the page (with a short pulse so it catches the eye) and lists every malicious
file. If some files are only suspicious, an orange box appears. If everything
is clean, a green box says that no known malicious hashes were found. This is
a notification box inside the page, not a browser `alert()`. The wording is
careful on purpose: "Safe" means no known-malicious hash matched, not that the
file is guaranteed virus free.

**Feature 3 — File type detection.**
`detect_file_type()` takes the file name, splits off the extension with
`os.path.splitext()` and looks it up in the `FILE_TYPES` dictionary, which maps
`.pdf` to "PDF", `.exe` to "Windows Executable", and so on. If the extension is
not in the dictionary, Python's `mimetypes.guess_type()` is used as a backup,
and if even that fails the extension itself is shown. The detected type is
displayed in the results table and saved in the `file_type` column so it also
appears in the scan history.

## 8. Security points to mention in the report

- `secure_filename()` cleans every uploaded name, so `../../etc/passwd`
  becomes `etc_passwd` and cannot escape the uploads folder (path traversal).
- An extra check confirms the final path is really inside `uploads/`.
- Duplicate names are never overwritten: `notes.txt` becomes `notes_1.txt`.
- Uploaded files are only **opened in read-binary mode for hashing**. They are
  never executed, imported or opened by any other program.
- Empty selections, unreadable files and oversized uploads (over the MAX_UPLOAD_MB limit, 500 MB by default) are
  handled with a message instead of a crash.

## 9. Viva questions and answers

**1. What is SHA-256 and why is it used here?**
SHA-256 is a cryptographic hash function that turns any file into a fixed
64-character fingerprint. The same file always gives the same hash, and even a
one-bit change gives a completely different hash. So comparing hashes is a
reliable way to recognise a known file.

**2. Why read the file in 4096-byte blocks instead of all at once?**
`file.read()` without a size loads the whole file into memory. Reading in small
blocks and calling `sha256.update()` each time gives the same final hash while
using only a few kilobytes of RAM, so even a 2 GB file can be scanned.

**3. How does Flask receive several files from one input?**
The form uses `enctype="multipart/form-data"` and the input has the `multiple`
attribute. On the server, `request.files.getlist("files")` returns a list of
all uploaded files; `request.files["files"]` would return only the first one.

**4. Is your project a real antivirus?**
No. It is a basic signature (hash) based scanner. It detects only files whose
exact hash is already in the list. Real antivirus software also uses heuristic
analysis, behaviour monitoring, sandboxing and continuously updated signature
databases.

**5. If a file is reported Safe, is it definitely virus free?**
No. "Safe" only means no known-malicious hash matched. A brand new virus, or
even a one-byte modified copy of a known virus, has a different hash and would
not be detected.

**6. What is the difference between Malicious and Suspicious in your project?**
Malicious means the SHA-256 hash matched an entry in the known-malicious list —
that is a definite match. Suspicious comes from simple extra rules: the file can
run code (.exe, .bat, .vbs …) or it hides behind a double extension such as
`invoice.pdf.exe`. Suspicious is a warning, not a detection.

**7. Why is `secure_filename()` necessary?**
The filename comes from the user and cannot be trusted. Without cleaning it, a
name like `../../app.py` could make the server write outside the uploads folder
and overwrite project files. That attack is called path traversal.

**8. How did you add a column without losing old scan history?**
`init_db()` runs `PRAGMA table_info(scan_history)` to list the existing columns.
If `file_type` is missing it runs `ALTER TABLE scan_history ADD COLUMN
file_type TEXT`. `ALTER TABLE ... ADD COLUMN` only adds the column; existing
rows stay and get NULL, which the history page shows as "Unknown".

**9. How does file type detection work, and what is its weakness?**
It uses the file extension with a dictionary lookup and `mimetypes` as a
backup. The weakness is that the extension can be renamed — a virus called
`photo.jpg` would be reported as a JPEG image. A stronger method is reading the
file's magic number (the first few bytes) instead of trusting the name.

**10. Why does the scan continue after a malicious file is found?**
Because the user wants a result for every selected file. The `for` loop appends
the result and moves on, so one malicious file among ten does not hide the
status of the other nine.

**11. Where are the scan results stored, and why one row per file?**
In the SQLite table `scan_history`, one row per scanned file (filename, file
type, hash, result, time). Storing each file separately makes the history easy
to sort, count and search. `ORDER BY id DESC` puts the newest scan on top.

**12. How would you improve this project further?**
Add magic-number based type detection, compare hashes against an online
database such as VirusTotal through its API, allow the user to delete or
quarantine detected files, support ZIP inspection, and add user login.
