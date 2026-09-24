/* =========================================================
   Antivirus Scanner - scan page JavaScript
   1. Shows how many files the user selected, with their names.
   2. Sends the files to Flask with fetch() so the results appear
      on the same page (no reload).
   3. Builds a notification box inside the page (not alert()).
   ========================================================= */

const fileInput = document.getElementById("files");
const fileCount = document.getElementById("fileCount");
const fileList = document.getElementById("fileList");
const scanForm = document.getElementById("scanForm");
const scanButton = document.getElementById("scanButton");
const notificationArea = document.getElementById("notificationArea");
const resultsArea = document.getElementById("resultsArea");

/* Turn 20480 into "20.0 KB" so sizes are easy to read */
function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

/* ---------- 1. Show the selected files before scanning ---------- */
if (fileInput) {
    fileInput.addEventListener("change", function () {
        const files = fileInput.files;
        fileCount.textContent = "Selected files: " + files.length;
        fileList.innerHTML = "";

        for (let i = 0; i < files.length; i++) {
            const item = document.createElement("li");
            const name = document.createElement("span");
            const meta = document.createElement("span");

            name.textContent = files[i].name;
            meta.className = "file-meta";
            meta.textContent = formatSize(files[i].size);

            item.appendChild(name);
            item.appendChild(meta);
            fileList.appendChild(item);
        }
    });
}

/* ---------- 2. Send the files and show the results ---------- */
if (scanForm) {
    scanForm.addEventListener("submit", async function (event) {
        // Stop the normal page reload; we will use fetch instead.
        event.preventDefault();

        if (!fileInput.files.length) {
            showNotice("warning", "No file selected. Choose at least one file, then press Scan files.");
            return;
        }

        // Check the total size BEFORE uploading, so a huge file gives a clear
        // message instead of a failed upload.
        const maxMb = parseInt(scanForm.dataset.maxMb || "500", 10);
        let totalBytes = 0;
        for (let i = 0; i < fileInput.files.length; i++) {
            totalBytes += fileInput.files[i].size;
        }

        if (totalBytes > maxMb * 1024 * 1024) {
            showNotice("warning",
                "These files add up to " + formatSize(totalBytes) + ", which is more than the " +
                maxMb + " MB limit. Scan the very large files one at a time, or increase " +
                "<code>MAX_UPLOAD_MB</code> in app.py.");
            return;
        }

        scanButton.disabled = true;
        scanButton.textContent = "Scanning...";
        notificationArea.innerHTML = "";
        resultsArea.innerHTML = "";

        // Large files take a few seconds to upload and hash, so say so.
        if (totalBytes > 20 * 1024 * 1024) {
            showNotice("warning", "Uploading and hashing " + formatSize(totalBytes) +
                       ". Large files can take a few seconds, please wait.");
        }

        try {
            const formData = new FormData(scanForm);

            const response = await fetch(scanForm.action, {
                method: "POST",
                body: formData,
                // This header tells Flask to answer with JSON
                headers: { "X-Requested-With": "fetch" }
            });

            // The server may answer with HTML (for example an error page),
            // so only call response.json() when the answer really is JSON.
            const contentType = response.headers.get("content-type") || "";
            let data = {};

            if (contentType.indexOf("application/json") !== -1) {
                data = await response.json();
            }

            if (!response.ok) {
                showNotice("warning", data.error ||
                    "The scan could not be completed. The server replied with status " +
                    response.status + ".");
                return;
            }

            if (!data.results) {
                showNotice("warning", "The server did not send any scan results. " +
                                      "Check the terminal where app.py is running.");
                return;
            }

            showNotification(data.summary);
            showResults(data.results, data.summary);
        } catch (error) {
            showNotice("warning",
                "The upload stopped before it finished. This usually means the files were " +
                "too large or the connection was interrupted. Check that app.py is still " +
                "running, then try fewer files at a time.");
        } finally {
            scanButton.disabled = false;
            scanButton.textContent = "Scan files";
        }
    });
}

/* ---------- 3. The notification box (Feature 2) ---------- */
function showNotice(kind, htmlText) {
    notificationArea.innerHTML =
        '<div class="notice notice-' + kind + '">' + htmlText + "</div>";
}

function showNotification(summary) {
    if (summary.malicious > 0) {
        let message = "<strong>&#9888; Warning: malicious file detected.</strong><ul>";
        summary.malicious_files.forEach(function (name) {
            message += "<li>" + escapeHtml(name) + "</li>";
        });
        message += "</ul>Do not open these files. Delete them from the uploads folder.";

        showNotice("danger", message);
        notificationArea.querySelector(".notice").classList.add("pulse");
    } else if (summary.suspicious > 0) {
        let message = "<strong>No known malicious hash matched, but these files need care:</strong><ul>";
        summary.suspicious_files.forEach(function (name) {
            message += "<li>" + escapeHtml(name) + "</li>";
        });
        message += "</ul>";
        showNotice("warning", message);
    } else {
        showNotice("safe", "<strong>&#10004; Scan completed. No known malicious hashes found.</strong>");
    }
}

/* ---------- 4. Build the summary boxes and result table ---------- */
function showResults(results, summary) {
    let html = '<section class="summary-row">';
    html += summaryBox(summary.total, "total files", "");
    html += summaryBox(summary.safe, "safe", "is-safe");
    html += summaryBox(summary.suspicious, "suspicious", "is-suspicious");
    html += summaryBox(summary.malicious, "malicious", "is-malicious");
    html += "</section>";
html += '<div class="card table-card"><div class="table-scroll"><table class="data-table"><thead><tr>' +
        "<th>File name</th>" +
        "<th>File type</th>" +
        "<th>SHA-256 hash</th>" +
        "<th>Result</th>" +
        "<th>Virus Type</th>" +
        "<th>Reason</th>" +
        "</tr></thead><tbody>";


    results.forEach(function (item) {
    html += "<tr>" +

            '<td class="cell-name">' +
                escapeHtml(item.filename) +
            "</td>" +

            "<td>" +
                escapeHtml(item.file_type) +
            "</td>" +

            '<td class="hash">' +
                escapeHtml(item.file_hash) +
            "</td>" +

            '<td>' +
                '<span class="tag tag-' + item.result.toLowerCase() + '">' +
                    escapeHtml(item.result) +
                "</span>" +
            "</td>" +

            '<td>' +
                escapeHtml(item.threat_type || "Unknown") +
            "</td>" +

            '<td class="reason">' +
                escapeHtml(item.reason || "No suspicious indicators detected") +
            "</td>" +

            "</tr>";
});

    
    html += "</tbody></table></div></div>";
    html += '<p class="disclaimer">Basic hash-based scanner. "Safe" means no known-malicious ' +
            "hash matched; it is not a guarantee that the file is virus free.</p>";

    resultsArea.innerHTML = html;
    resultsArea.scrollIntoView({ behavior: "smooth", block: "start" });
}

function summaryBox(number, label, extraClass) {
    return '<div class="summary-box ' + extraClass + '">' +
           '<span class="summary-number">' + number + "</span>" +
           '<span class="summary-label">' + label + "</span></div>";
}

/* Filenames come from the user, so escape them before putting them in HTML */
function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text === undefined || text === null ? "" : String(text);
    return div.innerHTML;
}
