/*
 * prep_sheets_exporter.js
 * Secure PrEP Google Sheets export client.
 * Clinical data is NOT accepted from the browser. Flask retrieves the
 * authoritative tenant record and sends the export to the facility webhook.
 */

async function getPrepExportCsrfToken() {
    const response = await fetch("/api/prep/csrf-token", {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        headers: { "Accept": "application/json" }
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.success || !data.csrf_token) {
        throw new Error(data.error || "Unable to initialize PrEP export security token.");
    }
    return data.csrf_token;
}

export async function exportCurrentPrepToGoogleSheets() {
    const uicField = document.getElementById("input-uic");
    const uic = uicField ? uicField.value.trim().toUpperCase() : (window.currentClient?.uic || "");
    if (!uic) return false;

    try {
        const csrfToken = await getPrepExportCsrfToken();
        const response = await fetch("/api/prep/sheets-backup", {
            method: "POST",
            credentials: "same-origin",
            cache: "no-store",
            headers: {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-CSRF-Token": csrfToken
            },
            body: JSON.stringify({ uic })
        });

        if (response.status === 401) {
            window.location.href = "/login";
            return false;
        }
        const result = await response.json().catch(() => ({}));
        return response.ok && result.success === true;
    } catch (_) {
        return false;
    }
}
