/*
 * auth_guard.js
 * Server-authoritative staff session guard for the multi-tenant Flask system.
 *
 * IMPORTANT:
 * - Flask /api/staff/me is the authorization source.
 * - localStorage is UI metadata only.
 * - This file does not initialize Firebase or read Firestore directly.
 */

function clearStoredAuthorization() {
    localStorage.removeItem("user_name");
    localStorage.removeItem("user_clearance");
    localStorage.removeItem("user_position");
}

window.getUserClearance = function () {
    return localStorage.getItem("user_clearance") || "Viewer";
};

window.hasWriteAccess = function () {
    return ["SuperAdmin", "Admin", "Editor"].includes(window.getUserClearance());
};

window.hasAdminAccess = function () {
    return ["SuperAdmin", "Admin"].includes(window.getUserClearance());
};

window.hasFacilityManagementAccess = function () {
    return ["Admin", "SuperAdmin"].includes(window.getUserClearance());
};

function isFacilityManagementPage() {
    return window.location.pathname.replace(/\/+$/, "") === "/facility";
}

function redirectToHub() {
    window.location.href = "/hub";
}

async function initializeFacilityAuthGuard() {
    try {
        const response = await fetch("/api/staff/me", {
            method: "GET",
            credentials: "same-origin",
            cache: "no-store",
            headers: { "Accept": "application/json" }
        });

        if (!response.ok) {
            clearStoredAuthorization();
            window.location.href = "/login";
            return;
        }

        const data = await response.json();
        if (!data.success || !data.staff) {
            clearStoredAuthorization();
            window.location.href = "/login";
            return;
        }

        const staff = data.staff;
        const validRoles = ["Viewer", "Editor", "Admin", "SuperAdmin"];
        if (!staff.uid || !staff.email || !staff.facility_id || !validRoles.includes(staff.clearance)) {
            clearStoredAuthorization();
            window.location.href = "/login";
            return;
        }

        localStorage.setItem("user_name", staff.name || "Staff");
        localStorage.setItem("user_clearance", staff.clearance);
        localStorage.setItem("user_position", staff.position || "Staff");

        if (isFacilityManagementPage() && !["Admin", "SuperAdmin"].includes(staff.clearance)) {
            redirectToHub();
            return;
        }
    } catch (error) {
        clearStoredAuthorization();
        window.location.href = "/login";
    }
}

initializeFacilityAuthGuard();
