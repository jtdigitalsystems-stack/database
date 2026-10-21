import os
import json
import secrets
import time
import hmac
import re
import io
import csv
import requests

from datetime import datetime, timezone
from functools import wraps

from dotenv import load_dotenv

load_dotenv()

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
    Response,
)

import firebase_admin
from firebase_admin import credentials, firestore

app = Flask(__name__)

# =========================================================
# FLASK / SESSION SECURITY
# =========================================================

FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "").strip()
if not FLASK_SECRET_KEY:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is required.")

app.secret_key = FLASK_SECRET_KEY

@app.errorhandler(413)
def request_entity_too_large(error):
    if request.path.startswith("/api/"):
        return jsonify({
            "success": False,
            "error": "Request body is too large. Reduce the import batch size and try again."
        }), 413
    return "Request body is too large.", 413

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_REFRESH_EACH_REQUEST=True,
    # Bulk ART/PrEP imports contain nested JSON and clinical history logs.
    # Keep a bounded request limit, configurable per deployment (default 16 MiB).
    MAX_CONTENT_LENGTH=int(os.getenv("MAX_CONTENT_LENGTH", str(16 * 1024 * 1024))),
)

PENDING_LOGIN_TTL = 300

# =========================================================
# MOTHER FIREBASE
# =========================================================

mother_db = None
mother_app = None

try:
    service_account_json = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()
    service_account_path = os.getenv("FIREBASE_SERVICE_ACCOUNT_PATH", "serviceAccountKey.json").strip()
    if service_account_json:
        mother_app = firebase_admin.initialize_app(
            credentials.Certificate(json.loads(service_account_json)),
            name="mother"
        )
        mother_db = firestore.client(app=mother_app)
    elif os.path.exists(service_account_path):
        mother_app = firebase_admin.initialize_app(
            credentials.Certificate(service_account_path),
            name="mother"
        )
        mother_db = firestore.client(app=mother_app)
except Exception as error:
    print("Mother Firebase initialization failed:", repr(error))
    mother_db = None

# =========================================================
# TENANT ADMIN APPS
# =========================================================

tenant_apps = {}

def get_facility_admin_sdk(facility_id):
    facility_id = str(facility_id or "").strip()

    if not facility_id or facility_id.lower() == "master":
        raise RuntimeError("Invalid tenant facility.")

    if mother_db is None:
        raise RuntimeError("Mother Firebase is unavailable.")

    if facility_id in tenant_apps:
        return tenant_apps[facility_id]

    facility_snapshot = (
        mother_db
        .collection("facilities")
        .document(facility_id)
        .get()
    )

    if not facility_snapshot.exists:
        raise RuntimeError(
            f"Facility [{facility_id}] does not exist."
        )

    facility_data = (
        facility_snapshot.to_dict()
        or {}
    )

    if facility_data.get("active") is False:
        raise RuntimeError(
            f"Facility [{facility_id}] is inactive."
        )

    firebase_config = facility_data.get(
        "firebase_config",
        {}
    )

    if not isinstance(firebase_config, dict):
        raise RuntimeError(
            f"Invalid Firebase configuration for [{facility_id}]."
        )

    expected_project_id = str(
        firebase_config.get("projectId", "")
    ).strip()

    if not expected_project_id:
        raise RuntimeError(
            f"Missing Firebase project ID for [{facility_id}]."
        )

    env_name = (
        "TENANT_SERVICE_ACCOUNT_"
        + facility_id.upper()
        .replace("-", "_")
        .replace(" ", "_")
    )

    service_account_value = os.getenv(
        env_name,
        ""
    ).strip()

    if not service_account_value:
        raise RuntimeError(
            f"Missing tenant service account configuration "
            f"for {facility_id}."
        )

    if service_account_value.startswith("{"):
        credential_data = json.loads(
            service_account_value
        )
        credential = credentials.Certificate(
            credential_data
        )
    else:
        if not os.path.exists(
            service_account_value
        ):
            raise RuntimeError(
                f"Tenant service account file not found "
                f"for {facility_id}."
            )

        credential = credentials.Certificate(
            service_account_value
        )

    credential_project_id = str(
        getattr(
            credential,
            "project_id",
            ""
        ) or ""
    ).strip()

    if not credential_project_id:
        raise RuntimeError(
            f"Tenant service account for [{facility_id}] "
            f"does not contain a Firebase project ID."
        )

    if credential_project_id != expected_project_id:
        print(
            "🚫 TENANT PROJECT BINDING FAILED:",
            {
                "facility_id": facility_id,
                "expected_project_id": expected_project_id,
                "credential_project_id": credential_project_id
            }
        )

        raise RuntimeError(
            f"Tenant Firebase project mismatch for [{facility_id}]."
        )

    tenant_app = firebase_admin.initialize_app(
        credential,
        name=f"tenant_{facility_id}"
    )

    tenant_apps[facility_id] = tenant_app

    print(
        "✅ TENANT FIREBASE PROJECT VERIFIED:",
        {
            "facility_id": facility_id,
            "project_id": credential_project_id
        }
    )

    return tenant_app

def verify_staff_tenant_token(facility_id, id_token):
    from firebase_admin import auth
    tenant_app = get_facility_admin_sdk(facility_id)
    return auth.verify_id_token(id_token, app=tenant_app, check_revoked=True)

# =========================================================
# LOGIN SECURITY HELPERS
# =========================================================

def clear_pending_login():
    session.pop("pending_login_email", None)
    session.pop("pending_facility_id", None)
    session.pop("pending_login_nonce", None)
    session.pop("pending_login_expires", None)
    session.modified = True

def set_pending_login(email, facility_id):
    session["pending_login_email"] = email
    session["pending_facility_id"] = facility_id
    session["pending_login_nonce"] = secrets.token_urlsafe(32)
    session["pending_login_expires"] = int(time.time()) + PENDING_LOGIN_TTL
    session.modified = True

def get_pending_login():
    email = str(session.get("pending_login_email", "")).strip().lower()
    facility_id = str(session.get("pending_facility_id", "")).strip()
    expires = int(session.get("pending_login_expires", 0) or 0)
    if not email or not facility_id or not expires or time.time() > expires:
        clear_pending_login()
        return None, None
    return email, facility_id

def valid_email(email):
    return bool(email and len(email) <= 254 and "@" in email and " " not in email)

def generic_login_failure(status=200):
    return jsonify({
        "success": False,
        "found": False,
        "error": "Unable to resolve account."
    }), status

# =========================================================
# STAFF LOGIN PAGE
# =========================================================
# =========================================================
# STAFF SESSION PROTECTION
# =========================================================

STAFF_SESSION_MAX_AGE = 8 * 60 * 60

def require_staff_session():
    staff_uid = str(session.get("staff_uid", "")).strip()
    staff_email = str(session.get("staff_email", "")).strip().lower()
    facility_id = str(session.get("facility_id", "")).strip()
    authenticated_at = int(session.get("authenticated_at", 0) or 0)

    if (
        not staff_uid
        or not staff_email
        or not facility_id
        or not authenticated_at
    ):
        session.clear()
        return False

    if time.time() - authenticated_at > STAFF_SESSION_MAX_AGE:
        session.clear()
        return False

    if facility_id.lower() == "master":
        session.clear()
        return False

    if mother_db is None:
        session.clear()
        return False

    try:
        staff_snapshot = (
            mother_db
            .collection("authorized_clinical_staff")
            .document(staff_email)
            .get()
        )

        if not staff_snapshot.exists:
            session.clear()
            return False

        staff_data = staff_snapshot.to_dict() or {}

        stored_uid = str(
            staff_data.get("uid", "")
        ).strip()

        stored_facility = str(
            staff_data.get("facility_id", "")
        ).strip()

        if (
            stored_uid != staff_uid
            or stored_facility != facility_id
            or staff_data.get("accountInitialized") is not True
        ):
            session.clear()
            return False

        facility_snapshot = (
            mother_db
            .collection("facilities")
            .document(facility_id)
            .get()
        )

        if not facility_snapshot.exists:
            session.clear()
            return False

        facility_data = facility_snapshot.to_dict() or {}

        if facility_data.get("active") is False:
            session.clear()
            return False

        return True

    except Exception:
        session.clear()
        return False


def staff_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if not require_staff_session():
            return redirect(url_for("login_page"))
        return view_function(*args, **kwargs)

    return wrapped_view


# =========================================================
# STAFF LOGIN PAGE
# =========================================================
from flask import send_from_directory
import os

@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon"
    )

@app.route("/", methods=["GET"])
@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")

@app.route("/landing.html", methods=["GET"])
@staff_required
def landing_page():
    return render_template("landing.html")

@app.route("/selectdb", methods=["GET"])
@staff_required
def selectdb_page():
    return render_template("selectdb.html")


@app.route("/facility", methods=["GET"])
@staff_required
def facility_page():
    # Supply the tenant's Firebase configuration to facility.html, which
    # includes firebase_config.html and expects the firebase_config variable.
    facility_id = str(session.get("facility_id", "")).strip()

    if not facility_id or facility_id.lower() == "master":
        session.clear()
        return redirect(url_for("login_page"))

    if mother_db is None:
        return "Facility database is temporarily unavailable.", 503

    try:
        facility_snapshot = (
            mother_db.collection("facilities")
            .document(facility_id)
            .get()
        )

        if not facility_snapshot.exists:
            session.clear()
            return redirect(url_for("login_page"))

        facility_data = facility_snapshot.to_dict() or {}
        if facility_data.get("active") is False:
            session.clear()
            return redirect(url_for("login_page"))

        firebase_config = facility_data.get("firebase_config", {})
        if not isinstance(firebase_config, dict):
            firebase_config = {}

        return render_template(
            "facility.html",
            firebase_config=firebase_config,
        )
    except Exception:
        app.logger.exception("Unable to load facility page configuration")
        return "Unable to load facility configuration. Please try again.", 503


@app.route("/reports", methods=["GET"])
@staff_required
def reports_page():
    return render_template("reports.html")


@app.route("/profile", methods=["GET"])
@staff_required
def profile_page():
    return render_template("profile.html")


@app.route("/resources", methods=["GET"])
@staff_required
def resources_page():
    return render_template("resources.html")

# =========================================================
# RESOLVE STAFF FACILITY
# =========================================================

@app.route("/api/resolve-user", methods=["GET"])
def resolve_user():
    try:
        if mother_db is None:
            return generic_login_failure(503)

        email = str(request.args.get("email", "")).strip().lower()
        if not valid_email(email):
            clear_pending_login()
            return generic_login_failure()

        staff_snapshot = mother_db.collection("authorized_clinical_staff").document(email).get()
        if not staff_snapshot.exists:
            clear_pending_login()
            return generic_login_failure()

        staff_data = staff_snapshot.to_dict() or {}
        facility_id = str(staff_data.get("facility_id", "")).strip()

        if (
            not facility_id
            or facility_id.lower() == "master"
            or facility_id.upper() == "NONE SELECTED"
            or staff_data.get("accountInitialized") is not True
        ):
            clear_pending_login()
            return generic_login_failure()

        facility_snapshot = mother_db.collection("facilities").document(facility_id).get()
        if not facility_snapshot.exists:
            clear_pending_login()
            return generic_login_failure()

        facility_data = facility_snapshot.to_dict() or {}
        if facility_data.get("active") is False:
            clear_pending_login()
            return generic_login_failure()

        set_pending_login(email, facility_id)
        return jsonify({
            "success": True,
            "found": True,
            "facility_id": facility_id
        }), 200

    except Exception as error:
        print("Staff facility resolution failed:", repr(error))
        clear_pending_login()
        return generic_login_failure(503)

# =========================================================
# TENANT FIREBASE CONFIG
# =========================================================

@app.route("/api/login/firebase-config", methods=["GET"])
def staff_login_firebase_config():
    try:
        if mother_db is None:
            return jsonify({"success": False, "error": "Authentication service unavailable."}), 503

        email, facility_id = get_pending_login()
        if not email or not facility_id:
            return jsonify({"success": False, "error": "Login session has expired. Please try again."}), 401

        staff_snapshot = mother_db.collection("authorized_clinical_staff").document(email).get()
        if not staff_snapshot.exists:
            clear_pending_login()
            return jsonify({"success": False, "error": "Unable to resolve account."}), 403

        staff_data = staff_snapshot.to_dict() or {}
        if (
            str(staff_data.get("facility_id", "")).strip() != facility_id
            or staff_data.get("accountInitialized") is not True
        ):
            clear_pending_login()
            return jsonify({"success": False, "error": "Invalid tenant authentication context."}), 403

        facility_snapshot = mother_db.collection("facilities").document(facility_id).get()
        if not facility_snapshot.exists:
            return jsonify({"success": False, "error": "Facility node is not available."}), 404

        facility_data = facility_snapshot.to_dict() or {}
        if facility_data.get("active") is False:
            return jsonify({"success": False, "error": "Facility authentication is unavailable."}), 403

        firebase_config = facility_data.get("firebase_config", {})
        if not isinstance(firebase_config, dict):
            return jsonify({"success": False, "error": "Invalid facility Firebase configuration."}), 500

        required = ("apiKey", "authDomain", "projectId", "appId")
        if not all(str(firebase_config.get(key, "")).strip() for key in required):
            return jsonify({"success": False, "error": "Incomplete facility Firebase configuration."}), 500

        return jsonify({
            "success": True,
            "facility_id": facility_id,
            "facility_name": facility_data.get("facility_name", facility_id),
            "firebase": firebase_config
        }), 200

    except Exception as error:
        print("Staff tenant config failed:", repr(error))
        return jsonify({"success": False, "error": "Unable to initialize facility authentication."}), 503

# =========================================================
# ESTABLISH STAFF SESSION
# =========================================================

@app.route("/api/staff/session", methods=["POST"])
def establish_staff_session():
    try:
        if mother_db is None:
            return jsonify({"success": False, "error": "Authentication service unavailable."}), 503

        email, facility_id = get_pending_login()
        if not email or not facility_id:
            session.clear()
            return jsonify({"success": False, "error": "Login session expired. Please sign in again."}), 401

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"success": False, "error": "Invalid authentication request."}), 400

        id_token = str(payload.get("id_token", "")).strip()
        if not id_token or len(id_token) > 8192:
            return jsonify({"success": False, "error": "Firebase authentication token is required."}), 401

        decoded_token = verify_staff_tenant_token(facility_id, id_token)
        uid = str(decoded_token.get("uid", "")).strip()
        token_email = str(decoded_token.get("email", "")).strip().lower()

        if not uid or not token_email or token_email != email:
            clear_pending_login()
            return jsonify({"success": False, "error": "Authenticated account does not match login request."}), 403

        staff_snapshot = mother_db.collection("authorized_clinical_staff").document(email).get()
        if not staff_snapshot.exists:
            clear_pending_login()
            return jsonify({"success": False, "error": "Security verification failed."}), 403

        staff_data = staff_snapshot.to_dict() or {}
        stored_uid = str(staff_data.get("uid", "")).strip()
        stored_facility = str(staff_data.get("facility_id", "")).strip()

        if (
            stored_uid != uid
            or stored_facility != facility_id
            or staff_data.get("accountInitialized") is not True
        ):
            clear_pending_login()
            return jsonify({"success": False, "error": "Security verification failed."}), 403

        facility_snapshot = mother_db.collection("facilities").document(facility_id).get()
        if not facility_snapshot.exists:
            clear_pending_login()
            return jsonify({"success": False, "error": "Security verification failed."}), 403

        facility_data = facility_snapshot.to_dict() or {}
        if facility_data.get("active") is False:
            clear_pending_login()
            return jsonify({"success": False, "error": "Facility authentication is unavailable."}), 403

        clearance = str(staff_data.get("clearancePermission", "Viewer")).strip()
        position = str(staff_data.get("positionRole", "Staff")).strip()
        name = str(staff_data.get("lastNameFirstName", staff_data.get("name", email))).strip() or email

        session.clear()
        session["staff_uid"] = uid
        session["staff_email"] = token_email
        session["facility_id"] = facility_id
        session["staff_clearance"] = clearance
        session["staff_position"] = position
        session["staff_name"] = name
        session["authenticated_at"] = int(time.time())
        session.modified = True

        return jsonify({
            "success": True,
            "facility_id": facility_id,
            "clearancePermission": clearance,
            "positionRole": position
        }), 200

    except Exception as error:
        print("Staff session establishment failed:", repr(error))
        session.clear()
        return jsonify({"success": False, "error": "Unable to establish authenticated staff session."}), 403

@app.route("/api/staff/me", methods=["GET"])
def staff_me():
    if not require_staff_session():
        return jsonify({
            "success": False,
            "error": "Authentication required."
        }), 401

    facility_id = str(session.get("facility_id", "")).strip()
    facility_name = facility_id or "Facility"
    if mother_db is not None and facility_id:
        try:
            facility_snapshot = mother_db.collection("facilities").document(facility_id).get()
            if facility_snapshot.exists:
                facility_data = facility_snapshot.to_dict() or {}
                facility_name = str(
                    facility_data.get("facility_name")
                    or facility_data.get("name")
                    or facility_data.get("displayName")
                    or facility_data.get("display_name")
                    or facility_id
                ).strip() or facility_id
        except Exception as error:
            app.logger.warning("Unable to resolve staff facility display name: %r", error)

    return jsonify({
        "success": True,
        "staff": {
            "uid": session.get("staff_uid"),
            "email": session.get("staff_email"),
            "facility_id": facility_id,
            "facility_name": facility_name,
            "clearance": session.get("staff_clearance"),
            "position": session.get("staff_position"),
            "name": session.get("staff_name"),
        }
    }), 200
# =========================================================
# AUTHENTICATED TENANT FIREBASE CONFIG
# =========================================================

@app.route("/api/firebase-config", methods=["GET"])
def firebase_config():
    if not require_staff_session():
        return jsonify({
            "success": False,
            "error": "Authentication required."
        }), 401

    facility_id = str(session.get("facility_id", "")).strip()

    if not facility_id or facility_id.lower() == "master":
        session.clear()
        return jsonify({
            "success": False,
            "error": "Invalid facility context."
        }), 403

    if mother_db is None:
        return jsonify({
            "success": False,
            "error": "Mother database unavailable."
        }), 503

    try:
        facility_snapshot = (
            mother_db
            .collection("facilities")
            .document(facility_id)
            .get()
        )

        if not facility_snapshot.exists:
            session.clear()
            return jsonify({
                "success": False,
                "error": "Facility not found."
            }), 403

        facility_data = facility_snapshot.to_dict() or {}

        if facility_data.get("active") is False:
            session.clear()
            return jsonify({
                "success": False,
                "error": "Facility authentication is unavailable."
            }), 403

        firebase_config = facility_data.get(
            "firebase_config",
            {}
        )

        if not isinstance(firebase_config, dict):
            return jsonify({
                "success": False,
                "error": "Invalid Firebase configuration."
            }), 500

        required_keys = [
            "apiKey",
            "authDomain",
            "projectId",
            "storageBucket",
            "messagingSenderId",
            "appId"
        ]

        if not all(
            str(firebase_config.get(key, "")).strip()
            for key in required_keys
        ):
            return jsonify({
                "success": False,
                "error": "Incomplete Firebase configuration."
            }), 500

        return jsonify({
            "success": True,
            "facility_id": facility_id,
            "facility_name": str(
                facility_data.get("facility_name")
                or facility_data.get("name")
                or facility_data.get("displayName")
                or facility_data.get("display_name")
                or facility_id
            ).strip(),
            "name": str(
                facility_data.get("facility_name")
                or facility_data.get("name")
                or facility_data.get("displayName")
                or facility_data.get("display_name")
                or facility_id
            ).strip(),
            "firebase": firebase_config
        }), 200

    except Exception as error:
        print(
            "Authenticated Firebase config lookup failed:",
            repr(error)
        )
        return jsonify({
            "success": False,
            "error": "Unable to load facility configuration."
        }), 500 



# =========================================================
# FACILITY STAFF USER MANAGEMENT
# =========================================================

FACILITY_USER_CLEARANCES = {"Viewer", "Editor", "Admin"}


def get_facility_user_admin_context():
    """Authorize facility-admin user management and bind it to the session tenant."""
    if not require_staff_session():
        return None, (jsonify({"success": False, "error": "Authentication required."}), 401)

    facility_id = str(session.get("facility_id", "")).strip()
    staff_uid = str(session.get("staff_uid", "")).strip()
    staff_email = str(session.get("staff_email", "")).strip().lower()
    if not facility_id or facility_id.lower() == "master" or not staff_uid or not staff_email:
        session.clear()
        return None, (jsonify({"success": False, "error": "Invalid facility context."}), 403)
    if mother_db is None:
        return None, (jsonify({"success": False, "error": "Mother database unavailable."}), 503)

    try:
        staff_snap = mother_db.collection("authorized_clinical_staff").document(staff_email).get()
        if not staff_snap.exists:
            session.clear()
            return None, (jsonify({"success": False, "error": "Staff authorization could not be verified."}), 403)
        staff = staff_snap.to_dict() or {}
        if (str(staff.get("uid", "")).strip() != staff_uid
                or str(staff.get("facility_id", "")).strip() != facility_id
                or staff.get("accountInitialized") is not True):
            session.clear()
            return None, (jsonify({"success": False, "error": "Staff authorization could not be verified."}), 403)
        clearance = str(staff.get("clearancePermission", "Viewer")).strip()
        if clearance not in {"Admin", "SuperAdmin"}:
            return None, (jsonify({"success": False, "error": "Facility Admin clearance is required to manage staff accounts."}), 403)
        tenant_app = get_facility_admin_sdk(facility_id)
        return {
            "facility_id": facility_id,
            "uid": staff_uid,
            "email": staff_email,
            "name": str(staff.get("lastNameFirstName", staff.get("name", staff_email))).strip() or staff_email,
            "tenant_app": tenant_app,
            "tenant_db": firestore.client(app=tenant_app),
        }, None
    except Exception as exc:
        app.logger.exception("Facility user admin context failed: %r", exc)
        return None, (jsonify({"success": False, "error": "Unable to initialize facility user management."}), 503)


def facility_user_profile(uid, email, name, bday, position, permission, facility_id, assigned_signature=None):
    """Tenant staff profile matching the SuperAdmin provisioning contract."""
    return {
        "uid": uid,
        "email": email,
        "lastNameFirstName": name,
        "bday": bday or "",
        "positionRole": position or "Staff",
        "clearancePermission": permission,
        "facility_id": facility_id,
        "accountInitialized": True,
        "assignedSignature": assigned_signature or f"USER-{uid[:6].upper()}",
    }


@app.route("/api/users", methods=["GET"])
def facility_list_users():
    context, error = get_facility_user_admin_context()
    if error:
        return error
    requested_facility = str(request.args.get("facility_id", "")).strip()
    if requested_facility and requested_facility != context["facility_id"]:
        return jsonify({"success": False, "error": "You cannot access users from another facility."}), 403
    try:
        docs = context["tenant_db"].collection("authorized_clinical_staff").stream()
        users = []
        for snap in docs:
            data = snap.to_dict() or {}
            if data.get("accountInitialized") is not True:
                continue
            if str(data.get("facility_id", "")).strip() != context["facility_id"]:
                continue
            users.append({
                "uid": str(data.get("uid", "")),
                "email": str(data.get("email", snap.id)),
                "lastNameFirstName": str(data.get("lastNameFirstName", data.get("name", ""))),
                "positionRole": str(data.get("positionRole", "Staff")),
                "clearancePermission": str(data.get("clearancePermission", "Viewer")),
                "bday": str(data.get("bday", "")),
            })
        users.sort(key=lambda item: item["lastNameFirstName"].casefold())
        return jsonify({"success": True, "facility_id": context["facility_id"], "users": users}), 200
    except Exception as exc:
        app.logger.exception("Facility user list failed: %r", exc)
        return jsonify({"success": False, "error": "Unable to load facility staff accounts."}), 503


@app.route("/api/provision-user", methods=["POST"])
def facility_provision_user():
    context, error = get_facility_user_admin_context()
    if error:
        return error
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"success": False, "error": "Invalid user request."}), 400

    email = str(payload.get("new_email") or payload.get("email") or "").strip().lower()
    name = str(payload.get("name") or "").strip()
    password = str(payload.get("password") or "")
    bday = str(payload.get("bday") or "").strip()
    position = str(payload.get("position") or "Staff").strip() or "Staff"
    permission = str(payload.get("permission") or "Editor").strip()
    if not valid_email(email):
        return jsonify({"success": False, "error": "Enter a valid email address."}), 400
    if len(name) < 2:
        return jsonify({"success": False, "error": "Full name is required."}), 400
    if len(password) < 6:
        return jsonify({"success": False, "error": "Password must contain at least 6 characters."}), 400
    if permission not in FACILITY_USER_CLEARANCES:
        return jsonify({"success": False, "error": "Invalid permission clearance."}), 400

    from firebase_admin import auth
    tenant_app = context["tenant_app"]
    tenant_db = context["tenant_db"]
    created_uid = None
    try:
        # Prevent duplicate authorization records before creating an Auth account.
        tenant_profile_ref = tenant_db.collection("authorized_clinical_staff").document(email)
        if tenant_profile_ref.get().exists or mother_db.collection("authorized_clinical_staff").document(email).get().exists:
            return jsonify({"success": False, "error": "This email is already registered in the staff directory."}), 409

        user_record = auth.create_user(email=email, password=password, display_name=name, app=tenant_app)
        created_uid = str(user_record.uid).strip()
        if not created_uid:
            raise RuntimeError("Firebase Authentication returned no UID.")
        profile = facility_user_profile(created_uid, email, name, bday, position, permission, context["facility_id"])
        tenant_profile_ref.set(profile)
        try:
            mother_db.collection("authorized_clinical_staff").document(email).set({
                "uid": created_uid,
                "email": email,
                "lastNameFirstName": name,
                "positionRole": position,
                "clearancePermission": permission,
                "facility_id": context["facility_id"],
                "accountInitialized": True,
            })
        except Exception:
            tenant_profile_ref.delete()
            raise
        return jsonify({"success": True, "uid": created_uid, "message": "Staff account created successfully."}), 201
    except Exception as exc:
        app.logger.exception("Facility staff provisioning failed: %r", exc)
        if created_uid:
            try:
                tenant_db.collection("authorized_clinical_staff").document(email).delete()
            except Exception:
                pass
            try:
                auth.delete_user(created_uid, app=tenant_app)
            except Exception:
                pass
        message = str(exc)
        if "EMAIL_EXISTS" in message.upper() or "already exists" in message.lower():
            return jsonify({"success": False, "error": "This email is already registered in the facility's Firebase Authentication."}), 409
        return jsonify({"success": False, "error": "Unable to create staff account. Check the facility Firebase configuration and server logs."}), 503


@app.route("/api/update-user", methods=["POST"])
def facility_update_user():
    context, error = get_facility_user_admin_context()
    if error:
        return error
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"success": False, "error": "Invalid user request."}), 400

    uid = str(payload.get("uid") or "").strip()
    old_email = str(payload.get("old_email") or "").strip().lower()
    email = str(payload.get("new_email") or payload.get("email") or "").strip().lower()
    name = str(payload.get("name") or "").strip()
    password = str(payload.get("password") or "")
    bday = str(payload.get("bday") or "").strip()
    position = str(payload.get("position") or "Staff").strip() or "Staff"
    permission = str(payload.get("permission") or "Editor").strip()
    if not uid or not valid_email(email) or len(name) < 2:
        return jsonify({"success": False, "error": "UID, valid email, and full name are required."}), 400
    if password and len(password) < 6:
        return jsonify({"success": False, "error": "A new password must contain at least 6 characters."}), 400
    if permission not in FACILITY_USER_CLEARANCES:
        return jsonify({"success": False, "error": "Invalid permission clearance."}), 400
    if uid == context["uid"] and permission != "Admin":
        return jsonify({"success": False, "error": "You cannot remove your own Admin clearance."}), 400

    from firebase_admin import auth
    tenant_app = context["tenant_app"]
    tenant_db = context["tenant_db"]
    try:
        user_record = auth.get_user(uid, app=tenant_app)
        actual_old_email = str(user_record.email or old_email).strip().lower()
        old_email = old_email or actual_old_email
        if actual_old_email != old_email:
            return jsonify({"success": False, "error": "The selected account email no longer matches. Refresh the staff list and try again."}), 409
        if email != old_email:
            if tenant_db.collection("authorized_clinical_staff").document(email).get().exists or mother_db.collection("authorized_clinical_staff").document(email).get().exists:
                return jsonify({"success": False, "error": "A staff account with the new email already exists."}), 409

        old_profile_ref = tenant_db.collection("authorized_clinical_staff").document(old_email)
        old_profile_snap = old_profile_ref.get()
        old_profile = old_profile_snap.to_dict() or {}
        if not old_profile_snap.exists or str(old_profile.get("uid", "")).strip() != uid or str(old_profile.get("email", old_email)).strip().lower() != old_email or str(old_profile.get("facility_id", "")).strip() != context["facility_id"]:
            return jsonify({"success": False, "error": "The selected account does not belong to this facility."}), 403
        if str(old_profile.get("clearancePermission", "Viewer")).strip() == "SuperAdmin":
            return jsonify({"success": False, "error": "SuperAdmin accounts cannot be modified through facility user management."}), 403

        auth.update_user(uid, email=email, display_name=name, **({"password": password} if password else {}), app=tenant_app)
        profile = facility_user_profile(
            uid, email, name, bday or str(old_profile.get("bday", "")), position, permission,
            context["facility_id"], str(old_profile.get("assignedSignature") or f"USER-{uid[:6].upper()}")
        )
        tenant_db.collection("authorized_clinical_staff").document(email).set(profile)
        mother_db.collection("authorized_clinical_staff").document(email).set({
            "uid": uid,
            "email": email,
            "lastNameFirstName": name,
            "positionRole": position,
            "clearancePermission": permission,
            "facility_id": context["facility_id"],
            "accountInitialized": True,
        })
        if old_email and old_email != email:
            old_profile_ref.delete()
            mother_db.collection("authorized_clinical_staff").document(old_email).delete()
        return jsonify({"success": True, "uid": uid, "message": "Staff account updated successfully."}), 200
    except Exception as exc:
        app.logger.exception("Facility staff update failed: %r", exc)
        return jsonify({"success": False, "error": "Unable to update staff account. Check the facility Firebase configuration and server logs."}), 503


@app.route("/api/delete-user", methods=["POST"])
def facility_delete_user():
    context, error = get_facility_user_admin_context()
    if error:
        return error
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"success": False, "error": "Invalid delete request."}), 400
    uid = str(payload.get("uid") or "").strip()
    email = str(payload.get("email") or "").strip().lower()
    if not uid or not valid_email(email):
        return jsonify({"success": False, "error": "A valid staff UID and email are required."}), 400
    if uid == context["uid"]:
        return jsonify({"success": False, "error": "You cannot delete your own active staff account."}), 400

    from firebase_admin import auth
    try:
        tenant_app = context["tenant_app"]
        tenant_db = context["tenant_db"]
        user_record = auth.get_user(uid, app=tenant_app)
        if str(user_record.email or "").strip().lower() != email:
            return jsonify({"success": False, "error": "The selected account email no longer matches. Refresh the staff list and try again."}), 409
        tenant_profile_ref = tenant_db.collection("authorized_clinical_staff").document(email)
        tenant_profile = tenant_profile_ref.get()
        tenant_data = tenant_profile.to_dict() or {}
        if (not tenant_profile.exists
                or str(tenant_data.get("uid", "")).strip() != uid
                or str(tenant_data.get("facility_id", "")).strip() != context["facility_id"]):
            return jsonify({"success": False, "error": "The selected account does not belong to this facility."}), 403
        if str(tenant_data.get("clearancePermission", "Viewer")).strip() == "SuperAdmin":
            return jsonify({"success": False, "error": "SuperAdmin accounts cannot be deleted through facility user management."}), 403
        staff_ref = mother_db.collection("authorized_clinical_staff").document(email)
        staff_snap = staff_ref.get()
        if staff_snap.exists:
            staff_data = staff_snap.to_dict() or {}
            if str(staff_data.get("uid", "")).strip() != uid or str(staff_data.get("facility_id", "")).strip() != context["facility_id"]:
                return jsonify({"success": False, "error": "The central staff identity does not match this facility account."}), 403
        auth.delete_user(uid, app=tenant_app)
        tenant_profile_ref.delete()
        staff_snap = staff_ref.get()
        if staff_snap.exists:
            staff_data = staff_snap.to_dict() or {}
            if str(staff_data.get("uid", "")).strip() == uid and str(staff_data.get("facility_id", "")).strip() == context["facility_id"]:
                staff_ref.delete()
        return jsonify({"success": True, "message": "Staff account successfully removed."}), 200
    except Exception as exc:
        app.logger.exception("Facility staff deletion failed: %r", exc)
        return jsonify({"success": False, "error": "Unable to remove staff account. Check the facility Firebase configuration and server logs."}), 503


# =========================================================
# ART DATABASE — SERVER-SIDE SECURITY BOUNDARY
# =========================================================

ART_CSRF_SESSION_KEY = "art_csrf_token"
ART_MAX_UIC_LENGTH = 128
ART_MAX_STRING_LENGTH = 4000
ART_MAX_LOG_ITEMS = 250
ART_ALLOWED_ROLES = {"Viewer", "Editor", "Admin", "SuperAdmin"}
ART_WRITE_ROLES = {"Editor", "Admin", "SuperAdmin"}

ART_DEMOGRAPHIC_FIELDS = {
    "lastName", "firstName", "middleName", "suffix", "sex", "kp",
    "bday", "contactNumber", "emailAddress", "address", "philhealthNumber",
    "ohasisUrl", "inception", "incDate", "incFrom", "outcome", "outDate",
    "outTo", "t0Date", "t0Result", "modeOfTransmission", "hasOi", "artDate", "artRegimen", "artBy",
    "iptChecked", "iptStartDate", "iptEndDate", "cptChecked", "cptStartDate",
    "cptEndDate", "tbStatus", "tbTreatmentStart", "tbTreatmentCompleted",
    "confirmatoryStatus", "confirmatoryResult", "confirmatoryDate",
    "confirmatoryCode", "dispenseDate", "pillsDispensed", "dispensedBy",
    "cd4Logs", "vlLogs", "oiLogs", "stiLogs", "refillLogs",
    "generated_serial_code", "meta_counters_state"
}

ART_REGISTRY_FIELDS = {
    "artEnrollmentDate", "vlStatus", "vlValue", "latestCd4Count",
    "pillsRemaining", "retentionStatus", "nextRefillDate",
    "generated_serial_code", "meta_counters_state"
}


def art_json_safe(value, depth=0):
    """Allow only JSON-like primitives/containers with bounded size."""
    if depth > 6:
        raise ValueError("ART payload nesting is too deep.")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value) > ART_MAX_STRING_LENGTH:
            raise ValueError("ART text field is too long.")
        return value
    if isinstance(value, list):
        if len(value) > ART_MAX_LOG_ITEMS:
            raise ValueError("ART history contains too many entries.")
        return [art_json_safe(item, depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > 100:
            raise ValueError("ART object contains too many fields.")
        clean = {}
        for key, item in value.items():
            key = str(key)
            if len(key) > 128:
                raise ValueError("ART field name is too long.")
            clean[key] = art_json_safe(item, depth + 1)
        return clean
    raise ValueError("Unsupported ART data type.")


def get_art_staff_context(required_roles=None):
    """Revalidate staff session and current Mother DB authorization."""
    if not require_staff_session():
        return None, (jsonify({"success": False, "error": "Authentication required."}), 401)

    facility_id = str(session.get("facility_id", "")).strip()
    staff_uid = str(session.get("staff_uid", "")).strip()
    staff_email = str(session.get("staff_email", "")).strip().lower()

    if not facility_id or facility_id.lower() == "master" or not staff_uid or not staff_email:
        session.clear()
        return None, (jsonify({"success": False, "error": "Invalid staff context."}), 403)

    if mother_db is None:
        return None, (jsonify({"success": False, "error": "Mother database unavailable."}), 503)

    try:
        snapshot = mother_db.collection("authorized_clinical_staff").document(staff_email).get()
        if not snapshot.exists:
            session.clear()
            return None, (jsonify({"success": False, "error": "Staff authorization could not be verified."}), 403)

        staff = snapshot.to_dict() or {}
        role = str(staff.get("clearancePermission", "Viewer")).strip()
        stored_uid = str(staff.get("uid", "")).strip()
        stored_facility = str(staff.get("facility_id", "")).strip()

        if stored_uid != staff_uid or stored_facility != facility_id or staff.get("accountInitialized") is not True:
            session.clear()
            return None, (jsonify({"success": False, "error": "Staff authorization could not be verified."}), 403)

        if role not in ART_ALLOWED_ROLES:
            return None, (jsonify({"success": False, "error": "Invalid staff clearance."}), 403)

        if required_roles and role not in set(required_roles):
            return None, (jsonify({"success": False, "error": "Insufficient permissions."}), 403)

        name = str(staff.get("lastNameFirstName", staff.get("name", staff_email))).strip() or staff_email
        return {
            "uid": staff_uid,
            "email": staff_email,
            "facility_id": facility_id,
            "role": role,
            "position": str(staff.get("positionRole", "Staff")).strip(),
            "name": name,
        }, None
    except Exception:
        return None, (jsonify({"success": False, "error": "Unable to verify staff authorization."}), 503)


def get_or_create_art_csrf_token():
    token = session.get(ART_CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[ART_CSRF_SESSION_KEY] = token
        session.modified = True
    return token


def verify_art_csrf_token():
    expected = str(session.get(ART_CSRF_SESSION_KEY, ""))
    supplied = str(request.headers.get("X-CSRF-Token", "")).strip()
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def art_normalize_uic(value):
    uic = str(value or "").strip().upper()
    if not uic or len(uic) > ART_MAX_UIC_LENGTH or not re.fullmatch(r"[A-Z0-9._:-]+", uic):
        return None
    return uic


def art_get_tenant_db(facility_id):
    tenant_app = get_facility_admin_sdk(facility_id)
    return firestore.client(app=tenant_app)


def art_audit(db, context, action, uic=None):
    """Write compact audit metadata for successful ART CREATE, UPDATE, or ARCHIVE actions only."""
    action = str(action or "").upper()
    if action not in {"CREATE", "UPDATE", "ARCHIVE"}:
        return
    try:
        ref = db.collection("art_audit_logs").document()
        ref.set({
            "event_id": ref.id,
            "action": action,
            "record_type": "ART",
            "uic": uic or "",
            "facility_id": context["facility_id"],
            "staff_uid": context["uid"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as audit_error:
        # Audit failure must not reverse an already-committed client operation.
        print("ART audit write failed:", repr(audit_error))



@app.route("/dashboard", methods=["GET"])
@app.route("/dbv3.html", methods=["GET"])
@staff_required
def art_dashboard_page():
    return render_template("dbv3.html")


@app.route("/api/art/csrf-token", methods=["GET"])
def art_csrf_token():
    context, error = get_art_staff_context()
    if error:
        return error
    return jsonify({"success": True, "csrf_token": get_or_create_art_csrf_token()}), 200


@app.route("/api/art/registry", methods=["GET"])
def art_registry():
    context, error = get_art_staff_context()
    if error:
        return error
    try:
        db = art_get_tenant_db(context["facility_id"])
        registry_docs = list(db.collection("clients_registry").stream())
        demo_docs = {
            snap.id: (snap.to_dict() or {})
            for snap in db.collection("clients_demographics").stream()
        }

        records = []
        for snap in registry_docs:
            uic = snap.id
            registry = snap.to_dict() or {}

            # Soft-deleted/archived ART records remain in Firestore,
            # but must not appear in the normal active registry.
            if registry.get("isArchived", False) is True:
                continue

            demo = demo_docs.get(uic, {})

            # Defensive check in case only the demographics document
            # carries the archive marker.
            if demo.get("isArchived", False) is True:
                continue

            records.append({
                "id": uic,
                "registry": registry,
                "demographics": demo,
            })
        return jsonify({"success": True, "facility_id": context["facility_id"], "records": records}), 200
    except Exception:
        return jsonify({"success": False, "error": "Unable to load ART registry."}), 503


@app.route("/api/art/client/<uic>", methods=["GET"])
def art_client(uic):
    context, error = get_art_staff_context()
    if error:
        return error
    normalized = art_normalize_uic(uic)
    if not normalized:
        return jsonify({"success": False, "error": "Invalid UIC."}), 400
    try:
        db = art_get_tenant_db(context["facility_id"])
        demo_snap = db.collection("clients_demographics").document(normalized).get()
        reg_snap = db.collection("clients_registry").document(normalized).get()
        if not demo_snap.exists and not reg_snap.exists:
            return jsonify({"success": False, "error": "Client record not found."}), 404
        return jsonify({
            "success": True,
            "uic": normalized,
            "demographics": demo_snap.to_dict() if demo_snap.exists else {},
            "registry": reg_snap.to_dict() if reg_snap.exists else {},
        }), 200
    except Exception:
        return jsonify({"success": False, "error": "Unable to load ART client record."}), 503


@app.route("/api/art/client", methods=["POST"])
def art_save_client():
    context, error = get_art_staff_context(ART_WRITE_ROLES)
    if error:
        return error
    if not verify_art_csrf_token():
        return jsonify({"success": False, "error": "CSRF validation failed."}), 403

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"success": False, "error": "Invalid ART request."}), 400

    uic = art_normalize_uic(payload.get("uic"))
    if not uic:
        return jsonify({"success": False, "error": "Invalid UIC."}), 400

    demographics = payload.get("demographics", {})
    registry = payload.get("registry", {})
    if not isinstance(demographics, dict) or not isinstance(registry, dict):
        return jsonify({"success": False, "error": "Invalid ART record payload."}), 400

    try:
        demographics = art_json_safe(demographics)
        registry = art_json_safe(registry)
        counter_state = art_json_safe(payload.get("meta_counters_state", {}))
        if not isinstance(counter_state, dict):
            counter_state = {}

        demo = {k: v for k, v in demographics.items() if k in ART_DEMOGRAPHIC_FIELDS}
        reg = {k: v for k, v in registry.items() if k in ART_REGISTRY_FIELDS}

        serial = str(demo.get("generated_serial_code") or reg.get("generated_serial_code") or "---").strip()
        if len(serial) > ART_MAX_STRING_LENGTH:
            return jsonify({"success": False, "error": "Invalid client code."}), 400
        demo["generated_serial_code"] = serial
        reg["generated_serial_code"] = serial
        reg.setdefault("artEnrollmentDate", demo.get("artDate", "---"))
        reg.setdefault("retentionStatus", demo.get("outcome", "Active"))

        now = datetime.now(timezone.utc).isoformat()
        demo["lastUpdatedAt"] = now
        demo["lastUpdatedBy"] = context["name"]

        reg["lastUpdatedAt"] = now
        reg["lastUpdatedBy"] = context["name"]

        # A normal save represents an active record.
        # Explicitly clear soft-delete markers so a restored record
        # can become visible in the active registry again.
        demo["isArchived"] = False
        reg["isArchived"] = False

        db = art_get_tenant_db(context["facility_id"])
        is_new_record = payload.get("is_new_record") is True

        # Facility-local duplicate lock: reject a duplicate UIC on creation.
        existing_demo_ref = db.collection("clients_demographics").document(uic)
        existing_reg_ref = db.collection("clients_registry").document(uic)
        existing_demo = existing_demo_ref.get()
        existing_reg = existing_reg_ref.get()
        if is_new_record and (existing_demo.exists or existing_reg.exists):
            return jsonify({
                "success": False,
                "error": f"UIC already exists check [{uic}]",
                "duplicate": {"field": "UIC", "value": uic, "existing_uic": uic}
            }), 409

        # Client Code must be unique within this facility, including on edits;
        # a record is allowed to retain its own current code.
        if serial and serial != "---":
            code_key = serial.casefold()
            for collection_name in ("clients_demographics", "clients_registry"):
                matches = db.collection(collection_name).where("generated_serial_code", "==", serial).stream()
                for match in matches:
                    if match.id != uic:
                        return jsonify({
                            "success": False,
                            "error": f"Client Code already exists check [{serial}]",
                            "duplicate": {"field": "Client Code", "value": serial, "existing_uic": match.id}
                        }), 409
        audit_action = "UPDATE" if (existing_demo.exists or existing_reg.exists) else "CREATE"
        batch = db.batch()
        batch.set(db.collection("clients_demographics").document(uic), demo, merge=True)
        batch.set(db.collection("clients_registry").document(uic), reg, merge=True)
        batch.set(db.collection("facility_profile").document("serial_counters"), {
            "meta_counters_state": counter_state,
            "last_recorded_year": datetime.now().year,
            "last_generated_code": serial,
            "lastUpdatedAt": now,
            "lastUpdatedBy": context["name"],
        }, merge=True)
        batch.commit()
        art_audit(db, context, audit_action, uic)
        return jsonify({"success": True, "uic": uic, "facility_id": context["facility_id"]}), 200
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception:
        return jsonify({"success": False, "error": "Unable to save ART client record."}), 503


@app.route("/api/art/client/<uic>", methods=["DELETE"])
def art_delete_client(uic):
    """
    Soft-delete an ART client.

    The source documents are NEVER physically deleted.

    Flow:
        1. Read the current demographics + registry records.
        2. Save a complete historical snapshot to deleted_logs.
        3. Mark both source documents as isArchived=True.
        4. Keep the original documents intact for restore/audit.
    """
    context, error = get_art_staff_context(ART_WRITE_ROLES)
    if error:
        return error

    if not verify_art_csrf_token():
        return jsonify({
            "success": False,
            "error": "CSRF validation failed."
        }), 403

    normalized = art_normalize_uic(uic)
    if not normalized:
        return jsonify({
            "success": False,
            "error": "Invalid UIC."
        }), 400

    try:
        db = art_get_tenant_db(context["facility_id"])

        demo_ref = db.collection("clients_demographics").document(normalized)
        reg_ref = db.collection("clients_registry").document(normalized)

        demo_snap = demo_ref.get()
        reg_snap = reg_ref.get()

        if not demo_snap.exists and not reg_snap.exists:
            return jsonify({
                "success": True,
                "deleted": False,
                "archived": False,
                "uic": normalized
            }), 200

        demo_data = demo_snap.to_dict() if demo_snap.exists else {}
        reg_data = reg_snap.to_dict() if reg_snap.exists else {}

        # Prevent repeatedly archiving an already archived record.
        if (
            demo_data.get("isArchived", False) is True
            or reg_data.get("isArchived", False) is True
        ):
            return jsonify({
                "success": True,
                "deleted": False,
                "archived": True,
                "already_archived": True,
                "uic": normalized
            }), 200

        now = datetime.now(timezone.utc).isoformat()

        archive_ref = db.collection("deleted_logs").document(
            f"{normalized}_ART_REV_{int(time.time() * 1000)}"
        )

        archive_payload = {
            "record_type": "ART",
            "archiveVersion": 1,
            "uic_reference_key": normalized,
            "archivedAtTimestamp": now,
            "deletedBy": context["name"],
            "deletedByUid": context["uid"],
            "deletedByEmail": context["email"],
            "facility_id": context["facility_id"],

            # Full historical snapshots for recovery/export.
            "historicalDemographics": demo_data,
            "historicalRegistryMetrics": reg_data,

            "auditMeta": {
                "lastUpdatedBy": (
                    demo_data.get(
                        "dispensedBy",
                        demo_data.get(
                            "lastUpdatedBy",
                            "Unspecified staff"
                        )
                    )
                    if demo_snap.exists else "Unspecified staff"
                ),
                "recordInceptionDate": (
                    demo_data.get("artDate", "---")
                    if demo_snap.exists else "---"
                ),
                "finalRetentionOutcome": (
                    reg_data.get(
                        "retentionStatus",
                        demo_data.get("outcome", "Unknown")
                    )
                    if (demo_snap.exists or reg_snap.exists)
                    else "Unknown"
                ),
            },
        }

        archive_meta = {
            "isArchived": True,
            "archivedAt": now,
            "archivedBy": context["name"],
            "archivedByUid": context["uid"],
            "archivedByEmail": context["email"],
            "archiveReason": "Soft deleted",
            "archiveRef": archive_ref.path,
        }

        # One atomic batch:
        # archive snapshot + mark original documents as archived.
        batch = db.batch()

        batch.set(archive_ref, archive_payload)

        if demo_snap.exists:
            batch.set(
                demo_ref,
                archive_meta,
                merge=True
            )

        if reg_snap.exists:
            batch.set(
                reg_ref,
                archive_meta,
                merge=True
            )

        batch.commit()

        # Mirror the complete immutable archive snapshot to this facility's backup spreadsheet.
        # This is best-effort: the authoritative Firestore archive is already committed.
        try:
            _, archive_sync_error = _sheets_backup_post(context, {
                "record_type": "ART_ARCHIVE",
                "archive_id": archive_ref.id,
                "uic": normalized,
                "archived_at": now,
                "archived_by": context["name"],
                "archived_by_uid": context["uid"],
                "archived_by_email": context["email"],
                "archive_reason": "Soft deleted",
                "historical_demographics": demo_data,
                "historical_registry": reg_data,
                "archive_payload": archive_payload,
            })
            if archive_sync_error:
                print("ART archive Sheets mirror did not complete for", normalized)
        except Exception as archive_sync_exc:
            print("ART archive Sheets mirror failed:", repr(archive_sync_exc))

        art_audit(
            db,
            context,
            "ARCHIVE",
            normalized
        )

        return jsonify({
            "success": True,
            "deleted": False,
            "archived": True,
            "soft_deleted": True,
            "uic": normalized,
            "archive_ref": archive_ref.path,
        }), 200

    except Exception as error:
        print(
            "Unable to soft-delete ART client:",
            repr(error)
        )
        return jsonify({
            "success": False,
            "error": "Unable to archive ART client record."
        }), 503


# PREP DATABASE — SERVER-SIDE SECURITY BOUNDARY
# =========================================================

PREP_CSRF_SESSION_KEY = "prep_csrf_token"
PREP_MAX_UIC_LENGTH = 128
PREP_MAX_STRING_LENGTH = 4000
PREP_MAX_LOG_ITEMS = 250
PREP_ALLOWED_ROLES = {"Viewer", "Editor", "Admin", "SuperAdmin"}
PREP_WRITE_ROLES = {"Editor", "Admin", "SuperAdmin"}

PREP_DEMOGRAPHIC_FIELDS = {
    "lastName", "firstName", "middleName", "suffix", "sex", "kp",
    "bday", "contactNumber", "emailAddress", "address",
    "prepDate", "prepStatus", "prepDosage", "prepRegimen",
    "prepRegimenOther", "t0Date", "t0Result", "serumCreatinine",
    "creatinineClearance", "weight", "stiLogs", "gahtToggle",
    "gahtSpecify", "dispenseDate", "pillsDispensed", "dispensedBy",
    "refillLogs", "generated_serial_code", "ohasisUrl"
}

PREP_REGISTRY_FIELDS = {
    "prepEnrollmentDate", "prepStatus", "prepDosage", "prepRegimen",
    "pillsRemaining", "nextRefillDate", "generated_serial_code"
}


def prep_json_safe(value, depth=0):
    """Allow bounded JSON-like values only."""
    if depth > 6:
        raise ValueError("PrEP payload nesting is too deep.")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value) > PREP_MAX_STRING_LENGTH:
            raise ValueError("PrEP text field is too long.")
        return value
    if isinstance(value, list):
        if len(value) > PREP_MAX_LOG_ITEMS:
            raise ValueError("PrEP history contains too many entries.")
        return [prep_json_safe(item, depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > 100:
            raise ValueError("PrEP object contains too many fields.")
        clean = {}
        for key, item in value.items():
            key = str(key)
            if len(key) > 128:
                raise ValueError("PrEP field name is too long.")
            clean[key] = prep_json_safe(item, depth + 1)
        return clean
    raise ValueError("Unsupported PrEP data type.")


def get_prep_staff_context(required_roles=None):
    """Revalidate the staff session and current Mother DB authorization."""
    if not require_staff_session():
        return None, (jsonify({"success": False, "error": "Authentication required."}), 401)

    facility_id = str(session.get("facility_id", "")).strip()
    staff_uid = str(session.get("staff_uid", "")).strip()
    staff_email = str(session.get("staff_email", "")).strip().lower()

    if not facility_id or facility_id.lower() == "master" or not staff_uid or not staff_email:
        session.clear()
        return None, (jsonify({"success": False, "error": "Invalid staff context."}), 403)

    if mother_db is None:
        return None, (jsonify({"success": False, "error": "Mother database unavailable."}), 503)

    try:
        snapshot = (
            mother_db.collection("authorized_clinical_staff")
            .document(staff_email)
            .get()
        )
        if not snapshot.exists:
            session.clear()
            return None, (jsonify({"success": False, "error": "Staff authorization could not be verified."}), 403)

        staff = snapshot.to_dict() or {}
        role = str(staff.get("clearancePermission", "Viewer")).strip()
        stored_uid = str(staff.get("uid", "")).strip()
        stored_facility = str(staff.get("facility_id", "")).strip()

        if (
            stored_uid != staff_uid
            or stored_facility != facility_id
            or staff.get("accountInitialized") is not True
        ):
            session.clear()
            return None, (jsonify({"success": False, "error": "Staff authorization could not be verified."}), 403)

        if role not in PREP_ALLOWED_ROLES:
            return None, (jsonify({"success": False, "error": "Invalid staff clearance."}), 403)

        if required_roles and role not in set(required_roles):
            return None, (jsonify({"success": False, "error": "Insufficient permissions."}), 403)

        name = str(
            staff.get("lastNameFirstName", staff.get("name", staff_email))
        ).strip() or staff_email

        return {
            "uid": staff_uid,
            "email": staff_email,
            "facility_id": facility_id,
            "role": role,
            "position": str(staff.get("positionRole", "Staff")).strip(),
            "name": name,
        }, None
    except Exception:
        return None, (jsonify({"success": False, "error": "Unable to verify staff authorization."}), 503)


def get_or_create_prep_csrf_token():
    token = session.get(PREP_CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[PREP_CSRF_SESSION_KEY] = token
        session.modified = True
    return token


def verify_prep_csrf_token():
    expected = str(session.get(PREP_CSRF_SESSION_KEY, ""))
    supplied = str(request.headers.get("X-CSRF-Token", "")).strip()
    return bool(
        expected
        and supplied
        and hmac.compare_digest(expected, supplied)
    )


def prep_normalize_uic(value):
    uic = str(value or "").strip().upper()
    if (
        not uic
        or len(uic) > PREP_MAX_UIC_LENGTH
        or not re.fullmatch(r"[A-Z0-9._:-]+", uic)
    ):
        return None
    return uic


def prep_get_tenant_db(facility_id):
    tenant_app = get_facility_admin_sdk(facility_id)
    return firestore.client(app=tenant_app)


def prep_audit(db, context, action, uic=None):
    """Write compact audit metadata for successful PrEP CREATE, UPDATE, or ARCHIVE actions only."""
    action = str(action or "").upper()
    if action not in {"CREATE", "UPDATE", "ARCHIVE"}:
        return
    try:
        ref = db.collection("prep_audit_logs").document()
        ref.set({
            "event_id": ref.id,
            "action": action,
            "record_type": "PrEP",
            "uic": uic or "",
            "facility_id": context["facility_id"],
            "staff_uid": context["uid"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as audit_error:
        # Audit failure must not reverse an already-committed client operation.
        print("PrEP audit write failed:", repr(audit_error))



@app.route("/prepdb.html", methods=["GET"])
@app.route("/prep", methods=["GET"])
@staff_required
def prep_dashboard_page():
    return render_template("prepdb.html")


@app.route("/api/prep/csrf-token", methods=["GET"])
def prep_csrf_token():
    context, error = get_prep_staff_context()
    if error:
        return error
    return jsonify({
        "success": True,
        "csrf_token": get_or_create_prep_csrf_token(),
        "facility_id": context["facility_id"],
    }), 200


@app.route("/api/prep/registry", methods=["GET"])
def prep_registry():
    context, error = get_prep_staff_context()
    if error:
        return error

    try:
        db = prep_get_tenant_db(context["facility_id"])
        registry_docs = db.collection("prep_registry").stream()
        demographic_docs = db.collection("prep_demographics").stream()

        demographics = {
            doc.id: doc.to_dict() or {}
            for doc in demographic_docs
        }

        records = []
        for doc in registry_docs:
            records.append({
                "uic": doc.id,
                "registry": doc.to_dict() or {},
                "demographics": demographics.get(doc.id, {}),
            })

        return jsonify({
            "success": True,
            "facility_id": context["facility_id"],
            "records": records,
        }), 200
    except Exception:
        return jsonify({
            "success": False,
            "error": "Unable to load PrEP registry."
        }), 503


@app.route("/api/prep/client/<uic>", methods=["GET"])
def prep_client(uic):
    context, error = get_prep_staff_context()
    if error:
        return error

    normalized = prep_normalize_uic(uic)
    if not normalized:
        return jsonify({
            "success": False,
            "error": "Invalid UIC."
        }), 400

    try:
        db = prep_get_tenant_db(context["facility_id"])
        demo_snap = db.collection("prep_demographics").document(normalized).get()
        reg_snap = db.collection("prep_registry").document(normalized).get()

        if not demo_snap.exists and not reg_snap.exists:
            return jsonify({
                "success": False,
                "error": "PrEP client record not found."
            }), 404

        return jsonify({
            "success": True,
            "uic": normalized,
            "demographics": demo_snap.to_dict() if demo_snap.exists else {},
            "registry": reg_snap.to_dict() if reg_snap.exists else {},
        }), 200
    except Exception:
        return jsonify({
            "success": False,
            "error": "Unable to load PrEP client record."
        }), 503


@app.route("/api/prep/client", methods=["POST"])
def prep_save_client():
    context, error = get_prep_staff_context(PREP_WRITE_ROLES)
    if error:
        return error

    if not verify_prep_csrf_token():
        return jsonify({
            "success": False,
            "error": "Invalid or missing CSRF token."
        }), 403

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({
            "success": False,
            "error": "Invalid request payload."
        }), 400

    normalized = prep_normalize_uic(payload.get("uic"))
    if not normalized:
        return jsonify({
            "success": False,
            "error": "Invalid UIC."
        }), 400

    try:
        demographics_raw = payload.get("demographics") or {}
        registry_raw = payload.get("registry") or {}

        if not isinstance(demographics_raw, dict) or not isinstance(registry_raw, dict):
            raise ValueError("Invalid PrEP record structure.")

        demographics = {
            key: prep_json_safe(value)
            for key, value in demographics_raw.items()
            if key in PREP_DEMOGRAPHIC_FIELDS
        }
        registry = {
            key: prep_json_safe(value)
            for key, value in registry_raw.items()
            if key in PREP_REGISTRY_FIELDS
        }

        if not demographics:
            raise ValueError("PrEP demographic data is required.")
        if not registry:
            raise ValueError("PrEP registry data is required.")

        now = datetime.now(timezone.utc).isoformat()
        demographics["lastUpdatedAt"] = now
        demographics["lastUpdatedBy"] = context["name"]
        registry["lastUpdatedAt"] = now
        registry["lastUpdatedBy"] = context["name"]

        db = prep_get_tenant_db(context["facility_id"])
        is_new_record = payload.get("is_new_record") is True
        existing_demo_ref = db.collection("prep_demographics").document(normalized)
        existing_reg_ref = db.collection("prep_registry").document(normalized)
        existing_demo = existing_demo_ref.get()
        existing_reg = existing_reg_ref.get()
        if is_new_record and (existing_demo.exists or existing_reg.exists):
            return jsonify({
                "success": False,
                "error": f"UIC already exists check [{normalized}]",
                "duplicate": {"field": "UIC", "value": normalized, "existing_uic": normalized}
            }), 409

        serial = str(demographics.get("generated_serial_code") or registry.get("generated_serial_code") or "---").strip()
        if serial and serial != "---":
            for collection_name in ("prep_demographics", "prep_registry"):
                matches = db.collection(collection_name).where("generated_serial_code", "==", serial).stream()
                for match in matches:
                    if match.id != normalized:
                        return jsonify({
                            "success": False,
                            "error": f"Client Code already exists check [{serial}]",
                            "duplicate": {"field": "Client Code", "value": serial, "existing_uic": match.id}
                        }), 409

        demo_ref = db.collection("prep_demographics").document(normalized)
        reg_ref = db.collection("prep_registry").document(normalized)

        audit_action = "UPDATE" if (existing_demo.exists or existing_reg.exists) else "CREATE"
        batch.set(demo_ref, demographics, merge=True)
        batch.set(reg_ref, registry, merge=True)
        batch.commit()

        prep_audit(db, context, audit_action, normalized)
        return jsonify({
            "success": True,
            "uic": normalized,
        }), 200
    except ValueError as exc:
        return jsonify({
            "success": False,
            "error": str(exc)
        }), 400
    except Exception:
        return jsonify({
            "success": False,
            "error": "Unable to save PrEP client record."
        }), 503


@app.route("/api/prep/client/<uic>", methods=["DELETE"])
def prep_delete_client(uic):
    """
    Archive and remove an active PrEP client record.

    The active record is removed from:
        - prep_demographics
        - prep_registry

    A complete historical copy is retained in:
        - prep_archive

    Security:
        1. Staff session validation
        2. Facility/tenant binding
        3. Write-role authorization
        4. CSRF validation
        5. UIC normalization
        6. Full archive before removal
        7. Atomic Firestore batch
        8. Audit logging
    """

    # =========================================================
    # 1. AUTHENTICATION + ROLE AUTHORIZATION
    # =========================================================

    context, error = get_prep_staff_context(PREP_WRITE_ROLES)

    if error:
        return error

    # =========================================================
    # 2. CSRF PROTECTION
    # =========================================================

    if not verify_prep_csrf_token():
        return jsonify({
            "success": False,
            "error": "Invalid or missing CSRF token."
        }), 403

    # =========================================================
    # 3. NORMALIZE + VALIDATE UIC
    # =========================================================

    normalized = prep_normalize_uic(uic)

    if not normalized:
        return jsonify({
            "success": False,
            "error": "Invalid UIC."
        }), 400

    # =========================================================
    # 4. ACCESS ONLY AUTHENTICATED STAFF'S TENANT DB
    # =========================================================

    try:
        db = prep_get_tenant_db(
            context["facility_id"]
        )

        # =====================================================
        # 5. LOCATE ACTIVE PREP DOCUMENTS
        # =====================================================

        demo_ref = (
            db.collection("prep_demographics")
            .document(normalized)
        )

        reg_ref = (
            db.collection("prep_registry")
            .document(normalized)
        )

        demo_snap = demo_ref.get()
        reg_snap = reg_ref.get()

        # =====================================================
        # 6. NOTHING FOUND
        # =====================================================

        if not demo_snap.exists and not reg_snap.exists:
            return jsonify({
                "success": True,
                "deleted": False,
                "archived": False,
                "uic": normalized,
                "message": "No active PrEP record found."
            }), 200

        # =====================================================
        # 7. CAPTURE COMPLETE HISTORICAL SNAPSHOT
        # =====================================================

        demo_data = (
            demo_snap.to_dict()
            if demo_snap.exists
            else {}
        )

        registry_data = (
            reg_snap.to_dict()
            if reg_snap.exists
            else {}
        )

        # =====================================================
        # 8. CREATE UNIQUE ARCHIVE DOCUMENT
        # =====================================================

        archive_id = (
            f"{normalized}_PREP_ARCHIVE_"
            f"{int(time.time() * 1000)}"
        )

        archive_ref = (
            db.collection("prep_archive")
            .document(archive_id)
        )

        # =====================================================
        # 9. COMPLETE ARCHIVE PAYLOAD
        # =====================================================

        archive_payload = {

            # -----------------------------------------------
            # Record identity
            # -----------------------------------------------

            "record_type": "PREP",

            "uic_reference_key": normalized,

            "archive_id": archive_id,

            # -----------------------------------------------
            # Facility ownership
            # -----------------------------------------------

            "facility_id": context["facility_id"],

            # -----------------------------------------------
            # Archive metadata
            # -----------------------------------------------

            "archiveStatus": "ARCHIVED",

            "archivedAtTimestamp": (
                datetime.now(timezone.utc).isoformat()
            ),

            "archiveReason": "Deleted by authorized staff",

            # -----------------------------------------------
            # Staff who performed the deletion
            # -----------------------------------------------

            "deletedBy": context["name"],

            "deletedByUid": context["uid"],

            "deletedByEmail": context["email"],

            "deletedByRole": context["role"],

            # -----------------------------------------------
            # COMPLETE HISTORICAL RECORD
            # -----------------------------------------------

            "historicalDemographics": demo_data,

            "historicalRegistryMetrics": registry_data,

            # -----------------------------------------------
            # Audit metadata
            # -----------------------------------------------

            "auditMeta": {

                "lastUpdatedBy": (
                    demo_data.get(
                        "dispensedBy",
                        demo_data.get(
                            "lastUpdatedBy",
                            "Unspecified staff"
                        )
                    )
                ),

                "recordInceptionDate": (
                    demo_data.get(
                        "prepDate",
                        demo_data.get(
                            "prepEnrollmentDate",
                            "---"
                        )
                    )
                ),

                "finalRetentionOutcome": (
                    demo_data.get(
                        "prepStatus",
                        "Unknown"
                    )
                ),

                "archiveReason": (
                    "Deleted by authorized staff"
                ),

                "sourceCollections": {
                    "demographics": (
                        "prep_demographics"
                        if demo_snap.exists
                        else None
                    ),

                    "registry": (
                        "prep_registry"
                        if reg_snap.exists
                        else None
                    )
                }
            }
        }

        # =====================================================
        # 10. ATOMIC FIRESTORE BATCH
        #
        # Archive FIRST and remove active records
        # in the SAME batch.
        # =====================================================

        batch = db.batch()

        # -----------------------------------------------
        # Create permanent PrEP archive
        # -----------------------------------------------

        batch.set(
            archive_ref,
            archive_payload
        )

        # -----------------------------------------------
        # Remove active demographics document
        # -----------------------------------------------

        if demo_snap.exists:
            batch.delete(demo_ref)

        # -----------------------------------------------
        # Remove active registry document
        # -----------------------------------------------

        if reg_snap.exists:
            batch.delete(reg_ref)

        # -----------------------------------------------
        # Commit atomically
        # -----------------------------------------------

        batch.commit()

        # Mirror the full archive snapshot to the facility backup spreadsheet.
        # Firestore remains authoritative if the external backup is temporarily unavailable.
        try:
            _, archive_sync_error = _sheets_backup_post(context, {
                "record_type": "PREP_ARCHIVE",
                "archive_id": archive_ref.id,
                "uic": normalized,
                "archived_at": archive_payload.get("archivedAtTimestamp", ""),
                "archived_by": context["name"],
                "archived_by_uid": context["uid"],
                "archived_by_email": context["email"],
                "archive_reason": archive_payload.get("archiveReason", "Deleted by authorized staff"),
                "historical_demographics": demo_data,
                "historical_registry": registry_data,
                "archive_payload": archive_payload,
            })
            if archive_sync_error:
                print("PrEP archive Sheets mirror did not complete for", normalized)
        except Exception as archive_sync_exc:
            print("PrEP archive Sheets mirror failed:", repr(archive_sync_exc))

        # =====================================================
        # 11. AUDIT LOG
        # =====================================================

        prep_audit(
            db,
            context,
            "ARCHIVE",
            normalized
        )

        # =====================================================
        # 12. SUCCESS RESPONSE
        # =====================================================

        return jsonify({
            "success": True,
            "deleted": True,
            "archived": True,
            "archiveCollection": "prep_archive",
            "archiveId": archive_id,
            "uic": normalized,
            "message": (
                "PrEP client archived successfully "
                "and removed from the active registry."
            )
        }), 200

    # =========================================================
    # VALIDATION ERROR
    # =========================================================

    except ValueError as exc:

        return jsonify({
            "success": False,
            "error": str(exc)
        }), 400

    # =========================================================
    # SERVER / FIRESTORE ERROR
    # =========================================================

    except Exception as exc:

        app.logger.exception(
            "PREP ARCHIVE/DELETE FAILED | "
            "UIC=%s | Facility=%s",
            normalized,
            context.get("facility_id")
        )

        return jsonify({
            "success": False,
            "error": (
                "Unable to archive and delete "
                "PrEP client record."
            )
        }), 503
# ============================================================
# SECURE ART EXPORT
# ============================================================

ART_EXPORT_ROLES = {"Editor", "Admin", "SuperAdmin"}

ART_EXPORT_ALLOWED_SCOPES = {"active", "deleted"}

ART_EXPORT_ALLOWED_VL = {
    "",
    "Pending",
    "Undetectable",
    "Detectable",
    "Unknown",
}

ART_EXPORT_ALLOWED_RETENTION = {
    "",
    "Active",
    "LTFU",
    "Transferred Out",
    "Transferred In",
    "Died",
    "Stopped",
    "Unknown",
}


def art_export_clean_csv_value(value):
    """
    Prevent CSV/formula injection when exported values are opened
    in Excel, LibreOffice, Google Sheets, etc.
    """
    if value is None:
        return ""

    if isinstance(value, bool):
        text = "TRUE" if value else "FALSE"
    elif isinstance(value, (dict, list)):
        text = str(value)
    else:
        text = str(value)

    text = text.replace("\x00", "").strip()

    if text.startswith(("=", "+", "-", "@")):
        return "'" + text

    return text


def art_export_mask_pii(value):
    """
    Mask common PII fields for exports where hide_pii=True.
    """
    if value is None:
        return ""

    text = str(value).strip()

    if not text:
        return ""

    if len(text) <= 2:
        return "*" * len(text)

    if len(text) <= 4:
        return text[0] + ("*" * (len(text) - 1))

    return text[0] + ("*" * (len(text) - 2)) + text[-1]


def art_export_prepare_row(
    uic,
    demographics,
    registry,
    hide_pii=False,
    deleted=False,
):
    """
    Convert an ART record into a controlled export row.

    Do not blindly export the entire Firestore document.
    Only explicitly approved fields are included.
    """

    demographics = demographics if isinstance(demographics, dict) else {}
    registry = registry if isinstance(registry, dict) else {}

    def get_value(source, *keys):
        for key in keys:
            value = source.get(key)
            if value not in (None, ""):
                return value
        return ""

    row = {
        "UIC": uic,

        "Last Name": get_value(
            demographics,
            "lastName",
        ),
        "First Name": get_value(
            demographics,
            "firstName",
        ),
        "Middle Name": get_value(
            demographics,
            "middleName",
        ),
        "Suffix": get_value(
            demographics,
            "suffix",
        ),
        "Sex": get_value(
            demographics,
            "sex",
        ),
        "Key Population": get_value(
            demographics,
            "kp",
        ),
        "Birth Date": get_value(
            demographics,
            "bday",
        ),
        "Contact Number": get_value(
            demographics,
            "contactNumber",
        ),
        "Email Address": get_value(
            demographics,
            "emailAddress",
        ),
        "Address": get_value(
            demographics,
            "address",
        ),
        "PhilHealth Number": get_value(
            demographics,
            "philhealthNumber",
        ),
        "Mode of Transmission": get_value(
            demographics,
            "modeOfTransmission",
        ),

        "ART Enrollment Date": get_value(
            registry,
            "artEnrollmentDate",
        ) or get_value(
            demographics,
            "artDate",
        ),

        "ART Regimen": get_value(
            demographics,
            "artRegimen",
        ),

        "ART Status": get_value(
            demographics,
            "outcome",
        ),

        "VL Status": get_value(
            registry,
            "vlStatus",
        ),

        "VL Value": get_value(
            registry,
            "vlValue",
        ),

        "Latest CD4": get_value(
            registry,
            "latestCd4Count",
        ),

        "Pills Remaining": get_value(
            registry,
            "pillsRemaining",
        ),

        "Retention Status": get_value(
            registry,
            "retentionStatus",
        ),

        "Next Refill Date": get_value(
            registry,
            "nextRefillDate",
        ),

        "Dispense Date": get_value(
            demographics,
            "dispenseDate",
        ),

        "Pills Dispensed": get_value(
            demographics,
            "pillsDispensed",
        ),

        "Dispensed By": get_value(
            demographics,
            "dispensedBy",
        ),

        "Generated Serial Code": get_value(
            registry,
            "generated_serial_code",
        ) or get_value(
            demographics,
            "generated_serial_code",
        ),

        "OHA-SIS URL": get_value(
            demographics,
            "ohasisUrl",
        ),
    }

    if deleted:
        row["Deleted Record"] = "YES"

    if hide_pii:
        row["Last Name"] = art_export_mask_pii(row["Last Name"])
        row["First Name"] = art_export_mask_pii(row["First Name"])
        row["Middle Name"] = art_export_mask_pii(row["Middle Name"])
        row["Contact Number"] = art_export_mask_pii(row["Contact Number"])
        row["Email Address"] = art_export_mask_pii(row["Email Address"])
        row["Address"] = art_export_mask_pii(row["Address"])
        row["PhilHealth Number"] = art_export_mask_pii(
            row["PhilHealth Number"]
        )

    return {
        key: art_export_clean_csv_value(value)
        for key, value in row.items()
    }


def art_export_date_matches(value, start_date, end_date):
    """
    Compare YYYY-MM-DD style dates safely.

    Empty/malformed dates are not treated as matching a supplied
    date filter.
    """
    if not start_date and not end_date:
        return True

    if not value:
        return False

    text = str(value).strip()[:10]

    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return False

    if start_date and text < start_date:
        return False

    if end_date and text > end_date:
        return False

    return True


def art_export_registry_records(db):
    """
    Load active ART records from the tenant database.

    The tenant DB is already selected exclusively from the
    authenticated staff session.
    """
    registry_docs = list(
        db.collection("clients_registry").stream()
    )

    demographics_docs = {
        snap.id: (snap.to_dict() or {})
        for snap in db.collection("clients_demographics").stream()
    }

    records = []

    for snap in registry_docs:
        uic = snap.id
        registry = snap.to_dict() or {}
        demographics = demographics_docs.get(uic, {})

        # Active export must never include soft-deleted records.
        if registry.get("isArchived", False) is True:
            continue

        if demographics.get("isArchived", False) is True:
            continue

        records.append(
            {
                "uic": uic,
                "registry": registry,
                "demographics": demographics,
            }
        )

    return records


def art_export_deleted_records(db):
    """
    Load only archived ART records from deleted_logs.

    Deleted records are recognized using record_type == ART where
    available, with a conservative fallback for older archive docs.
    """
    records = []

    for snap in db.collection("deleted_logs").stream():
        data = snap.to_dict() or {}

        record_type = str(
            data.get("record_type", "")
        ).strip().upper()

        if record_type and record_type != "ART":
            continue

        historical_demo = data.get(
            "historicalDemographics",
            {},
        )

        historical_registry = data.get(
            "historicalRegistryMetrics",
            {},
        )

        if not isinstance(historical_demo, dict):
            historical_demo = {}

        if not isinstance(historical_registry, dict):
            historical_registry = {}

        uic = str(
            data.get("uic_reference_key")
            or data.get("uic")
            or snap.id.split("_REV_")[0]
            or ""
        ).strip()

        if not uic:
            continue

        records.append(
            {
                "uic": uic,
                "registry": historical_registry,
                "demographics": historical_demo,
                "archived_at": data.get(
                    "archivedAtTimestamp",
                    "",
                ),
                "deleted_by": data.get(
                    "deletedBy",
                    "",
                ),
            }
        )

    return records


@app.route("/export.html", methods=["GET"])
@app.route("/export", methods=["GET"])
@staff_required
def art_export_page():
    """
    Securely render the ART export page.

    The page itself never receives tenant credentials or service
    account information.
    """
    return render_template("export.html")


# GOOGLE SHEETS BACKUP — SERVER-SIDE, TENANT-SCOPED
# =========================================================

SHEETS_BACKUP_TIMEOUT_SECONDS = 20


def _sheets_backup_scalar(value, default="---"):
    """Convert Firestore values into safe, compact Apps Script cell values."""
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, default=str)
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            pass
    return str(value)


def _sheets_backup_latest_log(logs, value_keys, date_keys=()):
    """Pick the last populated log item from a list of history objects."""
    if not isinstance(logs, list):
        return "---", "---"
    for item in reversed(logs):
        if not isinstance(item, dict):
            continue
        value = next((item.get(k) for k in value_keys if item.get(k) not in (None, "")), None)
        date = next((item.get(k) for k in date_keys if item.get(k) not in (None, "")), None)
        if value is not None or date is not None:
            return _sheets_backup_scalar(value), _sheets_backup_scalar(date)
    return "---", "---"


def _sheets_backup_post(context, payload):
    """Send a server-built record to the authenticated facility's GAS endpoint."""
    facility_id = context["facility_id"]
    snap = mother_db.collection("facilities").document(facility_id).get()
    if not snap.exists:
        return None, (jsonify({"success": False, "error": "Facility configuration not found."}), 503)
    facility = snap.to_dict() or {}
    webhook = str(facility.get("gas_webhook_url", "")).strip()
    if not webhook.startswith("https://script.google.com/") and not webhook.startswith("https://script.googleusercontent.com/"):
        return None, (jsonify({"success": False, "error": "A valid facility Google Apps Script web-app URL is not configured."}), 400)
    payload["facility_id"] = facility_id
    payload["synchronized_at"] = datetime.now(timezone.utc).isoformat()
    try:
        response = requests.post(webhook, json=payload, timeout=SHEETS_BACKUP_TIMEOUT_SECONDS, allow_redirects=True)
        body = response.json() if response.content else {}
        if response.status_code != 200 or not isinstance(body, dict) or body.get("success") is not True:
            print("Google Sheets backup rejected:", facility_id, response.status_code, str(body)[:500])
            return None, (jsonify({"success": False, "error": "Google Sheets rejected the backup. Check the Apps Script deployment and logs."}), 502)
        return body, None
    except requests.RequestException as error:
        print("Google Sheets backup transport error:", facility_id, repr(error))
        return None, (jsonify({"success": False, "error": "Could not reach the facility Google Sheets backup endpoint."}), 502)
    except ValueError as error:
        print("Google Sheets backup returned invalid JSON:", facility_id, repr(error))
        return None, (jsonify({"success": False, "error": "Google Sheets returned an invalid response."}), 502)


@app.route("/api/art/sheets-backup", methods=["POST"])
def art_sheets_backup():
    context, error = get_art_staff_context(ART_WRITE_ROLES)
    if error:
        return error
    if not verify_art_csrf_token():
        return jsonify({"success": False, "error": "CSRF validation failed."}), 403
    request_data = request.get_json(silent=True) or {}
    uic = art_normalize_uic(request_data.get("uic"))
    if not uic:
        return jsonify({"success": False, "error": "A valid UIC is required."}), 400
    try:
        db = art_get_tenant_db(context["facility_id"])
        demo_snap = db.collection("clients_demographics").document(uic).get()
        reg_snap = db.collection("clients_registry").document(uic).get()
        if not demo_snap.exists and not reg_snap.exists:
            return jsonify({"success": False, "error": "ART record not found in this facility."}), 404
        demo, reg = (demo_snap.to_dict() or {}), (reg_snap.to_dict() or {})
        vl_value, vl_date = _sheets_backup_latest_log(demo.get("vlLogs", []), ("result", "vlValue", "value", "count"), ("date", "testDate", "collectionDate"))
        cd4_value, _ = _sheets_backup_latest_log(demo.get("cd4Logs", []), ("result", "cd4Count", "value", "count"), ("date", "testDate"))
        oi_logs = demo.get("oiLogs", []) if isinstance(demo.get("oiLogs", []), list) else []
        payload = {
            "record_type": "ART", "uic": uic,
            "ohasis_url": demo.get("ohasisUrl", "---"),
            "art_enrollment_date": reg.get("artEnrollmentDate", demo.get("artDate", "---")),
            "first_name": demo.get("firstName", "---"), "last_name": demo.get("lastName", "---"),
            "central_id": demo.get("centralId", demo.get("central_id", "---")),
            "patient_code": demo.get("generated_serial_code", reg.get("generated_serial_code", "---")),
            "live_vl_value": reg.get("vlValue", vl_value), "live_vl_status": reg.get("vlStatus", "---"),
            "live_cd4_value": reg.get("latestCd4Count", cd4_value), "current_retention_status": reg.get("retentionStatus", demo.get("outcome", "---")),
            "estimated_next_refill": reg.get("nextRefillDate", "---"),
            "middle_name": demo.get("middleName", "---"), "suffix": demo.get("suffix", "---"),
            "sex": demo.get("sex", "---"), "key_population": demo.get("kp", "---"),
            "birthdate": demo.get("bday", "---"), "calculated_age": demo.get("calculatedAge", "---"),
            "contact_number": demo.get("contactNumber", "---"), "email_address": demo.get("emailAddress", "---"),
            "address": demo.get("address", "---"), "philhealth_number": demo.get("philhealthNumber", "---"),
            "inception_status": demo.get("inception", "---"), "inception_date": demo.get("incDate", "---"),
            "inception_source": demo.get("incFrom", "---"), "mode_of_transmission": demo.get("modeOfTransmission", "Unknown"),
            "outcome_date": demo.get("outDate", "---"), "outcome_notes": demo.get("outTo", "---"),
            "t0_test_date": demo.get("t0Date", "---"), "t0_test_result": demo.get("t0Result", "---"),
            "arv_regimen_type": demo.get("artRegimen", "---"), "art_initiated_by": demo.get("artBy", "---"),
            "ipt_status": demo.get("iptChecked", "NO"), "ipt_start_date": demo.get("iptStartDate", "---"), "ipt_completed_date": demo.get("iptEndDate", "---"),
            "cpt_status": demo.get("cptChecked", "NO"), "cpt_start_date": demo.get("cptStartDate", "---"), "cpt_completed_date": demo.get("cptEndDate", "---"),
            "tb_status": demo.get("tbStatus", "No active TB"), "tb_treatment_start": demo.get("tbTreatmentStart", "---"), "tb_treatment_completed": demo.get("tbTreatmentCompleted", "---"),
            "confirmatory_status": demo.get("confirmatoryStatus", "---"), "confirmatory_result": demo.get("confirmatoryResult", "---"),
            "confirmatory_date": demo.get("confirmatoryDate", "---"), "confirmatory_code": demo.get("confirmatoryCode", "---"),
            "last_dispense_date": demo.get("dispenseDate", "---"), "pills_dispensed": demo.get("pillsDispensed", 0),
            "calculated_pills_remaining": reg.get("pillsRemaining", 0), "dispensed_by": demo.get("dispensedBy", "---"),
            "run_out_date": reg.get("runOutDate", "---"), "history_log_flag": "YES", "last_updated_by": demo.get("lastUpdatedBy", context["name"]),
            "vl_date": vl_date,
        }
        for i in range(1, 6):
            item = oi_logs[i-1] if len(oi_logs) >= i and isinstance(oi_logs[i-1], dict) else {}
            payload[f"oi_{i}_name"] = item.get("name", item.get("type", "---"))
            payload[f"oi_{i}_date"] = item.get("date", "---")
        _, post_error = _sheets_backup_post(context, payload)
        if post_error:
            return post_error
        return jsonify({"success": True, "message": "ART record backed up to Google Sheets.", "uic": uic}), 200
    except Exception as error:
        print("ART Google Sheets backup failed:", repr(error))
        return jsonify({"success": False, "error": "Unable to back up ART record."}), 503


@app.route("/api/prep/sheets-backup", methods=["POST"])
def prep_sheets_backup():
    context, error = get_prep_staff_context(PREP_WRITE_ROLES)
    if error:
        return error
    if not verify_prep_csrf_token():
        return jsonify({"success": False, "error": "CSRF validation failed."}), 403
    request_data = request.get_json(silent=True) or {}
    uic = prep_normalize_uic(request_data.get("uic"))
    if not uic:
        return jsonify({"success": False, "error": "A valid UIC is required."}), 400
    try:
        db = prep_get_tenant_db(context["facility_id"])
        demo_snap = db.collection("prep_demographics").document(uic).get()
        reg_snap = db.collection("prep_registry").document(uic).get()
        if not demo_snap.exists and not reg_snap.exists:
            return jsonify({"success": False, "error": "PrEP record not found in this facility."}), 404
        demo, reg = (demo_snap.to_dict() or {}), (reg_snap.to_dict() or {})
        payload = {
            "record_type": "PREP", "uic": uic,
            "ohasis_url": demo.get("ohasisUrl", "---"), "prep_enrollment_date": reg.get("prepEnrollmentDate", demo.get("prepDate", "---")),
            "patient_code": demo.get("generated_serial_code", reg.get("generated_serial_code", "---")),
            "first_name": demo.get("firstName", "---"), "middle_name": demo.get("middleName", "---"),
            "last_name": demo.get("lastName", "---"), "suffix": demo.get("suffix", "---"),
            "sex": demo.get("sex", "---"), "key_population": demo.get("kp", "---"),
            "birthdate": demo.get("bday", "---"), "calculated_age": demo.get("calculatedAge", "---"),
            "contact_number": demo.get("contactNumber", "---"), "email_address": demo.get("emailAddress", "---"),
            "address": demo.get("address", "---"), "prep_status": reg.get("prepStatus", demo.get("prepStatus", "---")),
            "prep_intended_dosage": reg.get("prepDosage", demo.get("prepDosage", "---")),
            "prep_regimen": reg.get("prepRegimen", demo.get("prepRegimen", "---")),
            "t0_test_date": demo.get("t0Date", "---"), "t0_test_result": demo.get("t0Result", "---"),
            "serum_creatinine": demo.get("serumCreatinine", "---"), "creatinine_clearance": demo.get("creatinineClearance", "---"),
            "weight": demo.get("weight", "---"), "sti_diagnoses": demo.get("stiLogs", "None"),
            "gaht_status": demo.get("gahtSpecify", demo.get("gahtToggle", "No")),
            "last_updated_by": demo.get("lastUpdatedBy", context["name"]),
        }
        _, post_error = _sheets_backup_post(context, payload)
        if post_error:
            return post_error
        return jsonify({"success": True, "message": "PrEP record backed up to Google Sheets.", "uic": uic}), 200
    except Exception as error:
        print("PrEP Google Sheets backup failed:", repr(error))
        return jsonify({"success": False, "error": "Unable to back up PrEP record."}), 503




@app.route("/api/art/export", methods=["POST"])
def art_export():
    """
    Secure server-side ART CSV export.

    Security boundary:
        Browser
          -> authenticated Flask session
          -> Mother DB staff revalidation
          -> role check
          -> CSRF check
          -> server-selected tenant
          -> tenant Admin SDK
          -> controlled CSV
    """

    context, error = get_art_staff_context(
        ART_EXPORT_ROLES
    )

    if error:
        return error

    if not verify_art_csrf_token():
        return jsonify(
            {
                "success": False,
                "error": "CSRF validation failed.",
            }
        ), 403

    payload = request.get_json(
        silent=True
    )

    if not isinstance(payload, dict):
        return jsonify(
            {
                "success": False,
                "error": "Invalid export request.",
            }
        ), 400

    scope = str(
        payload.get("scope", "active")
    ).strip().lower()

    if scope not in ART_EXPORT_ALLOWED_SCOPES:
        return jsonify(
            {
                "success": False,
                "error": "Invalid export scope.",
            }
        ), 400

    start_date = str(
        payload.get("date_start", "")
    ).strip()

    end_date = str(
        payload.get("date_end", "")
    ).strip()

    vl_status = str(
        payload.get("vl_status", "")
    ).strip()

    retention_status = str(
        payload.get("retention_status", "")
    ).strip()

    hide_pii = payload.get(
        "hide_pii",
        False,
    )

    if not isinstance(hide_pii, bool):
        return jsonify(
            {
                "success": False,
                "error": "Invalid PII export option.",
            }
        ), 400

    date_pattern = r"^\d{4}-\d{2}-\d{2}$"

    if start_date and not re.fullmatch(
        date_pattern,
        start_date,
    ):
        return jsonify(
            {
                "success": False,
                "error": "Invalid start date.",
            }
        ), 400

    if end_date and not re.fullmatch(
        date_pattern,
        end_date,
    ):
        return jsonify(
            {
                "success": False,
                "error": "Invalid end date.",
            }
        ), 400

    if start_date and end_date and start_date > end_date:
        return jsonify(
            {
                "success": False,
                "error": "Invalid date range.",
            }
        ), 400

    if vl_status not in ART_EXPORT_ALLOWED_VL:
        return jsonify(
            {
                "success": False,
                "error": "Invalid viral load filter.",
            }
        ), 400

    if retention_status not in ART_EXPORT_ALLOWED_RETENTION:
        return jsonify(
            {
                "success": False,
                "error": "Invalid retention filter.",
            }
        ), 400

    try:
        # IMPORTANT:
        # facility_id comes exclusively from the validated session.
        # It is NEVER accepted from the browser.
        db = art_get_tenant_db(
            context["facility_id"]
        )

        if scope == "deleted":
            source_records = art_export_deleted_records(db)
        else:
            source_records = art_export_registry_records(db)

        rows = []

        for record in source_records:
            uic = str(
                record.get("uic", "")
            ).strip()

            demographics = record.get(
                "demographics",
                {},
            )

            registry = record.get(
                "registry",
                {},
            )

            if not isinstance(demographics, dict):
                demographics = {}

            if not isinstance(registry, dict):
                registry = {}

            enrollment_date = (
                registry.get("artEnrollmentDate")
                or demographics.get("artDate")
                or demographics.get("incDate")
                or ""
            )

            if not art_export_date_matches(
                enrollment_date,
                start_date,
                end_date,
            ):
                continue

            current_vl_status = str(
                registry.get(
                    "vlStatus",
                    ""
                )
            ).strip()

            if vl_status and current_vl_status != vl_status:
                continue

            current_retention = str(
                registry.get(
                    "retentionStatus",
                    ""
                )
            ).strip()

            if (
                retention_status
                and current_retention != retention_status
            ):
                continue

            row = art_export_prepare_row(
                uic=uic,
                demographics=demographics,
                registry=registry,
                hide_pii=hide_pii,
                deleted=(scope == "deleted"),
            )

            if scope == "deleted":
                row["Archived At"] = art_export_clean_csv_value(
                    record.get("archived_at", "")
                )
                row["Deleted By"] = art_export_clean_csv_value(
                    record.get("deleted_by", "")
                )

                if hide_pii:
                    row["Deleted By"] = art_export_mask_pii(
                        row["Deleted By"]
                    )

            rows.append(row)

        if scope == "deleted":
            fieldnames = [
                "UIC",
                "Last Name",
                "First Name",
                "Middle Name",
                "Suffix",
                "Sex",
                "Key Population",
                "Birth Date",
                "Contact Number",
                "Email Address",
                "Address",
                "PhilHealth Number",
                "Mode of Transmission",
                "ART Enrollment Date",
                "ART Regimen",
                "ART Status",
                "VL Status",
                "VL Value",
                "Latest CD4",
                "Pills Remaining",
                "Retention Status",
                "Next Refill Date",
                "Dispense Date",
                "Pills Dispensed",
                "Dispensed By",
                "Generated Serial Code",
                "OHA-SIS URL",
                "Deleted Record",
                "Archived At",
                "Deleted By",
            ]
        else:
            fieldnames = [
                "UIC",
                "Last Name",
                "First Name",
                "Middle Name",
                "Suffix",
                "Sex",
                "Key Population",
                "Birth Date",
                "Contact Number",
                "Email Address",
                "Address",
                "PhilHealth Number",
                "Mode of Transmission",
                "ART Enrollment Date",
                "ART Regimen",
                "ART Status",
                "VL Status",
                "VL Value",
                "Latest CD4",
                "Pills Remaining",
                "Retention Status",
                "Next Refill Date",
                "Dispense Date",
                "Pills Dispensed",
                "Dispensed By",
                "Generated Serial Code",
                "OHA-SIS URL",
            ]

        output = io.StringIO(
            newline=""
        )

        writer = csv.DictWriter(
            output,
            fieldnames=fieldnames,
            extrasaction="ignore",
            quoting=csv.QUOTE_MINIMAL,
        )

        writer.writeheader()

        for row in rows:
            writer.writerow(row)

        csv_data = output.getvalue()


        response = Response(
            csv_data,
            mimetype="text/csv; charset=utf-8",
        )

        filename_scope = (
            "DELETED"
            if scope == "deleted"
            else "ACTIVE"
        )

        response.headers["Content-Disposition"] = (
            "attachment; "
            f'filename="ART_{filename_scope}_EXPORT.csv"'
        )

        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, max-age=0"
        )

        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

        response.headers["X-Content-Type-Options"] = "nosniff"

        return response

    except Exception:
        return jsonify(
            {
                "success": False,
                "error": "Unable to generate ART export.",
            }
        ), 503


# =========================================================
# DATA MIGRATION & BULK IMPORT — STAFF SECURITY BOUNDARY
# =========================================================

@app.route("/batch-import", methods=["GET"])
@staff_required
def batch_import_page():
    return render_template("upload.html")

@app.route("/api/batch-import-clients", methods=["POST"])
def batch_import_clients():
    """
    Import mapped records into the authenticated staff member's
    facility database.

    Security:
        1. Revalidate staff session and Mother DB authorization
        2. Enforce write-role authorization
        3. Verify CSRF token
        4. Derive tenant from authenticated session
        5. Validate and bound request payload
        6. Normalize UICs
        7. Allowlist fields using the existing ART/PrEP schemas
        8. Commit Firestore writes in a bounded batch
        9. Record audit metadata without logging clinical payloads
    """

    # -----------------------------------------------------
    # 1. AUTHENTICATION + WRITE AUTHORIZATION
    # -----------------------------------------------------

    context, error = get_art_staff_context(ART_WRITE_ROLES)

    if error:
        return error

    # -----------------------------------------------------
    # 2. CSRF PROTECTION
    # -----------------------------------------------------

    if not verify_art_csrf_token():
        return jsonify({
            "success": False,
            "error": "Invalid or missing CSRF token."
        }), 403

    # -----------------------------------------------------
    # 3. REQUEST VALIDATION
    # -----------------------------------------------------

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({
            "success": False,
            "error": "Invalid migration request."
        }), 400

    records = payload.get("records")

    if not isinstance(records, list) or not records:
        return jsonify({
            "success": False,
            "error": "No data records supplied for migration."
        }), 400

    # The current mapper submits chunks of 100 records.
    if len(records) > 100:
        return jsonify({
            "success": False,
            "error": "Maximum 100 records per migration request."
        }), 413

    # -----------------------------------------------------
    # 4. PREPARE THE TENANT DATABASE
    # -----------------------------------------------------

    try:
        facility_id = context["facility_id"]
        db = art_get_tenant_db(facility_id)

        batch = db.batch()
        write_count = 0
        imported_uics = []
        skipped_count = 0

        now = datetime.now(timezone.utc).isoformat()

        def keep_nonblank_fields(data):
            """Omit blank incoming values while preserving False and numeric 0."""
            cleaned = {}
            for key, value in data.items():
                if value is None:
                    continue
                if isinstance(value, str) and not value.strip():
                    continue
                cleaned[key] = value
            return cleaned

        def merge_nonblank(existing, incoming):
            """Overlay only populated uploaded fields on the fetched database record."""
            merged = dict(existing or {})
            merged.update(keep_nonblank_fields(incoming))
            return merged

        # -------------------------------------------------
        # 5. VALIDATE + MAP EACH RECORD
        # -------------------------------------------------

        for item in records:
            if not isinstance(item, dict):
                raise ValueError("A migration record is invalid.")

            uic = art_normalize_uic(item.get("uic"))

            if not uic:
                skipped_count += 1
                continue

            raw_demo = item.get("demographics") or {}
            raw_registry = item.get("registry") or {}

            if not isinstance(raw_demo, dict):
                raise ValueError(
                    f"Invalid demographics structure for UIC {uic}."
                )

            if not isinstance(raw_registry, dict):
                raise ValueError(
                    f"Invalid registry structure for UIC {uic}."
                )

            # Bound and validate incoming JSON-like values.
            raw_demo = art_json_safe(raw_demo)
            raw_registry = art_json_safe(raw_registry)

            if not isinstance(raw_demo, dict) or not isinstance(
                raw_registry, dict
            ):
                raise ValueError("Invalid record structure.")

            # The HTML mapper uses shorter aliases for these fields.
            demo_aliases = {
                "iptStart": "iptStartDate",
                "iptEnd": "iptEndDate",
                "cptStart": "cptStartDate",
                "cptEnd": "cptEndDate",
                "tbStart": "tbTreatmentStart",
                "tbEnd": "tbTreatmentCompleted",
            }

            for old_key, new_key in demo_aliases.items():
                if old_key in raw_demo and new_key not in raw_demo:
                    raw_demo[new_key] = raw_demo[old_key]

            # The HTML mapper currently places these two fields
            # in registry, while staff.py stores them in demographics.
            for key in ("artRegimen", "artBy"):
                if key in raw_registry and key not in raw_demo:
                    raw_demo[key] = raw_registry[key]

            # Allowlisted ART fields only.
            art_demo = {
                key: value
                for key, value in raw_demo.items()
                if key in ART_DEMOGRAPHIC_FIELDS
            }

            art_registry = {
                key: value
                for key, value in raw_registry.items()
                if key in ART_REGISTRY_FIELDS
            }

            # PrEP uses its own collections and field allowlists.
            prep_demo = {
                key: value
                for key, value in raw_demo.items()
                if key in PREP_DEMOGRAPHIC_FIELDS
            }

            prep_registry = {
                key: value
                for key, value in raw_registry.items()
                if key in PREP_REGISTRY_FIELDS
            }

            # The mapper calls this field prepDate. The staff PrEP
            # schema also supports prepEnrollmentDate in its registry.
            if raw_demo.get("prepDate") and not prep_registry.get(
                "prepEnrollmentDate"
            ):
                prep_registry["prepEnrollmentDate"] = raw_demo["prepDate"]

            # If mapped PrEP details exist, derive its registry fields
            # from the demographic values where applicable.
            for key in (
                "prepStatus",
                "prepDosage",
                "prepRegimen",
                "generated_serial_code",
            ):
                if key in raw_demo and key not in prep_registry:
                    prep_registry[key] = raw_demo[key]

            # Filter again after derived fields are added.
            prep_registry = {
                key: value
                for key, value in prep_registry.items()
                if key in PREP_REGISTRY_FIELDS
            }

            # Blank uploaded cells must not erase values already stored in Firestore.
            # Keep explicit False and 0 values because they may be meaningful.
            art_demo = keep_nonblank_fields(art_demo)
            art_registry = keep_nonblank_fields(art_registry)
            prep_demo = keep_nonblank_fields(prep_demo)
            prep_registry = keep_nonblank_fields(prep_registry)

            # Determine whether the row contains ART and/or PrEP data.
            has_art_data = bool(art_demo or art_registry)
            has_prep_data = bool(prep_demo or prep_registry)

            if not has_art_data and not has_prep_data:
                skipped_count += 1
                continue

            # -------------------------------------------------
            # 6. WRITE ART DOCUMENTS
            # -------------------------------------------------

            if has_art_data:
                art_demo_ref = db.collection("clients_demographics").document(uic)
                art_reg_ref = db.collection("clients_registry").document(uic)
                existing_art_demo_snap = art_demo_ref.get()
                existing_art_reg_snap = art_reg_ref.get()

                if art_demo:
                    art_demo = merge_nonblank(
                        existing_art_demo_snap.to_dict() if existing_art_demo_snap.exists else {},
                        art_demo,
                    )
                    art_demo["lastUpdatedAt"] = now
                    art_demo["lastUpdatedBy"] = context["name"]
                    batch.set(art_demo_ref, art_demo, merge=True)
                    write_count += 1

                if art_registry:
                    art_registry = merge_nonblank(
                        existing_art_reg_snap.to_dict() if existing_art_reg_snap.exists else {},
                        art_registry,
                    )
                    art_registry["lastUpdatedAt"] = now
                    art_registry["lastUpdatedBy"] = context["name"]
                    batch.set(art_reg_ref, art_registry, merge=True)
                    write_count += 1

            # -------------------------------------------------
            # 7. WRITE PREP DOCUMENTS
            # -------------------------------------------------

            if has_prep_data:
                prep_demo_ref = db.collection("prep_demographics").document(uic)
                prep_reg_ref = db.collection("prep_registry").document(uic)
                existing_prep_demo_snap = prep_demo_ref.get()
                existing_prep_reg_snap = prep_reg_ref.get()

                if prep_demo:
                    prep_demo = merge_nonblank(
                        existing_prep_demo_snap.to_dict() if existing_prep_demo_snap.exists else {},
                        prep_demo,
                    )
                    prep_demo["lastUpdatedAt"] = now
                    prep_demo["lastUpdatedBy"] = context["name"]
                    batch.set(prep_demo_ref, prep_demo, merge=True)
                    write_count += 1

                if prep_registry:
                    prep_registry = merge_nonblank(
                        existing_prep_reg_snap.to_dict() if existing_prep_reg_snap.exists else {},
                        prep_registry,
                    )
                    prep_registry["lastUpdatedAt"] = now
                    prep_registry["lastUpdatedBy"] = context["name"]
                    batch.set(prep_reg_ref, prep_registry, merge=True)
                    write_count += 1

            imported_uics.append(uic)

        # -----------------------------------------------------
        # 8. REJECT EMPTY IMPORTS
        # -----------------------------------------------------

        if write_count == 0:
            return jsonify({
                "success": False,
                "error": "No valid mapped records were available to import.",
                "skipped": skipped_count,
            }), 400

        # -----------------------------------------------------
        # 9. COMMIT TENANT DATABASE WRITES
        # -----------------------------------------------------

        # Four document writes per record maximum; with 100 records,
        # the current mapper remains below Firestore's 500-write limit.
        batch.commit()

        # Audit is intentionally limited to individual CREATE/UPDATE/ARCHIVE operations.

        return jsonify({
            "success": True,
            "facility_id": facility_id,
            "count": len(imported_uics),
            "skipped": skipped_count,
            "message": "Migration batch imported successfully.",
        }), 200

    except ValueError as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 400

    except Exception as exc:
        # Log technical details server-side only.
        print(
            "Bulk import failed:",
            {
                "facility_id": context.get("facility_id"),
                "error": repr(exc),
            }
        )

        return jsonify({
            "success": False,
            "error": "Unable to import migration batch.",
        }), 503


@app.route("/art-import", methods=["GET"])
@staff_required
def art_import_page():
    return render_template("art_import.html")


@app.route("/prep-upload", methods=["GET"])
@staff_required
def prep_upload_page():
    return render_template("prep_upload.html")


# =========================================================
# STAFF LOGOUT
# =========================================================

@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("login_page"))

# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5002"))
    app.run(host="127.0.0.1", port=port, debug=True)
