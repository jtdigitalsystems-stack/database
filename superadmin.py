import os

import json

import requests

import re

import secrets

import hmac

from datetime import datetime, timedelta

from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    session,
    redirect,
    url_for
)

from dotenv import load_dotenv

from functools import wraps

import firebase_admin

from firebase_admin import credentials, auth, firestore

load_dotenv()

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY"
)

if not app.secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable is required."
    )

app.config["SESSION_COOKIE_HTTPONLY"] = True

app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_COOKIE_SECURE"] = (
    os.getenv(
        "FLASK_SESSION_COOKIE_SECURE",
        "false"
    ).strip().lower()
    == "true"
)

db_admin = None

service_account_env = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")

secret_path = os.getenv("FIREBASE_CREDENTIALS_PATH", "serviceAccountKey.json")

try:
    if service_account_env:
        service_account_info = json.loads(service_account_env)
        cred = credentials.Certificate(service_account_info)
        firebase_admin.initialize_app(cred)
        db_admin = firestore.client()
        print("✅ Central Firebase Admin SDK initialized via Environment Variable.")
    elif os.path.exists(secret_path):
        cred = credentials.Certificate(secret_path)
        firebase_admin.initialize_app(cred)
        db_admin = firestore.client()
        print("✅ Central Firebase Admin SDK initialized via Local Secret File.")
    else:
        print("⚠️ Warning: Firebase Admin credentials not found. Central Admin features will fail until 'serviceAccountKey.json' is present.")
except Exception as init_err:
    print(f"❌ Error initializing Central Firebase Admin SDK: {init_err}")

DEFAULT_FIREBASE_CONFIG = {
    "apiKey": os.getenv("FIREBASE_API_KEY", ""),
    "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN", ""),
    "projectId": os.getenv("FIREBASE_PROJECT_ID", ""),
    "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET", ""),
    "messagingSenderId": os.getenv("FIREBASE_MESSAGING_SENDER_ID", ""),
    "appId": os.getenv("FIREBASE_APP_ID", ""),
    "measurementId": os.getenv("FIREBASE_MEASUREMENT_ID", "")
}

def get_active_facility_id():
    """
    Resolve the facility context from trusted server-side state.

    SECURITY:
    - NEVER trust X-Facility-ID from the client.
    - SuperAdmin uses the server-side selected facility.
    - Normal authenticated users use their verified facility.
    - No client-controlled header may override the trusted context.
    """

    # -----------------------------------------------------
    # 1. SUPERADMIN
    #
    # SuperAdmin facility selection is stored server-side
    # in the Flask session by /api/select-facility.
    # -----------------------------------------------------

    superadmin_email = session.get("superadmin_email")

    if superadmin_email:

        selected_facility = (
            session.get("active_facility_id")
        )

        if selected_facility:
            return selected_facility

        return "master"


    # -----------------------------------------------------
    # 2. NORMAL AUTHENTICATED USER
    #
    # The facility should have been resolved during login
    # from the central Mother DB.
    # -----------------------------------------------------

    authenticated_facility = (
        session.get("facility_id")
        or session.get("active_facility_id")
    )

    if authenticated_facility:
        return authenticated_facility


    # -----------------------------------------------------
    # 3. NO TRUSTED FACILITY CONTEXT
    # -----------------------------------------------------

    return "master"

def get_bearer_token():
    """
    Extract Firebase ID token from the Authorization header.

    Expected format:

        Authorization: Bearer <Firebase ID Token>
    """

    auth_header = request.headers.get("Authorization", "")

    if not auth_header:
        return None

    if not auth_header.startswith("Bearer "):
        return None

    return auth_header[7:].strip()

def verify_superadmin_request():
    """
    Verify that the current API request comes from an
    authorized SuperAdmin Firebase account.

    Authentication flow:

        Firebase Authentication
                ↓
        Firebase UID + email
                ↓
        Mother Database
        authorized_clinical_staff/{email}
                ↓
        UID verification
                ↓
        SuperAdmin clearance verification
                ↓
        Master facility verification
                ↓
        Access granted
    """

    # ---------------------------------------------------------
    # Firebase Admin SDK must already be initialized.
    # ---------------------------------------------------------

    if db_admin is None:

        return {
            "success": False,
            "status": 500,
            "error": "Central Firebase Admin SDK is not initialized."
        }


    # ---------------------------------------------------------
    # Get Firebase ID token from browser request.
    # ---------------------------------------------------------

    token = get_bearer_token()


    if not token:

        return {
            "success": False,
            "status": 401,
            "error": "Missing Firebase authorization token."
        }


    try:

        # -----------------------------------------------------
        # Verify Firebase ID token
        # -----------------------------------------------------

        print(
            "🔐 SUPERADMIN: Verifying Firebase ID token..."
        )


        decoded_token = auth.verify_id_token(
            token
        )


        authenticated_uid = (
            decoded_token.get("uid") or ""
        ).strip()


        authenticated_email = (
            decoded_token.get("email") or ""
        ).strip().lower()


        print(
            "✅ SUPERADMIN FIREBASE TOKEN VERIFIED:",
            {
                "uid": authenticated_uid,
                "email": authenticated_email
            }
        )


        # -----------------------------------------------------
        # Make sure Firebase provided both UID and email.
        # -----------------------------------------------------

        if not authenticated_uid:

            print(
                "🚫 SUPERADMIN ACCESS DENIED: "
                "Firebase UID is missing."
            )

            return {
                "success": False,
                "status": 401,
                "error": "Firebase account UID is missing."
            }


        if not authenticated_email:

            print(
                "🚫 SUPERADMIN ACCESS DENIED: "
                "Firebase email is missing."
            )

            return {
                "success": False,
                "status": 401,
                "error": "Firebase account email is missing."
            }


        # -----------------------------------------------------
        # Mother Database lookup
        #
        # Your Mother DB structure is:
        #
        # authorized_clinical_staff/{email}
        #
        # Therefore:
        #
        # authorized_clinical_staff/
        #     jtorrecampo@lakanconnect.com
        #
        # is the SuperAdmin's central identity record.
        # -----------------------------------------------------

        print(
            "🔎 SUPERADMIN MOTHER DB LOOKUP:",
            authenticated_email
        )


        central_profile = (
            db_admin
            .collection(
                "authorized_clinical_staff"
            )
            .document(
                authenticated_email
            )
            .get()
        )


        # -----------------------------------------------------
        # Profile MUST exist.
        #
        # Unlike normal facility lookup, a SuperAdmin must
        # have an explicit central authorization record.
        # -----------------------------------------------------

        if not central_profile.exists:

            print(
                "🚫 SUPERADMIN ACCESS DENIED: "
                "Mother DB profile not found:",
                authenticated_email
            )

            return {
                "success": False,
                "status": 403,
                "error": (
                    "No authorized SuperAdmin profile "
                    "was found for this account."
                )
            }


        profile_data = (
            central_profile.to_dict() or {}
        )


        print(
            "🔎 SUPERADMIN MOTHER DB PROFILE:",
            {
                "email":
                    profile_data.get("email"),

                "uid":
                    profile_data.get("uid"),

                "facility_id":
                    profile_data.get("facility_id"),

                "clearancePermission":
                    profile_data.get(
                        "clearancePermission"
                    ),

                "accountInitialized":
                    profile_data.get(
                        "accountInitialized"
                    )
            }
        )


        # -----------------------------------------------------
        # Verify UID
        #
        # Firebase Auth UID MUST match the UID stored in
        # the Mother Database.
        # -----------------------------------------------------

        profile_uid = str(
            profile_data.get(
                "uid",
                ""
            )
        ).strip()


        if profile_uid != authenticated_uid:

            print(
                "🚫 SUPERADMIN ACCESS DENIED: UID mismatch"
            )


            print(
                "   Firebase UID:",
                authenticated_uid
            )


            print(
                "   Mother DB UID:",
                profile_uid
            )


            return {
                "success": False,
                "status": 403,
                "error": (
                    "SuperAdmin identity verification failed."
                )
            }


        print(
            "✅ SUPERADMIN UID VERIFIED"
        )


        # -----------------------------------------------------
        # Verify email
        #
        # The email stored in Mother DB must also match the
        # authenticated Firebase email.
        # -----------------------------------------------------

        profile_email = (
            str(
                profile_data.get(
                    "email",
                    ""
                )
            )
            .strip()
            .lower()
        )


        if profile_email != authenticated_email:

            print(
                "🚫 SUPERADMIN ACCESS DENIED: "
                "Email mismatch"
            )


            print(
                "   Firebase email:",
                authenticated_email
            )


            print(
                "   Mother DB email:",
                profile_email
            )


            return {
                "success": False,
                "status": 403,
                "error": (
                    "SuperAdmin email verification failed."
                )
            }


        print(
            "✅ SUPERADMIN EMAIL VERIFIED"
        )


        # -----------------------------------------------------
        # Verify accountInitialized
        #
        # This MUST be a Boolean True.
        #
        # Correct:
        #
        #     accountInitialized: true
        #
        # Incorrect:
        #
        #     accountInitialized: "true"
        # -----------------------------------------------------

        account_initialized = (
            profile_data.get(
                "accountInitialized"
            )
        )


        if account_initialized is not True:

            print(
                "🚫 SUPERADMIN ACCESS DENIED: "
                "accountInitialized is not Boolean true"
            )


            return {
                "success": False,
                "status": 403,
                "error": (
                    "SuperAdmin account is not initialized."
                )
            }


        print(
            "✅ SUPERADMIN ACCOUNT INITIALIZED"
        )


        # -----------------------------------------------------
        # Verify SuperAdmin clearance
        #
        # This is REQUIRED.
        # -----------------------------------------------------

        profile_clearance = (
            str(
                profile_data.get(
                    "clearancePermission",
                    ""
                )
            )
            .strip()
        )


        if profile_clearance != "SuperAdmin":

            print(
                "🚫 SUPERADMIN ACCESS DENIED:",
                profile_clearance
            )


            return {
                "success": False,
                "status": 403,
                "error": (
                    "SuperAdmin clearance is required."
                )
            }


        print(
            "✅ SUPERADMIN CLEARANCE VERIFIED"
        )


        # -----------------------------------------------------
        # Verify master facility node
        #
        # The SuperAdmin is not a tenant-level facility user.
        #
        # Therefore the central profile must use:
        #
        #     facility_id = master
        # -----------------------------------------------------

        profile_facility_id = (
            str(
                profile_data.get(
                    "facility_id",
                    ""
                )
            )
            .strip()
        )


        if profile_facility_id != "master":

            print(
                "🚫 SUPERADMIN ACCESS DENIED: "
                "Invalid facility node:",
                profile_facility_id
            )


            return {
                "success": False,
                "status": 403,
                "error": (
                    "SuperAdmin is not assigned "
                    "to the master node."
                )
            }


        print(
            "✅ SUPERADMIN MASTER NODE VERIFIED"
        )


        # -----------------------------------------------------
        # SUPERADMIN AUTHORIZATION SUCCESS
        # -----------------------------------------------------

        print(
            "🛡️ SUPERADMIN VERIFIED:",
            {
                "email":
                    authenticated_email,

                "uid":
                    authenticated_uid,

                "facility_id":
                    profile_facility_id,

                "clearance":
                    profile_clearance
            }
        )


        return {
            "success": True,
            "status": 200,

            "uid":
                authenticated_uid,

            "email":
                authenticated_email,

            "facility_id":
                profile_facility_id,

            "clearancePermission":
                profile_clearance,

            "staff":
                profile_data,

            "decoded_token":
                decoded_token
        }


    except Exception as verify_error:
        print(
        "❌ SUPERADMIN TOKEN VERIFICATION FAILED:",
        type(verify_error).__name__,
        repr(verify_error)
    )

    return {
        "success": False,
        "status": 401,
        "error": "Invalid or expired Firebase authorization token."
    }

CSRF_SESSION_KEY = "superadmin_csrf_token"

def get_or_create_csrf_token():
    """
    Retrieve the current SuperAdmin CSRF token.

    If no token exists in the Flask session, generate a
    cryptographically secure random token and store it.

    SECURITY:
    - Token is generated server-side.
    - Token is stored in the signed Flask session.
    - Token is never accepted from a URL parameter.
    - Token is never derived from the Firebase UID/email.
    """

    token = session.get(
        CSRF_SESSION_KEY
    )

    if not token:

        token = secrets.token_urlsafe(32)

        session[CSRF_SESSION_KEY] = token

        session.modified = True

    return token

def verify_csrf_token():
    """
    Verify the CSRF token supplied by the browser.

    Expected header:

        X-CSRF-Token: <token>

    SECURITY:
    - Requires an existing server-side session token.
    - Uses constant-time comparison.
    - Missing or invalid tokens are rejected.
    """

    session_token = session.get(
        CSRF_SESSION_KEY
    )

    supplied_token = (
        request.headers.get(
            "X-CSRF-Token",
            ""
        ).strip()
    )

    if not session_token:
        return {
            "success": False,
            "status": 403,
            "error": "CSRF security session is not initialized."
        }

    if not supplied_token:
        return {
            "success": False,
            "status": 403,
            "error": "Missing CSRF security token."
        }

    if not hmac.compare_digest(
        session_token,
        supplied_token
    ):
        return {
            "success": False,
            "status": 403,
            "error": "Invalid CSRF security token."
        }

    return {
        "success": True
    }

@app.route(
    "/api/superadmin/csrf-token",
    methods=["GET"]
)
def get_superadmin_csrf_token():

    verification = verify_superadmin_request()

    if not verification.get("success"):

        return jsonify({
            "success": False,
            "error": verification.get(
                "error",
                "SuperAdmin authorization required."
            )
        }), verification.get(
            "status",
            403
        )

    token = get_or_create_csrf_token()

    return jsonify({
        "success": True,
        "csrf_token": token
    }), 200

def require_superadmin(function):

    """
    Protect a Flask API endpoint so that only the configured
    SuperAdmin account can use it.

    Authentication:

        Firebase ID Token
                ↓
        Firebase UID + Email
                ↓
        Mother DB verification
                ↓
        SuperAdmin clearance
                ↓
        Flask session
                ↓
        CSRF verification for state-changing requests
                ↓
        Endpoint
    """

    @wraps(function)
    def decorated_function(*args, **kwargs):

        # -------------------------------------------------
        # 1. Verify Firebase SuperAdmin identity
        # -------------------------------------------------

        verification = verify_superadmin_request()

        if not verification.get("success"):

            return jsonify({
                "success": False,
                "error": verification.get(
                    "error",
                    "SuperAdmin authorization required."
                )
            }), verification.get(
                "status",
                403
            )


        # -------------------------------------------------
        # 2. CSRF protection
        #
        # GET requests are read-only and therefore do not
        # require a CSRF token.
        #
        # State-changing requests MUST provide one.
        # -------------------------------------------------

        if request.method in {
            "POST",
            "PUT",
            "PATCH",
            "DELETE"
        }:

            csrf_verification = verify_csrf_token()

            if not csrf_verification.get(
                "success"
            ):

                print(
                    "🚫 SUPERADMIN CSRF BLOCK:",
                    {
                        "method": request.method,
                        "path": request.path,
                        "reason": csrf_verification.get(
                            "error"
                        )
                    }
                )

                return jsonify({
                    "success": False,
                    "error": csrf_verification.get(
                        "error",
                        "CSRF validation failed."
                    )
                }), csrf_verification.get(
                    "status",
                    403
                )


        # -------------------------------------------------
        # 3. Authorization + CSRF checks passed
        # -------------------------------------------------

        return function(
            *args,
            **kwargs
        )


    return decorated_function

def get_facility_settings(facility_id):
    """
    Retrieve configuration for a specific facility.

    SECURITY:
    - DEFAULT_FIREBASE_CONFIG is returned ONLY for the explicit
      'master' facility.
    - A tenant facility can NEVER silently fall back to the
      Master Firebase configuration.
    - Missing/invalid facility configuration returns None.
    - Backend errors fail closed.
    """

    facility_id = str(
        facility_id or ""
    ).strip()


    # ---------------------------------------------------------
    # EXPLICIT MASTER NODE
    #
    # Master configuration is allowed ONLY when the caller
    # explicitly requests the master node.
    # ---------------------------------------------------------

    if facility_id.lower() == "master":

        return {
            "facility_name":
                "Master Node / Default Facility",

            "firebase_config":
                DEFAULT_FIREBASE_CONFIG,

            "gas_webhook_url":
                os.getenv(
                    "GAS_WEBHOOK_URL",
                    ""
                )
        }


    # ---------------------------------------------------------
    # NON-MASTER FACILITIES REQUIRE CENTRAL DB
    # ---------------------------------------------------------

    if not facility_id:

        print(
            "❌ FACILITY SETTINGS RESOLUTION FAILED: "
            "Facility ID is empty."
        )

        return None


    if db_admin is None:

        print(
            "❌ FACILITY SETTINGS RESOLUTION FAILED: "
            f"Central Firebase unavailable for [{facility_id}]."
        )

        return None


    # ---------------------------------------------------------
    # LOOK UP TENANT FACILITY
    # ---------------------------------------------------------

    try:

        facility_doc = (
            db_admin
            .collection("facilities")
            .document(facility_id)
            .get()
        )


        if not facility_doc.exists:

            print(
                "❌ FACILITY SETTINGS RESOLUTION FAILED: "
                f"Facility [{facility_id}] does not exist."
            )

            return None


        facility_data = (
            facility_doc.to_dict()
            or {}
        )


        # -----------------------------------------------------
        # REQUIRED TENANT FIREBASE CONFIGURATION
        # -----------------------------------------------------

        firebase_config = (
            facility_data.get(
                "firebase_config"
            )
        )


        if not isinstance(
            firebase_config,
            dict
        ):

            print(
                "❌ FACILITY SETTINGS INVALID: "
                f"Facility [{facility_id}] has no valid Firebase configuration."
            )

            return None


        project_id = str(
            firebase_config.get(
                "projectId",
                ""
            )
        ).strip()


        if not project_id:

            print(
                "❌ FACILITY SETTINGS INVALID: "
                f"Facility [{facility_id}] Firebase projectId is missing."
            )

            return None


        # -----------------------------------------------------
        # RETURN VERIFIED TENANT CONFIGURATION
        # -----------------------------------------------------

        return facility_data


    except Exception as e:

        print(
            "❌ FACILITY SETTINGS LOOKUP ERROR:",
            {
                "facility_id":
                    facility_id,

                "error":
                    repr(e)
            }
        )


        # -----------------------------------------------------
        # FAIL CLOSED
        # -----------------------------------------------------

        return None

def get_facility_admin_sdk(facility_id):
    """
    Retrieve or initialize the Firebase Admin SDK instance
    for a specific tenant facility.

    SECURITY:
    - Master is never used as a tenant.
    - Missing facility configuration fails closed.
    - Tenant configuration errors NEVER fall back to Master.
    """

    facility_id = str(
        facility_id or ""
    ).strip()


    # ---------------------------------------------------------
    # INVALID / MASTER FACILITY
    # ---------------------------------------------------------

    if not facility_id:

        print(
            "❌ FACILITY SDK RESOLUTION FAILED: "
            "Facility ID is empty."
        )

        return None, None


    if facility_id.lower() == "master":

        print(
            "❌ FACILITY SDK RESOLUTION BLOCKED: "
            "Master cannot be used as a tenant."
        )

        return None, None


    if db_admin is None:

        print(
            "❌ FACILITY SDK RESOLUTION FAILED: "
            "Central Firebase Admin SDK unavailable."
        )

        return None, None


    # ---------------------------------------------------------
    # LOAD VERIFIED TENANT SETTINGS
    # ---------------------------------------------------------

    facility_settings = (
        get_facility_settings(
            facility_id
        )
    )


    if not facility_settings:

        print(
            "❌ FACILITY SDK RESOLUTION FAILED: "
            f"No valid configuration for [{facility_id}]."
        )

        return None, None


    f_config = (
        facility_settings.get(
            "firebase_config",
            {}
        )
    )


    if not isinstance(
        f_config,
        dict
    ):

        print(
            "❌ FACILITY SDK RESOLUTION FAILED: "
            f"Invalid Firebase configuration for [{facility_id}]."
        )

        return None, None


    project_id = str(
        f_config.get(
            "projectId",
            ""
        )
    ).strip()


    if not project_id:

        print(
            "❌ FACILITY SDK RESOLUTION FAILED: "
            f"Missing projectId for [{facility_id}]."
        )

        return None, None


    app_name = (
        f"facility_app_{facility_id}"
    )


    # ---------------------------------------------------------
    # REUSE EXISTING TENANT APP
    # ---------------------------------------------------------

    try:

        facility_app = (
            firebase_admin.get_app(
                app_name
            )
        )


        return (
            facility_app,
            firestore.client(
                facility_app
            )
        )


    except ValueError:

        pass


    # ---------------------------------------------------------
    # TENANT SERVICE ACCOUNT
    #
    # IMPORTANT:
    # The browser Firebase config is a CLIENT configuration.
    # It is NOT a server credential for accessing another
    # Firebase project's Firestore/Admin APIs.
    #
    # Each tenant must have its own server-side service-account
    # JSON path supplied through the environment, for example:
    #
    # TENANT_SERVICE_ACCOUNT_LAKAN_CC=
    #     C:/.../lakan_cc-service-account.json
    #
    # Never fall back to projectId-only initialization here.
    # ---------------------------------------------------------

    service_account_env = (
        "TENANT_SERVICE_ACCOUNT_"
        + re.sub(
            r"[^A-Z0-9]+",
            "_",
            facility_id.upper()
        ).strip("_")
    )

    service_account_path = str(
        os.getenv(
            service_account_env,
            ""
        )
    ).strip()

    if not service_account_path:
        print(
            "❌ TENANT ADMIN SDK INITIALIZATION BLOCKED: "
            f"Missing environment variable [{service_account_env}] "
            f"for facility [{facility_id}]."
        )
        return None, None

    if not os.path.isfile(service_account_path):
        print(
            "❌ TENANT ADMIN SDK INITIALIZATION BLOCKED: "
            f"Service-account file not found for [{facility_id}]: "
            f"{service_account_path}"
        )
        return None, None

    try:
        tenant_credential = credentials.Certificate(
            service_account_path
        )

        credential_project_id = str(
            getattr(
                tenant_credential,
                "project_id",
                ""
            )
            or ""
        ).strip()

        if (
            not credential_project_id
            or credential_project_id != project_id
        ):
            print(
                "❌ TENANT ADMIN SDK INITIALIZATION BLOCKED: "
                f"Service-account project mismatch for [{facility_id}]. "
                f"Expected [{project_id}], "
                f"got [{credential_project_id or 'UNKNOWN'}]."
            )
            return None, None

        try:
            facility_app = firebase_admin.initialize_app(
                tenant_credential,
                name=app_name
            )
        except ValueError:
            facility_app = firebase_admin.get_app(
                app_name
            )

        print(
            "✅ TENANT ADMIN SDK INITIALIZED:",
            {
                "facility_id": facility_id,
                "project_id": project_id,
                "method": "server-service-account",
                "credential_env": service_account_env
            }
        )

        return (
            facility_app,
            firestore.client(
                facility_app
            )
        )

    except Exception as err:
        print(
            "❌ TENANT ADMIN SDK INITIALIZATION FAILED:",
            {
                "facility_id": facility_id,
                "project_id": project_id,
                "credential_env": service_account_env,
                "error": repr(err)
            }
        )

        return None, None

def convert_excel_serial_to_date(val):
    """Safely converts Excel serial integer dates (e.g., 42842 or 32400) or standard date strings to YYYY-MM-DD format."""
    if val is None or val == "" or str(val).strip() in ["---", "NONE", "0", "None", "null"]:
        return ""
    try:
        num_val = float(val)
        if 10000 < num_val < 80000:  # Excel serial range for standard dates
            excel_epoch = datetime(1899, 12, 30)
            converted_date = excel_epoch + timedelta(days=num_val)
            return converted_date.strftime("%Y-%m-%d")
    except (ValueError, TypeError):
        pass
    
    return str(val).strip()

def _build_firestore_rest_fields(doc_dict):
    fields = {}
    for key, val in doc_dict.items():
        if isinstance(val, bool):
            fields[key] = {"booleanValue": val}
        elif isinstance(val, int):
            fields[key] = {"integerValue": str(val)}
        elif isinstance(val, float):
            fields[key] = {"doubleValue": val}
        elif isinstance(val, list):
            array_values = []
            for item in val:
                if isinstance(item, dict):
                    array_values.append({"mapValue": {"fields": _build_firestore_rest_fields(item)}})
                else:
                    array_values.append({"stringValue": str(item)})
            fields[key] = {"arrayValue": {"values": array_values}}
        elif isinstance(val, dict):
            fields[key] = {"mapValue": {"fields": _build_firestore_rest_fields(val)}}
        else:
            fields[key] = {"stringValue": str(val) if val is not None else ""}
    return fields

@app.route('/')
def super_admin_dashboard_root():
    """
    Render the SuperAdmin Control Center only when a valid
    server-side SuperAdmin session exists.

    IMPORTANT:
    The browser navigation to "/" does not carry the Firebase
    Authorization header, so this page route intentionally
    validates the Flask session instead of the Firebase token.

    The session itself is created only after
    /api/superadmin/session successfully verifies:

        Firebase ID token
            ↓
        Mother DB
            ↓
        UID
            ↓
        Email
            ↓
        accountInitialized
            ↓
        SuperAdmin clearance
            ↓
        master facility
    """

    superadmin_uid = session.get(
        "superadmin_uid"
    )

    superadmin_email = session.get(
        "superadmin_email"
    )

    superadmin_clearance = session.get(
        "superadmin_clearance"
    )


    # -----------------------------------------------------
    # No authenticated SuperAdmin Flask session.
    # -----------------------------------------------------

    if not (
        superadmin_uid
        and superadmin_email
        and superadmin_clearance == "SuperAdmin"
    ):

        session.clear()

        return redirect(
            url_for(
                "superadmin_login"
            )
        )


    # -----------------------------------------------------
    # Dashboard is now allowed to receive the Master
    # Firebase client configuration.
    #
    # This is intentional because:
    #
    # 1. The route is already protected.
    # 2. Firebase client configuration is not a secret.
    # 3. The dashboard needs it to initialize Master Auth.
    #
    # It is NOT exposed to normal user pages.
    # -----------------------------------------------------

    return render_template(
        "sadashboard.html",
        firebase_config=DEFAULT_FIREBASE_CONFIG
    )

@app.route('/superadmin-login')
def superadmin_login():

    return render_template(
        'superadmin_login.html',
        firebase_config=DEFAULT_FIREBASE_CONFIG
    )

@app.route(
    "/api/superadmin/session",
    methods=["GET"]
)
def superadmin_session():
    """
    Bootstrap the trusted Flask SuperAdmin session.

    Firebase Authentication proves the browser controls the
    Firebase account.

    Mother DB verification proves that the Firebase account
    is actually the authorized SuperAdmin.

    Only AFTER both checks succeed do we create the Flask
    server-side SuperAdmin session.

    This endpoint intentionally does NOT use @require_superadmin
    because it is the endpoint that establishes the session
    required by protected SuperAdmin page/API flows.
    """

    verification = verify_superadmin_request()


    # -----------------------------------------------------
    # Authorization failed.
    # -----------------------------------------------------

    if not verification.get("success"):

        session.clear()

        return jsonify({
            "success": False,
            "error": verification.get(
                "error",
                "SuperAdmin authorization required."
            )
        }), verification.get(
            "status",
            403
        )


    # -----------------------------------------------------
    # Verified SuperAdmin identity.
    # -----------------------------------------------------

    uid = verification.get(
        "uid"
    )

    email = (
        verification.get(
            "email"
        ) or ""
    ).strip().lower()

    clearance = (
        verification.get(
            "clearancePermission"
        ) or ""
    ).strip()

    facility_id = (
        verification.get(
            "facility_id"
        ) or ""
    ).strip()


    # -----------------------------------------------------
    # Defensive validation.
    #
    # These values should already have been checked by
    # verify_superadmin_request(), but we keep this boundary
    # explicit before creating the server session.
    # -----------------------------------------------------

    if (
        not uid
        or not email
        or clearance != "SuperAdmin"
        or facility_id != "master"
    ):

        session.clear()

        return jsonify({
            "success": False,
            "error": (
                "SuperAdmin session could not be established."
            )
        }), 403


    # -----------------------------------------------------
    # Establish trusted server-side SuperAdmin identity.
    # -----------------------------------------------------

    session.clear()

    session["superadmin_uid"] = uid

    session["superadmin_email"] = email

    session["superadmin_clearance"] = "SuperAdmin"

    # No tenant is selected immediately after login.
    session["active_facility_id"] = None

    # Explicitly mark the session as modified so Flask
    # persists the new authenticated state.
    session.modified = True


    print(
        "🛡️ SUPERADMIN FLASK SESSION ESTABLISHED:",
        {
            "uid": uid,
            "email": email,
            "clearance": "SuperAdmin",
            "facility_id": "master"
        }
    )


    return jsonify({
        "success": True,
        "message": (
            "SuperAdmin identity verified and "
            "server session established."
        ),
        "uid": uid,
        "email": email,
        "clearancePermission": "SuperAdmin",
        "facility_id": "master"
    }), 200

# =========================================================
# SUPERADMIN LOGOUT
# =========================================================



@app.route(
    "/api/firebase-config",
    methods=["GET"]
)
@require_superadmin
def get_firebase_config():
    """
    Return the Master Firebase client configuration to an
    already-authenticated SuperAdmin.

    This endpoint is NOT available to anonymous users or
    normal facility users.
    """

    return jsonify({
        "success": True,
        "facility_id": "master",
        "facility_name": "Master Node",
        "firebase": DEFAULT_FIREBASE_CONFIG
    }), 200

@app.route('/api/superadmin/logout', methods=['POST'])
@require_superadmin
def superadmin_logout():
    try:
        session.clear()

        return jsonify({
            "success": True,
            "message": "SuperAdmin session logged out successfully."
        }), 200

    except Exception:
        return jsonify({
            "success": False,
            "error": "Unable to log out."
        }), 500

@app.route('/api/select-facility', methods=['POST'])
@require_superadmin
def select_facility():
    """
    Select the active facility for the authenticated SuperAdmin session.

    SECURITY:
    - SuperAdmin authorization is required.
    - Facility must be explicitly supplied.
    - 'master' cannot be selected as a tenant facility.
    - Facility must exist in the Mother DB before it is stored
      in the Flask session.
    """

    try:

        # =====================================================
        # MOTHER DB CHECK
        # =====================================================

        if db_admin is None:
            return jsonify({
                "success": False,
                "error": "Central Firebase Admin SDK is not initialized."
            }), 500


        # =====================================================
        # REQUEST DATA
        # =====================================================

        data = request.get_json(
            force=True,
            silent=True
        ) or {}

        facility_id = str(
            data.get("facility_id", "")
        ).strip()


        # =====================================================
        # BASIC VALIDATION
        # =====================================================

        if not facility_id:
            return jsonify({
                "success": False,
                "error": "Facility ID is required."
            }), 400


        if facility_id in [
            "master",
            "NONE SELECTED"
        ]:
            return jsonify({
                "success": False,
                "error": "A valid facility node must be selected."
            }), 400


        # =====================================================
        # VERIFY FACILITY EXISTS
        # =====================================================

        facility_ref = (
            db_admin
            .collection("facilities")
            .document(facility_id)
        )

        facility_snapshot = facility_ref.get()


        if not facility_snapshot.exists:

            print(
                "🚫 FACILITY SELECTION DENIED: "
                f"Unknown facility [{facility_id}]"
            )

            return jsonify({
                "success": False,
                "error": "Facility node does not exist."
            }), 404


        # =====================================================
        # VERIFY FACILITY IS VALID
        # =====================================================

        facility_data = (
            facility_snapshot.to_dict()
            or {}
        )


        facility_name = str(
            facility_data.get(
                "facility_name",
                facility_id
            )
        ).strip()


        if not facility_name:

            print(
                "🚫 FACILITY SELECTION DENIED: "
                f"Facility [{facility_id}] has invalid metadata."
            )

            return jsonify({
                "success": False,
                "error": "Facility node contains invalid configuration."
            }), 500


        # =====================================================
        # STORE SERVER-SIDE FACILITY CONTEXT
        # =====================================================

        session["active_facility_id"] = facility_id


        print(
            "✅ SUPERADMIN FACILITY SELECTED:",
            {
                "facility_id": facility_id,
                "facility_name": facility_name
            }
        )


        # =====================================================
        # SUCCESS
        # =====================================================

        return jsonify({
            "success": True,
            "active_facility_id": facility_id,
            "facility_name": facility_name
        }), 200


    except Exception as e:

        print(
            "❌ Facility Selection Error:",
            repr(e)
        )

        return jsonify({
            "success": False,
            "error": (
                "An internal error occurred while "
                "selecting the facility."
            )
        }), 500

@app.route('/api/facilities', methods=['GET'])
@require_superadmin
def list_facilities():
    """
    Retrieve the registered facility directory for SuperAdmin.

    SECURITY:
    This endpoint intentionally returns only facility metadata.
    Infrastructure credentials such as Firebase configuration and
    Google Apps Script webhook URLs are NOT exposed in the list API.
    """

    try:

        # ---------------------------------------------------------
        # Firebase Admin SDK check
        # ---------------------------------------------------------

        if db_admin is None:

            return jsonify({
                "success": False,
                "error": (
                    "Firebase Admin SDK not initialized. "
                    "Ensure 'serviceAccountKey.json' exists "
                    "in your project folder."
                )
            }), 500


        # ---------------------------------------------------------
        # Read facility registry
        # ---------------------------------------------------------

        facilities_ref = (
            db_admin
            .collection("facilities")
            .stream()
        )


        facilities_list = []


        # ---------------------------------------------------------
        # Build SAFE facility objects
        #
        # IMPORTANT:
        # Do NOT return the entire Firestore document.
        # ---------------------------------------------------------

        for doc in facilities_ref:

            f_data = doc.to_dict() or {}


            facility = {
                "id": doc.id,
                "facility_id": f_data.get(
                    "facility_id",
                    doc.id
                ),
                "facility_name": f_data.get(
                    "facility_name",
                    ""
                ),
                "contact_number": f_data.get(
                    "contact_number",
                    ""
                ),
                "email": f_data.get(
                    "email",
                    ""
                ),
                "address": f_data.get(
                    "address",
                    ""
                ),
                "created_at": f_data.get(
                    "created_at"
                ),
                "updated_at": f_data.get(
                    "updated_at"
                )
            }


            facilities_list.append(
                facility
            )


        # ---------------------------------------------------------
        # SUCCESS
        # ---------------------------------------------------------

        print(
            f"✅ SUPERADMIN FACILITIES LOADED: "
            f"{len(facilities_list)} facility node(s)"
        )


        return jsonify({
            "success": True,
            "facilities": facilities_list
        }), 200


    except Exception as e:

        print(
            "❌ SUPERADMIN FACILITIES LOAD ERROR:",
            str(e)
        )


        return jsonify({
            "success": False,
            "error": "Unable to load facility registry."
        }), 500

@app.route('/api/facilities/<facility_id>', methods=['GET'])
@require_superadmin
def get_facility(facility_id):
    """
    Retrieve safe, explicitly-allowed details for one facility.

    SECURITY:
    - SuperAdmin authentication is required.
    - The endpoint never returns the entire Firestore document.
    - Sensitive infrastructure fields such as Firebase configuration
      and Google Apps Script webhook URLs are intentionally excluded.
    - Only fields required by the SuperAdmin facility-management UI
      are returned.
    """

    try:

        # ---------------------------------------------------------
        # FIREBASE ADMIN SDK CHECK
        # ---------------------------------------------------------

        if db_admin is None:

            return jsonify({
                "success": False,
                "error": "Firebase Admin SDK is not initialized."
            }), 500


        # ---------------------------------------------------------
        # NORMALIZE FACILITY ID
        # ---------------------------------------------------------

        facility_id = str(
            facility_id
        ).strip()


        if not facility_id:

            return jsonify({
                "success": False,
                "error": "Facility ID is required."
            }), 400


        # ---------------------------------------------------------
        # PROTECT MASTER NODE
        # ---------------------------------------------------------

        if facility_id.lower() == "master":

            return jsonify({
                "success": False,
                "error": "The master facility cannot be accessed through this endpoint."
            }), 403


        # ---------------------------------------------------------
        # LOAD FACILITY
        # ---------------------------------------------------------

        facility_ref = (
            db_admin
            .collection("facilities")
            .document(facility_id)
        )


        facility_snapshot = facility_ref.get()


        if not facility_snapshot.exists:

            return jsonify({
                "success": False,
                "error": "Facility node not found."
            }), 404


        f_data = (
            facility_snapshot.to_dict()
            or {}
        )


        # ---------------------------------------------------------
        # SAFE RESPONSE OBJECT
        #
        # IMPORTANT:
        # Never return f_data directly.
        #
        # The SuperAdmin facility-management UI requires the
        # client Firebase configuration and GAS webhook URL.
        # These are NOT server service-account credentials.
        #
        # NEVER return:
        #   - service-account JSON
        #   - private keys
        #   - server credential paths
        #   - any future undocumented fields
        # ---------------------------------------------------------

        facility = {

            "id": facility_snapshot.id,

            "facility_id": f_data.get(
                "facility_id",
                facility_snapshot.id
            ),

            "facility_name": f_data.get(
                "facility_name",
                ""
            ),

            "contact_number": f_data.get(
                "contact_number",
                ""
            ),

            "email": f_data.get(
                "email",
                ""
            ),

            "address": f_data.get(
                "address",
                ""
            ),

            "gas_webhook_url": f_data.get(
                "gas_webhook_url",
                ""
            ),

            "firebase_config": f_data.get(
                "firebase_config",
                {}
            ),

            "created_at": f_data.get(
                "created_at"
            ),

            "updated_at": f_data.get(
                "updated_at"
            )
        }


        # ---------------------------------------------------------
        # SUCCESS
        # ---------------------------------------------------------

        print(
            f"✅ SUPERADMIN FACILITY DETAIL LOADED SAFELY: "
            f"[{facility_snapshot.id}]"
        )


        return jsonify({
            "success": True,
            "facility": facility
        }), 200


    except Exception as e:

        # ---------------------------------------------------------
        # SERVER-SIDE LOGGING ONLY
        # ---------------------------------------------------------

        print(
            "❌ SUPERADMIN FACILITY DETAIL ERROR:",
            str(e)
        )


        # ---------------------------------------------------------
        # CONTROLLED CLIENT RESPONSE
        # ---------------------------------------------------------

        return jsonify({
            "success": False,
            "error": "Unable to load facility details."
        }), 500

@app.route('/api/facilities', methods=['POST'])
@require_superadmin
def create_facility():
    """
    Create a new facility in the Mother DB.

    SECURITY:
    - SuperAdmin + CSRF protection are enforced by @require_superadmin.
    - The master node can never be created/overwritten.
    - Existing facility nodes cannot be silently overwritten.
    - Firebase configuration must be a valid object containing a projectId.
    - Raw backend exceptions are never returned to the client.
    """

    try:

        # =====================================================
        # MOTHER DB CHECK
        # =====================================================

        if db_admin is None:
            return jsonify({
                "success": False,
                "error": "Central Firebase Admin SDK is not initialized."
            }), 500


        # =====================================================
        # REQUEST DATA
        # =====================================================

        data = request.get_json(
            force=True,
            silent=True
        ) or {}


        facility_name = str(
            data.get("facility_name", "")
        ).strip()


        contact_number = str(
            data.get("contact_number", "")
        ).strip()


        email = str(
            data.get("email", "")
        ).strip().lower()


        address = str(
            data.get("address", "")
        ).strip()


        gas_webhook_url = str(
            data.get("gas_webhook_url", "")
        ).strip()


        raw_firebase_config = data.get(
            "firebase_config",
            {}
        )


        # =====================================================
        # BASIC VALIDATION
        # =====================================================

        if not facility_name:
            return jsonify({
                "success": False,
                "error": "Facility name is required."
            }), 400


        if len(facility_name) > 150:
            return jsonify({
                "success": False,
                "error": "Facility name is too long."
            }), 400


        # =====================================================
        # GENERATE SAFE FACILITY ID
        # =====================================================

        facility_id = (
            facility_name
            .lower()
            .strip()
            .replace(" ", "_")
            .replace("/", "_")
        )


        # Remove characters that should never be part
        # of a Firestore facility identifier.
        facility_id = "".join(
            character
            for character in facility_id
            if (
                character.isalnum()
                or character in [
                    "_",
                    "-"
                ]
            )
        )


        facility_id = (
            facility_id
            .strip("_-")
        )


        if not facility_id:
            return jsonify({
                "success": False,
                "error": "Facility name produced an invalid facility ID."
            }), 400


        if len(facility_id) > 100:
            return jsonify({
                "success": False,
                "error": "Generated facility ID is too long."
            }), 400


        if facility_id.lower() == "master":
            return jsonify({
                "success": False,
                "error": "The master facility is reserved."
            }), 400


        # =====================================================
        # FIREBASE CONFIG VALIDATION
        # =====================================================

        if isinstance(
            raw_firebase_config,
            str
        ):

            if not raw_firebase_config.strip():
                return jsonify({
                    "success": False,
                    "error": "Firebase configuration is required."
                }), 400

            try:

                firebase_config = json.loads(
                    raw_firebase_config
                )

            except (TypeError, ValueError):

                return jsonify({
                    "success": False,
                    "error": "Invalid Firebase Config JSON format."
                }), 400

        else:

            firebase_config = raw_firebase_config


        if not isinstance(
            firebase_config,
            dict
        ):

            return jsonify({
                "success": False,
                "error": "Firebase configuration must be a JSON object."
            }), 400


        project_id = str(
            firebase_config.get(
                "projectId",
                ""
            )
        ).strip()


        if not project_id:

            return jsonify({
                "success": False,
                "error": "Firebase configuration must contain projectId."
            }), 400


        # =====================================================
        # PREVENT FACILITY OVERWRITE
        # =====================================================

        facility_ref = (
            db_admin
            .collection("facilities")
            .document(facility_id)
        )


        existing_snapshot = (
            facility_ref.get()
        )


        if existing_snapshot.exists:

            print(
                "🚫 FACILITY CREATION DENIED: "
                f"Facility already exists [{facility_id}]"
            )

            return jsonify({
                "success": False,
                "error": "A facility with this ID already exists."
            }), 409


        # =====================================================
        # FACILITY PAYLOAD
        # =====================================================

        facility_doc_payload = {

            "facility_id":
                facility_id,

            "facility_name":
                facility_name,

            "contact_number":
                contact_number,

            "email":
                email,

            "address":
                address,

            "gas_webhook_url":
                gas_webhook_url,

            "firebase_config":
                firebase_config,

            "created_at":
                firestore.SERVER_TIMESTAMP

        }


        # =====================================================
        # ATOMIC CREATE
        # =====================================================

        # create() fails if another request creates the same
        # facility between our existence check and this write.
        facility_ref.create(
            facility_doc_payload
        )


        print(
            "✅ SUPERADMIN FACILITY CREATED:",
            {
                "facility_id":
                    facility_id,

                "facility_name":
                    facility_name,

                "project_id":
                    project_id
            }
        )


        return jsonify({
            "success": True,
            "facility_id": facility_id,
            "message": "Facility node created successfully."
        }), 201


    except Exception as e:

        # -----------------------------------------------------
        # SERVER LOG ONLY
        # -----------------------------------------------------

        print(
            "❌ SUPERADMIN FACILITY CREATE ERROR:",
            repr(e)
        )


        # -----------------------------------------------------
        # CONTROLLED CLIENT RESPONSE
        # -----------------------------------------------------

        return jsonify({
            "success": False,
            "error": "Unable to create facility node."
        }), 500

@app.route('/api/facilities/<facility_id>/update', methods=['POST'])
@require_superadmin
def update_facility(facility_id):
    """
    Update an existing facility node.

    SECURITY:
    - SuperAdmin + CSRF protection are enforced by @require_superadmin.
    - Facility ID comes from the trusted URL path.
    - Facility ID cannot be changed through the request body.
    - The master node is protected.
    - Firebase configuration is validated before storage.
    - Raw backend exceptions are never returned to the client.
    """

    try:

        # =====================================================
        # MOTHER DB CHECK
        # =====================================================

        if db_admin is None:
            return jsonify({
                "success": False,
                "error": "Central Firebase Admin SDK is not initialized."
            }), 500


        # =====================================================
        # NORMALIZE FACILITY ID
        # =====================================================

        facility_id = str(
            facility_id
        ).strip()


        if not facility_id:
            return jsonify({
                "success": False,
                "error": "Facility ID is required."
            }), 400


        if facility_id.lower() == "master":
            return jsonify({
                "success": False,
                "error": "The master facility cannot be modified."
            }), 403


        # =====================================================
        # VERIFY FACILITY EXISTS
        # =====================================================

        facility_ref = (
            db_admin
            .collection("facilities")
            .document(facility_id)
        )


        facility_snapshot = (
            facility_ref.get()
        )


        if not facility_snapshot.exists:

            print(
                "🚫 FACILITY UPDATE DENIED: "
                f"Unknown facility [{facility_id}]"
            )

            return jsonify({
                "success": False,
                "error": "Facility node not found."
            }), 404


        # =====================================================
        # REQUEST DATA
        # =====================================================

        data = request.get_json(
            force=True,
            silent=True
        ) or {}


        facility_name = str(
            data.get("facility_name", "")
        ).strip()


        contact_number = str(
            data.get("contact_number", "")
        ).strip()


        email = str(
            data.get("email", "")
        ).strip().lower()


        address = str(
            data.get("address", "")
        ).strip()


        gas_webhook_url = str(
            data.get("gas_webhook_url", "")
        ).strip()


        raw_firebase_config = data.get(
            "firebase_config",
            {}
        )


        # =====================================================
        # BASIC VALIDATION
        # =====================================================

        if not facility_name:
            return jsonify({
                "success": False,
                "error": "Facility name is required."
            }), 400


        if len(facility_name) > 150:
            return jsonify({
                "success": False,
                "error": "Facility name is too long."
            }), 400


        # =====================================================
        # FIREBASE CONFIG
        # =====================================================

        firebase_config = None


        if isinstance(
            raw_firebase_config,
            str
        ):

            if raw_firebase_config.strip():

                try:

                    firebase_config = json.loads(
                        raw_firebase_config
                    )

                except (TypeError, ValueError):

                    return jsonify({
                        "success": False,
                        "error": "Invalid Firebase Config JSON format."
                    }), 400

        elif isinstance(
            raw_firebase_config,
            dict
        ):

            if raw_firebase_config:
                firebase_config = raw_firebase_config

        else:

            return jsonify({
                "success": False,
                "error": "Firebase configuration must be a JSON object."
            }), 400


        # =====================================================
        # VALIDATE FIREBASE CONFIG IF SUPPLIED
        # =====================================================

        if firebase_config is not None:

            if not isinstance(
                firebase_config,
                dict
            ):

                return jsonify({
                    "success": False,
                    "error": "Firebase configuration must be a JSON object."
                }), 400


            project_id = str(
                firebase_config.get(
                    "projectId",
                    ""
                )
            ).strip()


            if not project_id:

                return jsonify({
                    "success": False,
                    "error": "Firebase configuration must contain projectId."
                }), 400


        # =====================================================
        # BUILD UPDATE PAYLOAD
        # =====================================================

        update_payload = {

            "facility_name":
                facility_name,

            "contact_number":
                contact_number,

            "email":
                email,

            "address":
                address,

            "gas_webhook_url":
                gas_webhook_url,

            "updated_at":
                firestore.SERVER_TIMESTAMP

        }


        if firebase_config is not None:

            update_payload[
                "firebase_config"
            ] = firebase_config


        # =====================================================
        # UPDATE
        # =====================================================

        facility_ref.update(
            update_payload
        )


        print(
            "✅ SUPERADMIN FACILITY UPDATED:",
            {
                "facility_id":
                    facility_id,

                "facility_name":
                    facility_name
            }
        )


        return jsonify({
            "success": True,
            "message": "Facility updated successfully."
        }), 200


    except Exception as e:

        print(
            "❌ SUPERADMIN FACILITY UPDATE ERROR:",
            repr(e)
        )


        return jsonify({
            "success": False,
            "error": "Unable to update facility node."
        }), 500

@app.route('/api/facilities/<facility_id>/delete', methods=['POST'])
@require_superadmin
def delete_facility(facility_id):
    """
    Remove a facility from the Mother DB registry.

    IMPORTANT:
    This does NOT delete the underlying Firebase tenant project.

    SECURITY:
    - SuperAdmin + CSRF protection are enforced.
    - Master node cannot be deleted.
    - Facility must exist.
    - Deletion is blocked if registered staff still belong
      to the facility.
    - Raw backend exceptions are never returned to the client.
    """

    try:

        # =====================================================
        # MOTHER DB CHECK
        # =====================================================

        if db_admin is None:
            return jsonify({
                "success": False,
                "error": "Central Firebase Admin SDK is not initialized."
            }), 500


        # =====================================================
        # NORMALIZE FACILITY ID
        # =====================================================

        facility_id = str(
            facility_id
        ).strip()


        if not facility_id:
            return jsonify({
                "success": False,
                "error": "Facility ID is required."
            }), 400


        if facility_id.lower() == "master":
            return jsonify({
                "success": False,
                "error": "The master facility cannot be deleted."
            }), 403


        # =====================================================
        # VERIFY FACILITY EXISTS
        # =====================================================

        facility_ref = (
            db_admin
            .collection("facilities")
            .document(facility_id)
        )


        facility_snapshot = (
            facility_ref.get()
        )


        if not facility_snapshot.exists:

            print(
                "🚫 FACILITY DELETE DENIED: "
                f"Unknown facility [{facility_id}]"
            )

            return jsonify({
                "success": False,
                "error": "Facility node not found."
            }), 404


        # =====================================================
        # CHECK FOR REGISTERED USERS
        # =====================================================

        users_query = (
            db_admin
            .collection("authorized_clinical_staff")
            .where(
                "facility_id",
                "==",
                facility_id
            )
            .limit(1)
        )


        existing_user = next(
            users_query.stream(),
            None
        )


        if existing_user is not None:

            print(
                "🚫 FACILITY DELETE BLOCKED: "
                f"Facility [{facility_id}] still has registered staff."
            )

            return jsonify({
                "success": False,
                "error": (
                    "Facility cannot be deleted while registered "
                    "staff accounts are still assigned to it."
                )
            }), 409


        # =====================================================
        # DELETE MOTHER DB REGISTRY NODE
        # =====================================================

        facility_ref.delete()


        # =====================================================
        # CLEAR ACTIVE SESSION CONTEXT
        # =====================================================

        if (
            session.get("active_facility_id")
            == facility_id
        ):

            session.pop(
                "active_facility_id",
                None
            )

            session.modified = True


        print(
            "✅ SUPERADMIN FACILITY REGISTRY DELETED:",
            facility_id
        )


        # =====================================================
        # SUCCESS
        # =====================================================

        return jsonify({
            "success": True,
            "message": "Facility registration removed successfully."
        }), 200


    except Exception as e:

        print(
            "❌ SUPERADMIN FACILITY DELETE ERROR:",
            repr(e)
        )


        return jsonify({
            "success": False,
            "error": "Unable to delete facility node."
        }), 500

def _parse_firestore_rest_fields(fields_dict):
    """Helper to cleanly extract Python primitive types from Firestore REST API JSON fields."""
    parsed = {}
    for key, value_obj in fields_dict.items():
        if "stringValue" in value_obj:
            parsed[key] = value_obj["stringValue"]
        elif "booleanValue" in value_obj:
            parsed[key] = value_obj["booleanValue"]
        elif "integerValue" in value_obj:
            parsed[key] = int(value_obj["integerValue"])
        elif "doubleValue" in value_obj:
            parsed[key] = float(value_obj["doubleValue"])
        else:
            parsed[key] = ""
    return parsed

@app.route('/api/users', methods=['GET'])
@require_superadmin
def list_users():
    """
    Lists users for the authenticated SuperAdmin's active facility.

    SECURITY:
    - SuperAdmin authorization is mandatory.
    - Facility context is controlled by the Flask session.
    - Client-supplied facility_id is NOT trusted.
    - The master node is never queried through this endpoint.
    - Only the minimum staff fields required by the dashboard are returned.
    """

    try:

        # =====================================================
        # 1. FIREBASE MASTER DB CHECK
        # =====================================================

        if db_admin is None:

            return jsonify({
                "success": False,
                "error": "Firebase Admin SDK is unavailable."
            }), 500


        # =====================================================
        # 2. SERVER-CONTROLLED FACILITY CONTEXT
        # =====================================================

        facility_id = (
            session.get("active_facility_id") or ""
        )

        facility_id = str(
            facility_id
        ).strip()


        # =====================================================
        # 3. NEVER ALLOW MASTER / EMPTY TENANT CONTEXT
        # =====================================================

        if not facility_id or facility_id in [
            "master",
            "NONE SELECTED"
        ]:

            return jsonify({
                "success": False,
                "error": (
                    "No facility is currently selected. "
                    "Select a facility before viewing staff users."
                )
            }), 400


        # =====================================================
        # 4. VERIFY FACILITY EXISTS IN MOTHER DB
        # =====================================================

        facility_ref = (
            db_admin
            .collection("facilities")
            .document(facility_id)
        )

        facility_snapshot = facility_ref.get()


        if not facility_snapshot.exists:

            print(
                "🚫 USER REGISTRY DENIED: "
                f"Unknown facility [{facility_id}]"
            )

            return jsonify({
                "success": False,
                "error": "Selected facility does not exist."
            }), 404


        # =====================================================
        # 5. RESOLVE TENANT ADMIN SDK
        # =====================================================

        target_app, target_db = get_facility_admin_sdk(
            facility_id
        )

        if target_app is None or target_db is None:
            print(
                "❌ TENANT USER REGISTRY SDK ERROR:",
                f"Unable to initialize tenant Admin SDK "
                f"for [{facility_id}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "Unable to connect to the selected "
                    "facility staff registry."
                )
            }), 502


        # =====================================================
        # 6. QUERY ONLY THE SELECTED TENANT
        # =====================================================

        documents = []

        for snapshot in (
            target_db
            .collection("authorized_clinical_staff")
            .stream()
        ):
            documents.append({
                "name": snapshot.id,
                "fields": snapshot.to_dict() or {}
            })

        # =====================================================
        # 7. PARSE TENANT STAFF DOCUMENTS
        # =====================================================
        # `documents` already comes directly from the tenant
        # Admin SDK stream above. Do NOT call response.json();
        # there is no REST response in this Admin SDK path.

        users_list = []


        for document in documents:

            raw_fields = (
                document
                .get("fields", {})
            )


            parsed_data = (
                raw_fields
                if isinstance(raw_fields, dict)
                else {}
            )


            document_name = (
                document
                .get("name", "")
                .split("/")
                [-1]
            )


            # -------------------------------------------------
            # SECURITY: Ignore malformed records
            # -------------------------------------------------

            user_uid = str(
                parsed_data
                .get("uid", "")
            ).strip()

            user_email = str(
                parsed_data
                .get(
                    "email",
                    document_name
                )
            ).strip().lower()


            if not user_uid or not user_email:

                continue


            # -------------------------------------------------
            # SECURITY: Tenant identity must agree
            # -------------------------------------------------

            profile_facility_id = str(
                parsed_data
                .get(
                    "facility_id",
                    ""
                )
            ).strip()


            if profile_facility_id != facility_id:

                print(
                    "⚠️ TENANT USER SKIPPED: "
                    f"Profile facility mismatch "
                    f"[{user_email}] → "
                    f"[{profile_facility_id}] "
                    f"expected [{facility_id}]"
                )

                continue


            # -------------------------------------------------
            # SAFE RESPONSE OBJECT
            # -------------------------------------------------

            users_list.append({

                "email":
                    user_email,

                "uid":
                    user_uid,

                "lastNameFirstName":
                    parsed_data.get(
                        "lastNameFirstName",
                        ""
                    ),

                "bday":
                    parsed_data.get(
                        "bday",
                        ""
                    ),

                "positionRole":
                    parsed_data.get(
                        "positionRole",
                        "Staff"
                    ),

                "clearancePermission":
                    parsed_data.get(
                        "clearancePermission",
                        "Viewer"
                    ),

                "facility_id":
                    facility_id
            })


        # =====================================================
        # 8. SUCCESS
        # =====================================================

        print(
            "✅ SUPERADMIN USER REGISTRY LOADED:",
            {
                "facility_id": facility_id,
                "user_count": len(users_list)
            }
        )


        return jsonify({
            "success": True,
            "facility_id": facility_id,
            "users": users_list
        }), 200


    except requests.RequestException as request_error:

        print(
            "❌ USER REGISTRY NETWORK ERROR:",
            repr(request_error)
        )

        return jsonify({
            "success": False,
            "error": (
                "Unable to connect to the facility "
                "user registry."
            )
        }), 502


    except Exception as e:

        print(
            "❌ LIST USERS INTERNAL ERROR:",
            repr(e)
        )

        return jsonify({
            "success": False,
            "error": (
                "Unable to load the facility "
                "staff registry."
            )
        }), 500

@app.route('/api/provision-user', methods=['POST'])
@require_superadmin
def provision_user():
    """
    Provision a staff account inside a specific facility tenant.

    SECURITY:
    - SuperAdmin authorization is required.
    - Only Viewer, Editor, and Admin may be assigned.
    - SuperAdmin accounts cannot be created through this endpoint.
    - Target facility must exist in the Mother Database.
    - Firebase Auth and tenant Firestore creation must both succeed.
    - Mother DB indexing is required for successful provisioning.
    """

    try:

        # =====================================================
        # REQUEST DATA
        # =====================================================

        data = request.get_json(
            force=True,
            silent=True
        ) or {}

        name = str(
            data.get("name", "")
        ).strip()

        bday = str(
            data.get("bday", "")
        ).strip()

        email = str(
            data.get("email", "")
        ).strip().lower()

        password = data.get("password")

        position = str(
            data.get("position", "Staff")
        ).strip()

        permission = str(
            data.get("permission", "Viewer")
        ).strip()

        facility_id = str(
            get_active_facility_id() or ""
        ).strip()
        print(
            "🛡️ SUPERADMIN PROVISION ACTIVE FACILITY:",
            facility_id
            )


        # =====================================================
        # BASIC VALIDATION
        # =====================================================

        if not email:
            return jsonify({
                "success": False,
                "error": "Email address is required."
            }), 400


        if not password or not isinstance(password, str):
            return jsonify({
                "success": False,
                "error": "Password is required."
            }), 400


        if len(password) < 6:
            return jsonify({
                "success": False,
                "error": "Password must contain at least 6 characters."
            }), 400


        if not facility_id:
            return jsonify({
                "success": False,
                "error": "Target facility is required."
            }), 400


        if facility_id in [
            "master",
            "NONE SELECTED"
        ]:
            return jsonify({
                "success": False,
                "error": "A valid facility node must be selected."
            }), 400


        # =====================================================
        # EMAIL VALIDATION
        # =====================================================

        if (
            "@" not in email
            or "." not in email.split("@")[-1]
            or " " in email
        ):
            return jsonify({
                "success": False,
                "error": "Please provide a valid email address."
            }), 400


        # =====================================================
        # ROLE / CLEARANCE VALIDATION
        #
        # SuperAdmin MUST NEVER be created through the
        # ordinary facility-user provisioning endpoint.
        # =====================================================

        allowed_permissions = {
            "Viewer",
            "Editor",
            "Admin"
        }

        if permission not in allowed_permissions:

            print(
                "🚫 USER PROVISION DENIED: "
                f"Invalid clearance [{permission}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "Invalid user permission. "
                    "Allowed permissions are Viewer, Editor, or Admin."
                )
            }), 400


        # =====================================================
        # FACILITY VALIDATION
        #
        # NEVER provision into a facility that does not exist
        # in the Mother Database.
        # =====================================================

        if db_admin is None:
            return jsonify({
                "success": False,
                "error": "Central Firebase Admin SDK is not initialized."
            }), 500


        facility_ref = (
            db_admin
            .collection("facilities")
            .document(facility_id)
        )

        facility_snapshot = facility_ref.get()


        if not facility_snapshot.exists:

            print(
                "🚫 USER PROVISION DENIED: "
                f"Facility [{facility_id}] does not exist."
            )

            return jsonify({
                "success": False,
                "error": "Target facility node does not exist."
            }), 404


        facility_settings = (
            facility_snapshot.to_dict()
            or {}
        )


        # =====================================================
        # FIREBASE TENANT CONFIGURATION
        # =====================================================

        f_config = (
            facility_settings.get(
                "firebase_config",
                {}
            )
        )


        if not isinstance(f_config, dict):
            return jsonify({
                "success": False,
                "error": "Target facility Firebase configuration is invalid."
            }), 500


        project_id = str(
            f_config.get("projectId", "")
        ).strip()


        if not project_id:

            print(
                "🚫 USER PROVISION DENIED: "
                f"Facility [{facility_id}] has incomplete Firebase configuration."
            )

            return jsonify({
                "success": False,
                "error": (
                    "Target facility Firebase configuration "
                    "is incomplete."
                )
            }), 500


        # =====================================================
        # CHECK MOTHER DB FOR EXISTING CENTRAL USER
        #
        # This prevents accidentally overwriting the central
        # identity record for an existing account.
        # =====================================================

        central_user_ref = (
            db_admin
            .collection("authorized_clinical_staff")
            .document(email)
        )

        central_user_snapshot = (
            central_user_ref.get()
        )


        if central_user_snapshot.exists:

            existing_user = (
                central_user_snapshot.to_dict()
                or {}
            )

            existing_facility = str(
                existing_user.get(
                    "facility_id",
                    ""
                )
            ).strip()


            print(
                "🚫 USER PROVISION DENIED: "
                f"Central account already exists [{email}] "
                f"→ [{existing_facility}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "This email is already registered "
                    "in the central user directory."
                )
            }), 409


        # =====================================================
        # RESOLVE TENANT ADMIN SDK
        # =====================================================

        target_app, target_db = get_facility_admin_sdk(
            facility_id
        )

        if target_app is None or target_db is None:
            return jsonify({
                "success": False,
                "error": (
                    "Unable to connect to the target "
                    "facility Firebase project."
                )
            }), 502


        # =====================================================
        # CREATE FIREBASE AUTH ACCOUNT
        # =====================================================

        try:
            tenant_user = firebase_admin.auth.create_user(
                email=email,
                password=password,
                display_name=name,
                app=target_app
            )

        except firebase_admin.auth.EmailAlreadyExistsError:
            return jsonify({
                "success": False,
                "error": (
                    "Email already exists in "
                    "the target facility."
                )
            }), 409

        except Exception as auth_error:
            print(
                "❌ TARGET FIREBASE AUTH PROVISION FAILED:",
                repr(auth_error)
            )

            return jsonify({
                "success": False,
                "error": "Unable to create the facility user account."
            }), 400


        facility_user_uid = str(
            tenant_user.uid
        ).strip()

        if not facility_user_uid:
            print(
                "❌ TARGET FIREBASE AUTH ERROR: "
                "Missing UID from created account."
            )

            return jsonify({
                "success": False,
                "error": (
                    "Facility account creation returned "
                    "an incomplete authentication response."
                )
            }), 500


        # =====================================================
        # CREATE TENANT STAFF PROFILE
        # =====================================================

        staff_profile = {
            "uid": facility_user_uid,
            "email": email,
            "lastNameFirstName": name,
            "bday": bday,
            "positionRole": position,
            "clearancePermission": permission,
            "facility_id": facility_id,
            "accountInitialized": True,
            "assignedSignature": (
                f"USER-{facility_user_uid[:6].upper()}"
            )
        }

        try:
            (
                target_db
                .collection("authorized_clinical_staff")
                .document(email)
                .set(staff_profile)
            )

        except Exception as firestore_error:
            print(
                "❌ TARGET FIRESTORE PROVISION FAILED:",
                repr(firestore_error)
            )

            # Roll back the tenant Auth account so a failed
            # profile write cannot leave an orphaned login.
            try:
                firebase_admin.auth.delete_user(
                    facility_user_uid,
                    app=target_app
                )
                print(
                    "✅ TENANT AUTH ROLLBACK COMPLETED:",
                    facility_user_uid
                )
            except Exception as rollback_error:
                print(
                    "❌ TENANT AUTH ROLLBACK FAILED:",
                    repr(rollback_error)
                )

            return jsonify({
                "success": False,
                "error": (
                    "Facility staff profile creation failed. "
                    "The authentication account was rolled back."
                )
            }), 500


        # =====================================================
        # CREATE MOTHER DB CENTRAL INDEX
        # =====================================================

        try:

            central_user_ref.set({
                "uid": facility_user_uid,
                "email": email,
                "lastNameFirstName": name,
                "positionRole": position,
                "clearancePermission": permission,
                "facility_id": facility_id,
                "accountInitialized": True
            })


        except Exception as mother_error:

            print(
                "❌ MOTHER DB INDEX CREATION FAILED:",
                repr(mother_error)
            )


            # Do NOT report success because login discovery
            # depends on the Mother DB record.
            #
            # Roll back the tenant profile and Auth account so
            # a failed central index does not leave a partially
            # provisioned facility user.

            try:
                (
                    target_db
                    .collection("authorized_clinical_staff")
                    .document(email)
                    .delete()
                )
            except Exception as profile_rollback_error:
                print(
                    "❌ TENANT PROFILE ROLLBACK FAILED:",
                    repr(profile_rollback_error)
                )

            try:
                firebase_admin.auth.delete_user(
                    facility_user_uid,
                    app=target_app
                )
            except Exception as auth_rollback_error:
                print(
                    "❌ TENANT AUTH ROLLBACK FAILED:",
                    repr(auth_rollback_error)
                )

            return jsonify({
                "success": False,
                "error": (
                    "Facility account was created, "
                    "but central authorization indexing failed. "
                    "The tenant account was rolled back."
                )
            }), 500


        # =====================================================
        # SUCCESS
        # =====================================================

        print(
            "✅ SUPERADMIN USER PROVISIONED:",
            {
                "email": email,
                "uid": facility_user_uid,
                "facility_id": facility_id,
                "permission": permission
            }
        )


        return jsonify({
            "success": True,
            "uid": facility_user_uid,
            "message": (
                f"Staff account successfully provisioned "
                f"in facility [{facility_id}]."
            )
        }), 201


    except Exception as e:

        # IMPORTANT:
        # Never expose raw internal exceptions to the browser.

        print(
            "❌ Provision User Error:",
            repr(e)
        )


        return jsonify({
            "success": False,
            "error": (
                "An internal error occurred while "
                "provisioning the staff account."
            )
        }), 500

@app.route('/api/update-user', methods=['POST'])
@require_superadmin
def update_user():
    """
    Update a facility staff account.

    SECURITY:
    - SuperAdmin authorization is required.
    - Target facility must exist.
    - Existing user must belong to the specified facility.
    - UID and old email must match the existing tenant profile.
    - Only Viewer, Editor, and Admin may be assigned.
    - SuperAdmin cannot be assigned through this endpoint.
    - Firebase Auth, tenant Firestore, and Mother DB must remain
      synchronized.
    """

    try:

        # =====================================================
        # REQUEST DATA
        # =====================================================

        data = request.get_json(
            force=True,
            silent=True
        ) or {}

        uid = str(
            data.get("uid", "")
        ).strip()

        old_email = str(
            data.get("old_email", "")
        ).strip().lower()

        new_email = str(
            data.get("new_email", "")
        ).strip().lower()

        name = str(
            data.get("name", "")
        ).strip()

        position = str(
            data.get("position", "Staff")
        ).strip()

        permission = str(
            data.get("permission", "Viewer")
        ).strip()

        facility_id = str(
            get_active_facility_id() or ""
        ).strip()
        print(
             "🛡️ SUPERADMIN UPDATE ACTIVE FACILITY:",
                 facility_id
        )


        # =====================================================
        # BASIC VALIDATION
        # =====================================================

        if not uid:
            return jsonify({
                "success": False,
                "error": "User UID is required."
            }), 400

        if not old_email or not new_email:
            return jsonify({
                "success": False,
                "error": "Current and new email addresses are required."
            }), 400

        if (
            "@" not in old_email
            or "." not in old_email.split("@")[-1]
            or " " in old_email
        ):
            return jsonify({
                "success": False,
                "error": "Current email address is invalid."
            }), 400

        if (
            "@" not in new_email
            or "." not in new_email.split("@")[-1]
            or " " in new_email
        ):
            return jsonify({
                "success": False,
                "error": "New email address is invalid."
            }), 400

        if not facility_id:
            return jsonify({
                "success": False,
                "error": "Target facility is required."
            }), 400

        if facility_id in [
            "master",
            "NONE SELECTED"
        ]:
            return jsonify({
                "success": False,
                "error": "A valid facility node must be selected."
            }), 400


        # =====================================================
        # ROLE VALIDATION
        # =====================================================

        allowed_permissions = {
            "Viewer",
            "Editor",
            "Admin"
        }

        if permission not in allowed_permissions:

            print(
                "🚫 USER UPDATE DENIED: "
                f"Invalid clearance [{permission}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "Invalid user permission. "
                    "Allowed permissions are Viewer, Editor, or Admin."
                )
            }), 400


        # =====================================================
        # MOTHER DB MUST BE AVAILABLE
        # =====================================================

        if db_admin is None:
            return jsonify({
                "success": False,
                "error": "Central Firebase Admin SDK is not initialized."
            }), 500


        # =====================================================
        # VALIDATE FACILITY
        # =====================================================

        facility_ref = (
            db_admin
            .collection("facilities")
            .document(facility_id)
        )

        facility_snapshot = facility_ref.get()

        if not facility_snapshot.exists:

            print(
                "🚫 USER UPDATE DENIED: "
                f"Facility [{facility_id}] does not exist."
            )

            return jsonify({
                "success": False,
                "error": "Target facility node does not exist."
            }), 404


        facility_settings = (
            facility_snapshot.to_dict()
            or {}
        )


        # =====================================================
        # LOAD TARGET FACILITY ADMIN SDK
        # =====================================================

        target_app, target_db = get_facility_admin_sdk(
            facility_id
        )

        if target_app is None or target_db is None:

            print(
                "❌ USER UPDATE FAILED: "
                f"Unable to initialize facility SDK [{facility_id}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "Unable to connect to the target facility database."
                )
            }), 500


        # =====================================================
        # LOAD EXISTING TENANT USER PROFILE
        # =====================================================

        old_user_ref = (
            target_db
            .collection("authorized_clinical_staff")
            .document(old_email)
        )

        old_user_snapshot = old_user_ref.get()


        if not old_user_snapshot.exists:

            print(
                "🚫 USER UPDATE DENIED: "
                f"Tenant profile not found [{old_email}] "
                f"in [{facility_id}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "The existing user profile was not found "
                    "in the target facility."
                )
            }), 404


        existing_user = (
            old_user_snapshot.to_dict()
            or {}
        )


        # =====================================================
        # VERIFY EXISTING USER IDENTITY
        #
        # Never allow the caller to say:
        # "Here is UID X, update email Y"
        #
        # We verify the existing tenant document first.
        # =====================================================

        existing_uid = str(
            existing_user.get("uid", "")
        ).strip()

        existing_email = str(
            existing_user.get("email", old_email)
        ).strip().lower()

        existing_facility = str(
            existing_user.get("facility_id", "")
        ).strip()


        if existing_uid != uid:

            print(
                "🚫 USER UPDATE DENIED: "
                f"UID mismatch for [{old_email}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "The supplied UID does not match "
                    "the existing facility account."
                )
            }), 403


        if existing_email != old_email:

            print(
                "🚫 USER UPDATE DENIED: "
                f"Email mismatch for [{old_email}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "The supplied email does not match "
                    "the existing facility account."
                )
            }), 403


        if existing_facility != facility_id:

            print(
                "🚫 USER UPDATE DENIED: "
                f"Facility mismatch for [{old_email}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "The user does not belong "
                    "to the selected facility."
                )
            }), 403


        # =====================================================
        # PROTECT SUPERADMIN
        #
        # Even if somebody manually sends a SuperAdmin-style
        # record through this endpoint, do not allow it.
        # =====================================================

        existing_permission = str(
            existing_user.get(
                "clearancePermission",
                "Viewer"
            )
        ).strip()


        if existing_permission == "SuperAdmin":

            print(
                "🚫 USER UPDATE DENIED: "
                f"Attempt to modify SuperAdmin [{old_email}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "SuperAdmin accounts cannot be modified "
                    "through facility user management."
                )
            }), 403


        # =====================================================
        # CHECK NEW EMAIL COLLISION
        # =====================================================

        if new_email != old_email:

            new_user_ref = (
                target_db
                .collection("authorized_clinical_staff")
                .document(new_email)
            )

            new_user_snapshot = new_user_ref.get()

            if new_user_snapshot.exists:

                print(
                    "🚫 USER UPDATE DENIED: "
                    f"Email already exists [{new_email}]"
                )

                return jsonify({
                    "success": False,
                    "error": (
                        "The new email address is already "
                        "registered in this facility."
                    )
                }), 409


        # =====================================================
        # UPDATE FIREBASE AUTH
        # =====================================================

        try:

            target_auth = auth.Client(
                target_app
            )

            auth_update_kwargs = {
                "display_name": name
            }

            if new_email != old_email:
                auth_update_kwargs["email"] = new_email


            target_auth.update_user(
                uid,
                **auth_update_kwargs
            )


        except Exception as auth_error:

            print(
                "❌ TARGET AUTH UPDATE FAILED:",
                repr(auth_error)
            )

            return jsonify({
                "success": False,
                "error": (
                    "Unable to update the facility "
                    "authentication account."
                )
            }), 500


        # =====================================================
        # PREPARE NEW TENANT PROFILE
        # =====================================================

        updated_user_data = {
            "uid": uid,
            "email": new_email,
            "lastNameFirstName": name,
            "positionRole": position,
            "clearancePermission": permission,
            "facility_id": facility_id,
            "accountInitialized": True,
            "assignedSignature": (
                f"USER-{uid[:6].upper()}"
            )
        }


        # =====================================================
        # UPDATE TENANT FIRESTORE
        # =====================================================

        try:

            if new_email != old_email:

                old_user_ref.delete()

                target_db.collection(
                    "authorized_clinical_staff"
                ).document(
                    new_email
                ).set(
                    updated_user_data
                )

            else:

                old_user_ref.update(
                    updated_user_data
                )


        except Exception as firestore_error:

            print(
                "❌ TARGET FIRESTORE UPDATE FAILED:",
                repr(firestore_error)
            )

            return jsonify({
                "success": False,
                "error": (
                    "Authentication was updated, but the "
                    "facility staff profile could not be synchronized."
                )
            }), 500


        # =====================================================
        # UPDATE MOTHER DB INDEX
        # =====================================================

        try:

            mother_user_ref_old = (
                db_admin
                .collection("authorized_clinical_staff")
                .document(old_email)
            )


            mother_user_ref_new = (
                db_admin
                .collection("authorized_clinical_staff")
                .document(new_email)
            )


            mother_user_snapshot = (
                mother_user_ref_old.get()
            )


            if not mother_user_snapshot.exists:

                print(
                    "❌ MOTHER DB UPDATE FAILED: "
                    f"Central profile missing [{old_email}]"
                )

                return jsonify({
                    "success": False,
                    "error": (
                        "Facility account was updated, "
                        "but its central authorization profile "
                        "was not found."
                    )
                }), 500


            mother_existing = (
                mother_user_snapshot.to_dict()
                or {}
            )


            mother_uid = str(
                mother_existing.get("uid", "")
            ).strip()

            mother_facility = str(
                mother_existing.get(
                    "facility_id",
                    ""
                )
            ).strip()


            if mother_uid != uid:

                print(
                    "❌ MOTHER DB UPDATE DENIED: "
                    f"UID mismatch [{old_email}]"
                )

                return jsonify({
                    "success": False,
                    "error": (
                        "Central authorization identity "
                        "verification failed."
                    )
                }), 500


            if mother_facility != facility_id:

                print(
                    "❌ MOTHER DB UPDATE DENIED: "
                    f"Facility mismatch [{old_email}]"
                )

                return jsonify({
                    "success": False,
                    "error": (
                        "Central authorization facility "
                        "verification failed."
                    )
                }), 500


            mother_updated_data = {
                "uid": uid,
                "email": new_email,
                "lastNameFirstName": name,
                "positionRole": position,
                "clearancePermission": permission,
                "facility_id": facility_id,
                "accountInitialized": True
            }


            if new_email != old_email:

                mother_user_ref_old.delete()

                mother_user_ref_new.set(
                    mother_updated_data
                )

            else:

                mother_user_ref_old.update(
                    mother_updated_data
                )


        except Exception as mother_error:

            print(
                "❌ MOTHER DB UPDATE FAILED:",
                repr(mother_error)
            )

            return jsonify({
                "success": False,
                "error": (
                    "Facility account was updated, "
                    "but the central authorization index "
                    "could not be synchronized."
                )
            }), 500


        # =====================================================
        # SUCCESS
        # =====================================================

        print(
            "✅ SUPERADMIN USER UPDATED:",
            {
                "uid": uid,
                "old_email": old_email,
                "new_email": new_email,
                "facility_id": facility_id,
                "permission": permission
            }
        )


        return jsonify({
            "success": True,
            "message": (
                "Staff account successfully updated "
                "across the facility and central registry."
            )
        }), 200


    except Exception as e:

        print(
            "❌ Update User Error:",
            repr(e)
        )

        return jsonify({
            "success": False,
            "error": (
                "An internal error occurred while "
                "updating the staff account."
            )
        }), 500

@app.route('/api/reset-user-password', methods=['POST'])
@require_superadmin
def reset_user_password():
    """
    Reset the password of a facility staff account.

    SECURITY:
    - SuperAdmin authentication is mandatory.
    - CSRF protection is enforced by @require_superadmin.
    - Facility context comes ONLY from the server-side Flask session.
    - The client cannot choose another facility.
    - The target user must exist in the selected tenant.
    - UID, email, and facility_id must agree.
    - SuperAdmin accounts cannot be targeted.
    - Password is never logged or returned.
    """

    try:

        # =====================================================
        # 1. MOTHER DB MUST BE AVAILABLE
        # =====================================================

        if db_admin is None:

            return jsonify({
                "success": False,
                "error": (
                    "Central Firebase Admin SDK "
                    "is not initialized."
                )
            }), 500


        # =====================================================
        # 2. REQUEST DATA
        # =====================================================

        data = request.get_json(
            force=True,
            silent=True
        ) or {}


        uid = str(
            data.get("uid", "")
        ).strip()

        new_password = data.get(
            "new_password"
        )


        # =====================================================
        # 3. BASIC INPUT VALIDATION
        # =====================================================

        if not uid:

            return jsonify({
                "success": False,
                "error": "User UID is required."
            }), 400


        if not isinstance(
            new_password,
            str
        ):

            return jsonify({
                "success": False,
                "error": "A valid new password is required."
            }), 400


        new_password = new_password.strip()


        if len(new_password) < 6:

            return jsonify({
                "success": False,
                "error": (
                    "Password must contain "
                    "at least 6 characters."
                )
            }), 400


        # =====================================================
        # 4. SERVER-CONTROLLED FACILITY CONTEXT
        #
        # NEVER accept facility_id from the request body,
        # query string, or client-controlled header.
        # =====================================================

        facility_id = str(
            session.get(
                "active_facility_id",
                ""
            )
        ).strip()


        if not facility_id:

            return jsonify({
                "success": False,
                "error": (
                    "No facility is currently selected."
                )
            }), 400


        if facility_id in {
            "master",
            "NONE SELECTED"
        }:

            return jsonify({
                "success": False,
                "error": (
                    "A valid facility must be selected "
                    "before resetting a staff password."
                )
            }), 400


        # =====================================================
        # 5. VERIFY FACILITY EXISTS
        # =====================================================

        facility_ref = (
            db_admin
            .collection("facilities")
            .document(facility_id)
        )


        facility_snapshot = (
            facility_ref.get()
        )


        if not facility_snapshot.exists:

            print(
                "🚫 PASSWORD RESET DENIED: "
                f"Unknown facility [{facility_id}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "Selected facility "
                    "does not exist."
                )
            }), 404


        # =====================================================
        # 6. LOAD TARGET FACILITY ADMIN SDK
        # =====================================================

        target_app, target_db = (
            get_facility_admin_sdk(
                facility_id
            )
        )


        if (
            target_app is None
            or target_db is None
        ):

            print(
                "❌ PASSWORD RESET FAILED: "
                f"Unable to initialize tenant SDK "
                f"[{facility_id}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "Unable to connect to the "
                    "selected facility database."
                )
            }), 500


        # =====================================================
        # 7. FIND USER BY UID
        #
        # The browser supplies the UID only as a target
        # identifier. We DO NOT trust it by itself.
        #
        # We locate the actual tenant profile and verify
        # that its stored UID matches.
        # =====================================================

        staff_collection = (
            target_db
            .collection(
                "authorized_clinical_staff"
            )
        )


        staff_query = (
            staff_collection
            .where(
                "uid",
                "==",
                uid
            )
            .limit(1)
            .stream()
        )


        staff_docs = list(
            staff_query
        )


        if not staff_docs:

            print(
                "🚫 PASSWORD RESET DENIED: "
                f"Tenant user not found "
                f"[{uid}] in [{facility_id}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "The selected staff account "
                    "was not found in this facility."
                )
            }), 404


        staff_doc = staff_docs[0]


        staff_data = (
            staff_doc.to_dict()
            or {}
        )


        # =====================================================
        # 8. VERIFY TENANT UID
        # =====================================================

        stored_uid = str(
            staff_data.get(
                "uid",
                ""
            )
        ).strip()


        if stored_uid != uid:

            print(
                "🚨 PASSWORD RESET BLOCKED: "
                "Tenant UID mismatch"
            )

            return jsonify({
                "success": False,
                "error": (
                    "Staff account identity "
                    "verification failed."
                )
            }), 403


        # =====================================================
        # 9. VERIFY TENANT EMAIL
        # =====================================================

        staff_email = str(
            staff_data.get(
                "email",
                staff_doc.id
            )
        ).strip().lower()


        document_email = (
            str(
                staff_doc.id
            )
            .strip()
            .lower()
        )


        if not staff_email:

            print(
                "🚨 PASSWORD RESET BLOCKED: "
                f"Missing staff email [{uid}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "Staff account identity "
                    "is incomplete."
                )
            }), 403


        if staff_email != document_email:

            print(
                "🚨 PASSWORD RESET BLOCKED: "
                "Tenant document/email mismatch"
            )

            return jsonify({
                "success": False,
                "error": (
                    "Staff account identity "
                    "verification failed."
                )
            }), 403


        # =====================================================
        # 10. VERIFY FACILITY OWNERSHIP
        # =====================================================

        staff_facility = str(
            staff_data.get(
                "facility_id",
                ""
            )
        ).strip()


        if staff_facility != facility_id:

            print(
                "🚨 PASSWORD RESET BLOCKED: "
                "Facility mismatch"
            )

            return jsonify({
                "success": False,
                "error": (
                    "The staff account does not "
                    "belong to the selected facility."
                )
            }), 403


        # =====================================================
        # 11. VERIFY ACCOUNT INITIALIZATION
        # =====================================================

        if (
            staff_data.get(
                "accountInitialized"
            )
            is not True
        ):

            print(
                "🚫 PASSWORD RESET DENIED: "
                "Account is not initialized"
            )

            return jsonify({
                "success": False,
                "error": (
                    "The staff account "
                    "is not initialized."
                )
            }), 403


        # =====================================================
        # 12. NEVER RESET A SUPERADMIN ACCOUNT
        # =====================================================

        clearance = str(
            staff_data.get(
                "clearancePermission",
                ""
            )
        ).strip()


        if clearance == "SuperAdmin":

            print(
                "🚨 PASSWORD RESET BLOCKED: "
                f"SuperAdmin target [{staff_email}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "SuperAdmin accounts cannot "
                    "be modified through facility "
                    "user management."
                )
            }), 403


        # =====================================================
        # 13. UPDATE FIREBASE AUTH PASSWORD
        # =====================================================

        try:

            target_auth = auth.Client(
                target_app
            )


            target_auth.update_user(
                uid,
                password=new_password
            )


        except Exception as auth_error:

            print(
                "❌ TARGET AUTH PASSWORD RESET FAILED:",
                repr(auth_error)
            )

            return jsonify({
                "success": False,
                "error": (
                    "Unable to reset the "
                    "facility user's password."
                )
            }), 500


        # =====================================================
        # 14. SUCCESS
        #
        # IMPORTANT:
        # Never return the password.
        # Never log the password.
        # =====================================================

        print(
            "✅ SUPERADMIN PASSWORD RESET:",
            {
                "uid": uid,
                "email": staff_email,
                "facility_id": facility_id
            }
        )


        return jsonify({
            "success": True,
            "message": (
                "Staff member password "
                "reset successfully."
            )
        }), 200


    except Exception as e:

        # =====================================================
        # 15. CONTROLLED INTERNAL ERROR
        # =====================================================

        print(
            "❌ RESET USER PASSWORD INTERNAL ERROR:",
            repr(e)
        )


        return jsonify({
            "success": False,
            "error": (
                "An internal error occurred "
                "while resetting the password."
            )
        }), 500

@app.route('/api/delete-user', methods=['POST'])
@require_superadmin
def delete_user():
    """
    Delete a facility staff account.

    SECURITY:
    - SuperAdmin authorization is required.
    - Target facility must exist.
    - Existing user must belong to the specified facility.
    - UID and email must match the existing tenant profile.
    - SuperAdmin accounts cannot be deleted through this endpoint.
    - Firebase Auth, tenant Firestore, and Mother DB must be
      cleaned up before reporting success.
    """

    try:

        # =====================================================
        # REQUEST DATA
        # =====================================================

        data = request.get_json(
            force=True,
            silent=True
        ) or {}

        uid = str(
            data.get("uid", "")
        ).strip()

        email = str(
            data.get("email", "")
        ).strip().lower()

        facility_id = str(
            get_active_facility_id() or ""
        ).strip()
        print(
            "🛡️ SUPERADMIN DELETE ACTIVE FACILITY:",
            facility_id
        )


        # =====================================================
        # BASIC VALIDATION
        # =====================================================

        if not uid:
            return jsonify({
                "success": False,
                "error": "User UID is required."
            }), 400


        if not email:
            return jsonify({
                "success": False,
                "error": "User email is required."
            }), 400


        if (
            "@" not in email
            or "." not in email.split("@")[-1]
            or " " in email
        ):
            return jsonify({
                "success": False,
                "error": "Invalid user email address."
            }), 400


        if not facility_id:
            return jsonify({
                "success": False,
                "error": "Target facility is required."
            }), 400


        if facility_id in [
            "master",
            "NONE SELECTED"
        ]:
            return jsonify({
                "success": False,
                "error": "A valid facility node must be selected."
            }), 400


        # =====================================================
        # MOTHER DB MUST BE AVAILABLE
        # =====================================================

        if db_admin is None:
            return jsonify({
                "success": False,
                "error": "Central Firebase Admin SDK is not initialized."
            }), 500


        # =====================================================
        # VALIDATE FACILITY
        # =====================================================

        facility_ref = (
            db_admin
            .collection("facilities")
            .document(facility_id)
        )

        facility_snapshot = facility_ref.get()


        if not facility_snapshot.exists:

            print(
                "🚫 USER DELETE DENIED: "
                f"Facility [{facility_id}] does not exist."
            )

            return jsonify({
                "success": False,
                "error": "Target facility node does not exist."
            }), 404


        # =====================================================
        # LOAD TARGET FACILITY FIREBASE
        # =====================================================

        target_app, target_db = get_facility_admin_sdk(
            facility_id
        )


        if target_app is None or target_db is None:

            print(
                "❌ USER DELETE FAILED: "
                f"Unable to initialize facility SDK [{facility_id}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "Unable to connect to the target facility database."
                )
            }), 500


        # =====================================================
        # LOAD EXISTING TENANT USER PROFILE
        # =====================================================

        user_ref = (
            target_db
            .collection("authorized_clinical_staff")
            .document(email)
        )

        user_snapshot = user_ref.get()


        if not user_snapshot.exists:

            print(
                "🚫 USER DELETE DENIED: "
                f"Tenant profile not found [{email}] "
                f"in [{facility_id}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "The user profile was not found "
                    "in the target facility."
                )
            }), 404


        existing_user = (
            user_snapshot.to_dict()
            or {}
        )


        # =====================================================
        # VERIFY TENANT IDENTITY
        # =====================================================

        existing_uid = str(
            existing_user.get("uid", "")
        ).strip()

        existing_email = str(
            existing_user.get("email", email)
        ).strip().lower()

        existing_facility = str(
            existing_user.get("facility_id", "")
        ).strip()

        existing_permission = str(
            existing_user.get(
                "clearancePermission",
                "Viewer"
            )
        ).strip()


        # -----------------------------------------------------
        # UID MATCH
        # -----------------------------------------------------

        if existing_uid != uid:

            print(
                "🚫 USER DELETE DENIED: "
                f"UID mismatch for [{email}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "The supplied UID does not match "
                    "the existing facility account."
                )
            }), 403


        # -----------------------------------------------------
        # EMAIL MATCH
        # -----------------------------------------------------

        if existing_email != email:

            print(
                "🚫 USER DELETE DENIED: "
                f"Email mismatch for [{email}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "The supplied email does not match "
                    "the existing facility account."
                )
            }), 403


        # -----------------------------------------------------
        # FACILITY MATCH
        # -----------------------------------------------------

        if existing_facility != facility_id:

            print(
                "🚫 USER DELETE DENIED: "
                f"Facility mismatch for [{email}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "The user does not belong "
                    "to the selected facility."
                )
            }), 403


        # =====================================================
        # PROTECT SUPERADMIN
        # =====================================================

        if existing_permission == "SuperAdmin":

            print(
                "🚫 USER DELETE DENIED: "
                f"Attempt to delete SuperAdmin [{email}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "SuperAdmin accounts cannot be deleted "
                    "through facility user management."
                )
            }), 403


        # =====================================================
        # VERIFY MOTHER DB RECORD BEFORE DELETION
        #
        # We want the central identity to match before we
        # start destructive operations.
        # =====================================================

        mother_user_ref = (
            db_admin
            .collection("authorized_clinical_staff")
            .document(email)
        )

        mother_snapshot = (
            mother_user_ref.get()
        )


        if not mother_snapshot.exists:

            print(
                "❌ USER DELETE BLOCKED: "
                f"Mother DB profile missing [{email}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "Central authorization profile was not found. "
                    "Deletion was blocked to prevent inconsistent records."
                )
            }), 500


        mother_user = (
            mother_snapshot.to_dict()
            or {}
        )


        mother_uid = str(
            mother_user.get("uid", "")
        ).strip()

        mother_facility = str(
            mother_user.get(
                "facility_id",
                ""
            )
        ).strip()

        mother_permission = str(
            mother_user.get(
                "clearancePermission",
                "Viewer"
            )
        ).strip()


        if mother_uid != uid:

            print(
                "❌ USER DELETE BLOCKED: "
                f"Mother DB UID mismatch [{email}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "Central authorization identity "
                    "verification failed."
                )
            }), 500


        if mother_facility != facility_id:

            print(
                "❌ USER DELETE BLOCKED: "
                f"Mother DB facility mismatch [{email}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "Central authorization facility "
                    "verification failed."
                )
            }), 500


        if mother_permission == "SuperAdmin":

            print(
                "🚫 USER DELETE BLOCKED: "
                f"Mother DB identifies [{email}] as SuperAdmin"
            )

            return jsonify({
                "success": False,
                "error": (
                    "SuperAdmin accounts cannot be deleted "
                    "through facility user management."
                )
            }), 403


        # =====================================================
        # DELETE FIREBASE AUTH ACCOUNT
        # =====================================================

        try:

            target_auth = auth.Client(
                target_app
            )

            target_auth.delete_user(
                uid
            )


        except Exception as auth_error:

            print(
                "❌ TARGET AUTH DELETE FAILED:",
                repr(auth_error)
            )

            return jsonify({
                "success": False,
                "error": (
                    "Unable to delete the facility "
                    "authentication account."
                )
            }), 500


        # =====================================================
        # DELETE TENANT FIRESTORE PROFILE
        # =====================================================

        try:

            user_ref.delete()


        except Exception as firestore_error:

            print(
                "❌ TARGET FIRESTORE DELETE FAILED:",
                repr(firestore_error)
            )

            return jsonify({
                "success": False,
                "error": (
                    "Authentication account was deleted, "
                    "but the facility profile could not be removed. "
                    "Manual reconciliation is required."
                )
            }), 500


        # =====================================================
        # DELETE MOTHER DB INDEX
        # =====================================================

        try:

            mother_user_ref.delete()


        except Exception as mother_error:

            print(
                "❌ MOTHER DB DELETE FAILED:",
                repr(mother_error)
            )

            return jsonify({
                "success": False,
                "error": (
                    "Facility account was deleted, "
                    "but the central authorization profile "
                    "could not be removed. "
                    "Manual reconciliation is required."
                )
            }), 500


        # =====================================================
        # SUCCESS
        # =====================================================

        print(
            "✅ SUPERADMIN USER DELETED:",
            {
                "uid": uid,
                "email": email,
                "facility_id": facility_id
            }
        )


        return jsonify({
            "success": True,
            "message": (
                "Staff account successfully removed "
                "from the facility and central registry."
            )
        }), 200


    except Exception as e:

        print(
            "❌ Delete User Error:",
            repr(e)
        )

        return jsonify({
            "success": False,
            "error": (
                "An internal error occurred while "
                "deleting the staff account."
            )
        }), 500

from concurrent.futures import ThreadPoolExecutor

@app.route('/api/batch-import-clients', methods=['POST'])
@require_superadmin
def batch_import_clients():
    """
    Bulk imports mapped patient records directly to the
    ACTIVE TENANT'S isolated database.

    Attempts Admin SDK write first, and falls back to
    concurrent REST API commits.
    """

    try:
        # =====================================================
        # 1. RESOLVE ACTIVE FACILITY
        # =====================================================

        facility_id = get_active_facility_id()


        # =====================================================
        # 2. READ REQUEST PAYLOAD
        # =====================================================

        payload = request.get_json(
            force=True,
            silent=True
        ) or {}

        records = payload.get(
            "records",
            []
        )


        if not records:
            return jsonify({
                "success": False,
                "error": (
                    "No data records supplied "
                    "for migration."
                )
            }), 400


        # =====================================================
        # 3. RESOLVE FACILITY CONFIGURATION
        # =====================================================

        facility_settings = (
            get_facility_settings(
                facility_id
            )
        )


        if not facility_settings:

            print(
                "❌ BATCH IMPORT BLOCKED: "
                f"Unable to resolve facility [{facility_id}]"
            )

            return jsonify({
                "success": False,
                "error": (
                    "Unable to resolve the selected "
                    "facility configuration."
                )
            }), 503


        # =====================================================
        # 4. RESOLVE FIREBASE CONFIGURATION
        # =====================================================

        f_config = (
            facility_settings.get(
                "firebase_config",
                {}
            )
        )


        if not isinstance(
            f_config,
            dict
        ):

            return jsonify({
                "success": False,
                "error": (
                    "Facility Firebase configuration "
                    "is invalid."
                )
            }), 503


        target_project_id = (
            f_config.get(
                "projectId"
            )
        )

        target_api_key = (
            f_config.get(
                "apiKey"
            )
        )


        # =====================================================
        # 5. RESOLVE TENANT ADMIN SDK
        # =====================================================

        target_app, target_db = (
            get_facility_admin_sdk(
                facility_id
            )
        )


        imported_count = 0


        # =====================================================
        # OPTION A
        # ADMIN SDK INSTANCE AVAILABLE
        # =====================================================

        if target_db:

            batch = target_db.batch()


            for item in records:

                uic = str(
                    item.get(
                        "uic",
                        ""
                    )
                ).strip().upper()


                if not uic:
                    continue


                raw_demo = item.get(
                    "demographics",
                    {}
                )

                raw_reg = item.get(
                    "registry",
                    {}
                )


                # -------------------------------------------------
                # DEMOGRAPHICS PAYLOAD
                # -------------------------------------------------

                demo_payload = {

                    "lastName": str(
                        raw_demo.get(
                            "lastName",
                            ""
                        )
                    ).strip(),

                    "firstName": str(
                        raw_demo.get(
                            "firstName",
                            ""
                        )
                    ).strip(),

                    "middleName": str(
                        raw_demo.get(
                            "middleName",
                            ""
                        )
                    ).strip(),

                    "suffix": str(
                        raw_demo.get(
                            "suffix",
                            ""
                        )
                    ).strip(),

                    "sex": str(
                        raw_demo.get(
                            "sex",
                            "Male"
                        )
                    ).capitalize(),

                    "kp": str(
                        raw_demo.get(
                            "kp",
                            "Specify"
                        )
                    ).strip(),

                    "bday": (
                        convert_excel_serial_to_date(
                            raw_demo.get(
                                "bday"
                            )
                        )
                    ),

                    "contactNumber": str(
                        raw_demo.get(
                            "contactNumber",
                            "---"
                        )
                    ).strip(),

                    "emailAddress": str(
                        raw_demo.get(
                            "emailAddress",
                            "---"
                        )
                    ).strip(),

                    "address": str(
                        raw_demo.get(
                            "address",
                            ""
                        )
                    ).strip(),

                    "philhealthNumber": str(
                        raw_demo.get(
                            "philhealthNumber",
                            "---"
                        )
                    ).strip(),

                    "ohasisUrl": str(
                        raw_demo.get(
                            "ohasisUrl",
                            ""
                        )
                    ).strip(),

                    "inception": str(
                        raw_demo.get(
                            "inception",
                            "OPD"
                        )
                    ).upper(),

                    "incDate": (
                        convert_excel_serial_to_date(
                            raw_demo.get(
                                "incDate"
                            )
                        )
                    ),

                    "incFrom": str(
                        raw_demo.get(
                            "incFrom",
                            "---"
                        )
                    ).strip(),

                    "outDate": (
                        convert_excel_serial_to_date(
                            raw_demo.get(
                                "outDate"
                            )
                        )
                    ),

                    "outTo": str(
                        raw_demo.get(
                            "outTo",
                            "---"
                        )
                    ).strip(),

                    "t0Date": (
                        convert_excel_serial_to_date(
                            raw_demo.get(
                                "t0Date"
                            )
                        )
                    ),

                    "t0Result": str(
                        raw_demo.get(
                            "t0Result",
                            "Reactive"
                        )
                    ).strip(),

                    "artDate": (
                        convert_excel_serial_to_date(
                            raw_demo.get(
                                "artDate"
                            )
                            or raw_reg.get(
                                "artEnrollmentDate"
                            )
                        )
                    ),

                    "artRegimen": str(
                        raw_demo.get(
                            "artRegimen"
                        )
                        or raw_reg.get(
                            "artRegimen",
                            "3TC/TDF/DTG"
                        )
                    ).strip(),

                    "artBy": str(
                        raw_demo.get(
                            "artBy",
                            "Authorized Clinical Staff"
                        )
                    ).strip(),

                    "generated_serial_code": str(
                        raw_demo.get(
                            "generated_serial_code"
                        )
                        or raw_reg.get(
                            "generated_serial_code",
                            "---"
                        )
                    ).strip()
                }


                # -------------------------------------------------
                # NORMALIZE OUTCOME
                # -------------------------------------------------

                raw_outcome = str(
                    raw_demo.get(
                        "outcome",
                        "Active"
                    )
                ).upper()


                if (
                    "ALIVE" in raw_outcome
                    or "ACTIVE" in raw_outcome
                ):

                    demo_payload["outcome"] = "Active"

                elif (
                    "DEAD" in raw_outcome
                    or "DECEASED" in raw_outcome
                ):

                    demo_payload["outcome"] = "Deceased"

                elif "TRANS" in raw_outcome:

                    demo_payload["outcome"] = "Trans-out"

                elif (
                    "LTFU" in raw_outcome
                    or "LOST" in raw_outcome
                ):

                    demo_payload["outcome"] = "LTFU"

                else:

                    demo_payload["outcome"] = "Active"


                # -------------------------------------------------
                # OPTIONAL LOGS
                # -------------------------------------------------

                if (
                    "oiLogs" in raw_demo
                    and isinstance(
                        raw_demo["oiLogs"],
                        list
                    )
                ):

                    demo_payload["oiLogs"] = (
                        raw_demo["oiLogs"]
                    )


                if (
                    "stiLogs" in raw_demo
                    and isinstance(
                        raw_demo["stiLogs"],
                        list
                    )
                ):

                    demo_payload["stiLogs"] = (
                        raw_demo["stiLogs"]
                    )


                # -------------------------------------------------
                # REGISTRY PAYLOAD
                # -------------------------------------------------

                registry_payload = {

                    "artEnrollmentDate": (
                        demo_payload["artDate"]
                        or "---"
                    ),

                    "vlStatus": str(
                        raw_reg.get(
                            "vlStatus",
                            "Unknown"
                        )
                    ).strip(),

                    "vlValue": str(
                        raw_reg.get(
                            "vlValue",
                            "---"
                        )
                    ).strip(),

                    "latestCd4Count": str(
                        raw_reg.get(
                            "latestCd4Count",
                            "---"
                        )
                    ).strip(),

                    "pillsRemaining": int(
                        raw_reg.get(
                            "pillsRemaining",
                            0
                        )
                        or 0
                    ),

                    "retentionStatus": (
                        demo_payload["outcome"]
                    ),

                    "nextRefillDate": (
                        convert_excel_serial_to_date(
                            raw_reg.get(
                                "nextRefillDate"
                            )
                        )
                    ),

                    "generated_serial_code": (
                        demo_payload[
                            "generated_serial_code"
                        ]
                    )
                }


                # -------------------------------------------------
                # TENANT DOCUMENT REFERENCES
                # -------------------------------------------------

                demo_ref = (
                    target_db
                    .collection(
                        "clients_demographics"
                    )
                    .document(uic)
                )

                registry_ref = (
                    target_db
                    .collection(
                        "clients_registry"
                    )
                    .document(uic)
                )


                batch.set(
                    demo_ref,
                    demo_payload,
                    merge=True
                )

                batch.set(
                    registry_ref,
                    registry_payload,
                    merge=True
                )


                imported_count += 1


                # -------------------------------------------------
                # COMMIT EVERY 400 RECORDS
                # -------------------------------------------------

                if imported_count % 400 == 0:

                    batch.commit()

                    batch = (
                        target_db.batch()
                    )


            # -----------------------------------------------------
            # COMMIT REMAINING RECORDS
            # -----------------------------------------------------

            if imported_count % 400 != 0:
                batch.commit()


            return jsonify({
                "success": True,
                "count": imported_count,
                "message": (
                    "Successfully migrated "
                    f"{imported_count} patient records "
                    f"directly to tenant [{facility_id}]."
                )
            }), 200


        # =====================================================
        # OPTION B
        # FAST PARALLEL REST API FALLBACK
        # =====================================================

        elif (
            target_project_id
            and target_api_key
        ):

            def push_single_record(item):

                uic = str(
                    item.get(
                        "uic",
                        ""
                    )
                ).strip().upper()


                if not uic:
                    return False


                raw_demo = item.get(
                    "demographics",
                    {}
                )

                raw_reg = item.get(
                    "registry",
                    {}
                )


                # -------------------------------------------------
                # DEMOGRAPHICS PAYLOAD
                # -------------------------------------------------

                demo_payload = {

                    "lastName": str(
                        raw_demo.get(
                            "lastName",
                            ""
                        )
                    ).strip(),

                    "firstName": str(
                        raw_demo.get(
                            "firstName",
                            ""
                        )
                    ).strip(),

                    "middleName": str(
                        raw_demo.get(
                            "middleName",
                            ""
                        )
                    ).strip(),

                    "suffix": str(
                        raw_demo.get(
                            "suffix",
                            ""
                        )
                    ).strip(),

                    "sex": str(
                        raw_demo.get(
                            "sex",
                            "Male"
                        )
                    ).capitalize(),

                    "kp": str(
                        raw_demo.get(
                            "kp",
                            "Specify"
                        )
                    ).strip(),

                    "bday": (
                        convert_excel_serial_to_date(
                            raw_demo.get(
                                "bday"
                            )
                        )
                    ),

                    "contactNumber": str(
                        raw_demo.get(
                            "contactNumber",
                            "---"
                        )
                    ).strip(),

                    "emailAddress": str(
                        raw_demo.get(
                            "emailAddress",
                            "---"
                        )
                    ).strip(),

                    "address": str(
                        raw_demo.get(
                            "address",
                            ""
                        )
                    ).strip(),

                    "philhealthNumber": str(
                        raw_demo.get(
                            "philhealthNumber",
                            "---"
                        )
                    ).strip(),

                    "ohasisUrl": str(
                        raw_demo.get(
                            "ohasisUrl",
                            ""
                        )
                    ).strip(),

                    "inception": str(
                        raw_demo.get(
                            "inception",
                            "OPD"
                        )
                    ).upper(),

                    "incDate": (
                        convert_excel_serial_to_date(
                            raw_demo.get(
                                "incDate"
                            )
                        )
                    ),

                    "incFrom": str(
                        raw_demo.get(
                            "incFrom",
                            "---"
                        )
                    ).strip(),

                    "outDate": (
                        convert_excel_serial_to_date(
                            raw_demo.get(
                                "outDate"
                            )
                        )
                    ),

                    "outTo": str(
                        raw_demo.get(
                            "outTo",
                            "---"
                        )
                    ).strip(),

                    "t0Date": (
                        convert_excel_serial_to_date(
                            raw_demo.get(
                                "t0Date"
                            )
                        )
                    ),

                    "t0Result": str(
                        raw_demo.get(
                            "t0Result",
                            "Reactive"
                        )
                    ).strip(),

                    "artDate": (
                        convert_excel_serial_to_date(
                            raw_demo.get(
                                "artDate"
                            )
                            or raw_reg.get(
                                "artEnrollmentDate"
                            )
                        )
                    ),

                    "artRegimen": str(
                        raw_demo.get(
                            "artRegimen"
                        )
                        or raw_reg.get(
                            "artRegimen",
                            "3TC/TDF/DTG"
                        )
                    ).strip(),

                    "artBy": str(
                        raw_demo.get(
                            "artBy",
                            "Authorized Clinical Staff"
                        )
                    ).strip(),

                    "generated_serial_code": str(
                        raw_demo.get(
                            "generated_serial_code"
                        )
                        or raw_reg.get(
                            "generated_serial_code",
                            "---"
                        )
                    ).strip()
                }


                # -------------------------------------------------
                # NORMALIZE OUTCOME
                # -------------------------------------------------

                raw_outcome = str(
                    raw_demo.get(
                        "outcome",
                        "Active"
                    )
                ).upper()


                if (
                    "ALIVE" in raw_outcome
                    or "ACTIVE" in raw_outcome
                ):

                    demo_payload["outcome"] = "Active"

                elif (
                    "DEAD" in raw_outcome
                    or "DECEASED" in raw_outcome
                ):

                    demo_payload["outcome"] = "Deceased"

                elif "TRANS" in raw_outcome:

                    demo_payload["outcome"] = "Trans-out"

                elif (
                    "LTFU" in raw_outcome
                    or "LOST" in raw_outcome
                ):

                    demo_payload["outcome"] = "LTFU"

                else:

                    demo_payload["outcome"] = "Active"


                # -------------------------------------------------
                # REGISTRY PAYLOAD
                # -------------------------------------------------

                registry_payload = {

                    "artEnrollmentDate": (
                        demo_payload["artDate"]
                        or "---"
                    ),

                    "vlStatus": str(
                        raw_reg.get(
                            "vlStatus",
                            "Unknown"
                        )
                    ).strip(),

                    "vlValue": str(
                        raw_reg.get(
                            "vlValue",
                            "---"
                        )
                    ).strip(),

                    "latestCd4Count": str(
                        raw_reg.get(
                            "latestCd4Count",
                            "---"
                        )
                    ).strip(),

                    "pillsRemaining": int(
                        raw_reg.get(
                            "pillsRemaining",
                            0
                        )
                        or 0
                    ),

                    "retentionStatus": (
                        demo_payload["outcome"]
                    ),

                    "nextRefillDate": (
                        convert_excel_serial_to_date(
                            raw_reg.get(
                                "nextRefillDate"
                            )
                        )
                    ),

                    "generated_serial_code": (
                        demo_payload[
                            "generated_serial_code"
                        ]
                    )
                }


                # -------------------------------------------------
                # FIRESTORE REST ENDPOINTS
                # -------------------------------------------------

                demo_url = (
                    "https://firestore.googleapis.com/v1/"
                    f"projects/{target_project_id}/"
                    "databases/(default)/documents/"
                    f"clients_demographics/{uic}"
                    f"?key={target_api_key}"
                )


                reg_url = (
                    "https://firestore.googleapis.com/v1/"
                    f"projects/{target_project_id}/"
                    "databases/(default)/documents/"
                    f"clients_registry/{uic}"
                    f"?key={target_api_key}"
                )


                demo_response = requests.patch(
                    demo_url,
                    json={
                        "fields": _build_firestore_rest_fields(
                            demo_payload
                        )
                    },
                    timeout=10
                )


                reg_response = requests.patch(
                    reg_url,
                    json={
                        "fields": _build_firestore_rest_fields(
                            registry_payload
                        )
                    },
                    timeout=10
                )


                # -------------------------------------------------
                # VERIFY REST WRITE RESULTS
                # -------------------------------------------------

                if not (
                    200 <= demo_response.status_code < 300
                    and
                    200 <= reg_response.status_code < 300
                ):

                    print(
                        "❌ REST IMPORT WRITE FAILED:",
                        {
                            "facility_id":
                                facility_id,

                            "uic":
                                uic,

                            "demo_status":
                                demo_response.status_code,

                            "registry_status":
                                reg_response.status_code
                        }
                    )

                    return False


                return True


            # =====================================================
            # PARALLEL IMPORT
            # =====================================================

            with ThreadPoolExecutor(
                max_workers=20
            ) as executor:

                results = list(
                    executor.map(
                        push_single_record,
                        records
                    )
                )


                imported_count = sum(
                    1
                    for result in results
                    if result
                )


            return jsonify({
                "success": True,
                "count": imported_count,
                "message": (
                    "Successfully migrated "
                    f"{imported_count} patient records "
                    f"directly to tenant [{facility_id}] "
                    "via REST."
                )
            }), 200


        # =====================================================
        # NO DATABASE AVAILABLE
        # =====================================================

        return jsonify({
            "success": False,
            "error": (
                "Database initialization failed "
                f"for '{facility_id}'."
            )
        }), 503


    # =========================================================
    # GLOBAL ERROR HANDLER
    # =========================================================

    except Exception as e:

        print(
            "❌ Batch Import Exception:",
            repr(e)
        )

        return jsonify({
            "success": False,
            "error": (
                "Unable to complete the "
                "batch import operation."
            )
        }), 500

# =========================================================
# SUPERADMIN APPLICATION RUNNER
# =========================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("SUPERADMIN_PORT", "5001")),
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true"
    )
