GOOGLE SHEETS BACKUP REBUILD — AUDIT + ARCHIVE + EDIT UPSERT

Files:
- staff.py: merged from the latest uploaded staff(20261018-115754).py; preserves its existing routes and CSV export, adds tenant-scoped Google Sheets sync endpoints and best-effort audit/archive mirroring.
- dbv3.html and prepdb.html: UI versions that call Sheets backup only after Firestore save succeeds. Saves/edits use UIC upsert so an edit updates the existing row.
- Code.gs: receiver for ART, PrEP, audit events, and archive snapshots. Uses the original no-shared-secret webhook setup, with one deployment URL per facility.
- createBackUp.gs: non-destructive initializer for all six tabs.
- exporter JS files: server-backed upsert callers.

TABS
- Registry_Master_Logs: current ART records, upsert by UIC (column F).
- PrEP_Master_Logs: current PrEP records, upsert by UIC (column D).
- ART_Audit_Logs / PrEP_Audit_Logs: minimal audit metadata, idempotent upsert by event ID.
- ART_Archived_Records / PrEP_Archived_Records: immutable archive snapshots upserted by archive ID. Full historical demographics, registry data and archive payload are JSON cells.

DEPLOY
1. Back up your current deployed files. Compare the merged staff.py against your live version before deployment; this build is based on the latest file uploaded in this conversation, not a live server pull.
2. Ensure requests is installed (requirements.txt already includes it).
3. Replace the spreadsheet-bound Apps Script Code.gs and createBackUp.gs with these files. Save. Run setupMasterSheets() from the Apps Script editor if the function is available; it initializes missing tabs without clearing existing data.
4. Deploy Apps Script as a Web App using the same access arrangement as your original working setup. Put that deployment URL in that facility's facilities/{facility_id}.gas_webhook_url in the Mother DB. Each facility must have its own spreadsheet and deployment URL.
5. Deploy staff.py and both HTML pages together. No GOOGLE_SHEETS_BACKUP_TOKEN or setBackupSecret() is required in this version.
6. Test with test records: create ART and PrEP; edit each same UIC; verify row counts do not increase and values update. Archive one test record of each type and verify the archive tab. Trigger an action that writes an audit event and verify the audit tab.

BEHAVIOR / LIMITS
- Firestore remains the authoritative store. Audit and archive mirroring are best-effort; if Google Sheets is unavailable, the Firestore action is not rolled back. Logs are printed for mirror failures. A durable retry queue is not included in this package.
- The audit sheets intentionally contain audit metadata, not clinical payloads. Archive tabs contain full historical snapshots, which are sensitive; restrict spreadsheet access and sharing accordingly.
- Local syntax checks do not verify live Apps Script deployment, facility webhook URLs, or real sheet writes. Live end-to-end verification is still required. This version intentionally preserves the original no-shared-secret setup; restrict web-app access and keep each facility URL private because the receiver does not authenticate requests with a shared token.


COMPACT AUDIT LOGGING
---------------------
Firestore and the facility's backup Google Sheet receive audit entries only for
CREATE, UPDATE, and ARCHIVE actions. Each entry stores only event_id, action,
record_type, UIC, facility_id, staff_uid, and timestamp. Read/list/view/export,
manual backup requests, and bulk-import wrapper events are not logged as audit
events. Archive snapshots remain in the separate archive collections/tabs.
Existing historical audit documents are not automatically deleted by this update.


Update note: staff.py was patched from the latest uploaded source file. Firestore audit events are limited to successful ART/PrEP CREATE, UPDATE, and ARCHIVE operations and contain only event_id, action, record_type, uic, facility_id, staff_uid, and timestamp.
