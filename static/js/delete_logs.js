/**
 * static/js/delete_logs.js
 * Patient Registry Archiving and Purge Controller
 */

async function executeArchivalPipeline(uic, staffName) {
    if (!window.fb) {
        throw new Error("Database reference (window.fb) is not initialized.");
    }

    const { db, doc, getDoc, setDoc, deleteDoc } = window.fb;
    const trackingTimestamp = new Date().toISOString();

    console.log(`🔒 Initiating archival sequence for record node: [${uic}]`);

    const demoRef = doc(db, "clients_demographics", uic);
    const registryRef = doc(db, "clients_registry", uic);

    const [demoSnap, registrySnap] = await Promise.all([
        getDoc(demoRef),
        getDoc(registryRef)
    ]);

    if (!demoSnap.exists() && !registrySnap.exists()) {
        console.warn(`⚠️ Target record [${uic}] contains no active structural footprints.`);
        return false;
    }

    const activeDemographicData = demoSnap.exists() ? demoSnap.data() : {};
    const activeRegistryData = registrySnap.exists() ? registrySnap.data() : {};

    const archivedPayload = {
        uic_reference_key: uic,
        archivedAtTimestamp: trackingTimestamp,
        deletedBy: staffName || "Unknown Clinician/Staff",
        historicalDemographics: activeDemographicData,
        historicalRegistryMetrics: activeRegistryData,
        auditMeta: {
            lastUpdatedBy: activeDemographicData.dispensedBy || "Unspecified staff",
            recordInceptionDate: activeDemographicData.artDate || "---",
            finalRetentionOutcome: activeDemographicData.outcome || "Unknown"
        }
    };

    const archiveRef = doc(db, "deleted_logs", `${uic}_REV_${Date.now()}`);
    await setDoc(archiveRef, archivedPayload);

    await Promise.all([
        deleteDoc(registryRef),
        deleteDoc(demoRef)
    ]);

    return true;
}

/**
 * Renders a secure confirmation modal requiring the user to type "delete" to proceed.
 */
export function openSecureDeleteModal(uic, staffName, onSuccessCallback) {
    const modalId = `delete-gate-${Date.now()}`;
    const modalHtml = `
        <div id="${modalId}" class="fixed inset-0 bg-slate-900/60 backdrop-blur-sm z-[100] flex items-center justify-center p-4 animate-in fade-in duration-200">
            <div class="bg-white w-[400px] max-w-full rounded-xl border border-slate-200 p-6 shadow-2xl flex flex-col gap-4 animate-in zoom-in-95 duration-200">
                <div class="flex items-start gap-3">
                    <div class="p-2 bg-rose-50 text-rose-600 rounded-lg border border-rose-100 flex-shrink-0">
                        <i data-lucide="alert-triangle" class="w-5 h-5"></i>
                    </div>
                    <div>
                        <h3 class="text-sm font-black text-slate-900 uppercase tracking-tight">Confirm Record Archival</h3>
                        <p class="text-xs text-slate-500 mt-1 leading-relaxed">
                            You are permanently removing client node <span class="font-mono font-bold text-rose-600 bg-rose-50 px-1 py-0.5 rounded border border-rose-100">${uic}</span> from active registry databases.
                        </p>
                    </div>
                </div>

                <div class="border-t border-slate-100 pt-3">
                    <label class="text-[10px] uppercase font-bold text-slate-400 block mb-1.5">Type <span class="font-mono font-black text-slate-900 select-all">delete</span> to authorize processing:</label>
                    <input type="text" id="${modalId}-input" autocomplete="off" placeholder="Type text here..." class="w-full bg-slate-50 border border-slate-300 rounded-lg py-2 px-3 text-xs font-mono font-bold focus:outline-none focus:border-rose-500 focus:bg-white transition text-center text-rose-600 tracking-wide">
                </div>

                <div class="flex gap-2 pt-1">
                    <button type="button" id="${modalId}-cancel" class="flex-1 bg-slate-100 text-slate-700 py-2 rounded-lg font-bold text-xs uppercase transition hover:bg-slate-200 border border-slate-200">Cancel</button>
                    <button type="button" id="${modalId}-confirm" disabled class="flex-1 bg-rose-300 text-white py-2 rounded-lg font-bold text-xs uppercase cursor-not-allowed transition border border-transparent shadow-sm">Confirm Archive</button>
                </div>
            </div>
        </div>
    `;

    document.body.insertAdjacentHTML('beforeend', modalHtml);
    if (window.lucide) window.lucide.createIcons();

    const modalElement = document.getElementById(modalId);
    const inputElement = document.getElementById(`${modalId}-input`);
    const confirmBtn = document.getElementById(`${modalId}-confirm`);
    const cancelBtn = document.getElementById(`${modalId}-cancel`);

    const destroyModal = () => { modalElement.remove(); };

    inputElement.addEventListener('input', (e) => {
        if (e.target.value.trim().toLowerCase() === 'delete') {
            confirmBtn.disabled = false;
            confirmBtn.className = "flex-1 bg-rose-600 hover:bg-rose-700 text-white py-2 rounded-lg font-bold text-xs uppercase transition shadow-md shadow-rose-100 border border-rose-700 cursor-pointer";
        } else {
            confirmBtn.disabled = true;
            confirmBtn.className = "flex-1 bg-rose-300 text-white py-2 rounded-lg font-bold text-xs uppercase cursor-not-allowed transition border border-transparent shadow-sm";
        }
    });

    cancelBtn.addEventListener('click', destroyModal);

    confirmBtn.addEventListener('click', async () => {
        if (inputElement.value.trim().toLowerCase() !== 'delete') return;

        confirmBtn.disabled = true;
        confirmBtn.innerText = "Processing...";

        try {
            const success = await executeArchivalPipeline(uic, staffName);
            destroyModal();
            if (onSuccessCallback) onSuccessCallback(success);
        } catch (err) {
            destroyModal();
            console.error("Archival Exception Error:", err);
            alert("CRITICAL DATABASE TRANSACTION EXCEPTION: Action halted due to access control errors.");
        }
    });
}