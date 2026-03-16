document.addEventListener("DOMContentLoaded", () => {
    const scanBtn   = document.getElementById("scanBtn");
    const resultDiv = document.getElementById("result");
    const loading   = document.getElementById("loading");
    const laserBar  = document.getElementById("laserBar");
    const btnText   = document.getElementById("btnText");

    scanBtn.addEventListener("click", async () => {
        // First check if user has selected any text — do this BEFORE loading state
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            const [selRes] = await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: () => window.getSelection().toString().trim()
            });

            if (!selRes?.result) {
                // Nothing selected — show prompt, do NOT start loading
                showSelectPrompt();
                return;
            }
        } catch (err) {
            showError(err.message);
            return;
        }

        // Text is selected — proceed with scan
        setLoading(true);
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            chrome.scripting.executeScript(
                { target: { tabId: tab.id }, func: extractEmailContent },
                async ([res]) => {
                    if (!res?.result?.text) { showError("No content selected or detected."); setLoading(false); return; }
                    try {
                        const response = await fetch("http://127.0.0.1:5000/predict_api", {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ email_content: res.result.text })
                        });
                        if (!response.ok) throw new Error("ML server not reachable");
                        const data = await response.json();
                        showResult(data, res.result.source);
                    } catch (err) { showError(err.message); }
                    finally { setLoading(false); }
                }
            );
        } catch (err) { showError(err.message); setLoading(false); }
    });

    function setLoading(state) {
        scanBtn.disabled = state;
        loading.classList.toggle("hidden", !state);
        if (state) {
            resultDiv.classList.add("hidden");
            laserBar.classList.remove("hidden");
            btnText.textContent = "SCANNING...";
        } else {
            laserBar.classList.add("hidden");
            btnText.textContent = "EXECUTE SCAN";
        }
    }

    function showResult(data, source) {
        const isPhishing = data.prediction === "PHISHING";
        const score      = parseFloat(data.score).toFixed(1);
        const links      = data.malicious_links ?? 0;
        const markers    = (data.identified_words ?? []).slice(0, 3);

        const markersHTML = markers.length
            ? markers.map(w => `<span style="display:inline-block;padding:1px 7px;background:rgba(248,113,113,0.12);border:1px solid rgba(248,113,113,0.3);border-radius:4px;font-size:10px;color:#fca5a5;font-family:'JetBrains Mono',monospace;margin:2px 2px 0 0;text-transform:uppercase;">${w}</span>`).join('')
            : `<span style="font-size:10px;color:rgba(255,255,255,0.3);font-family:'JetBrains Mono',monospace;">None detected</span>`;

        const verdictIcon = isPhishing
            ? `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`
            : `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#6ee7b7" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`;

        resultDiv.className = `result-card ${isPhishing ? "danger" : "safe"}`;
        resultDiv.innerHTML = `
            <div class="result-verdict">
                <div class="verdict-icon">${verdictIcon}</div>
                <span class="verdict-label">${data.prediction}</span>
            </div>
            <div class="result-rows">
                <div class="result-row">
                    <span class="rk">Source</span>
                    <span class="rv" style="font-size:11px;color:rgba(255,255,255,0.55)">${source}</span>
                </div>
                <div class="result-row">
                    <span class="rk">Malicious Links</span>
                    <span class="rv" style="color:${links > 0 ? '#f87171' : '#6ee7b7'}">${links}</span>
                </div>
            </div>
            <div class="score-bar-wrap">
                <div class="score-bar-label">
                    <span>Risk Score</span>
                    <span style="color:${isPhishing ? '#f87171' : '#6ee7b7'}">${score}%</span>
                </div>
                <div class="score-bar-track">
                    <div class="score-bar-fill" id="scoreBarFill" style="width:0%"></div>
                </div>
            </div>
            ${markers.length || isPhishing ? `<div style="margin-top:10px;padding-top:10px;border-top:1px solid rgba(255,255,255,0.06)"><div style="font-size:9px;color:rgba(255,255,255,0.3);font-family:'JetBrains Mono',monospace;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px">Forensic Markers</div><div>${markersHTML}</div></div>` : ''}
        `;
        resultDiv.classList.remove("hidden");
        requestAnimationFrame(() => requestAnimationFrame(() => {
            const fill = document.getElementById("scoreBarFill");
            if (fill) fill.style.width = `${score}%`;
        }));
    }

    function showSelectPrompt() {
        resultDiv.className = "result-card prompt";
        resultDiv.innerHTML = `
            <div style="display:flex;align-items:center;gap:9px;margin-bottom:10px">
                <div style="width:28px;height:28px;display:flex;align-items:center;justify-content:center;background:rgba(251,191,36,0.14);border:1px solid rgba(251,191,36,0.3);border-radius:8px;flex-shrink:0;">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M1 6v16l7-4 8 4 7-4V2l-7 4-8-4-7 4z"/><line x1="8" y1="2" x2="8" y2="18"/><line x1="16" y1="6" x2="16" y2="22"/></svg>
                </div>
                <span style="font-family:'Bricolage Grotesque',sans-serif;font-size:15px;font-weight:800;color:#fbbf24;letter-spacing:0.04em;">Select Mail Content</span>
            </div>
            <p style="font-size:12px;color:rgba(255,255,255,0.6);line-height:1.6;margin-bottom:12px;font-family:'DM Sans',sans-serif;">
                No text is selected. Please highlight the email content you want to scan, then click <strong style="color:rgba(255,255,255,0.85)">Execute Scan</strong> again.
            </p>
            <div style="padding:10px 12px;background:rgba(251,191,36,0.06);border:1px solid rgba(251,191,36,0.18);border-radius:10px;">
                <div style="font-size:9px;color:rgba(251,191,36,0.6);font-family:'JetBrains Mono',monospace;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:6px;">How to select</div>
                <div style="display:flex;flex-direction:column;gap:4px;">
                    <div style="display:flex;align-items:center;gap:7px;font-size:11px;color:rgba(255,255,255,0.5);font-family:'DM Sans',sans-serif;">
                        <span style="color:#fbbf24;font-weight:700;font-family:'JetBrains Mono',monospace;font-size:10px;">1.</span> Open the suspicious email
                    </div>
                    <div style="display:flex;align-items:center;gap:7px;font-size:11px;color:rgba(255,255,255,0.5);font-family:'DM Sans',sans-serif;">
                        <span style="color:#fbbf24;font-weight:700;font-family:'JetBrains Mono',monospace;font-size:10px;">2.</span> Select all text <kbd style="background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.15);border-radius:4px;padding:1px 5px;font-size:9px;font-family:'JetBrains Mono',monospace;color:rgba(255,255,255,0.7);">Ctrl+A</kbd> or highlight manually
                    </div>
                    <div style="display:flex;align-items:center;gap:7px;font-size:11px;color:rgba(255,255,255,0.5);font-family:'DM Sans',sans-serif;">
                        <span style="color:#fbbf24;font-weight:700;font-family:'JetBrains Mono',monospace;font-size:10px;">3.</span> Come back and click Execute Scan
                    </div>
                </div>
            </div>
        `;
        resultDiv.classList.remove("hidden");
    }

    function showError(msg) {
        resultDiv.className = "result-card error";
        resultDiv.innerHTML = `
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                <span style="font-size:12px;font-weight:700;color:#f87171;font-family:'DM Sans',sans-serif;">Connection Error</span>
            </div>
            <div class="error-msg">${msg}</div>
            <div style="margin-top:8px;font-size:9px;color:rgba(255,255,255,0.3);font-family:'JetBrains Mono',monospace;">Make sure PhishGuard is running at 127.0.0.1:5000</div>
        `;
        resultDiv.classList.remove("hidden");
    }
});

function extractEmailContent() {
    const selection = window.getSelection().toString().trim();
    if (selection) return { text: selection, source: "Highlighted Selection" };
    const bodyText = document.body.innerText.slice(0, 5000);
    const links    = Array.from(document.links).map(l => l.href).join(" ");
    return { text: bodyText + " " + links, source: "Full Page Context" };
}
