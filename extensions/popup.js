document.addEventListener("DOMContentLoaded", () => {
    const scanBtn = document.getElementById("scanBtn");
    const resultDiv = document.getElementById("result");
    const loading = document.getElementById("loading");

    scanBtn.addEventListener("click", async () => {
        setLoading(true);

        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

            chrome.scripting.executeScript(
                {
                    target: { tabId: tab.id },
                    func: extractEmailContent
                },
                async ([res]) => {
                    if (!res?.result?.text) {
                        throw new Error("No content selected or detected.");
                    }

                    const response = await fetch("http://127.0.0.1:5000/predict_api", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ email_content: res.result.text })
                    });

                    if (!response.ok) {
                        throw new Error("ML server not reachable");
                    }

                    const data = await response.json();
                    showResult(data, res.result.source);
                }
            );
        } catch (err) {
            showError(err.message);
        } finally {
            setLoading(false);
        }
    });

    function setLoading(state) {
        scanBtn.disabled = state;
        scanBtn.classList.toggle("pulse", !state);
        loading.classList.toggle("hidden", !state);
        resultDiv.classList.add("hidden");
    }

    function showResult(data, source) {
        resultDiv.className = `result ${data.prediction === "PHISHING" ? "danger" : "safe"}`;
        resultDiv.innerHTML = `
            <small style="opacity:.6">Source: ${source}</small><br>
            <strong>Verdict:</strong> ${data.prediction}<br>
            <strong>Risk Score:</strong> ${data.score}%<br>
            <small>Suspicious links: ${data.malicious_links}</small>
        `;
        resultDiv.classList.remove("hidden");
    }

    function showError(msg) {
        resultDiv.className = "result danger";
        resultDiv.textContent = "Error: " + msg;
        resultDiv.classList.remove("hidden");
    }
});

function extractEmailContent() {
    const selection = window.getSelection().toString().trim();
    if (selection) {
        return { text: selection, source: "Highlighted Selection" };
    }

    const bodyText = document.body.innerText.slice(0, 5000);
    const links = Array.from(document.links).map(l => l.href).join(" ");

    return {
        text: bodyText + " " + links,
        source: "Full Page Context"
    };
}
