document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    const resultDiv = document.getElementById('result');
    const loadingText = document.getElementById('loading');

    scanBtn.addEventListener('click', async () => {
        // UI Reset
        resultDiv.style.display = 'none';
        loadingText.style.display = 'block';
        scanBtn.disabled = true;

        try {
            // 1. Get the current active browser tab
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

            // 2. Execute script to get targeted content
            chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: () => {
                    // Priority 1: User Selection
                    const selection = window.getSelection().toString().trim();
                    if (selection.length > 0) {
                        return { text: selection, source: "Highlighted Selection" };
                    }

                    // Priority 2: Semantic Main Content
                    const mainArea = document.querySelector('main') || 
                                     document.querySelector('article') || 
                                     document.body;
                    
                    // Capture links to maintain Layer 2 & 4 integrity
                    const links = Array.from(document.querySelectorAll('a'))
                                       .map(a => a.href)
                                       .join(' ');

                    return { 
                        text: mainArea.innerText + " " + links, 
                        source: "Full Page Context" 
                    };
                }
            }, async (results) => {
                try {
                    const { text, source } = results[0].result;

                    // 3. Send to Flask API
                    const response = await fetch('http://127.0.0.1:5000/predict_api', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email_content: text })
                    });

                    if (!response.ok) throw new Error("Server Error: Check Flask Terminal");

                    const data = await response.json();

                    // 4. Update UI with Source Info
                    loadingText.style.display = 'none';
                    resultDiv.style.display = 'block';
                    resultDiv.className = data.prediction === 'PHISHING' ? 'danger' : 'safe';
                    
                    resultDiv.innerHTML = `
                        <div style="font-size: 0.7rem; opacity: 0.6; margin-bottom: 5px;">Source: ${source}</div>
                        <strong>Verdict:</strong> ${data.prediction}<br>
                        <strong>Risk Score:</strong> ${data.score}%<br>
                        <small>Detected ${data.malicious_links} suspicious link(s)</small>
                    `;
                } catch (err) {
                    handleError(err.message);
                } finally {
                    scanBtn.disabled = false;
                }
            });

        } catch (error) {
            handleError(error.message);
        }
    });

    function handleError(msg) {
        loadingText.style.display = 'none';
        resultDiv.style.display = 'block';
        resultDiv.className = 'danger';
        resultDiv.innerText = "Error: " + msg;
        scanBtn.disabled = false;
    }
});