/**
 * Main application JavaScript.
 * Handles URL sample auto-filling, form validation, and loading indicators.
 */
document.addEventListener("DOMContentLoaded", () => {
    // 1. Sample URL auto-fill
    const samplePills = document.querySelectorAll(".sample-pill");
    const urlInput = document.getElementById("url-input");
    const analyzerForm = document.getElementById("analyzer-form");
    const analyzeBtn = document.getElementById("btn-analyze");

    if (samplePills && urlInput) {
        samplePills.forEach(pill => {
            pill.addEventListener("click", () => {
                const sampleUrl = pill.getAttribute("data-url");
                if (sampleUrl) {
                    urlInput.value = sampleUrl;
                    urlInput.focus();
                }
            });
        });
    }

    // 2. Loading state on submit
    if (analyzerForm && analyzeBtn) {
        analyzerForm.addEventListener("submit", (e) => {
            const val = urlInput.value.trim();
            if (!val) {
                e.preventDefault();
                alert("Please enter a valid website URL.");
                return;
            }
            analyzeBtn.disabled = true;
            analyzeBtn.innerHTML = `
                <span style="display:inline-block; animation: spin 1s infinite linear;">⟳</span>
                Analyzing Features...
            `;
        });
    }
});

// Keyframe animation for spinner
const style = document.createElement("style");
style.textContent = `
@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}
`;
document.head.appendChild(style);
