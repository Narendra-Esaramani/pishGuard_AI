/**
 * Result Page JavaScript.
 * Handles SVG gauge animation, Robustness test AJAX trigger, Feedback submission, and Technical details toggle.
 */
document.addEventListener("DOMContentLoaded", () => {
    // 1. Animate SVG Gauge
    const progressCircle = document.getElementById("gauge-progress");
    if (progressCircle) {
        const score = parseInt(progressCircle.getAttribute("data-score") || "0", 10);
        const radius = progressCircle.r.baseVal.value;
        const circumference = 2 * Math.PI * radius;
        progressCircle.style.strokeDasharray = `${circumference} ${circumference}`;
        
        // Calculate offset (inverted for clockwise fill)
        const offset = circumference - (score / 100) * circumference;
        setTimeout(() => {
            progressCircle.style.strokeDashoffset = offset;
        }, 150);
    }

    // 2. Technical Details Accordion Toggle
    const accordionHeader = document.getElementById("tech-accordion-header");
    const accordionBody = document.getElementById("tech-accordion-body");
    const accordionIcon = document.getElementById("accordion-icon");
    
    if (accordionHeader && accordionBody) {
        accordionHeader.addEventListener("click", () => {
            const isOpen = accordionBody.classList.contains("open");
            if (isOpen) {
                accordionBody.classList.remove("open");
                if (accordionIcon) accordionIcon.textContent = "▼";
            } else {
                accordionBody.classList.add("open");
                if (accordionIcon) accordionIcon.textContent = "▲";
            }
        });
    }

    // 3. Robustness Test AJAX Execution
    const btnRunRobustness = document.getElementById("btn-run-robustness");
    const robustnessContainer = document.getElementById("robustness-results-container");
    
    if (btnRunRobustness && robustnessContainer) {
        btnRunRobustness.addEventListener("click", async () => {
            const targetUrl = btnRunRobustness.getAttribute("data-url");
            if (!targetUrl) return;

            btnRunRobustness.disabled = true;
            btnRunRobustness.innerHTML = "⟳ Running Perturbation Suite...";
            robustnessContainer.style.display = "block";
            robustnessContainer.innerHTML = `
                <div style="text-align:center; padding: 2rem; color: var(--text-secondary);">
                    <div style="font-size: 1.5rem; margin-bottom: 0.5rem; animation: spin 1s infinite linear; display: inline-block;">⟳</div>
                    <p>Generating 5 syntactic URL variants and evaluating model prediction consistency...</p>
                </div>
            `;

            try {
                const response = await fetch("/api/robustness-test", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url: targetUrl })
                });
                const resData = await response.json();

                if (resData.status === "success") {
                    const data = resData.data;
                    renderRobustnessResults(data, robustnessContainer);
                } else {
                    robustnessContainer.innerHTML = `
                        <div class="alert alert-danger">Error: ${resData.error || "Failed to complete robustness test"}</div>
                    `;
                }
            } catch (err) {
                robustnessContainer.innerHTML = `
                    <div class="alert alert-danger">Network Error: ${err.message}</div>
                `;
            } finally {
                btnRunRobustness.disabled = false;
                btnRunRobustness.innerHTML = "Re-Run Robustness Test";
            }
        });
    }

    function renderRobustnessResults(data, container) {
        const summ = data.summary;
        let variantRows = "";
        
        data.variants.forEach((v, idx) => {
            const consistencyBadge = v.is_consistent 
                ? `<span style="color:var(--color-safe); font-weight:700;">✓ Consistent</span>`
                : `<span style="color:var(--color-danger); font-weight:700;">⚠ Shifted</span>`;
                
            const deltaBadge = v.risk_delta > 0 
                ? `+${v.risk_delta}` 
                : `${v.risk_delta}`;
                
            variantRows += `
                <tr>
                    <td style="font-weight:600; color:#fff;">${v.variant_name}</td>
                    <td style="font-family:monospace; font-size:0.75rem; word-break:break-all;">${v.url}</td>
                    <td><span class="risk-badge ${v.badge_class}" style="font-size:0.75rem; padding:0.15rem 0.5rem;">${v.risk_score}/100</span></td>
                    <td style="font-size:0.8rem;">${deltaBadge}</td>
                    <td>${consistencyBadge}</td>
                </tr>
            `;
        });

        container.innerHTML = `
            <div style="margin-top: 1.5rem; background: #090d16; border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 1.5rem;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; margin-bottom:1rem; gap:1rem;">
                    <div>
                        <span style="font-size:0.8rem; color:var(--text-muted); text-transform:uppercase; font-weight:700;">Consistency Score</span>
                        <h3 style="font-size:1.5rem; color:#fff; font-weight:800;">${summ.consistency_percentage}% (${summ.consistent_predictions}/${summ.total_variants_tested} Consistent)</h3>
                    </div>
                    <div style="background:rgba(6,182,212,0.1); border:1px solid rgba(6,182,212,0.3); padding:0.4rem 0.9rem; border-radius:var(--radius-full); font-size:0.85rem; font-weight:700; color:var(--accent-cyan);">
                        ${summ.stability_grade}
                    </div>
                </div>
                <p style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1.25rem;">${summ.stability_description}</p>
                <div class="feature-table-wrapper">
                    <table class="feature-table">
                        <thead>
                            <tr>
                                <th>Mutation Type</th>
                                <th>Mutated URL</th>
                                <th>Variant Risk</th>
                                <th>Score Δ</th>
                                <th>Decision Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${variantRows}
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    }

    // 4. Feedback Submission Handler
    const btnFeedbackCorrect = document.getElementById("btn-feedback-correct");
    const btnFeedbackIncorrect = document.getElementById("btn-feedback-incorrect");
    const feedbackStatusMsg = document.getElementById("feedback-status-msg");
    const reportDataEl = document.getElementById("report-data");

    if (btnFeedbackCorrect && btnFeedbackIncorrect && reportDataEl) {
        const url = reportDataEl.getAttribute("data-url");
        const pred = reportDataEl.getAttribute("data-pred");
        const prob = parseFloat(reportDataEl.getAttribute("data-prob") || "0.5");
        const score = parseInt(reportDataEl.getAttribute("data-score") || "50", 10);

        async function submitUserFeedback(type) {
            btnFeedbackCorrect.disabled = true;
            btnFeedbackIncorrect.disabled = true;
            if (feedbackStatusMsg) {
                feedbackStatusMsg.innerHTML = `<span style="color:var(--text-muted);">Saving feedback...</span>`;
            }

            try {
                const res = await fetch("/api/feedback", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        url: url,
                        predicted_label: pred,
                        probability: prob,
                        risk_score: score,
                        user_feedback: type,
                        actual_label: type === "Correct" ? pred : (pred === "phishing" ? "legitimate" : "phishing"),
                        comments: `Submitted via web report UI`
                    })
                });
                const resJson = await res.json();
                if (resJson.status === "success") {
                    if (type === "Correct") {
                        btnFeedbackCorrect.classList.add("selected");
                    } else {
                        btnFeedbackIncorrect.classList.add("selected");
                    }
                    if (feedbackStatusMsg) {
                        feedbackStatusMsg.innerHTML = `<span style="color:var(--color-safe); font-weight:600;">✓ Thank you! Your feedback has been recorded in the retraining registry.</span>`;
                    }
                } else {
                    if (feedbackStatusMsg) {
                        feedbackStatusMsg.innerHTML = `<span style="color:var(--color-danger);">Error: ${resJson.error}</span>`;
                    }
                }
            } catch (e) {
                if (feedbackStatusMsg) {
                    feedbackStatusMsg.innerHTML = `<span style="color:var(--color-danger);">Submission error: ${e.message}</span>`;
                }
            }
        }

        btnFeedbackCorrect.addEventListener("click", () => submitUserFeedback("Correct"));
        btnFeedbackIncorrect.addEventListener("click", () => submitUserFeedback("Incorrect"));
    }
});
