# Limitations and Future Work

## 1. Prototype Limitations
1. **Dynamic Client-Side Obfuscation**: Highly sophisticated phishing pages employing client-side Single Page Application (SPA) rendering and dynamic JavaScript DOM generation may conceal form targets until interactive user execution.
2. **Short-Lived Ephemeral Domains**: Fast-flux domain campaigns registered minutes before an attack may exhibit neutral structural characteristics before community reputation lists index them.
3. **Multi-Step Credential Flows**: Complex phishing workflows that split authentication into multi-step redirects across distinct domains require stateful multi-page session tracking.

---

## 2. Future Work & Research Roadmap
1. **Headless Browser Rendering**: Integrating lightweight Chromium/Playwright execution for full dynamic JavaScript DOM inspection.
2. **Visual Brand Similarity Analysis**: Incorporating deep visual embeddings (e.g. Siamese networks / Vision Transformers) to compare target page screenshots with legitimate brand logos.
3. **Graph-Based Certificate Telemetry**: Leveraging Certificate Transparency (CT) logs and DNS graph embeddings for early predictive domain classification.
4. **Browser Extension Integration**: Packaging the API into a lightweight Chrome/Firefox security extension for real-time browsing protection.
