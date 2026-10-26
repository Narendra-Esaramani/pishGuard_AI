# 48-Feature Compatibility & Pipeline Audit Report

## 1. Executive Summary
This report audits the exact alignment between the **48 Training Features** and the **Live Feature Extraction Pipeline**.

- **Total Benchmark Features**: 48
- **Pure URL & Domain Features**: 28 (100% extractable from URL syntax without network access)
- **HTML DOM Content Features**: 20 (live extracted when webpage is active; handled via calibrated fallback in offline mode)
- **Schema Compatibility**: 100% strict ordering and data-type alignment verified.

---

## 2. Feature-by-Feature Compatibility Matrix

| Feature Name | Training Availability | Live Availability | Training Calculation | Live Calculation | Data Type | Expected Range |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **NumDots** | Training Set | 100% Available (URL String) | URL string count of '.' | URL string count of '.' | `int/float` | 1 - 21 |
| **SubdomainLevel** | Training Set | 100% Available (URL String) | Count of subdomain segments | Count of subdomain segments | `int/float` | 0 - 14 |
| **PathLevel** | Training Set | 100% Available (URL String) | Path segment depth count | Path segment depth count | `int/float` | 0 - 18 |
| **UrlLength** | Training Set | 100% Available (URL String) | Total URL string character length | Total URL string character length | `int/float` | 12 - 253 |
| **NumDash** | Training Set | 100% Available (URL String) | Count of '-' in full URL | Count of '-' in full URL | `int/float` | 0 - 55 |
| **NumDashInHostname** | Training Set | 100% Available (URL String) | Count of '-' in hostname | Count of '-' in hostname | `int/float` | 0 - 9 |
| **AtSymbol** | Training Set | 100% Available (URL String) | Presence of '@' character (1/0) | Presence of '@' character (1/0) | `int/float` | 0 or 1 |
| **TildeSymbol** | Training Set | 100% Available (URL String) | Presence of '~' character (1/0) | Presence of '~' character (1/0) | `int/float` | 0 or 1 |
| **NumUnderscore** | Training Set | 100% Available (URL String) | Count of '_' in URL | Count of '_' in URL | `int/float` | 0 - 18 |
| **NumPercent** | Training Set | 100% Available (URL String) | Count of '%' in URL | Count of '%' in URL | `int/float` | 0 - 19 |
| **NumQueryComponents** | Training Set | 100% Available (URL String) | Count of query key-value pairs | Count of query key-value pairs | `int/float` | 0 - 23 |
| **NumAmpersand** | Training Set | 100% Available (URL String) | Count of '&' in URL | Count of '&' in URL | `int/float` | 0 - 22 |
| **NumHash** | Training Set | 100% Available (URL String) | Count of '#' in URL | Count of '#' in URL | `int/float` | 0 or 1 |
| **NumNumericChars** | Training Set | 100% Available (URL String) | Count of digits (0-9) in URL | Count of digits (0-9) in URL | `int/float` | 0 - 111 |
| **NoHttps** | Training Set | 100% Available (URL String) | 1 if not https, 0 if https | 1 if not https, 0 if https | `int/float` | 0 or 1 |
| **RandomString** | Training Set | 100% Available (URL String) | Entropy/random token detection (1/0) | Shannon entropy > 3.4 & hex token detection | `int/float` | 0 or 1 |
| **IpAddress** | Training Set | 100% Available (URL String) | 1 if hostname is IPv4/IPv6, 0 otherwise | socket/ipaddress parsing validation | `int/float` | 0 or 1 |
| **DomainInSubdomains** | Training Set | 100% Available (URL String) | 1 if brand/domain token in subdomain | Keyword token presence check | `int/float` | 0 or 1 |
| **DomainInPaths** | Training Set | 100% Available (URL String) | 1 if brand/domain token in path | Keyword token presence check | `int/float` | 0 or 1 |
| **HttpsInHostname** | Training Set | 100% Available (URL String) | 1 if 'http' in hostname string | Hostname token matching | `int/float` | 0 or 1 |
| **HostnameLength** | Training Set | 100% Available (URL String) | Hostname character length | len(hostname) | `int/float` | 4 - 137 |
| **PathLength** | Training Set | 100% Available (URL String) | Path character length | len(path) | `int/float` | 0 - 161 |
| **QueryLength** | Training Set | 100% Available (URL String) | Query character length | len(query) | `int/float` | 0 - 188 |
| **DoubleSlashInPath** | Training Set | 100% Available (URL String) | 1 if '//' in path, 0 otherwise | Path substring check | `int/float` | 0 or 1 |
| **NumSensitiveWords** | Training Set | 100% Available (URL String) | Count of sensitive security keywords | Count of security keywords in URL | `int/float` | 0 - 3 |
| **EmbeddedBrandName** | Training Set | 100% Available (URL String) | 1 if major brand in path/subdomain | Brand dictionary matching | `int/float` | 0 or 1 |
| **PctExtHyperlinks** | Training Set | Available (When HTML Live) | External href ratio (0.0 - 1.0) | DOM <a> tag href host comparison | `float` | 0.0 - 1.0 |
| **PctExtResourceUrls** | Training Set | Available (When HTML Live) | External resource ratio (0.0 - 1.0) | DOM <img>/<script>/<link> src comparison | `float` | 0.0 - 1.0 |
| **ExtFavicon** | Training Set | Available (When HTML Live) | 1 if favicon host differs from page | DOM <link rel='icon'> host check | `int/float` | 0 or 1 |
| **InsecureForms** | Training Set | Available (When HTML Live) | 1 if form action uses HTTP on HTTPS | DOM <form action> protocol inspection | `int/float` | 0 or 1 |
| **RelativeFormAction** | Training Set | Available (When HTML Live) | 1 if form action is relative URI | DOM <form action> relative URI check | `int/float` | 0 or 1 |
| **ExtFormAction** | Training Set | Available (When HTML Live) | 1 if form action posts to external domain | DOM <form action> external domain check | `int/float` | 0 or 1 |
| **AbnormalFormAction** | Training Set | Available (When HTML Live) | 1 if form action is empty/#/javascript: | DOM <form action> abnormal target check | `int/float` | 0 or 1 |
| **PctNullSelfRedirectHyperlinks** | Training Set | Available (When HTML Live) | Null/self-redirect link ratio | DOM <a> null/void link ratio | `float` | 0.0 - 1.0 |
| **FrequentDomainNameMismatch** | Training Set | Available (When HTML Live) | 1 if primary external domain != host | Counter mode comparison across links | `int/float` | 0 or 1 |
| **FakeLinkInStatusBar** | Training Set | Available (When HTML Live) | 1 if window.status manipulation found | DOM <script> window.status inspection | `int/float` | 0 or 1 |
| **RightClickDisabled** | Training Set | Available (When HTML Live) | 1 if context menu disabled | DOM <script> event.button/contextmenu check | `int/float` | 0 or 1 |
| **PopUpWindow** | Training Set | Available (When HTML Live) | 1 if popup prompt triggered | DOM <script> window.open/prompt check | `int/float` | 0 or 1 |
| **SubmitInfoToEmail** | Training Set | Available (When HTML Live) | 1 if mailto: in form or script | DOM form action/script mailto: check | `int/float` | 0 or 1 |
| **IframeOrFrame** | Training Set | Available (When HTML Live) | 1 if hidden/borderless iframe present | DOM <iframe> hidden/0px inspection | `int/float` | 0 or 1 |
| **MissingTitle** | Training Set | Available (When HTML Live) | 1 if <title> missing/empty | DOM <title> tag validation | `int/float` | 0 or 1 |
| **ImagesOnlyInForm** | Training Set | Available (When HTML Live) | 1 if form contains only image inputs | DOM form input type inspection | `int/float` | 0 or 1 |
| **SubdomainLevelRT** | Training Set | 100% Available (URL String) | Benchmark rule threshold (-1, 0, 1) | Rule threshold: 1 if <=1, 0 if 2, -1 if >=3 | `int/float` | -1, 0, 1 |
| **UrlLengthRT** | Training Set | 100% Available (URL String) | Benchmark rule threshold (-1, 0, 1) | Rule threshold: 1 if <=54, 0 if 55-75, -1 if >75 | `int/float` | -1, 0, 1 |
| **PctExtResourceUrlsRT** | Training Set | Available (When HTML Live) | Benchmark rule threshold (-1, 0, 1) | Rule threshold: 1 (<0.22), 0 (0.22-0.61), -1 (>=0.61) | `int/float` | -1, 0, 1 |
| **AbnormalExtFormActionR** | Training Set | Available (When HTML Live) | Benchmark rule threshold (-1, 0, 1) | Rule threshold based on abnormal/ext form action | `int/float` | -1, 0, 1 |
| **ExtMetaScriptLinkRT** | Training Set | Available (When HTML Live) | Benchmark rule threshold (-1, 0, 1) | Rule threshold: 1 (<0.17), 0 (0.17-0.81), -1 (>=0.81) | `int/float` | -1, 0, 1 |
| **PctExtNullSelfRedirectHyperlinksRT** | Training Set | Available (When HTML Live) | Benchmark rule threshold (-1, 0, 1) | Rule threshold: 1 (<0.31), 0 (0.31-0.67), -1 (>=0.67) | `int/float` | -1, 0, 1 |

---

## 3. Key Pipeline Safeguards
1. **Zero Silent Fallbacks to Biased Values**: Offline HTML features no longer inject false "legitimate" signatures into full models. Instead, the adaptive pipeline activates the 28-feature calibrated URL model.
2. **Out-of-Distribution Detection**: Input values exceeding the 99th percentile are flagged with data confidence adjustments.
3. **Dynamic Class Mapping**: `model.classes_` is resolved dynamically at runtime.
