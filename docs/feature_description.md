# Complete Feature Description Specification

The system analyzes 48 distinct features categorized into four functional groups:

## 1. URL Lexical & Structural Features (26 Features)
1. **NumDots**: Total number of dot (`.`) characters in the full URL.
2. **SubdomainLevel**: Count of nested subdomain labels preceding the registered domain.
3. **PathLevel**: Number of non-empty directory segments in the URL path.
4. **UrlLength**: Total character count of the URL string.
5. **NumDash**: Count of hyphen (`-`) characters across the entire URL.
6. **NumDashInHostname**: Count of hyphen (`-`) characters in the hostname component.
7. **AtSymbol**: Binary flag (1/0) indicating presence of `@` credential-masking character.
8. **TildeSymbol**: Binary flag (1/0) indicating presence of `~` user-directory character.
9. **NumUnderscore**: Count of underscore (`_`) characters in the URL.
10. **NumPercent**: Count of percent (`%`) characters indicating URL encoding.
11. **NumQueryComponents**: Number of key-value parameters in the query string.
12. **NumAmpersand**: Count of ampersand (`&`) query parameter separators.
13. **NumHash**: Count of anchor fragment (`#`) characters.
14. **NumNumericChars**: Total count of numerical digits (`0-9`) in the URL.
15. **NoHttps**: Binary flag (1 if scheme is not `https://`, 0 if `https://`).
16. **RandomString**: Binary flag (1/0) indicating high-entropy randomized strings or hash tokens.
17. **IpAddress**: Binary flag (1 if hostname is a raw IPv4/IPv6 address, 0 otherwise).
18. **DomainInSubdomains**: Binary flag (1 if registered domain/brand keyword appears in subdomain).
19. **DomainInPaths**: Binary flag (1 if registered domain keyword appears in URL path).
20. **HttpsInHostname**: Binary flag (1 if `http` or `https` token appears inside hostname text).
21. **HostnameLength**: Total character count of hostname.
22. **PathLength**: Total character count of path component.
23. **QueryLength**: Total character count of query component.
24. **DoubleSlashInPath**: Binary flag (1 if `//` appears in path segment).
25. **NumSensitiveWords**: Count of sensitive banking/security bait keywords.
26. **EmbeddedBrandName**: Binary flag (1 if major brand name is embedded in a non-brand domain).

## 2. Webpage DOM & Content Features (16 Features)
27. **PctExtHyperlinks**: Ratio of `<a>` hyperlinks pointing to external domains (0.0 to 1.0).
28. **PctExtResourceUrls**: Ratio of images/scripts/links loaded from external origins.
29. **ExtFavicon**: Binary flag (1 if page favicon originates from an external domain).
30. **InsecureForms**: Binary flag (1 if form actions submit unencrypted data).
31. **RelativeFormAction**: Binary flag (1 if form action uses relative URI).
32. **ExtFormAction**: Binary flag (1 if form posts to an external third-party domain).
33. **AbnormalFormAction**: Binary flag (1 if form action is empty, `#`, `about:blank`, or `javascript:`).
34. **PctNullSelfRedirectHyperlinks**: Ratio of links that self-redirect, use `#`, or `javascript:void(0)`.
35. **FrequentDomainNameMismatch**: Binary flag (1 if primary external domain differs from host).
36. **FakeLinkInStatusBar**: Binary flag (1 if script manipulates `window.status` on mouseover).
37. **RightClickDisabled**: Binary flag (1 if script disables context menu).
38. **PopUpWindow**: Binary flag (1 if page triggers automated popup prompts).
39. **SubmitInfoToEmail**: Binary flag (1 if form submits to a `mailto:` address).
40. **IframeOrFrame**: Binary flag (1 if hidden, zero-sized, or borderless iframes are present).
41. **MissingTitle**: Binary flag (1 if `<title>` tag is missing or empty).
42. **ImagesOnlyInForm**: Binary flag (1 if form contains only image inputs).

## 3. Rule-Threshold (RT) Benchmark Derivations (6 Features)
43. **SubdomainLevelRT**: Rule threshold for subdomain count: 1 (<=1), 0 (2), -1 (>=3).
44. **UrlLengthRT**: Rule threshold for URL length: 1 (<=54), 0 (55-75), -1 (>75).
45. **PctExtResourceUrlsRT**: Rule threshold for external resource ratio: 1 (<0.22), 0 (0.22-0.61), -1 (>=0.61).
46. **AbnormalExtFormActionR**: Rule threshold for abnormal/external form action.
47. **ExtMetaScriptLinkRT**: Rule threshold for external scripts/links ratio: 1 (<0.17), 0 (0.17-0.81), -1 (>=0.81).
48. **PctExtNullSelfRedirectHyperlinksRT**: Rule threshold for null/self-redirect ratio: 1 (<0.31), 0 (0.31-0.67), -1 (>=0.67).
