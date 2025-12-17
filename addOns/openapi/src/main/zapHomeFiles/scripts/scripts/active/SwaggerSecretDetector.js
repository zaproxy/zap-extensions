// Note that new active scripts will initially be disabled
// -------------------------------------------------------------------
// Swagger Secrets & Version Detector - ZAP Active Scan Rule Script
// -------------------------------------------------------------------
const URI = Java.type("org.apache.commons.httpclient.URI");
const ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata",
);
const CommonAlertTag = Java.type("org.zaproxy.addon.commonlib.CommonAlertTag");
const SCAN_RULE_ID = "100043";

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: ${SCAN_RULE_ID}
name: Swagger UI Secret & Vulnerability Detector
description: >
  Detects exposed Swagger UI and OpenAPI endpoints that leak sensitive secrets such as API keys,
  OAuth client secrets, access tokens, or run vulnerable versions. This scanner performs comprehensive
  detection of sensitive information disclosure in API documentation.
solution: >
  Remove hardcoded secrets from API documentation, restrict access to API documentation endpoints,
  and upgrade Swagger UI to a secure version. Ensure proper authentication is required to access documentation.
category: info_gather
risk: high
confidence: medium
cweId: 522  # Insufficiently Protected Credentials
alertTags:
  ${CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()}: ${CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue()}
  ${CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()}: ${CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue()}
alertRefOverrides:
  ${SCAN_RULE_ID}-1:
    name: Vulnerable Swagger UI Version Detected
    description: |
        This Swagger UI version is known to contain vulnerabilities. Exploitation may allow unauthorized access, XSS, or token theft.

        Affected versions:
        - Swagger UI v2 < 2.2.10
        - Swagger UI v3 < 3.24.3
    solution: Upgrade to the latest version of Swagger UI. Regularly review and patch known issues.
  ${SCAN_RULE_ID}-2:
      name: Exposed Secrets in Swagger/OpenAPI Path
      description: >
        Swagger UI endpoint exposes sensitive secrets such as client secrets, API keys, or OAuth tokens.
        These secrets may be accessible in the HTML source and should not be exposed publicly, as this can lead to compromise.
      solution: Remove hardcoded secrets from documentation and ensure the endpoint is protected with authentication.
      references:
        - https://swagger.io/docs/open-source-tools/swagger-ui/usage/oauth2/
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/active/swagger-secret-detector.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/openapi-support/#id-100043
`);
}

// -------------------------------------------------------------------
// 1. List of commonly exposed Swagger/OpenAPI documentation paths
// -------------------------------------------------------------------
const SWAGGER_PATHS = [
  // Low Attack Strength
  "/swagger-ui/",
  "/v3/api-docs",
  "/swagger.json",
  "/openapi.json",
  "/api-docs",
  "/docs/",
  // Medium Attack Strength
  "/swagger",
  "/v2/api-docs",
  "/swagger-ui/index.html",
  "/openapi.yaml",
  "/swagger.yaml",
  "/swagger/ui/index.html",
  // High Attack Strength
  "/swagger/",
  "/swagger/index.html",
  "/swagger/ui",
  "/swagger/ui/",
  "/swagger/ui/index",
  "/swagger-ui",
  "/swagger-ui/index",
  "/docs",
];

// -------------------------------------------------------------------
// 2. Regex matchers for path filtering (more flexible than exact matches)
// -------------------------------------------------------------------
const SWAGGER_REGEX_PATHS = [
  /\/swagger\/?$/i,
  /\/swagger\/index\.html$/i,
  /\/swagger\/ui\/?$/i,
  /\/swagger\/ui\/index(\.html)?$/i,
  /\/swagger-ui\/?$/i,
  /\/swagger-ui\/index(\.html)?$/i,
  /\/docs\/?$/i,
  /\/api-docs$/i,
  /\/v2\/api-docs$/i,
  /\/v3\/api-docs$/i,
  /\/swagger\.(json|yaml)$/i,
  /\/openapi\.(json|yaml)$/i,
  /\/api(\/v[0-9]+)?\/.*$/i,
  /\/v[0-9]+\/swagger.*$/i,
  /\/v[0-9]+\/openapi.*$/i,
  /\/nswag\/?$/i,
  /\/redoc\/?$/i,
  /\/admin\/?$/i,
  /\/config(\.json|\.yaml|\.yml|\.php)?$/i,
  /\/debug(\.log|\.txt)?$/i,
  /\/\.env$/i,
  /\/\.git\/config$/i,
  /\/login\/?$/i,
  /\/signin\/?$/i,
  /\/upload\/.*$/i,
  /\/graphql$/i,
  /\/graphiql$/i,
  /\/phpinfo\.php$/i,
  /\/server-status$/i,
  /\/actuator\/.*$/i,
  /\/\.git\/HEAD$/i,
  /\/backup\.zip$/i,
  /\/db\.sql$/i,
];

// -------------------------------------------------------------------
// 3. Regex patterns to detect likely secrets in Swagger responses
// -------------------------------------------------------------------
const SECRET_REGEXES = [
  /["']?clientId["']?\s*:\s*["'](?!client_id|""|.{0,6}$).*?["']/gi,
  /["']?clientSecret["']?\s*:\s*["'](?!client_secret|""|.{0,6}$).*?["']/gi,
  /["']?oAuth2ClientId["']?\s*:\s*["'](?!client_id|""|.{0,6}$).*?["']/gi,
  /["']?oAuth2ClientSecret["']?\s*:\s*["'](?!client_secret|""|.{0,6}$).*?["']/gi,
  /["']?api_key["']?\s*:\s*["'](?!your_api_key_here|""|.{0,6}$).*?["']/gi,
  /["']?access_token["']?\s*:\s*["'](?!""|.{0,6}$).*?["']/gi,
  /["']?authorization["']?\s*:\s*["']Bearer\s+(?!""|.{0,6}$).*?["']/gi,
];

// -------------------------------------------------------------------
// 4. Known dummy/test values that should be ignored
// -------------------------------------------------------------------
const FALSE_POSITIVES = [
  "clientid",
  "clientsecret",
  "string",
  "n/a",
  "null",
  "na",
  "true",
  "false",
  "value_here",
  "your_key",
  "your_api_key_here",
  "demo_token",
  "test1234",
  "dummysecret",
  "{token}",
  "bearer{token}",
  "placeholder",
  "insert_value",
];

// -------------------------------------------------------------------
// 5. False positive filter: heuristic to skip known dummy/test data
// -------------------------------------------------------------------
function isFalsePositiveKV(kvString) {
  if (!kvString || kvString.length < 1) return true;

  const kvMatch = kvString.match(/["']?([^"']+)["']?\s*:\s*["']?([^"']+)["']?/);
  if (!kvMatch || kvMatch.length < 3) return false;

  const key = kvMatch[1].toLowerCase().trim();
  let value = kvMatch[2].toLowerCase().trim();
  value = value.replace(/[\s"'{}]/g, "");

  if (value.length < 8) return true;

  const contextKeys = ["example", "description", "title", "note"];
  for (let i = 0; i < contextKeys.length; i++) {
    if (key.indexOf(contextKeys[i]) !== -1) return true;
  }

  const junkTokens = [
    "test",
    "sample",
    "dummy",
    "mock",
    "try",
    "placeholder",
    "your",
    "insert",
  ];
  for (let i = 0; i < junkTokens.length; i++) {
    if (
      value.indexOf(junkTokens[i]) !== -1 ||
      key.indexOf(junkTokens[i]) !== -1
    )
      return true;
  }

  for (let i = 0; i < FALSE_POSITIVES.length; i++) {
    if (value === FALSE_POSITIVES[i]) return true;
  }

  return false;
}

// -------------------------------------------------------------------
// 6. Redact secret values in evidence (show only first 5 chars)
// -------------------------------------------------------------------
function redactSecret(secret) {
  const parts = secret.split(":");
  if (parts.length < 2) return secret;
  const value = parts.slice(1).join(":").trim().replace(/^"|"$/g, "");
  return parts[0] + ': "' + value.substring(0, 5) + '..."';
}

// -------------------------------------------------------------------
// 7. Detect Swagger UI version in HTML/JS
// -------------------------------------------------------------------
function detectSwaggerVersion(body) {
  if (body.indexOf("SwaggerUIBundle") !== -1) return 3;
  if (
    body.indexOf("SwaggerUi") !== -1 ||
    body.indexOf("window.swaggerUi") !== -1 ||
    body.indexOf("swashbuckleConfig") !== -1
  )
    return 2;
  if (body.indexOf("NSwag") !== -1 || body.indexOf("nswagui") !== -1) return 4;
  return 0;
}

function extractVersion(body) {
  const versionRegex = /version\s*[:=]\s*["']?(\d+\.\d+\.\d+)["']?/i;
  const match = body.match(versionRegex);
  return match ? match[1] : null;
}

function versionToInt(v) {
  const parts = v.split(".");
  return (
    parseInt(parts[0], 10) * 10000 +
    parseInt(parts[1], 10) * 100 +
    parseInt(parts[2], 10)
  );
}

// -------------------------------------------------------------------
// 8. Main scan logic: runs once per host
// -------------------------------------------------------------------
function scanHost(as, msg) {
  const origUri = msg.getRequestHeader().getURI();
  const scheme = origUri.getScheme();
  const host = origUri.getHost();
  const port = origUri.getPort();
  const base =
    scheme +
    "://" +
    host +
    (port !== -1 && port !== 80 && port !== 443 ? ":" + port : "");

  const pathsCount =
    as.getAttackStrength() == "LOW"
      ? 6
      : as.getAttackStrength() == "MEDIUM"
        ? 12
        : SWAGGER_PATHS.length;

  // --- Check static Swagger paths ---
  for (let i = 0; i < pathsCount; i++) {
    if (as.isStop()) return;
    scanPath(
      as,
      msg,
      scheme,
      host,
      port,
      SWAGGER_PATHS[i],
      base + SWAGGER_PATHS[i],
    );
  }
}

// -------------------------------------------------------------------
// 8. Main scan logic: runs once per node
// -------------------------------------------------------------------
function scanNode(as, msg) {
  // --- Check current request path if it matches any regex ---
  const origUri = msg.getRequestHeader().getURI();
  const currentPath = origUri.getPath();
  const scheme = origUri.getScheme();
  const host = origUri.getHost();
  const port = origUri.getPort();
  const base =
      scheme +
      "://" +
      host +
      (port !== -1 && port !== 80 && port !== 443 ? ":" + port : "");

  for (let r = 0; r < SWAGGER_REGEX_PATHS.length; r++) {
    if (as.isStop()) return;
    if (SWAGGER_REGEX_PATHS[r].test(currentPath)) {
      scanPath(as, msg, scheme, host, port, currentPath, base + currentPath)
      return;
    }
  }
}

// -------------------------------------------------------------------
// 9. Scan a single path (version + secret detection reused)
// -------------------------------------------------------------------
function scanPath(as, origMsg, scheme, host, port, pathOnly, fullPath) {
  const requestMsg = origMsg.cloneRequest();
  try {
    requestMsg.getRequestHeader().setMethod("GET");
    const newUri = new URI(scheme, null, host, port, pathOnly);
    requestMsg.getRequestHeader().setURI(newUri);
    requestMsg.getRequestHeader().setContentLength(0);

    const origHeaders = origMsg.getRequestHeader();
    ["User-Agent", "Cookie", "Authorization"].forEach(function (header) {
      const val = origHeaders.getHeader(header);
      if (val) requestMsg.getRequestHeader().setHeader(header, val);
    });

    as.sendAndReceive(requestMsg, false, false);
  } catch (err) {
    return;
  }

  const body = requestMsg.getResponseBody().toString();
  const version = detectSwaggerVersion(body);
  const semver = extractVersion(body);

  if (semver && (version === 2 || version === 3)) {
    const vInt = versionToInt(semver);
    if ((version === 2 && vInt < 20210) || (version === 3 && vInt < 32403)) {
      const cveReference =
        version === 2
          ? "https://nvd.nist.gov/vuln/detail/CVE-2019-17495"
          : "https://github.com/swagger-api/swagger-ui/releases/tag/v3.24.3";

      as.newAlert("100043-1")
        .setName("Vulnerable Swagger UI Version Detected (v" + semver + ")")
        .setOtherInfo("Discovered at: " + fullPath)
        .setReference(cveReference)
        .setMessage(requestMsg)
        .raise();
    }
  }

  detectSecrets(as, requestMsg, fullPath, body);
}

function detectSecrets(as, requestMsg, fullPath, body) {
  const matches = {};
  for (let j = 0; j < SECRET_REGEXES.length; j++) {
    const found = body.match(SECRET_REGEXES[j]);
    if (found) {
      for (let f = 0; f < found.length; f++) {
        const match = found[f];
        if (!isFalsePositiveKV(match)) {
          matches[match] = true;
        }
      }
    }
  }

  const evidenceRaw = Object.keys(matches);
  const redactedEvidence = evidenceRaw.map(redactSecret);
  // var evidenceString = redactedEvidence.length > 0 ? redactedEvidence[0] : null;
  const foundClientId = evidenceRaw.some((e) => /clientId/i.test(e));
  const foundSecret = evidenceRaw.some((e) =>
    /clientSecret|api_key|access_token|authorization/i.test(e),
  );

  if (foundClientId && foundSecret) {
    as.newAlert("100043-2")
      .setEvidence(redactedEvidence[0])
      .setOtherInfo("All secrets exposed:\n" + redactedEvidence.join("\n"))
      .setMessage(requestMsg)
      .raise();
  }
}
