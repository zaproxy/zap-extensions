/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.DiceMatcher;
import org.zaproxy.addon.commonlib.PolicyTag;

/**
 * Active scan rule that tests for JWT "none" algorithm vulnerabilities.
 *
 * <p>Detects servers that accept a JWT with the algorithm set to "none" and an empty signature,
 * which allows an attacker to forge arbitrary tokens without a secret key.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7519">RFC 7519 – JSON Web Token (JWT)</a>
 * @see <a href="https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/">CVE
 *     reference: Critical Vulnerabilities in JSON Web Token Libraries</a>
 */
public class JwtScanRule extends AbstractAppPlugin implements CommonActiveScanRuleInfo {

    private static final Logger LOGGER = LogManager.getLogger(JwtScanRule.class);

    static final int PLUGIN_ID = 40049;
    private static final String MESSAGE_PREFIX = "ascanalpha.jwt.";

    /**
     * Pattern matching a JWT: three base64url segments (header starts with "ey" after decoding
     * gives JSON) separated by dots. The signature may be empty (for "none" alg tokens).
     */
    static final Pattern JWT_PATTERN =
            Pattern.compile("(ey[A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]*)");

    private static final int BODY_SIMILARITY_THRESHOLD = 50;

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2025_A04_CRYPTO_FAIL,
                                CommonAlertTag.OWASP_2025_A07_AUTH_FAIL,
                                CommonAlertTag.OWASP_2021_A02_CRYPO_FAIL,
                                CommonAlertTag.OWASP_2021_A07_AUTH_FAIL,
                                CommonAlertTag.WSTG_V42_SESS_01_SESS_MANAGEMENT));
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 347; // CWE-347: Improper Verification of Cryptographic Signature
    }

    @Override
    public int getWascId() {
        return 13; // WASC-13: Information Leakage (closest mapping for auth bypass)
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public void scan() {
        HttpMessage baseMsg = getBaseMsg();

        // Only test requests that received a successful response
        if (isClientError(baseMsg) || isServerError(baseMsg)) {
            return;
        }

        List<JwtLocation> tokens = findJwts(baseMsg);
        if (tokens.isEmpty()) {
            LOGGER.debug("No JWT found in request to [{}]", baseMsg.getRequestHeader().getURI());
            return;
        }

        for (JwtLocation location : tokens) {
            if (isStop()) {
                return;
            }
            if (testNoneAlgorithm(location)) {
                return;
            }
        }
    }

    /**
     * Finds JWT tokens in the Authorization Bearer header and cookies of the given message.
     *
     * @param msg the HTTP message to inspect
     * @return list of located JWT tokens with their source information
     */
    List<JwtLocation> findJwts(HttpMessage msg) {
        List<JwtLocation> found = new ArrayList<>();

        String authHeader = msg.getRequestHeader().getHeader("Authorization");
        if (authHeader != null
                && authHeader.length() > 7
                && authHeader.substring(0, 7).equalsIgnoreCase("Bearer ")) {
            String candidate = authHeader.substring(7).trim();
            if (looksLikeJwt(candidate)) {
                found.add(new JwtLocation(JwtLocation.Source.HEADER, "Authorization", candidate));
                LOGGER.debug("Found JWT in Authorization header");
            }
        }

        for (HtmlParameter cookie : msg.getCookieParams()) {
            String value = cookie.getValue();
            if (looksLikeJwt(value)) {
                found.add(new JwtLocation(JwtLocation.Source.COOKIE, cookie.getName(), value));
                LOGGER.debug("Found JWT in cookie [{}]", cookie.getName());
            }
        }

        return found;
    }

    /**
     * Returns true if the given string matches the JWT pattern and its header decodes to JSON
     * containing an "alg" field.
     */
    static boolean looksLikeJwt(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        Matcher m = JWT_PATTERN.matcher(value);
        if (!m.matches()) {
            return false;
        }
        try {
            String header = decodeBase64Url(m.group(1));
            return header.contains("\"alg\"");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Tests whether the server accepts a JWT with algorithm set to "none" and an empty signature.
     *
     * @param location the JWT token and its location in the request
     * @return true if a vulnerability was detected and an alert raised
     */
    private boolean testNoneAlgorithm(JwtLocation location) {
        Matcher m = JWT_PATTERN.matcher(location.token);
        if (!m.matches()) {
            return false;
        }

        String headerPart = m.group(1);
        String payloadPart = m.group(2);

        String headerJson;
        try {
            headerJson = decodeBase64Url(headerPart);
        } catch (Exception e) {
            LOGGER.debug("Could not decode JWT header", e);
            return false;
        }

        String modifiedHeaderJson =
                headerJson.replaceAll("\"alg\"\\s*:\\s*\"[^\"]+\"", "\"alg\":\"none\"");
        if (modifiedHeaderJson.equals(headerJson)) {
            LOGGER.debug("Could not replace alg field in JWT header: {}", headerJson);
            return false;
        }

        String modifiedHeaderEncoded = encodeBase64Url(modifiedHeaderJson);
        // RFC 7519 §6: unsecured JWTs have an empty string as the JWS Signature
        String noneToken = modifiedHeaderEncoded + "." + payloadPart + ".";

        LOGGER.debug(
                "Testing JWT 'none' algorithm attack on [{}] in [{}]",
                location.name,
                location.source);

        try {
            HttpMessage attackMsg = getNewMsg();
            injectToken(attackMsg, location, noneToken);
            sendAndReceive(attackMsg);

            int attackStatus = attackMsg.getResponseHeader().getStatusCode();
            int originalStatus = getBaseMsg().getResponseHeader().getStatusCode();

            if (attackStatus == originalStatus) {
                String originalBody = getBaseMsg().getResponseBody().toString();
                String attackBody = attackMsg.getResponseBody().toString();
                int similarity = DiceMatcher.getMatchPercentage(originalBody, attackBody);

                LOGGER.debug(
                        "None-alg attack: original status={}, attack status={}, body similarity={}%",
                        originalStatus, attackStatus, similarity);

                if (similarity >= BODY_SIMILARITY_THRESHOLD) {
                    buildNoneAlgAlert(location, noneToken, headerJson, modifiedHeaderJson)
                            .setMessage(attackMsg)
                            .raise();
                    return true;
                }
            }
        } catch (IOException e) {
            LOGGER.debug("Error sending JWT 'none' algorithm attack", e);
        }

        return false;
    }

    private void injectToken(HttpMessage msg, JwtLocation location, String newToken) {
        if (location.source == JwtLocation.Source.HEADER) {
            msg.getRequestHeader().setHeader("Authorization", "Bearer " + newToken);
        } else {
            TreeSet<HtmlParameter> cookies = new TreeSet<>(msg.getCookieParams());
            cookies.removeIf(c -> c.getName().equals(location.name));
            cookies.add(new HtmlParameter(HtmlParameter.Type.cookie, location.name, newToken));
            msg.setCookieParams(cookies);
        }
    }

    private AlertBuilder buildNoneAlgAlert(
            JwtLocation location,
            String attackToken,
            String originalHeader,
            String modifiedHeader) {
        return newAlert()
                .setRisk(Alert.RISK_HIGH)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setParam(location.name)
                .setAttack(attackToken)
                .setOtherInfo(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "alert.noneAlg.otherinfo",
                                originalHeader,
                                modifiedHeader))
                .setAlertRef(getId() + "-1");
    }

    @Override
    public List<Alert> getExampleAlerts() {
        String exampleOriginalToken =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                        + ".eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6InVzZXIifQ"
                        + ".dummySignature";
        String exampleNoneToken =
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
                        + ".eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6InVzZXIifQ"
                        + ".";
        return List.of(
                buildNoneAlgAlert(
                                new JwtLocation(
                                        JwtLocation.Source.HEADER,
                                        "Authorization",
                                        exampleOriginalToken),
                                exampleNoneToken,
                                "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
                                "{\"alg\":\"none\",\"typ\":\"JWT\"}")
                        .build());
    }

    static String decodeBase64Url(String encoded) {
        int mod = encoded.length() % 4;
        String padded = mod == 0 ? encoded : encoded + "=".repeat(4 - mod);
        return new String(Base64.getUrlDecoder().decode(padded), StandardCharsets.UTF_8);
    }

    static String encodeBase64Url(String value) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    static class JwtLocation {
        enum Source {
            HEADER,
            COOKIE
        }

        final Source source;
        final String name;
        final String token;

        JwtLocation(Source source, String name, String token) {
            this.source = source;
            this.name = name;
            this.token = token;
        }
    }
}
