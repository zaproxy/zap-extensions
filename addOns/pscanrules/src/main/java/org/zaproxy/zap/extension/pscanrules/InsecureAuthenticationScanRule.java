/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/*
 * passively scans requests for insecure authentication
 */
public class InsecureAuthenticationScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
                    CommonAlertTag.OWASP_2021_A02_CRYPO_FAIL,
                    CommonAlertTag.OWASP_2017_A02_BROKEN_AUTH,
                    CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED,
                    CommonAlertTag.WSTG_V42_ATHN_01_CREDS_NO_CRYPTO);

    /** for logging. */
    private static final Logger LOGGER = LogManager.getLogger(InsecureAuthenticationScanRule.class);

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {

        String uri = null, method = null;
        String extraInfo = null; // value depends on which method is being used.
        String digestInfo = null;

        if (msg.getRequestHeader().isSecure()) {
            // If SSL is used then the use of 'weak' authentication methods isn't really an issue
            return;
        }

        uri = msg.getRequestHeader().getURI().toString();
        method = msg.getRequestHeader().getMethod();

        List<String> headers = msg.getRequestHeader().getHeaderValues(HttpHeader.AUTHORIZATION);
        if (!headers.isEmpty()) {
            for (Iterator<String> i = headers.iterator(); i.hasNext(); ) {
                String authHeaderValue = i.next();
                String authMechanism = null;
                if ((authHeaderValue.toLowerCase(Locale.ENGLISH).startsWith("basic "))
                        || (authHeaderValue.toLowerCase(Locale.ENGLISH).startsWith("digest "))) {
                    int alertRisk = Alert.RISK_MEDIUM; // Medium by default.. maybe even high.
                    int alertConf = Alert.CONFIDENCE_MEDIUM;
                    String username = null, password = null;

                    // gets Basic or Digest.. (trailing spaces trimmed off)
                    authMechanism = authHeaderValue.substring(0, 6).trim();

                    // Handle Basic Auth
                    if (authMechanism.toLowerCase(Locale.ENGLISH).equals("basic")) {
                        // Basic authentication... the username and password are merely base64
                        // encoded and
                        // sent over the wire.. not good!
                        String[] authValues =
                                authHeaderValue.split(
                                        " "); // do NOT convert to lowercase for the split.. will
                        // corrupt the base64 data
                        if (authValues.length == 2) {
                            LOGGER.debug(
                                    "{} Authentication Value: {}", authMechanism, authValues[1]);
                            // now decode it from base64 into the username and password
                            try {
                                String decoded =
                                        new String(Base64.getDecoder().decode(authValues[1]));
                                LOGGER.debug("Decoded Base64 value: {}", decoded);
                                String[] usernamePassword = decoded.split(":", 2);
                                if (usernamePassword.length > 1) {
                                    username = usernamePassword[0];
                                    password = usernamePassword[1];
                                } else {
                                    // no password to be had.. use the entire decoded string as the
                                    // username
                                    username = decoded;
                                }
                                if (password != null) {
                                    alertRisk = Alert.RISK_HIGH;
                                }
                            } catch (IllegalArgumentException e) {
                                LOGGER.error(
                                        "Invalid Base64 value for {} Authentication: {}",
                                        authMechanism,
                                        authValues[1]);
                            }
                        } else {
                            // malformed Basic Auth header?? warn, but ignore
                            LOGGER.debug(
                                    "Malformed {} Authentication Header: [{}], {} values found",
                                    authMechanism,
                                    authHeaderValue,
                                    authValues.length);
                            continue; // to the next header
                        }
                        extraInfo =
                                Constant.messages.getString(
                                        "pscanrules.authenticationcredentialscaptured.alert.basicauth.extrainfo",
                                        method,
                                        uri,
                                        authMechanism,
                                        username,
                                        password);
                    }

                    // Handle Digest Auth
                    if (authMechanism.toLowerCase(Locale.ENGLISH).equals("digest")) {
                        alertRisk = Alert.RISK_MEDIUM; // not as high as for Basic Auth, but worth
                        // raising as an issue.

                        // Digest authentication... the username is in plaintext, and the password
                        // is hashed
                        String[] authValues =
                                authHeaderValue.split(
                                        " ", 2); // do NOT convert to lowercase for the split.. will
                        // corrupt the base64 data
                        if (authValues.length == 2) {
                            LOGGER.debug(
                                    "{} Authentication Value: {}", authMechanism, authValues[1]);
                            // now grab the username from the string
                            Pattern pattern = Pattern.compile(".*username=\"([^\"]+)\".*");
                            Matcher matcher = pattern.matcher(authValues[1]);
                            if (matcher.matches()) {
                                username = matcher.group(1);
                            } else {
                                // no username in the Digest??
                                LOGGER.debug(
                                        "Malformed {} Authentication Header: [{}]. No username was found",
                                        authMechanism,
                                        authHeaderValue);
                                continue; // to the next header..
                            }
                        } else {
                            // malformed Digest Auth header?? warn, but ignore
                            LOGGER.debug(
                                    "Malformed {} Authentication Header: [{}], {} values found",
                                    authMechanism,
                                    authHeaderValue,
                                    authValues.length);
                            continue; // to the next header
                        }

                        extraInfo =
                                Constant.messages.getString(
                                        "pscanrules.authenticationcredentialscaptured.alert.digestauth.extrainfo",
                                        method,
                                        uri,
                                        authMechanism,
                                        username,
                                        authValues[1]);
                        digestInfo = authValues[1]; // info to output in the logging message.
                    }

                    buildCapturedAlert(alertRisk, alertConf, extraInfo).raise();

                    LOGGER.info(
                            "Authentication Credentials were captured. [{}] [{}] uses insecure authentication mechanism [{}], revealing username [{}] and password/additional information [{}]",
                            method,
                            uri,
                            authMechanism,
                            username,
                            (digestInfo != null) ? digestInfo : password);
                } // basic or digest authorisation
            } // end of authorization headers
        } // end of headers null check
    } // end of method

    /**
     * gets the plugin id
     *
     * @return
     */
    @Override
    public int getPluginId() {
        return 10105;
    }

    /** gets the plugin name */
    @Override
    public String getName() {
        return Constant.messages.getString("pscanrules.insecureauthentication.name");
    }

    public String getDescription() {
        return Constant.messages.getString("pscanrules.insecureauthentication.desc");
    }

    public String getSolution() {
        return Constant.messages.getString("pscanrules.insecureauthentication.soln");
    }

    public String getReference() {
        return Constant.messages.getString("pscanrules.insecureauthentication.refs");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    public int getCweId() {
        return 326; // CWE Id - Inadequate Encryption Strength
    }

    public int getWascId() {
        return 4; // WASC Id - Insufficient Transport Layer Protection
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (msg.getRequestHeader().isSecure()) {
            // If SSL is used then the use of 'weak' authentication methods isnt really an issue
            return;
        }
        List<String> authHeaders =
                msg.getResponseHeader().getHeaderValues(HttpHeader.WWW_AUTHENTICATE);
        if (!authHeaders.isEmpty()) {
            for (String auth : authHeaders) {
                if (auth.toLowerCase().indexOf("basic") > -1
                        || auth.toLowerCase().indexOf("digest") > -1) {
                    buildAlert(auth).raise();
                }
            }
        }
    }

    private AlertBuilder buildCapturedAlert(int alertRisk, int alertConf, String extraInfo) {
        return newAlert()
                .setName(
                        Constant.messages.getString(
                                "pscanrules.authenticationcredentialscaptured.name"))
                .setRisk(alertRisk)
                .setConfidence(alertConf)
                .setDescription(
                        Constant.messages.getString(
                                "pscanrules.authenticationcredentialscaptured.desc"))
                .setOtherInfo(extraInfo)
                .setSolution(
                        Constant.messages.getString(
                                "pscanrules.authenticationcredentialscaptured.soln"))
                .setReference(
                        Constant.messages.getString(
                                "pscanrules.authenticationcredentialscaptured.refs"))
                .setCweId(287) // CWE Id - Improper authentication
                .setWascId(1) // WASC Id - Insufficient authentication
                .setAlertRef(getPluginId() + "-1");
    }

    private AlertBuilder buildAlert(String auth) {
        return newAlert()
                .setRisk(Alert.RISK_MEDIUM)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getDescription())
                .setSolution(getSolution())
                .setReference(getReference())
                .setEvidence(HttpHeader.WWW_AUTHENTICATE + ": " + auth)
                .setCweId(getCweId())
                .setWascId(getWascId())
                .setAlertRef(getPluginId() + "-2");
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                buildCapturedAlert(
                                Alert.RISK_MEDIUM,
                                Alert.CONFIDENCE_MEDIUM,
                                "[POST] "
                                        + "[http://www.example.com] uses insecure authentication mechanism [Digest], "
                                        + "revealing username [admin] and additional information "
                                        + "[username=\"admin\", realm=\"members only\"].")
                        .build(),
                buildAlert("Basic realm=\"Private\"").build());
    }
}
