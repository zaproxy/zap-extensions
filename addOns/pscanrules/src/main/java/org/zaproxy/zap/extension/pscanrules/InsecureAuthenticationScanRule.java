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

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.encoder.Base64;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/*
 * passively scans requests for insecure authentication
 */
public class InsecureAuthenticationScanRule extends PluginPassiveScanner {

    /** for logging. */
    private static Logger log = Logger.getLogger(InsecureAuthenticationScanRule.class);

    /** determines if we should output Debug level logging */
    private boolean debugEnabled = log.isDebugEnabled();

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {

        String uri = null, method = null;
        String extraInfo = null; // valeu depends on which method is being used.
        String digestInfo = null;

        // DEBUG only
        // log.setLevel(org.apache.log4j.Level.DEBUG);
        // this.debugEnabled = true;

        if (msg.getRequestHeader().isSecure()) {
            // If SSL is used then the use of 'weak' authentication methods isn't really an issue
            return;
        }

        // get the URI
        try {
            uri = msg.getRequestHeader().getURI().getURI().toString();
            method = msg.getRequestHeader().getMethod();
        } catch (Exception e) {
            log.error("Error getting URI from message [" + msg + "]");
            return;
        }

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
                            if (this.debugEnabled)
                                log.debug(
                                        authMechanism + " Authentication Value: " + authValues[1]);
                            // now decode it from base64 into the username and password
                            try {
                                String decoded = new String(Base64.decode(authValues[1]));
                                if (this.debugEnabled)
                                    log.debug("Decoded Base64 value: " + decoded);
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
                            } catch (IOException e) {
                                log.error(
                                        "Invalid Base64 value for "
                                                + authMechanism
                                                + " Authentication: "
                                                + authValues[1]);
                            }
                        } else {
                            // malformed Basic Auth header?? warn, but ignore
                            if (this.debugEnabled)
                                log.debug(
                                        "Malformed "
                                                + authMechanism
                                                + " Authentication Header: ["
                                                + authHeaderValue
                                                + "], "
                                                + authValues.length
                                                + " values found");
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
                            if (this.debugEnabled)
                                log.debug(
                                        authMechanism + " Authentication Value: " + authValues[1]);
                            // now grab the username from the string
                            Pattern pattern = Pattern.compile(".*username=\"([^\"]+)\".*");
                            Matcher matcher = pattern.matcher(authValues[1]);
                            if (matcher.matches()) {
                                username = matcher.group(1);
                            } else {
                                // no username in the Digest??
                                if (this.debugEnabled)
                                    log.debug(
                                            "Malformed "
                                                    + authMechanism
                                                    + " Authentication Header: ["
                                                    + authHeaderValue
                                                    + "]. No username was found");
                                continue; // to the next header..
                            }
                        } else {
                            // malformed Digest Auth header?? warn, but ignore
                            if (this.debugEnabled)
                                log.debug(
                                        "Malformed "
                                                + authMechanism
                                                + " Authentication Header: ["
                                                + authHeaderValue
                                                + "], "
                                                + authValues.length
                                                + " values found");
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

                    newAlert()
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
                            .raise();

                    // and log it, without internationalising it.
                    log.info(
                            "Authentication Credentials were captured. ["
                                    + method
                                    + "] ["
                                    + uri
                                    + "] uses insecure authentication mechanism ["
                                    + authMechanism
                                    + "], revealing username ["
                                    + username
                                    + "] and password/additional information ["
                                    + ((digestInfo != null) ? digestInfo : password)
                                    + "]");
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
                    newAlert()
                            .setRisk(Alert.RISK_MEDIUM)
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setDescription(getDescription())
                            .setSolution(getSolution())
                            .setReference(getReference())
                            .setEvidence(HttpHeader.WWW_AUTHENTICATE + ": " + auth)
                            .setCweId(326) // CWE Id - Inadequate Encryption Strength
                            .setWascId(4) // WASC Id - Insufficient Transport Layer Protection
                            .raise();
                }
            }
        }
    }
}
