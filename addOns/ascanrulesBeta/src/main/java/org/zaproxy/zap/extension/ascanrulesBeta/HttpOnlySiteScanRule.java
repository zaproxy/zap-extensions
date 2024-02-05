/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.IOException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;

/**
 * Active scan rule which raises an alert if a site accessed via HTTP is not served under HTTPS
 * https://github.com/zaproxy/zaproxy/issues/2207
 *
 * @author sanchitlucknow@gmail.com
 */
public class HttpOnlySiteScanRule extends AbstractHostPlugin implements CommonActiveScanRuleInfo {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanbeta.httponlysite.";

    private static final int PLUGIN_ID = 10106;
    private static final int REDIR_LIMIT = 10;
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                    CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS);

    private static final Logger LOGGER = LogManager.getLogger(HttpOnlySiteScanRule.class);

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
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getCweId() {
        return 311; // CWE-311: Missing Encryption of Sensitive Data
    }

    @Override
    public int getWascId() {
        return 4; // WASC-04: Insufficient Transport Layer Protection
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    private AlertBuilder createAlert(String message, String oldUri, String newUri) {
        String otherInfoDetail =
                Constant.messages.getString(MESSAGE_PREFIX + "otherinfo." + message);

        return newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setUri(oldUri)
                .setOtherInfo(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "otherinfo", otherInfoDetail, newUri));
    }

    public void raiseAlert(HttpMessage newRequest, String message) {
        String oldUri = getBaseMsg().getRequestHeader().getURI().toString();
        String newUri = newRequest.getRequestHeader().getURI().toString();
        createAlert(message, oldUri, newUri).setMessage(newRequest).raise();
    }

    public URI constructURI(String redirect, URI oldURI) {
        try {
            return new URI(oldURI, redirect, true);
        } catch (URIException err) {
            try {
                return new URI(oldURI, redirect, true);
            } catch (URIException ex) {
                return null;
            }
        }
    }

    @Override
    public void scan() {

        if (getBaseMsg().getRequestHeader().isSecure()) { // Base request is HTTPS
            LOGGER.debug(
                    "The original request was HTTPS, so there is not much point in looking further.");
            return;
        }

        HttpMessage newRequest = getNewMsg();
        try {
            String host = newRequest.getRequestHeader().getURI().getHost();
            String path = newRequest.getRequestHeader().getURI().getPath();
            newRequest
                    .getRequestHeader()
                    .setURI(new URI("https", null, host, getPort(newRequest), path));
        } catch (URIException e) {
            LOGGER.error("Error creating HTTPS URL from HTTP URL:", e);
            return;
        }

        if (isStop()) {
            LOGGER.debug("Scan rule {} Stopping.", getName());
            return;
        }

        try {
            int count = 0;
            while (count < REDIR_LIMIT) {
                if (isStop()) {
                    LOGGER.debug("Scan rule {} Stopping.", getName());
                    return;
                }
                sendAndReceive(newRequest, false);
                int status = newRequest.getResponseHeader().getStatusCode();
                if (!HttpStatusCode.isRedirection(status)) {
                    break;
                }
                String redirect =
                        newRequest.getResponseHeader().getHeader(HttpFieldsNames.LOCATION);
                if (redirect == null || redirect.isEmpty()) {
                    raiseAlert(newRequest, "noredirection");
                    return;
                }
                URI oldURI = newRequest.getRequestHeader().getURI();
                URI newURI = constructURI(redirect, oldURI);
                if (newURI == null) {
                    raiseAlert(newRequest, "urinotencoded");
                    return;
                }
                newRequest.getRequestHeader().setURI(newURI);
                if (!oldURI.getHost().equals(newURI.getHost())) {
                    raiseAlert(newRequest, "differenthosts");
                    return;
                }
                if (newRequest.getRequestHeader().isSecure()) {
                    count++;
                } else {
                    raiseAlert(newRequest, "redirecttohttp");
                    return;
                }
            }
            if (count == REDIR_LIMIT) { // When redirection limit is exceeded
                raiseAlert(newRequest, "redirectionlimit");
                return;
            }
        } catch (SocketException | SocketTimeoutException e) {
            raiseAlert(newRequest, "connectionfail");
            return;
        } catch (SSLException e) {
            if (e.getMessage().contains("plaintext")) {
                raiseAlert(newRequest, "nossl");
            }
            return;
        } catch (IOException e) {
            LOGGER.error("Request couldn't go through:", e);
            return;
        }
    }

    private static int getPort(HttpMessage message) {
        int port = message.getRequestHeader().getURI().getPort();
        if (port == 80 || port == 443) {
            return -1;
        }
        return port;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        String domain = "example.com";
        return List.of(
                createAlert(
                                "noredirection",
                                HttpHeader.SCHEME_HTTP + domain,
                                HttpHeader.SCHEME_HTTPS + domain)
                        .build());
    }
}
