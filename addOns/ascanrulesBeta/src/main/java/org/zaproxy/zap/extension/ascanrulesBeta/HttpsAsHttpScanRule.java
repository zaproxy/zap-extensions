/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;

/**
 * Active scan rule which checks whether or not HTTPS content is also available via HTTP
 * https://github.com/zaproxy/zaproxy/issues/174
 */
public class HttpsAsHttpScanRule extends AbstractAppPlugin implements CommonActiveScanRuleInfo {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanbeta.httpsashttp.";

    private static final int PLUGIN_ID = 10047;
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                    CommonAlertTag.WSTG_V42_CRYP_03_CRYPTO_FAIL);

    private static final Logger LOGGER = LogManager.getLogger(HttpsAsHttpScanRule.class);

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
        return Alert.RISK_LOW;
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

    @Override
    public void scan() {

        if (!getBaseMsg().getRequestHeader().isSecure()) { // Base request isn't HTTPS
            LOGGER.debug(
                    "The original request was not HTTPS, so there is not much point in looking further.");
            return;
        }

        int originalStatusCode = getBaseMsg().getResponseHeader().getStatusCode();
        boolean was404 = isPage404(getBaseMsg());
        if (was404) {
            LOGGER.debug(
                    "The original request was not successfully completed (status = {}), so there is not much point in looking further.",
                    originalStatusCode);
            LOGGER.debug("isPage404 returned: {}", was404);
            return;
        }

        LOGGER.debug(
                "Checking if {} is available via HTTP.", getBaseMsg().getRequestHeader().getURI());

        HttpMessage newRequest = getNewMsg();

        try {
            newRequest.getRequestHeader().setSecure(false); // https becomes http
            LOGGER.debug("**{} ", newRequest.getRequestHeader().getURI());
        } catch (URIException e) {
            LOGGER.error("Error creating HTTP URL from HTTPS URL:", e);
            return;
        }

        // Check if the user stopped things. One request per URL so check before sending the request
        if (isStop()) {
            LOGGER.debug("Scan rule {} stopping.", getName());
            return;
        }

        try {
            sendAndReceive(newRequest, false);
        } catch (IOException e) {
            LOGGER.error("Error scanning a request via HTTP when the original was HTTPS:", e);
            return;
        }

        if (newRequest.getResponseHeader().getStatusCode() == HttpStatusCode.OK) { // 200 Success
            buildAlert(
                            getBaseMsg().getRequestHeader().getURI().toString(),
                            newRequest.getRequestHeader().getURI().toString())
                    .setMessage(newRequest)
                    .raise();
        }
    }

    private AlertBuilder buildAlert(String baseUrl, String newUrl) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setUri(baseUrl)
                .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "otherinfo", newUrl))
                .setEvidence(newUrl);
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(buildAlert("https://example.org/", "http://example.org/").build());
    }
}
