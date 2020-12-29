/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import java.io.IOException;
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
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * Active scan rule which checks whether or not elmah.axd is exposed.
 * https://github.com/zaproxy/zaproxy/issues/3279
 *
 * @author kingthorin+owaspzap@gmail.com
 */
public class ElmahScanRule extends AbstractHostPlugin {

    private static final String MESSAGE_PREFIX = "ascanrules.elmah.";
    private static final int PLUGIN_ID = 40028;

    private static final Logger LOG = LogManager.getLogger(ElmahScanRule.class);

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

    private String getOtherInfo() {
        return Constant.messages.getString(MESSAGE_PREFIX + "otherinfo");
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.IIS)
                || technologies.includes(Tech.Windows)
                || technologies.includes(Tech.ASP)
                || technologies.includes(Tech.MsSQL);
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getCweId() {
        return 215; // CWE-215: Information Exposure Through Debug Information
    }

    @Override
    public int getWascId() {
        return 13; // WASC-13: Information Leakage
    }

    @Override
    public void scan() {

        // Check if the user stopped things. One request per URL so check before
        // sending the request
        if (isStop()) {
            LOG.debug("Scan rule {} Stopping.", getName());
            return;
        }

        HttpMessage newRequest = getNewMsg();
        newRequest.getRequestHeader().setMethod(HttpRequestHeader.GET);
        newRequest.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, null);
        newRequest.setRequestBody("");
        URI baseUri = getBaseMsg().getRequestHeader().getURI();
        URI elmahUri = null;
        try {
            elmahUri =
                    new URI(
                            baseUri.getScheme(),
                            null,
                            baseUri.getHost(),
                            baseUri.getPort(),
                            "/elmah.axd");
        } catch (URIException uEx) {
            LOG.debug(
                    "An error occurred creating a URI for the: {} rule. {}",
                    getName(),
                    uEx.getMessage(),
                    uEx);
            return;
        }
        try {
            newRequest.getRequestHeader().setURI(elmahUri);
        } catch (URIException uEx) {
            LOG.debug(
                    "An error occurred setting the URI for a new request used by: {} rule. {}",
                    getName(),
                    uEx.getMessage(),
                    uEx);
            return;
        }
        try {
            sendAndReceive(newRequest, false);
        } catch (IOException e) {
            LOG.warn(
                    "An error occurred while checking [{}] [{}] for {} Caught {} {}",
                    newRequest.getRequestHeader().getMethod(),
                    newRequest.getRequestHeader().getURI(),
                    getName(),
                    e.getClass().getName(),
                    e.getMessage());
            return;
        }
        int statusCode = newRequest.getResponseHeader().getStatusCode();
        if (statusCode == HttpStatusCode.OK) {
            boolean hasContent = newRequest.getResponseBody().toString().contains("Error Log for");
            if (this.getAlertThreshold().equals(AlertThreshold.LOW) || hasContent) {
                raiseAlert(
                        newRequest,
                        getRisk(),
                        hasContent ? Alert.CONFIDENCE_HIGH : Alert.CONFIDENCE_LOW,
                        "");
            }
        } else if (this.getAlertThreshold().equals(AlertThreshold.LOW)
                && (statusCode == HttpStatusCode.UNAUTHORIZED
                        || statusCode == HttpStatusCode.FORBIDDEN)) {
            raiseAlert(newRequest, Alert.RISK_INFO, Alert.CONFIDENCE_LOW, getOtherInfo());
        }
    }

    private void raiseAlert(HttpMessage msg, int risk, int confidence, String otherInfo) {
        newAlert()
                .setRisk(risk)
                .setConfidence(confidence)
                .setOtherInfo(otherInfo)
                .setEvidence(msg.getResponseHeader().getPrimeHeader())
                .setMessage(msg)
                .raise();
    }
}
