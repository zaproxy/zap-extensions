/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.sharedutils;

import java.io.IOException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;

public abstract class AbstractAppFilePlugin extends AbstractAppPlugin {

    private static final Logger LOG = Logger.getLogger(AbstractAppFilePlugin.class);
    private final String filename;
    private final String messagePrefix;

    protected AbstractAppFilePlugin(String filename, String messagePrefix) {
        this.filename = filename;
        this.messagePrefix = messagePrefix;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(messagePrefix + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(messagePrefix + "desc");
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(messagePrefix + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(messagePrefix + "refs");
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

    private String getOtherInfo() {
        return Constant.messages.getString(messagePrefix + "otherinfo");
    }

    @Override
    public void scan() {
        // Check if the user stopped things. One request per URL so check before
        // sending the request
        if (isStop()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Scanner " + getName() + " Stopping.");
            }
            return;
        }

        HttpMessage newRequest = getNewMsg();
        newRequest.getRequestHeader().setMethod(HttpRequestHeader.GET);
        URI baseUri = getBaseMsg().getRequestHeader().getURI();
        URI newUri = null;
        try {
            String baseUriPath = baseUri.getPath() == null ? "" : baseUri.getPath();
            newUri =
                    new URI(
                            baseUri.getScheme(),
                            null,
                            baseUri.getHost(),
                            baseUri.getPort(),
                            createTestablePath(baseUriPath));
        } catch (URIException uEx) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                        "An error occurred creating a URI for the: "
                                + getName()
                                + " scanner. "
                                + uEx.getMessage(),
                        uEx);
            }
            return;
        }
        try {
            newRequest.getRequestHeader().setURI(newUri);
        } catch (URIException uEx) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                        "An error occurred setting the URI for a new request used by: "
                                + getName()
                                + " scanner. "
                                + uEx.getMessage(),
                        uEx);
            }
            return;
        }
        // Until https://github.com/zaproxy/zaproxy/issues/3563 is addressed
        // track completed in Kb
        // TODO change this when possible
        synchronized (getKb()) {
            if (getKb().getBoolean(newUri, messagePrefix)) {
                return;
            }
            getKb().add(newUri, messagePrefix, Boolean.TRUE);
        }
        try {
            sendAndReceive(newRequest, false);
        } catch (IOException e) {
            LOG.warn(
                    "An error occurred while checking ["
                            + newRequest.getRequestHeader().getMethod()
                            + "] ["
                            + newRequest.getRequestHeader().getURI()
                            + "] for "
                            + getName()
                            + " Caught "
                            + e.getClass().getName()
                            + " "
                            + e.getMessage());
            return;
        }
        if (isFalsePositive(newRequest)) {
            return;
        }
        int statusCode = newRequest.getResponseHeader().getStatusCode();
        if (statusCode == HttpStatusCode.OK) {
            raiseAlert(newRequest, getRisk(), "");
        } else if (statusCode == HttpStatusCode.UNAUTHORIZED
                || statusCode == HttpStatusCode.FORBIDDEN) {
            raiseAlert(newRequest, Alert.RISK_INFO, getOtherInfo());
        }
    }

    /**
     * Always returns false - override to add functionality to detect FPs
     *
     * @param msg
     * @return true if its a false positive
     */
    public boolean isFalsePositive(HttpMessage msg) {
        return false;
    }

    private String createTestablePath(String baseUriPath) {
        String newPath = "";
        if (baseUriPath.contains("/")) {
            if (baseUriPath.endsWith("/")) {
                newPath = baseUriPath + filename;
            } else {
                newPath = baseUriPath.substring(0, baseUriPath.lastIndexOf('/')) + "/" + filename;
            }
        } else {
            newPath = baseUriPath + "/" + filename;
        }
        return newPath;
    }

    private void raiseAlert(HttpMessage msg, int risk, String otherInfo) {
        bingo(
                risk, // Risk
                Alert.CONFIDENCE_HIGH, // Confidence
                getName(), // Name
                getDescription(), // Description
                msg.getRequestHeader().getURI().toString(), // URI
                null, // Param
                "", // Attack
                otherInfo, // OtherInfo
                getSolution(), // Solution
                msg.getResponseHeader().getPrimeHeader(), // Evidence
                getCweId(), // CWE ID
                getWascId(), // WASC ID
                msg); // HTTPMessage
    }
}
