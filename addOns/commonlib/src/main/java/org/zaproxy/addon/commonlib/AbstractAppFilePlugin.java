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
package org.zaproxy.addon.commonlib;

import java.io.IOException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;

/**
 * An {@code AbstractAppPlugin} that checks for the presence of a file.
 *
 * @since 1.0.0
 */
public abstract class AbstractAppFilePlugin extends AbstractAppPlugin {

    private static final Logger LOG = Logger.getLogger(AbstractAppFilePlugin.class);
    private final String filename;
    private final String messagePrefix;

    /**
     * Constructs an {@code AbstractAppFilePlugin} with the given file name and messages prefix.
     *
     * <p>The message prefix is used to load the messages for the alert and scan rule, from the main
     * resource bundle ({@link Constant#messages}).
     *
     * @param filename the name of the file to check if it's present.
     * @param messagePrefix the messages prefix (including the trailing period).
     */
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
        newRequest.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, null);
        newRequest.setRequestBody("");
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
            raiseAlert(newRequest, getRisk(), Alert.CONFIDENCE_MEDIUM, "");
        } else if (this.getAlertThreshold().equals(AlertThreshold.LOW)
                && (statusCode == HttpStatusCode.UNAUTHORIZED
                        || statusCode == HttpStatusCode.FORBIDDEN)) {
            raiseAlert(newRequest, Alert.RISK_INFO, Alert.CONFIDENCE_LOW, getOtherInfo());
        }
    }

    /**
     * Always returns false - override to add functionality to detect FPs
     *
     * @param msg the message being scanned (after being sent).
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

    private void raiseAlert(HttpMessage msg, int risk, int confidence, String otherInfo) {
        newAlert()
                .setRisk(risk)
                .setConfidence(confidence)
                .setOtherInfo(otherInfo)
                .setEvidence(msg.getResponseHeader().getPrimeHeader())
                .setMessage(msg)
                .raise();
    }

    public String getFilename() {
        return filename;
    }
}
