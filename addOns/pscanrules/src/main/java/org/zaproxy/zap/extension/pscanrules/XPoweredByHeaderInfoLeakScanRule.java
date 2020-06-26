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
package org.zaproxy.zap.extension.pscanrules;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * X-Powered-By Information Leak passive scan rule https://github.com/zaproxy/zaproxy/issues/1169
 *
 * @author kingthorin+owaspzap@gmail.com
 */
public class XPoweredByHeaderInfoLeakScanRule extends PluginPassiveScanner {

    private static final String MESSAGE_PREFIX = "pscanrules.xpoweredbyheaderinfoleak.";
    private static final String HEADER_NAME = "X-Powered-By";
    private static final int PLUGIN_ID = 10037;

    private static final Logger logger = Logger.getLogger(XPoweredByHeaderInfoLeakScanRule.class);

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Only checking the response for this plugin
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        long start = System.currentTimeMillis();

        if (isXPoweredByHeaderExist(msg)) {
            List<String> xpbHeaders = getXPoweredByHeaders(msg);
            raiseAlert(msg, id, xpbHeaders);
            if (logger.isDebugEnabled()) {
                logger.debug(
                        "\tScan of record "
                                + id
                                + " took "
                                + (System.currentTimeMillis() - start)
                                + " ms");
            }
        }
    }

    /**
     * Checks if there is any X-Powered-By header
     *
     * @param msg Response Http message
     * @return boolean status of existence
     */
    private boolean isXPoweredByHeaderExist(HttpMessage msg) {
        return !msg.getResponseHeader().getHeaderValues(HEADER_NAME).isEmpty();
    }

    /**
     * Extracts the list of "X-Powered-By" headers, and returns them without changing their cases.
     *
     * @param msg Response Http message
     * @return list of the matched headers
     */
    private List<String> getXPoweredByHeaders(HttpMessage msg) {
        List<String> matchedHeaders = new ArrayList<>();
        String headers = msg.getResponseHeader().toString();
        String[] headerElements = headers.split("\\r\\n");
        Pattern pattern = Pattern.compile("^X-Powered-By.*", Pattern.CASE_INSENSITIVE);
        for (String header : headerElements) {
            Matcher matcher = pattern.matcher(header);
            if (matcher.find()) {
                String match = matcher.group();
                matchedHeaders.add(match);
            }
        }
        return matchedHeaders;
    }

    /**
     * Raises an alert with the "Evidence" or "Other" field filled-in depending on the header
     * repetition.
     *
     * @param msg The Http message containing the response headers
     * @param id The ID of the message being scanned.
     */
    private void raiseAlert(HttpMessage msg, int id, List<String> xpbHeaders) {
        String alertEvidence = xpbHeaders.get(0);
        String alertOtherInfo = "";
        if (xpbHeaders.size() > 1) { // we have multiple X-Powered-By headers
            StringBuilder sb = new StringBuilder();
            sb.append(Constant.messages.getString(MESSAGE_PREFIX + "otherinfo.msg"));
            for (int i = 1; i < xpbHeaders.size(); i++) {
                sb.append(xpbHeaders.get(i));
                sb.append("\r\n");
            }
            alertOtherInfo = sb.toString();
        }
        newAlert()
                .setRisk(Alert.RISK_LOW)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getDescription())
                .setOtherInfo(alertOtherInfo)
                .setSolution(getSolution())
                .setReference(getReference())
                .setEvidence(alertEvidence)
                .setCweId(200)
                .setWascId(13)
                .raise();
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }
}
