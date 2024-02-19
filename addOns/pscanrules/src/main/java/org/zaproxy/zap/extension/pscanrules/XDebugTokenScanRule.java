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
package org.zaproxy.zap.extension.pscanrules;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/** X-Debug-Token passive scan rule https://github.com/zaproxy/zaproxy/issues/2452 */
public class XDebugTokenScanRule extends PluginPassiveScanner implements CommonPassiveScanRuleInfo {

    private static final String MESSAGE_PREFIX = "pscanrules.xdebugtoken.";
    private static final int PLUGIN_ID = 10056;

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
                    CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED,
                    CommonAlertTag.WSTG_V42_ERRH_01_ERR);

    private static final Logger LOGGER = LogManager.getLogger(XDebugTokenScanRule.class);

    private static final String X_DEBUG_TOKEN_HEADER = "X-Debug-Token";
    private static final String X_DEBUG_TOKEN_LINK_HEADER = "X-Debug-Token-Link";

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        long start = System.currentTimeMillis();

        // Check "Link" variant first as it's of greater concern/convenience.
        if (responseHasHeader(msg, X_DEBUG_TOKEN_LINK_HEADER)) {
            buildAlert(getHeaders(msg, X_DEBUG_TOKEN_LINK_HEADER).get(0)).raise();
            return;
        }
        // Check non-Link variant
        if (responseHasHeader(msg, X_DEBUG_TOKEN_HEADER)) {
            buildAlert(getHeaders(msg, X_DEBUG_TOKEN_HEADER).get(0)).raise();
            return;
        }

        LOGGER.debug("\tScan of record {} took {} ms", id, System.currentTimeMillis() - start);
    }

    private AlertBuilder buildAlert(String evidence) {
        return newAlert()
                .setRisk(getRisk())
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setDescription(getDescription())
                .setOtherInfo(getOtherInfo())
                .setSolution(getSolution())
                .setReference(getReference())
                .setEvidence(evidence)
                .setCweId(getCweId())
                .setWascId(getWascId());
    }

    /**
     * Checks if there is a relevant header
     *
     * @param msg Response Http message
     * @param header the name of the header field being looked for
     * @return boolean status of existence
     */
    private boolean responseHasHeader(HttpMessage msg, String header) {
        return !msg.getResponseHeader().getHeaderValues(header).isEmpty();
    }

    /**
     * Extracts the list of headers, and returns them without changing their cases.
     *
     * @param msg Response Http message
     * @param header the name of the header field(s) to be collected
     * @return list of the matched headers
     */
    private List<String> getHeaders(HttpMessage msg, String header) {
        List<String> matchedHeaders = new ArrayList<>();
        String headers = msg.getResponseHeader().toString();
        String[] headerElements = headers.split("\\r\\n");
        Pattern pattern = Pattern.compile("^" + header + ".*", Pattern.CASE_INSENSITIVE);
        for (String hdr : headerElements) {
            Matcher matcher = pattern.matcher(hdr);
            if (matcher.find()) {
                String match = matcher.group();
                matchedHeaders.add(match);
            }
        }
        return matchedHeaders;
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    public int getRisk() {
        return Alert.RISK_LOW;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    public String getOtherInfo() {
        return Constant.messages.getString(MESSAGE_PREFIX + "otherinfo");
    }

    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    public int getCweId() {
        return 200; // CWE Id 200 - Information Exposure
    }

    public int getWascId() {
        return 13; // WASC Id - Info leakage
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(buildAlert("X-Debug-Token-Link: /_profiler/97b958").build());
    }
}
