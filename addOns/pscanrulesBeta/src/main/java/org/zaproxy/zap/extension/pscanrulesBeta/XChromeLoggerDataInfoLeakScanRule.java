/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesBeta;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * X-ChromeLogger-Data header information leak passive scan rule
 *
 * @author kingthorin+owaspzap@gmail.com
 */
public class XChromeLoggerDataInfoLeakScanRule extends PluginPassiveScanner {

    private static final String MESSAGE_PREFIX = "pscanbeta.xchromeloggerdata.";
    private static final int PLUGIN_ID = 10052;
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN,
                    CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED,
                    CommonAlertTag.WSTG_V42_INFO_05_CONTENT_LEAK);
    private static final Logger logger =
            LogManager.getLogger(XChromeLoggerDataInfoLeakScanRule.class);

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        long start = System.currentTimeMillis();

        // Get the header(s)
        List<String> xcldHeader = msg.getResponseHeader().getHeaderValues("X-ChromeLogger-Data");
        // Add any header(s) using the alternate name
        List<String> xcpdHeader = msg.getResponseHeader().getHeaderValues("X-ChromePhp-Data");

        List<String> loggerHeaders = new ArrayList<>(2);

        if (!xcldHeader.isEmpty()) {
            loggerHeaders.addAll(xcldHeader);
        }
        if (!xcpdHeader.isEmpty()) {
            loggerHeaders.addAll(xcpdHeader);
        }

        if (!loggerHeaders.isEmpty()) { // Header(s) Found
            for (String xcldField : loggerHeaders) {
                newAlert()
                        .setRisk(Alert.RISK_MEDIUM)
                        .setConfidence(Alert.CONFIDENCE_HIGH)
                        .setDescription(getDescription())
                        .setOtherInfo(getOtherInfo(xcldField))
                        .setSolution(getSolution())
                        .setReference(getReference())
                        .setEvidence(xcldField)
                        .setCweId(200)
                        .setWascId(13)
                        .raise();
            }
        }
        logger.debug("\tScan of record {} took {}ms", id, System.currentTimeMillis() - start);
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

    private String getOtherInfo(String headerValue) {
        try {
            byte[] decodedByteArray = Base64.getDecoder().decode(headerValue);
            return Constant.messages.getString(MESSAGE_PREFIX + "otherinfo.msg")
                    + "\n"
                    + new String(decodedByteArray, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return Constant.messages.getString(MESSAGE_PREFIX + "otherinfo.error")
                    + " "
                    + headerValue;
        }
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}
