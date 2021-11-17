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
package org.zaproxy.zap.extension.pscanrulesBeta;

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
 * X-Backend-Server header information leak passive scan rule
 * https://github.com/zaproxy/zaproxy/issues/1169
 *
 * @author kingthorin+owaspzap@gmail.com
 */
public class XBackendServerInformationLeakScanRule extends PluginPassiveScanner {

    private static final String MESSAGE_PREFIX = "pscanbeta.xbackendserver.";
    private static final int PLUGIN_ID = 10039;

    private static final Logger logger =
            LogManager.getLogger(XBackendServerInformationLeakScanRule.class);
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                    CommonAlertTag.WSTG_V42_INFO_02_FINGERPRINT_WEB_SERVER);

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        long start = System.currentTimeMillis();

        List<String> xbsOption = msg.getResponseHeader().getHeaderValues("X-Backend-Server");
        if (!xbsOption.isEmpty()) { // Header Found
            // It is set so lets check it. Should only be one but it's a vector so iterate to be
            // sure.
            for (String xbsDirective : xbsOption) {
                newAlert()
                        .setRisk(Alert.RISK_LOW)
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setDescription(getDescription())
                        .setSolution(getSolution())
                        .setReference(getReference())
                        .setEvidence(xbsDirective)
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

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}
