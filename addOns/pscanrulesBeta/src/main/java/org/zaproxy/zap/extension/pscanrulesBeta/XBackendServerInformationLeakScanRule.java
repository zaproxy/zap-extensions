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
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
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
            Logger.getLogger(XBackendServerInformationLeakScanRule.class);

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
        if (logger.isDebugEnabled()) {
            logger.debug(
                    "\tScan of record "
                            + id
                            + " took "
                            + (System.currentTimeMillis() - start)
                            + " ms");
        }
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
