/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.util.List;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Feature Policy Header Missing passive scan rule https://github.com/zaproxy/zaproxy/issues/4885
 */
public class FeaturePolicyScanRule extends PluginPassiveScanner {

    private static final String MESSAGE_PREFIX = "pscanalpha.featurepolicymissing.";
    private static final Logger LOGGER = Logger.getLogger(FeaturePolicyScanRule.class);
    private static final int PLUGIN_ID = 10063;

    @Override
    public void scanHttpRequestSend(HttpMessage httpMessage, int id) {
        // Only checking the response for this scan rule
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage httpMessage, int id, Source source) {
        long start = System.currentTimeMillis();

        if (!httpMessage.getResponseHeader().isHtml()
                && !httpMessage.getResponseHeader().isJavaScript()) {
            return;
        }
        if (HttpStatusCode.isRedirection(httpMessage.getResponseHeader().getStatusCode())
                && !AlertThreshold.LOW.equals(this.getAlertThreshold())) {
            return;
        }

        // Feature-Policy is supported by Chrome 60+, Firefox 65+, Opera 47+, but not by Internet
        // Exploder or Safari
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy#Browser_compatibility
        List<String> featurePolicyOptions =
                httpMessage.getResponseHeader().getHeaderValues("Feature-Policy");
        if (featurePolicyOptions.isEmpty()) {
            newAlert()
                    .setRisk(Alert.RISK_LOW)
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setDescription(getAlertAttribute("desc"))
                    .setSolution(getAlertAttribute("soln"))
                    .setReference(getAlertAttribute("refs"))
                    .setCweId(16) // CWE-16: Configuration
                    .setWascId(15) // WASC-15: Application Misconfiguration
                    .raise();
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(
                    "\tScan of record "
                            + id
                            + " took "
                            + (System.currentTimeMillis() - start)
                            + " ms");
        }
    }

    @Override
    public void setParent(PassiveScanThread passiveScanThread) {
        // Nothing to do.
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private static String getAlertAttribute(String key) {
        return Constant.messages.getString(MESSAGE_PREFIX + key);
    }
}
