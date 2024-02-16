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

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Content Security Policy Header Missing passive scan rule
 * https://github.com/zaproxy/zaproxy/issues/1169
 */
public class ContentSecurityPolicyMissingScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    private static final String MESSAGE_PREFIX = "pscanrules.contentsecuritypolicymissing.";
    private static final int PLUGIN_ID = 10038;

    private static final Logger LOGGER =
            LogManager.getLogger(ContentSecurityPolicyMissingScanRule.class);
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG);

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        long start = System.currentTimeMillis();

        if ((!msg.getResponseHeader().isHtml()
                        || HttpStatusCode.isRedirection(msg.getResponseHeader().getStatusCode()))
                && !AlertThreshold.LOW.equals(this.getAlertThreshold())) {
            // Only really applies to HTML responses, but also check on Low threshold
            return;
        }

        if (!hasCspHeader(msg) && !CspUtils.hasMetaCsp(source)) {
            alertMissingCspHeader().raise();
        }

        if (hasObsoleteCspHeader(msg)) {
            alertObsoleteCspHeader().raise();
        }

        if (hasCspReportOnlyHeader(msg)) {
            alertCspReportOnlyHeader().raise();
        }

        LOGGER.debug("\tScan of record {} took {}ms", id, System.currentTimeMillis() - start);
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return getAlertAttribute("name");
    }

    private String getAlertAttribute(String key) {
        return Constant.messages.getString(MESSAGE_PREFIX + key);
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return Arrays.asList(
                alertMissingCspHeader().setUri("https://www.example.com").build(),
                alertObsoleteCspHeader().setUri("https://www.example.com").build(),
                alertCspReportOnlyHeader().setUri("https://www.example.com").build());
    }

    private static boolean hasCspHeader(HttpMessage msg) {
        return !msg.getResponseHeader()
                .getHeaderValues(HttpFieldsNames.CONTENT_SECURITY_POLICY)
                .isEmpty();
    }

    private static boolean hasObsoleteCspHeader(HttpMessage msg) {
        return !msg.getResponseHeader().getHeaderValues("X-Content-Security-Policy").isEmpty()
                || !msg.getResponseHeader().getHeaderValues("X-WebKit-CSP").isEmpty();
    }

    private static boolean hasCspReportOnlyHeader(HttpMessage msg) {
        return !msg.getResponseHeader()
                .getHeaderValues("Content-Security-Policy-Report-Only")
                .isEmpty();
    }

    private AlertBuilder buildAlert(int risk, int alertNum) {
        return newAlert()
                .setRisk(risk)
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setCweId(693) // CWE-693: Protection Mechanism Failure
                .setWascId(15) // WASC-15: Application Misconfiguration
                .setSolution(getAlertAttribute("soln"))
                .setReference(getAlertAttribute("refs"))
                .setAlertRef(PLUGIN_ID + "-" + alertNum);
    }

    private AlertBuilder alertMissingCspHeader() {
        return buildAlert(Alert.RISK_MEDIUM, 1).setDescription(getAlertAttribute("desc"));
    }

    private AlertBuilder alertObsoleteCspHeader() {
        return buildAlert(Alert.RISK_INFO, 2)
                .setName(getAlertAttribute("obs.name"))
                .setDescription(getAlertAttribute("obs.desc"));
    }

    private AlertBuilder alertCspReportOnlyHeader() {
        return buildAlert(Alert.RISK_INFO, 3)
                .setName(getAlertAttribute("ro.name"))
                .setDescription(getAlertAttribute("ro.desc"))
                .setReference(getAlertAttribute("ro.refs"));
    }
}
