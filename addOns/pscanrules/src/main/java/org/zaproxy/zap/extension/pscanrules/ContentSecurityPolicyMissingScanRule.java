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
 *
 * @author kingthorin+owaspzap@gmail.com
 */
public class ContentSecurityPolicyMissingScanRule extends PluginPassiveScanner {

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
            newAlert()
                    .setRisk(Alert.RISK_MEDIUM)
                    .setConfidence(Alert.CONFIDENCE_HIGH)
                    .setDescription(getAlertAttribute("desc"))
                    .setSolution(getAlertAttribute("soln"))
                    .setReference(getAlertAttribute("refs"))
                    .setCweId(693) // CWE-693: Protection Mechanism Failure
                    .setWascId(15) // WASC-15: Application Misconfiguration
                    .raise();
        }

        if (hasObsoleteCspHeader(msg)) {
            newAlert()
                    .setName(getAlertAttribute("obs.name"))
                    .setRisk(Alert.RISK_INFO)
                    .setConfidence(Alert.CONFIDENCE_HIGH)
                    .setDescription(getAlertAttribute("obs.desc"))
                    .setSolution(getAlertAttribute("soln"))
                    .setReference(getAlertAttribute("refs"))
                    .setCweId(693) // CWE-693: Protection Mechanism Failure
                    .setWascId(15) // WASC-15: Application Misconfiguration
                    .raise();
        }

        if (hasCspReportOnlyHeader(msg)) {
            newAlert()
                    .setName(getAlertAttribute("ro.name"))
                    .setRisk(Alert.RISK_INFO)
                    .setConfidence(Alert.CONFIDENCE_HIGH)
                    .setDescription(getAlertAttribute("ro.desc"))
                    .setSolution(getAlertAttribute("soln"))
                    .setReference(getAlertAttribute("ro.refs"))
                    .setCweId(693) // CWE-693: Protection Mechanism Failure
                    .setWascId(15) // WASC-15: Application Misconfiguration
                    .raise();
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

    private boolean hasCspHeader(HttpMessage msg) {
        // Content-Security-Policy is supported by Chrome 25+, Firefox 23+, Safari 7+, but not but
        // Internet Exploder
        List<String> cspOptions =
                msg.getResponseHeader().getHeaderValues(HttpFieldsNames.CONTENT_SECURITY_POLICY);

        return !cspOptions.isEmpty();
    }

    private boolean hasObsoleteCspHeader(HttpMessage msg) {
        // X-Content-Security-Policy is an obsolete header, supported by Firefox 4.0+, and IE 10+
        // (in a limited fashion), but obsolete since Firefox 23+ and Chrome 25+
        List<String> xcspOptions =
                msg.getResponseHeader().getHeaderValues("X-Content-Security-Policy");

        // X-WebKit-CSP is an obsolete header, supported by Chrome 14+, and Safari 6+, but
        // obsolete since Firefox 23+ and Chrome 25+
        List<String> xwkcspOptions = msg.getResponseHeader().getHeaderValues("X-WebKit-CSP");

        return !xcspOptions.isEmpty() || !xwkcspOptions.isEmpty();
    }

    private boolean hasCspReportOnlyHeader(HttpMessage msg) {
        List<String> cspROOptions =
                msg.getResponseHeader().getHeaderValues("Content-Security-Policy-Report-Only");

        return !cspROOptions.isEmpty();
    }
}
