/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Spectre vulnerability has shown that Javascript code can be used to read any part of memory in
 * the same address space. Browser architectures are been redesigned to keep sensitive data outside
 * of the address space of untrusted code.
 *
 * <p>To achieve this, three headers have been added:
 *
 * <ul>
 *   <li>Cross-Origin-Resource-Policy:
 *   <li>Cross-Origin-Embedder-Policy: only allow resources that have enabled CORP ou CORS
 *   <li>Cross-Origin-Opener-Policy: allow sites to control browsing context group
 * </ul>
 *
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cross-Origin_Resource_Policy_(CORP)">CORP
 *     on MDN</a>
 * @see <a href="https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header">Specs</a>
 */
public class SiteIsolationScanRule extends PluginPassiveScanner {
    /** Prefix for internationalized messages used by this rule */
    private static final String SITE_ISOLATION_MESSAGE_PREFIX = "pscanalpha.site-isolation.";

    private static final int PLUGIN_ID = 90004;
    public static final String CROSS_ORIGIN_RESOURCE_POLICY_HEADER = "Cross-Origin-Resource-Policy";
    public static final String CROSS_ORIGIN_EMBEDDER_POLICY_HEADER = "Cross-Origin-Embedder-Policy";

    private final CorpHeaderScanner corpHeaderScanner = new CorpHeaderScanner(this::newAlert);
    private final CoepHeaderScanner coepHeaderScanner = new CoepHeaderScanner(this::newAlert);

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        // Specs don't state that errors pages should be excluded
        // However, successful responses are associated to a resource
        // that should be protected.
        // Only consider HTTP Status code 2XX to avoid a False Positive
        if (!HttpStatusCode.isSuccess(msg.getResponseHeader().getStatusCode())) {
            return;
        }

        corpHeaderScanner.check(msg.getResponseHeader());
        coepHeaderScanner.check(msg.getResponseHeader());
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public String getName() {
        return SITE_ISOLATION_MESSAGE_PREFIX + "name";
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<Alert>();
        alerts.add(corpHeaderScanner.alert("").build());
        alerts.add(coepHeaderScanner.alert("").build());
        return alerts;
    }

    static class CorpHeaderScanner {
        private static final String CORP_MESSAGE_PREFIX = SITE_ISOLATION_MESSAGE_PREFIX + "corp.";
        private final Supplier<AlertBuilder> newAlert;

        public CorpHeaderScanner(Supplier<AlertBuilder> newAlert) {
            this.newAlert = newAlert;
        }

        public void check(HttpResponseHeader responseHeader) {
            List<String> corpHeaders =
                    responseHeader.getHeaderValues(
                            SiteIsolationScanRule.CROSS_ORIGIN_RESOURCE_POLICY_HEADER);
            if (corpHeaders.isEmpty()) {
                alert("").raise();
            }
            for (String corpHeader : corpHeaders) {
                if ("same-site".equalsIgnoreCase(corpHeader)
                        || !("same-origin".equalsIgnoreCase(corpHeader)
                                || "cross-origin".equalsIgnoreCase(corpHeader))) {
                    alert(corpHeader).raise();
                }
            }
        }

        private String getCorpString(String param) {
            return Constant.messages.getString(CORP_MESSAGE_PREFIX + param);
        }

        AlertBuilder alert(String evidence) {
            return newAlert.get()
                    .setRisk(Alert.RISK_LOW)
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setParam(CROSS_ORIGIN_RESOURCE_POLICY_HEADER)
                    .setDescription(getCorpString("desc"))
                    .setSolution(getCorpString("soln"))
                    .setReference(getCorpString("refs"))
                    .setCweId(16) // CWE-16: Configuration
                    .setWascId(14) // WASC-14: Server Misconfiguration
                    .setEvidence(evidence);
        }
    }

    static class CoepHeaderScanner {
        private static final String COEP_MESSAGE_PREFIX = SITE_ISOLATION_MESSAGE_PREFIX + "coep.";

        private final Supplier<AlertBuilder> newAlert;

        public CoepHeaderScanner(Supplier<AlertBuilder> newAlert) {
            this.newAlert = newAlert;
        }

        public void check(HttpResponseHeader responseHeader) {
            List<String> coepHeaders =
                    responseHeader.getHeaderValues(
                            SiteIsolationScanRule.CROSS_ORIGIN_EMBEDDER_POLICY_HEADER);
            if (coepHeaders.isEmpty()) {
                alert("").raise();
            }
            for (String coepHeader : coepHeaders) {
                // unsafe-none is the default value
                if (!"require-corp".equalsIgnoreCase(coepHeader)) {
                    alert(coepHeader).raise();
                }
            }
        }

        private String getCoepString(String param) {
            return Constant.messages.getString(COEP_MESSAGE_PREFIX + param);
        }

        AlertBuilder alert(String evidence) {
            return newAlert.get()
                    .setRisk(Alert.RISK_LOW)
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setParam(CROSS_ORIGIN_EMBEDDER_POLICY_HEADER)
                    .setDescription(getCoepString("desc"))
                    .setSolution(getCoepString("soln"))
                    .setReference(getCoepString("refs"))
                    .setCweId(16) // CWE-16: Configuration
                    .setWascId(14) // WASC-14: Server Misconfiguration
                    .setEvidence(evidence);
        }
    }
}
