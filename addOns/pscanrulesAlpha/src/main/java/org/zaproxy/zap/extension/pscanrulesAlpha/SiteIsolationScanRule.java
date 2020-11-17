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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Spectre vulnerability has shown that JavaScript code can be used to read any part of memory in
 * the same address space. Browser architectures are being <a href=
 * "https://chromium.googlesource.com/chromium/src/+/master/docs/security/side-channel-threat-model.md">re-thought</a>
 * to keep sensitive data outside of the address space of untrusted code.
 *
 * <p>To achieve this, three headers have been added:
 *
 * <ul>
 *   <li>Cross-Origin-Resource-Policy: opt-in mechanism for sharing resources
 *   <li>Cross-Origin-Embedder-Policy: only allow resources that have enabled CORP ou CORS
 *   <li>Cross-Origin-Opener-Policy: allow sites to control browsing context group
 * </ul>
 *
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cross-Origin_Resource_Policy_(CORP)">CORP
 *     on MDN</a>
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy">COEP
 *     on MDN</a>
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy">COOP
 *     on MDN</a>
 * @see <a href="https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header">COOP Specs</a>
 * @see <a href="https://html.spec.whatwg.org/multipage/origin.html#coep">COEP Specs</a>
 */
public class SiteIsolationScanRule extends PluginPassiveScanner {
    /** Prefix for internationalized messages used by this rule */
    private static final String SITE_ISOLATION_MESSAGE_PREFIX = "pscanalpha.site-isolation.";

    private static final int PLUGIN_ID = 90004;

    private final List<SiteIsolationHeaderScanRule> rules =
            Arrays.asList(
                    new CorpHeaderScanRule(this::newAlert),
                    new CoepHeaderScanRule(this::newAlert),
                    new CoopHeaderScanRule(this::newAlert));

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        // Specs don't state that errors pages should be excluded
        // However, successful responses are associated to a resource
        // that should be protected.
        // Only consider HTTP Status code 2XX to avoid a False Positive
        if (!HttpStatusCode.isSuccess(msg.getResponseHeader().getStatusCode())
                || getHelper().isPage200(msg)) {
            return;
        }

        rules.forEach(s -> s.build(msg.getResponseHeader()).forEach(AlertBuilder::raise));
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public String getName() {
        return Constant.messages.getString(SITE_ISOLATION_MESSAGE_PREFIX + "name");
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    public List<Alert> getExampleAlerts() {
        return rules.stream().map(s -> s.alert("").build()).collect(Collectors.toList());
    }

    abstract static class SiteIsolationHeaderScanRule {
        private final Supplier<AlertBuilder> newAlert;

        SiteIsolationHeaderScanRule(Supplier<AlertBuilder> newAlert) {
            this.newAlert = newAlert;
        }

        protected abstract String getHeader();

        protected abstract String getString(String param);

        abstract List<AlertBuilder> build(HttpResponseHeader responseHeader);

        protected boolean isDocument(HttpResponseHeader responseHeader) {
            return responseHeader.getHeaderValues(HttpHeader.CONTENT_TYPE).stream()
                    .anyMatch(
                            header ->
                                    header.startsWith("text/html")
                                            || header.startsWith("application/xml"));
        }

        protected AlertBuilder alert(String evidence) {
            return newAlert.get()
                    .setRisk(Alert.RISK_LOW)
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setParam(getHeader())
                    .setDescription(getString("desc"))
                    .setSolution(getString("soln"))
                    .setReference(getString("refs"))
                    .setCweId(16) // CWE-16: Configuration
                    .setWascId(14) // WASC-14: Server Misconfiguration
                    .setEvidence(evidence);
        }

        protected Stream<String> filterReportHeader(String coopHeader) {
            return Stream.of(coopHeader.split(";"))
                    .map(String::trim)
                    .filter(header -> !header.startsWith("report-to"));
        }
    }

    static class CorpHeaderScanRule extends SiteIsolationHeaderScanRule {
        public static final String HEADER = "Cross-Origin-Resource-Policy";
        private static final String CORP_MESSAGE_PREFIX = SITE_ISOLATION_MESSAGE_PREFIX + "corp.";
        public static final String CORS_PREFIX = "Access-Control-Allow-";

        CorpHeaderScanRule(Supplier<AlertBuilder> newAlert) {
            super(newAlert);
        }

        @Override
        List<AlertBuilder> build(HttpResponseHeader responseHeader) {
            boolean hasCorsHeader =
                    responseHeader.getHeaders().stream()
                            .anyMatch(header -> header.getName().startsWith(CORS_PREFIX));
            if (hasCorsHeader) {
                return Collections.emptyList();
            }

            List<String> corpHeaders = responseHeader.getHeaderValues(HEADER);
            if (corpHeaders.isEmpty()) {
                return Collections.singletonList(alert(""));
            }
            List<AlertBuilder> alerts = new ArrayList<>();
            for (String corpHeader : corpHeaders) {
                alerts.addAll(
                        filterReportHeader(corpHeader)
                                .filter(
                                        header ->
                                                "same-site".equalsIgnoreCase(header)
                                                        || !("same-origin".equalsIgnoreCase(header)
                                                                || "cross-origin"
                                                                        .equalsIgnoreCase(header)))
                                .map(this::alert)
                                .collect(Collectors.toList()));
            }
            return alerts;
        }

        @Override
        protected String getString(String param) {
            return Constant.messages.getString(CORP_MESSAGE_PREFIX + param);
        }

        @Override
        protected String getHeader() {
            return HEADER;
        }
    }

    static class CoepHeaderScanRule extends SiteIsolationHeaderScanRule {
        public static final String HEADER = "Cross-Origin-Embedder-Policy";
        private static final String COEP_MESSAGE_PREFIX = SITE_ISOLATION_MESSAGE_PREFIX + "coep.";

        CoepHeaderScanRule(Supplier<AlertBuilder> newAlert) {
            super(newAlert);
        }

        @Override
        List<AlertBuilder> build(HttpResponseHeader responseHeader) {
            if (!isDocument(responseHeader)) {
                return Collections.emptyList();
            }

            List<String> coepHeaders = responseHeader.getHeaderValues(HEADER);
            if (coepHeaders.isEmpty()) {
                return Collections.singletonList(alert(""));
            }

            List<AlertBuilder> alerts = new ArrayList<>();
            for (String coepHeader : coepHeaders) {
                // unsafe-none is the default value. It disables COEP checks.
                alerts.addAll(
                        filterReportHeader(coepHeader)
                                .filter(header -> !"require-corp".equalsIgnoreCase(header))
                                .map(this::alert)
                                .collect(Collectors.toList()));
            }
            return alerts;
        }

        @Override
        protected String getString(String param) {
            return Constant.messages.getString(COEP_MESSAGE_PREFIX + param);
        }

        @Override
        protected String getHeader() {
            return HEADER;
        }
    }

    static class CoopHeaderScanRule extends SiteIsolationHeaderScanRule {
        public static final String HEADER = "Cross-Origin-Opener-Policy";
        private static final String COOP_MESSAGE_PREFIX = SITE_ISOLATION_MESSAGE_PREFIX + "coop.";

        CoopHeaderScanRule(Supplier<AlertBuilder> newAlert) {
            super(newAlert);
        }

        @Override
        List<AlertBuilder> build(HttpResponseHeader responseHeader) {
            if (!isDocument(responseHeader)) {
                return Collections.emptyList();
            }

            List<String> coopHeaders = responseHeader.getHeaderValues(HEADER);
            if (coopHeaders.isEmpty()) {
                return Collections.singletonList(alert(""));
            }

            List<AlertBuilder> alerts = new ArrayList<>();
            for (String coopHeader : coopHeaders) {
                // unsafe-none is the default value
                alerts.addAll(
                        filterReportHeader(coopHeader)
                                .filter(header -> !"same-origin".equalsIgnoreCase(header))
                                .map(this::alert)
                                .collect(Collectors.toList()));
            }
            return alerts;
        }

        @Override
        protected String getString(String param) {
            return Constant.messages.getString(COOP_MESSAGE_PREFIX + param);
        }

        @Override
        protected String getHeader() {
            return HEADER;
        }
    }
}
