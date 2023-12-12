/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class FetchMetadataRequestHeadersScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {
    private static final String FETCH_METADATA_REQUEST_MESSAGE_PREFIX =
            "pscanalpha.metadata-request-headers.";

    private enum VulnType {
        MISSING("missing."),
        INVALID_VALUES("invalid-values.");

        private final String i18nKey;

        private VulnType(String i18nKey) {
            this.i18nKey = i18nKey;
        }

        String getI18nKey() {
            return i18nKey;
        }
    }

    private static final String INVALID_VALUE = "invalid";
    private static final int PLUGIN_ID = 90005;
    private final List<FetchMetaDataRequestHeaders> rules =
            List.of(
                    new SecFetchSite(this::newAlert),
                    new SecFetchMode(this::newAlert),
                    new SecFetchDest(this::newAlert),
                    new SecFetchUser(this::newAlert));

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(CommonAlertTag.WSTG_V42_SESS_05_CSRF);

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        rules.forEach(
                rule ->
                        rule.build(msg.getRequestHeader(), rule.getHeader(), rule.getValidValues())
                                .forEach(AlertBuilder::raise));
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(FETCH_METADATA_REQUEST_MESSAGE_PREFIX + "name");
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();

        alerts.addAll(
                rules.stream().map(s -> s.getMissingAlert().build()).collect(Collectors.toList()));
        alerts.addAll(
                rules.stream()
                        .map(s -> s.getInvalidValuesAlert(INVALID_VALUE).build())
                        .collect(Collectors.toList()));

        return alerts;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    abstract static class FetchMetaDataRequestHeaders {
        private final Supplier<AlertBuilder> newAlert;
        private final String alertRefMissing;
        private final String alertRefInvalid;

        FetchMetaDataRequestHeaders(
                Supplier<AlertBuilder> newAlert, String alertRefMissing, String alertRefInvalid) {
            this.newAlert = newAlert;
            this.alertRefMissing = PLUGIN_ID + alertRefMissing;
            this.alertRefInvalid = PLUGIN_ID + alertRefInvalid;
        }

        protected abstract String getHeader();

        protected abstract String getString(String param);

        protected abstract List<String> getValidValues();

        protected AlertBuilder getMissingAlert() {
            return alert(VulnType.MISSING, "");
        }

        protected AlertBuilder getInvalidValuesAlert(String evidence) {
            return alert(VulnType.INVALID_VALUES, evidence);
        }

        List<AlertBuilder> build(
                HttpRequestHeader httpRequestHeaders, String header, List<String> valid_values) {
            List<AlertBuilder> alert = new ArrayList<>();
            List<HttpHeaderField> httpHeaderFields = httpRequestHeaders.getHeaders();

            boolean hasHeader =
                    httpHeaderFields.stream()
                            .anyMatch(
                                    httpHeaderField ->
                                            httpHeaderField.getName().equalsIgnoreCase(header));

            if (!hasHeader) {
                alert.add(this.getMissingAlert());
            } else {
                List<String> value = httpRequestHeaders.getHeaderValues(header);
                if (!valid_values.contains(value.get(0))) {
                    alert.add(this.getInvalidValuesAlert(value.get(0)));
                }
            }
            return alert;
        }

        protected AlertBuilder alert(VulnType vulnType, String evidence) {
            String i18nKey = vulnType.getI18nKey();
            return newAlert.get()
                    .setRisk(Alert.RISK_INFO)
                    .setConfidence(Alert.CONFIDENCE_HIGH)
                    .setParam(getHeader())
                    .setName(getString(i18nKey + "name"))
                    .setDescription(getString(i18nKey + "desc"))
                    .setSolution(getString(i18nKey + "soln"))
                    .setReference(getString(i18nKey + "refs"))
                    .setAlertRef(vulnType == VulnType.MISSING ? alertRefMissing : alertRefInvalid)
                    .setCweId(352)
                    .setWascId(9)
                    .setEvidence(evidence);
        }
    }

    static class SecFetchSite extends FetchMetaDataRequestHeaders {
        public static final String HEADER = "Sec-Fetch-Site";
        private static final String SFS_PREFIX_MESSAGE =
                FETCH_METADATA_REQUEST_MESSAGE_PREFIX + "sfs.";
        private static final List<String> VALID_VALUES =
                List.of("same-origin", "same-site", "cross-site", "none");

        SecFetchSite(Supplier<AlertBuilder> newAlert) {
            super(newAlert, "-1", "-5");
        }

        @Override
        protected String getHeader() {
            return HEADER;
        }

        @Override
        protected String getString(String param) {
            return Constant.messages.getString(SFS_PREFIX_MESSAGE + param);
        }

        @Override
        protected List<String> getValidValues() {
            return VALID_VALUES;
        }
    }

    static class SecFetchMode extends FetchMetaDataRequestHeaders {
        public static final String HEADER = "Sec-Fetch-Mode";
        private static final String SFM_PREFIX_MESSAGE =
                FETCH_METADATA_REQUEST_MESSAGE_PREFIX + "sfm.";
        private static final List<String> VALID_VALUES =
                List.of("cors", "no-cors", "navigate", "same-origin", "websocket");

        SecFetchMode(Supplier<AlertBuilder> newAlert) {
            super(newAlert, "-2", "-6");
        }

        @Override
        protected String getHeader() {
            return HEADER;
        }

        @Override
        protected String getString(String param) {
            return Constant.messages.getString(SFM_PREFIX_MESSAGE + param);
        }

        @Override
        protected List<String> getValidValues() {
            return VALID_VALUES;
        }
    }

    static class SecFetchDest extends FetchMetaDataRequestHeaders {
        public static final String HEADER = "Sec-Fetch-Dest";
        private static final String SFD_PREFIX_MESSAGE =
                FETCH_METADATA_REQUEST_MESSAGE_PREFIX + "sfd.";
        private static final List<String> VALID_VALUES =
                List.of(
                        "audio",
                        "audioworklet",
                        "document",
                        "embed",
                        "empty",
                        "font",
                        "frame",
                        "iframe",
                        "image",
                        "manifest",
                        "object",
                        "paintworklet",
                        "report",
                        "script",
                        "serviceworker",
                        "sharedworker",
                        "style",
                        "track",
                        "video",
                        "worker",
                        "xslt");

        SecFetchDest(Supplier<AlertBuilder> newAlert) {
            super(newAlert, "-3", "-7");
        }

        @Override
        protected String getHeader() {
            return HEADER;
        }

        @Override
        protected String getString(String param) {
            return Constant.messages.getString(SFD_PREFIX_MESSAGE + param);
        }

        @Override
        protected List<String> getValidValues() {
            return VALID_VALUES;
        }
    }

    static class SecFetchUser extends FetchMetaDataRequestHeaders {
        public static final String HEADER = "Sec-Fetch-User";
        private static final String SFU_PREFIX_MESSAGE =
                FETCH_METADATA_REQUEST_MESSAGE_PREFIX + "sfu.";
        private static final List<String> VALID_VALUES = List.of("?1");

        SecFetchUser(Supplier<AlertBuilder> newAlert) {
            super(newAlert, "-4", "-8");
        }

        @Override
        protected String getHeader() {
            return HEADER;
        }

        @Override
        protected String getString(String param) {
            return Constant.messages.getString(SFU_PREFIX_MESSAGE + param);
        }

        @Override
        protected List<String> getValidValues() {
            return VALID_VALUES;
        }
    }
}
