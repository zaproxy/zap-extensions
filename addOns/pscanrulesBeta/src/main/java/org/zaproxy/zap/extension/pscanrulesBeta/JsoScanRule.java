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
package org.zaproxy.zap.extension.pscanrulesBeta;

import java.net.HttpCookie;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/** Java Serialized Objects (JSO) scan rule. Detect the magic sequence and generate an alert */
public class JsoScanRule extends PluginPassiveScanner implements CommonPassiveScanRuleInfo {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanbeta.jso.";

    private static final byte[] JSO_BYTE_MAGIC_SEQUENCE = {(byte) 0xac, (byte) 0xed, 0x00, 0x05};
    private static final String JSO_BASE_64_MAGIC_SEQUENCE = "rO0AB";
    private static final String JSO_URI_ENCODED_MAGIC_SEQUENCE = "%C2%AC%C3%AD%00%05";
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN,
                    CommonAlertTag.OWASP_2017_A08_INSECURE_DESERIAL);

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        checkJsoInQueryParameters(msg);

        checkJsoInHeaders(msg.getRequestHeader().getHeaders());

        checkJsoInCookies(msg.getRequestHeader().getHttpCookies());

        checkJsoInBody(msg.getRequestBody());
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        checkJsoInHeaders(msg.getResponseHeader().getHeaders());

        checkJsoInCookies(msg.getResponseHeader().getHttpCookies(null));

        checkJsoInBody(msg.getResponseBody());
    }

    private void checkJsoInQueryParameters(HttpMessage msg) {
        String escapedURI = msg.getRequestHeader().getURI().getEscapedQuery();
        if (escapedURI == null) {
            return;
        }
        String[] params = escapedURI.split("&");
        for (String param : params) {
            String[] strings = param.split("=");
            if (strings.length <= 1) {
                continue;
            }
            String value = strings[1];
            if (hasUriEncodedMagicSequence(value) || hasJsoBase64MagicSequence(value)) {
                createAlert("").raise();
            }
        }
    }

    private void checkJsoInBody(HttpBody body) {
        byte[] startOfBody = Arrays.copyOfRange(body.getBytes(), 0, JSO_BYTE_MAGIC_SEQUENCE.length);
        if (Arrays.equals(JSO_BYTE_MAGIC_SEQUENCE, startOfBody)
                || hasJsoBase64MagicSequence(body.toString())) {
            createAlert("").raise();
        }
    }

    private void checkJsoInCookies(List<HttpCookie> cookies) {
        for (HttpCookie cookie : cookies) {
            String value = cookie.getValue();
            if (!hasJsoMagicSequence(value)) {
                continue;
            }

            createAlert(cookie.toString()).raise();
        }
    }

    private void checkJsoInHeaders(List<HttpHeaderField> headers) {
        for (HttpHeaderField header : headers) {
            String value = header.getValue();
            if (!hasJsoMagicSequence(value)) {
                continue;
            }

            createAlert(header.toString()).raise();
        }
    }

    private AlertBuilder createAlert(String evidence) {
        return newAlert()
                .setRisk(Alert.RISK_MEDIUM)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getString("desc"))
                .setSolution(getString("soln"))
                .setReference(getString("refs"))
                .setEvidence(evidence)
                .setCweId(502); // CWE-502: Deserialization of Untrusted Data
    }

    private boolean hasJsoMagicSequence(String value) {
        return hasJsoBase64MagicSequence(value) || hasUriEncodedMagicSequence(value);
    }

    private static boolean hasUriEncodedMagicSequence(String value) {
        return value.startsWith(JSO_URI_ENCODED_MAGIC_SEQUENCE);
    }

    private static boolean hasJsoBase64MagicSequence(String value) {
        return value.startsWith(JSO_BASE_64_MAGIC_SEQUENCE);
    }

    private static String getString(String param) {
        return Constant.messages.getString(MESSAGE_PREFIX + param);
    }

    @Override
    public String getName() {
        return getString("name");
    }

    @Override
    public int getPluginId() {
        return 90002;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                createAlert(
                                "[Name=X-Custom-Info, Value=rO0ABXNyAEVvcmcuemFwcm94eS56YXAuZXh0ZW5zaW9uLnBzY2FucnVsZXNCZXRhLkpzb1NjYW5SdWxlVW5pdFRlc3QkQW5PYmplY3QAAAAAAAAAAQIAAHhw]")
                        .build());
    }
}
