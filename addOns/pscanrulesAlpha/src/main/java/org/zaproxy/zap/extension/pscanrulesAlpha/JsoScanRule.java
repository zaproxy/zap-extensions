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

import java.net.HttpCookie;
import java.util.Arrays;
import java.util.List;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/** Java Serialized Objects (JSO) scan rule. Detect the magic sequence and generate an alert */
public class JsoScanRule extends PluginPassiveScanner {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanalpha.jso.";

    private static final byte[] JSO_BYTE_MAGIC_SEQUENCE = {(byte) 0xac, (byte) 0xed, 0x00, 0x05};
    private static final String JSO_BASE_64_MAGIC_SEQUENCE = "rO0AB";
    private static final String JSO_URI_ENCODED_MAGIC_SEQUENCE = "%C2%AC%C3%AD%00%05";

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        checkJsoInQueryParameters(msg);

        checkJsoInHeaders(msg, msg.getRequestHeader().getHeaders());

        checkJsoInCookies(msg, msg.getRequestHeader().getHttpCookies());

        checkJsoInBody(msg, msg.getRequestBody());
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        checkJsoInHeaders(msg, msg.getResponseHeader().getHeaders());

        checkJsoInCookies(msg, msg.getResponseHeader().getHttpCookies(null));

        checkJsoInBody(msg, msg.getResponseBody());
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
                raiseAlert(msg, "");
            }
        }
    }

    private void checkJsoInBody(HttpMessage msg, HttpBody body) {
        byte[] startOfBody = Arrays.copyOfRange(body.getBytes(), 0, JSO_BYTE_MAGIC_SEQUENCE.length);
        if (Arrays.equals(JSO_BYTE_MAGIC_SEQUENCE, startOfBody)
                || hasJsoBase64MagicSequence(body.toString())) {
            raiseAlert(msg, "");
        }
    }

    private void checkJsoInCookies(HttpMessage msg, List<HttpCookie> cookies) {
        for (HttpCookie cookie : cookies) {
            String value = cookie.getValue();
            if (!hasJsoMagicSequence(value)) {
                continue;
            }

            raiseAlert(msg, cookie.toString());
        }
    }

    private void checkJsoInHeaders(HttpMessage msg, List<HttpHeaderField> headers) {
        for (HttpHeaderField header : headers) {
            String value = header.getValue();
            if (!hasJsoMagicSequence(value)) {
                continue;
            }

            raiseAlert(msg, header.toString());
        }
    }

    private void raiseAlert(HttpMessage msg, String evidence) {
        newAlert()
                .setRisk(Alert.RISK_MEDIUM)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getString("desc"))
                .setSolution(getString("soln"))
                .setReference(getString("refs"))
                .setEvidence(evidence)
                .setCweId(502) // CWE-502: Deserialization of Untrusted Data
                .raise();
    }

    private boolean hasJsoMagicSequence(String value) {
        return hasJsoBase64MagicSequence(value) || hasUriEncodedMagicSequence(value);
    }

    private boolean hasUriEncodedMagicSequence(String value) {
        return value.startsWith(JSO_URI_ENCODED_MAGIC_SEQUENCE);
    }

    private boolean hasJsoBase64MagicSequence(String value) {
        return value.startsWith(JSO_BASE_64_MAGIC_SEQUENCE);
    }

    private String getString(String param) {
        return Constant.messages.getString(MESSAGE_PREFIX + param);
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public String getName() {
        return getString("name");
    }

    @Override
    public int getPluginId() {
        return 90002;
    }
}
