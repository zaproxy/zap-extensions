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

import java.net.*;
import java.nio.charset.*;
import java.util.*;
import net.htmlparser.jericho.*;
import org.parosproxy.paros.*;
import org.parosproxy.paros.core.scanner.*;
import org.parosproxy.paros.network.*;
import org.zaproxy.zap.extension.pscan.*;

/** Java Serialized Objects (JSO) scanner. Detect the magic sequence and generate an alarm */
public class JsoScanner extends PluginPassiveScanner {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanalpha.jso.";

    private static final byte[] JSO_BYTE_MAGIC_SEQUENCE = {(byte) 0xac, (byte) 0xed, 0x00, 0x05};
    private static final String JSO_BASE_64_MAGIC_SEQUENCE = "rO0AB";
    private PassiveScanThread parent;

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // do nothing
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        checkJsoInHeaders(msg);

        checkJsoInCookies(msg);

        checkJsoInBody(msg);
    }

    private void checkJsoInBody(HttpMessage msg) {
        byte[] startOfBody =
                Arrays.copyOfRange(
                        msg.getResponseBody().getBytes(), 0, JSO_BYTE_MAGIC_SEQUENCE.length);
        String startOfBodyAsString =
                new String(
                        Arrays.copyOfRange(
                                msg.getResponseBody().getBytes(),
                                0,
                                JSO_BASE_64_MAGIC_SEQUENCE.length()),
                        StandardCharsets.UTF_8);
        if (Arrays.equals(JSO_BYTE_MAGIC_SEQUENCE, startOfBody)
                || hasJsoBase64MagicSequence(startOfBodyAsString)) {
            Alert alert = buidAlert(msg, "");
            parent.raiseAlert(getPluginId(), alert);
        }
    }

    private void checkJsoInCookies(HttpMessage msg) {
        for (HttpCookie cookie : msg.getResponseHeader().getHttpCookies(null)) {
            String value = cookie.getValue();
            if (!hasJsoBase64MagicSequence(value)) {
                continue;
            }

            Alert alert = buidAlert(msg, cookie.toString());
            parent.raiseAlert(getPluginId(), alert);
        }
    }

    private boolean hasJsoBase64MagicSequence(String value) {
        return value.startsWith(JSO_BASE_64_MAGIC_SEQUENCE);
    }

    private void checkJsoInHeaders(HttpMessage msg) {
        for (HttpHeaderField header : msg.getResponseHeader().getHeaders()) {
            String value = header.getValue();
            if (!hasJsoBase64MagicSequence(value)) {
                continue;
            }

            Alert alert = buidAlert(msg, header.toString());
            parent.raiseAlert(getPluginId(), alert);
        }
    }

    private Alert buidAlert(HttpMessage msg, String evidence) {
        Alert alert =
                new Alert(getPluginId(), Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, getName());
        alert.setDetail(
                Constant.messages.getString(MESSAGE_PREFIX + "desc"),
                msg.getRequestHeader().getURI() + "",
                null,
                "",
                "",
                getString("soln"),
                getString("refs"),
                evidence,
                502, // CWE-502: Deserialization of Untrusted Data
                -1, // No WASC-ID
                msg);
        return alert;
    }

    private String getString(String param) {
        return Constant.messages.getString(MESSAGE_PREFIX + param, "");
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        this.parent = parent;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public int getPluginId() {
        return 90303;
    }
}
