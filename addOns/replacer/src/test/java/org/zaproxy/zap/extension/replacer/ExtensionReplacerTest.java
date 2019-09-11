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
package org.zaproxy.zap.extension.replacer;

import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.REQ_BODY_STR;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.REQ_HEADER;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.REQ_HEADER_STR;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.RESP_BODY_STR;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.RESP_HEADER;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.RESP_HEADER_STR;

public class ExtensionReplacerTest {

    private static final String MATCHING_STRING_WITH_HEX_BYTE =
            new String(new byte[] {'a', 'b', 'c', 1, 3, 2, 'd', 'e', 'f'});
    private static final String REPLACED_STRING_WITH_BINARY_VALUE =
            new String(new byte[] {'a', 'b', 'c', 1, 2, 3, 'd', 'e', 'f'});
    private HttpMessage msg;

    @Before
    public void setUp() {
        msg = new HttpMessage();
    }

    @Test
    public void shouldReplaceHeaderByHexValueInRequest() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer = given_a_hex_byte_replacement_rule_for(REQ_HEADER);

        msg.setRequestHeader("GET / HTTP/1.1\r\n" + "X-CUSTOM: " + MATCHING_STRING_WITH_HEX_BYTE);

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(
                msg.getRequestHeader().getHeader("abc\\x01\\x03\\x02def"),
                equalTo(REPLACED_STRING_WITH_BINARY_VALUE));
    }

    @Test
    public void shouldReplaceHexValueInRequestHeader() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer = given_a_hex_byte_replacement_rule_for(REQ_HEADER_STR);

        msg.setRequestHeader("GET / HTTP/1.1\r\n" + "X-CUSTOM: " + MATCHING_STRING_WITH_HEX_BYTE);

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(
                msg.getRequestHeader().getHeader("X-CUSTOM"),
                equalTo(REPLACED_STRING_WITH_BINARY_VALUE));
    }

    @Test
    public void shouldReplaceHexValueInRequestBody() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer = given_a_hex_byte_replacement_rule_for(REQ_BODY_STR);

        msg.setRequestHeader("POST / HTTP/1.1");
        msg.setRequestBody(MATCHING_STRING_WITH_HEX_BYTE);

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestBody().toString(), equalTo(REPLACED_STRING_WITH_BINARY_VALUE));
    }

    @Test
    public void shouldReplaceHeaderByHexValueInResponse() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer = given_a_hex_byte_replacement_rule_for(RESP_HEADER);

        msg.setRequestHeader("GET / HTTP/1.1\r\n" + "X-CUSTOM: " + MATCHING_STRING_WITH_HEX_BYTE);

        // When
        extensionReplacer.onHttpResponseReceive(msg, 0, null);

        // Then
        assertThat(
                msg.getResponseHeader().getHeader("abc\\x01\\x03\\x02def"),
                equalTo(REPLACED_STRING_WITH_BINARY_VALUE));
    }

    @Test
    public void shouldReplaceHexValueInResponseHeader() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                given_a_hex_byte_replacement_rule_for(RESP_HEADER_STR);

        msg.setResponseHeader("HTTP/1.1 200 OK\r\nX-CUSTOM: " + MATCHING_STRING_WITH_HEX_BYTE);

        // When
        extensionReplacer.onHttpResponseReceive(msg, 0, null);

        // Then
        assertThat(
                msg.getResponseHeader().getHeader("X-CUSTOM"),
                equalTo(REPLACED_STRING_WITH_BINARY_VALUE));
    }

    @Test
    public void shouldReplaceHexValueInResponseBody() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer = given_a_hex_byte_replacement_rule_for(RESP_BODY_STR);

        msg.setResponseHeader("HTTP/1.1 200 OK");
        msg.setResponseBody(MATCHING_STRING_WITH_HEX_BYTE);

        // When
        extensionReplacer.onHttpResponseReceive(msg, 0, null);

        // Then
        assertThat(msg.getResponseBody().toString(), equalTo(REPLACED_STRING_WITH_BINARY_VALUE));
    }

    private ExtensionReplacer given_a_hex_byte_replacement_rule_for(
            ReplacerParamRule.MatchType respHeaderStr) {
        ExtensionReplacer extensionReplacer = new ExtensionReplacer();
        ReplacerParamRule hexByteRegexRule =
                new ReplacerParamRule(
                        "",
                        respHeaderStr,
                        "abc\\x01\\x03\\x02def",
                        true,
                        "abc\\x01\\x02\\x03def",
                        null,
                        true);
        extensionReplacer.getParams().getRules().add(hexByteRegexRule);
        return extensionReplacer;
    }
}
