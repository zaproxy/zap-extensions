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

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.REQ_BODY_STR;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.REQ_HEADER;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.REQ_HEADER_STR;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.RESP_BODY_STR;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.RESP_HEADER;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.RESP_HEADER_STR;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

class ExtensionReplacerTest {

    private static final String MATCHING_STRING_WITH_HEX_VALUE =
            new String(new byte[] {'a', 'b', 'c', 1, 3, 2, 'd', 'e', 'f'}, US_ASCII);
    private static final String REPLACED_STRING_WITH_BINARY_VALUE =
            new String(new byte[] {'a', 'b', 'c', 1, 2, 3, 'd', 'e', 'f'}, US_ASCII);
    private HttpMessage msg;

    @BeforeEach
    void setUp() {
        msg = new HttpMessage();
    }

    @Test
    void shouldAddHeaderByHexValueInRequest() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer = givenAHexByteReplacementRuleFor(REQ_HEADER);

        msg.setRequestHeader("GET / HTTP/1.1\r\n");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(
                msg.getRequestHeader().getHeader("abc\\x01\\x03\\x02def"),
                equalTo(REPLACED_STRING_WITH_BINARY_VALUE));
    }

    @Test
    void shouldReplaceHexValueInRequestHeader() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer = givenAHexByteReplacementRuleFor(REQ_HEADER_STR);

        msg.setRequestHeader("GET / HTTP/1.1\r\n" + "X-CUSTOM: " + MATCHING_STRING_WITH_HEX_VALUE);

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(
                msg.getRequestHeader().getHeader("X-CUSTOM"),
                equalTo(REPLACED_STRING_WITH_BINARY_VALUE));
    }

    @Test
    void shouldReplaceHexValueInRequestBody() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer = givenAHexByteReplacementRuleFor(REQ_BODY_STR);

        msg.setRequestHeader("POST / HTTP/1.1");
        msg.setRequestBody(MATCHING_STRING_WITH_HEX_VALUE);

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestBody().toString(), equalTo(REPLACED_STRING_WITH_BINARY_VALUE));
    }

    @Test
    void shouldReplaceHeaderByHexValueInResponse() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer = givenAHexByteReplacementRuleFor(RESP_HEADER);

        msg.setRequestHeader("GET / HTTP/1.1\r\n" + "X-CUSTOM: " + MATCHING_STRING_WITH_HEX_VALUE);

        // When
        extensionReplacer.onHttpResponseReceive(msg, 0, null);

        // Then
        assertThat(
                msg.getResponseHeader().getHeader("abc\\x01\\x03\\x02def"),
                equalTo(REPLACED_STRING_WITH_BINARY_VALUE));
    }

    @Test
    void shouldReplaceHexValueInResponseHeader() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer = givenAHexByteReplacementRuleFor(RESP_HEADER_STR);

        msg.setResponseHeader("HTTP/1.1 200 OK\r\nX-CUSTOM: " + MATCHING_STRING_WITH_HEX_VALUE);

        // When
        extensionReplacer.onHttpResponseReceive(msg, 0, null);

        // Then
        assertThat(
                msg.getResponseHeader().getHeader("X-CUSTOM"),
                equalTo(REPLACED_STRING_WITH_BINARY_VALUE));
    }

    @Test
    void shouldReplaceHexValueInResponseBody() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer = givenAHexByteReplacementRuleFor(RESP_BODY_STR);

        msg.setResponseHeader("HTTP/1.1 200 OK");
        msg.setResponseBody(MATCHING_STRING_WITH_HEX_VALUE);

        // When
        extensionReplacer.onHttpResponseReceive(msg, 0, null);

        // Then
        assertThat(msg.getResponseBody().toString(), equalTo(REPLACED_STRING_WITH_BINARY_VALUE));
    }

    private static ExtensionReplacer givenAHexByteReplacementRuleFor(
            ReplacerParamRule.MatchType matchType) {
        ExtensionReplacer extensionReplacer = new ExtensionReplacer();
        ReplacerParamRule hexByteRegexRule =
                new ReplacerParamRule(
                        "",
                        matchType,
                        "abc\\x01\\x03\\x02def",
                        true,
                        "abc\\x01\\x02\\x03def",
                        null,
                        true);
        extensionReplacer.getParams().getRules().add(hexByteRegexRule);
        return extensionReplacer;
    }
}
