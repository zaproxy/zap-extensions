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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.matchesRegex;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.REQ_BODY_STR;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.REQ_HEADER;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.REQ_HEADER_STR;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.RESP_BODY_STR;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.RESP_HEADER;
import static org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType.RESP_HEADER_STR;

import java.util.Map;
import java.util.regex.PatternSyntaxException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

class ExtensionReplacerTest {

    private static final String MATCHING_STRING_WITH_HEX_VALUE =
            new String(new byte[] {'a', 'b', 'c', 1, 3, 2, 'd', 'e', 'f'}, US_ASCII);
    private static final String REPLACED_STRING_WITH_BINARY_VALUE =
            new String(new byte[] {'a', 'b', 'c', 1, 2, 3, 'd', 'e', 'f'}, US_ASCII);
    private HttpMessage msg;

    private ExtensionReplacer extensionReplacer;

    @BeforeEach
    void setUp() throws Exception {
        msg = new HttpMessage();
        msg.setRequestHeader("GET https://example.com/ HTTP/1.1");

        extensionReplacer = new ExtensionReplacer();
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldSetEmptyAndNullUrl(String url) {
        // Given
        ReplacerParamRule rule = new ReplacerParamRule();
        // When
        rule.setUrl(url);
        // Then
        assertThat(rule.getUrl(), equalTo(""));
    }

    @Test
    void shouldSetValidUrlRegex() {
        // Given
        ReplacerParamRule rule = new ReplacerParamRule();
        String url = " a .* b ";
        // When
        rule.setUrl(url);
        // Then
        assertThat(rule.getUrl(), equalTo(url));
    }

    @Test
    void shouldThrowForInvalidUrlRegex() {
        // Given
        ReplacerParamRule rule = new ReplacerParamRule();
        // When
        assertThrows(PatternSyntaxException.class, () -> rule.setUrl("*"));
        // Then
        assertThat(rule.getUrl(), equalTo(""));
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://subdomain.example.com/", "https://example.org/"})
    void shouldMatchAllUrlsIfUrlEmpty(String targetUrl) {
        // Given
        ReplacerParamRule rule = new ReplacerParamRule();
        // When
        boolean matches = rule.matchesUrl(targetUrl);
        // Then
        assertThat(matches, equalTo(true));
    }

    @ParameterizedTest
    @CsvSource({
        "https://subdomain.example.com/,true",
        "https://example.org/,true",
        "http://example.org/,false",
        "http://subdomain.example.com, false"
    })
    void shouldMatchUrlRegex(String targetUrl, boolean expectedMatch) {
        // Given
        ReplacerParamRule rule = new ReplacerParamRule();
        rule.setUrl("^https://([^.]+\\.)?example\\.(com|org).*");
        // When
        boolean matches = rule.matchesUrl(targetUrl);
        // Then
        assertThat(matches, equalTo(expectedMatch));
    }

    @Test
    void shouldReplaceHostHeaderInRequest() throws HttpMalformedHeaderException {
        // Given
        msg.setRequestHeader("GET / HTTP/1.1\r\n" + hostHeader("x"));
        String replacement = "y";
        replacerRule(REQ_HEADER, HttpRequestHeader.HOST, replacement);

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(
                msg.getRequestHeader().getHeader(HttpRequestHeader.HOST), is(equalTo(replacement)));
        assertHostNormalizationDisabled(msg);
    }

    private void replacerRule(
            ReplacerParamRule.MatchType matchType, String matchString, String replacement) {
        extensionReplacer
                .getParams()
                .getRules()
                .add(
                        new ReplacerParamRule(
                                "", matchType, matchString, false, replacement, null, true));
    }

    private static String hostHeader(String value) {
        return HttpRequestHeader.HOST + ": " + value;
    }

    private static void assertHostNormalizationDisabled(HttpMessage msg) {
        @SuppressWarnings("unchecked")
        Map<String, Object> userObject = (Map<String, Object>) msg.getUserObject();
        assertThat(userObject, hasEntry("host.normalization", Boolean.FALSE));
    }

    @Test
    void shouldRemoveHostHeaderInRequest() throws HttpMalformedHeaderException {
        // Given
        msg.setRequestHeader("GET / HTTP/1.1\r\n" + hostHeader("x"));
        replacerRule(REQ_HEADER, HttpRequestHeader.HOST, "");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestHeader().getHeader(HttpRequestHeader.HOST), is(nullValue()));
        assertHostNormalizationDisabled(msg);
    }

    @Test
    void shouldReplaceHostHeaderInRequestHeader() throws HttpMalformedHeaderException {
        // Given
        String hostHeader = hostHeader("x");
        msg.setRequestHeader("GET / HTTP/1.1\r\n" + hostHeader);
        String replacement = "y";
        replacerRule(REQ_HEADER_STR, hostHeader, hostHeader(replacement));

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(
                msg.getRequestHeader().getHeader(HttpRequestHeader.HOST), is(equalTo(replacement)));
        assertHostNormalizationDisabled(msg);
    }

    @Test
    void shouldRemoveHostHeaderInRequestHeader() throws HttpMalformedHeaderException {
        // Given
        String hostHeader = hostHeader("x");
        msg.setRequestHeader("GET / HTTP/1.1\r\n" + hostHeader);
        replacerRule(REQ_HEADER_STR, hostHeader, "");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestHeader().getHeader(HttpRequestHeader.HOST), is(nullValue()));
        assertHostNormalizationDisabled(msg);
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

    @Test
    void shouldNotReplacePartialTokenValueInRequestHeader() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(REQ_HEADER_STR, "_TEST_", "}}");

        msg.setRequestHeader("GET / HTTP/1.1\r\nX-CUSTOM: _TEST_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestHeader().getHeader("X-CUSTOM"), equalTo("}}"));
    }

    @Test
    void shouldNotReplacePartialTokenValueInRequestBody() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(REQ_BODY_STR, "_TEST_", "}}");

        msg.setRequestHeader("POST / HTTP/1.1");
        msg.setRequestBody("_TEST_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestBody().toString(), equalTo("}}"));
    }

    @Test
    void shouldNotReplaceOpenTokenValueInRequestHeader() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(REQ_HEADER_STR, "_TEST_", "{{");

        msg.setRequestHeader("GET / HTTP/1.1\r\nX-CUSTOM: _TEST_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestHeader().getHeader("X-CUSTOM"), equalTo("{{"));
    }

    @Test
    void shouldNotReplaceOpenTokenValueInRequestBody() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(REQ_BODY_STR, "_TEST_", "{{");

        msg.setRequestHeader("POST / HTTP/1.1");
        msg.setRequestBody("_TEST_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestBody().toString(), equalTo("{{"));
    }

    @Test
    void shouldNotReplaceMalformedTokenValueInRequestHeader() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(REQ_HEADER_STR, "_TEST_", "{{MALFORMED}}");

        msg.setRequestHeader("GET / HTTP/1.1\r\nX-CUSTOM: _TEST_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestHeader().getHeader("X-CUSTOM"), equalTo("{{MALFORMED}}"));
    }

    @Test
    void shouldNotReplaceMalformedTokenValueInRequestBody() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(REQ_BODY_STR, "_TEST_", "{{MALFORMED}}");

        msg.setRequestHeader("POST / HTTP/1.1");
        msg.setRequestBody("_TEST_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestBody().toString(), equalTo("{{MALFORMED}}"));
    }

    @Test
    void shouldNotReplaceMalformedRINTTokenValueInRequestHeader()
            throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(
                        REQ_HEADER_STR, "_TEST_", "{{RINT|ABC|DEF}}");

        msg.setRequestHeader("GET / HTTP/1.1\r\nX-CUSTOM: _TEST_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestHeader().getHeader("X-CUSTOM"), equalTo("{{RINT|ABC|DEF}}"));
    }

    @Test
    void shouldNotReplaceMalformedRINTTokenValueInRequestBody()
            throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(REQ_BODY_STR, "_TEST_", "{{RINT|ABC|DEF}}");

        msg.setRequestHeader("POST / HTTP/1.1");
        msg.setRequestBody("_TEST_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestBody().toString(), equalTo("{{RINT|ABC|DEF}}"));
    }

    @Test
    void shouldReplaceMultipleTokenValuesInRequestHeader() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(
                        REQ_HEADER_STR, "_TEST_", "First: {{RINT|ABC|DEF}}, Second: {{RINT|9}}");

        msg.setRequestHeader("GET / HTTP/1.1\r\nX-CUSTOM: _TEST_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(
                msg.getRequestHeader().getHeader("X-CUSTOM"),
                matchesRegex("First: \\{\\{RINT\\|ABC\\|DEF\\}\\}, Second: [0-9]"));
    }

    @Test
    void shouldReplaceMultipleTokenValuesInRequestBody() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(
                        REQ_BODY_STR, "_TEST_", "First: {{RINT|ABC|DEF}}, Second: {{RINT|9}}");

        msg.setRequestHeader("POST / HTTP/1.1");
        msg.setRequestBody("_TEST_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(
                msg.getRequestBody().toString(),
                matchesRegex("First: \\{\\{RINT\\|ABC\\|DEF\\}\\}, Second: [0-9]"));
    }

    @Test
    void shouldReplaceTokenRINTValueInRequestHeader() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(REQ_HEADER_STR, "_INT_", "{{RINT}}");

        msg.setRequestHeader("GET / HTTP/1.1\r\nX-CUSTOM: _INT_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestHeader().getHeader("X-CUSTOM"), matchesRegex("^[0-9]+$"));
    }

    @Test
    void shouldReplaceTokenRINTValueWithMaxInRequestHeader() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(REQ_HEADER_STR, "_INT_MAX_", "{{RINT|9}}");

        msg.setRequestHeader("GET / HTTP/1.1\r\nX-CUSTOM: _INT_MAX_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestHeader().getHeader("X-CUSTOM"), matchesRegex("^[0-9]$"));
    }

    @Test
    void shouldReplaceTokenRINTValueWithMinMaxInRequestHeader()
            throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(
                        REQ_HEADER_STR, "_INT_MINMAX_", "{{RINT|5|9}}");

        msg.setRequestHeader("GET / HTTP/1.1\r\nX-CUSTOM: _INT_MINMAX_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestHeader().getHeader("X-CUSTOM"), matchesRegex("^[5-9]$"));
    }

    @Test
    void shouldReplaceTokenRINTValueInRequestBody() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(REQ_BODY_STR, "_INT_", "{{RINT}}");

        msg.setRequestHeader("POST / HTTP/1.1\r\n");
        msg.setRequestBody("_INT_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestBody().toString(), matchesRegex("^[0-9]+$"));
    }

    @Test
    void shouldReplaceTokenRINTValueWithMaxInRequestBody() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(REQ_BODY_STR, "_INT_MAX_", "{{RINT|9}}");

        msg.setRequestHeader("POST / HTTP/1.1\r\n");
        msg.setRequestBody("_INT_MAX_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestBody().toString(), matchesRegex("^[0-9]$"));
    }

    @Test
    void shouldReplaceTokenRINTValueWithMinMaxInRequestBody() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(
                        REQ_BODY_STR, "_INT_MINMAX_", "{{RINT|5|9}}");

        msg.setRequestHeader("POST / HTTP/1.1\r\n");
        msg.setRequestBody("_INT_MINMAX_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestBody().toString(), matchesRegex("^[5-9]$"));
    }

    @Test
    void shouldReplaceTokenUUIDValueInRequestHeader() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(REQ_HEADER_STR, "_UUID_", "{{UUID}}");

        msg.setRequestHeader("GET / HTTP/1.1\r\nX-CUSTOM: _UUID_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestHeader().getHeader("X-CUSTOM"), matchesRegex("^[a-z0-9-]+$"));
    }

    @Test
    void shouldReplaceTokenUUIDValueInRequestBody() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(REQ_BODY_STR, "_UUID_", "{{UUID}}");

        msg.setRequestHeader("POST / HTTP/1.1");
        msg.setRequestBody("_UUID_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestBody().toString(), matchesRegex("^[a-z0-9-]+$"));
    }

    @Test
    void shouldReplaceTokenTicksValueInRequestHeader() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(REQ_HEADER_STR, "_TICKS_", "{{TICKS}}");

        msg.setRequestHeader("GET / HTTP/1.1\r\nX-CUSTOM: _TICKS_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestHeader().getHeader("X-CUSTOM"), matchesRegex("^[0-9]+$"));
    }

    @Test
    void shouldNotReplaceTokenTicksValueInRequestHeader() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenANormalProcessingReplacementRuleFor(REQ_HEADER_STR, "_TICKS_", "--TICKS--");

        msg.setRequestHeader("GET / HTTP/1.1\r\nX-CUSTOM: _TICKS_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestHeader().getHeader("X-CUSTOM"), equalTo("--TICKS--"));
    }

    @Test
    void shouldReplaceTokenTicksValueInRequestBody() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenATokenProcessingReplacementRuleFor(REQ_BODY_STR, "_TICKS_", "{{TICKS}}");

        msg.setRequestHeader("POST / HTTP/1.1");
        msg.setRequestBody("_TICKS_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestBody().toString(), matchesRegex("^[0-9]+$"));
    }

    @Test
    void shouldNotReplaceTokenTicksValueInRequestBody() throws HttpMalformedHeaderException {
        // Given
        ExtensionReplacer extensionReplacer =
                givenANormalProcessingReplacementRuleFor(REQ_BODY_STR, "_TICKS_", "--TICKS--");

        msg.setRequestHeader("POST / HTTP/1.1");
        msg.setRequestBody("_TICKS_");

        // When
        extensionReplacer.onHttpRequestSend(msg, 0, null);

        // Then
        assertThat(msg.getRequestBody().toString(), equalTo("--TICKS--"));
    }

    @Test
    void shouldReplaceReportToHeaderValuesInResponse() throws HttpMalformedHeaderException {
        // Given
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Security-Policy-Report-Only: require-trusted-types-for 'script'; report-to https://csp.withgoogle.com/csp/apps-themes\r\n"
                        + "Cross-Origin-Resource-Policy: cross-origin\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin; report-to=\"apps-themes\"\r\n"
                        + "Report-To: {\"group\":\"apps-themes\",\"max_age\":2592000,\"endpoints\":[{\"url\":\"https://csp.withgoogle.com/csp/report-to/apps-themes\"}]}");
        extensionReplacer.getParams().getRule(ReplacerParam.REPORT_TO_DESC);
        extensionReplacer
                .getParams()
                .getRules()
                .add(
                        new ReplacerParamRule(
                                ReplacerParam.REPORT_TO_DESC,
                                ReplacerParamRule.MatchType.RESP_HEADER_STR,
                                ReplacerParam.REPORT_TO_REGEX,
                                true,
                                ReplacerParam.REPORT_TO_REPLACEMENT,
                                null,
                                true));
        // When
        extensionReplacer.onHttpResponseReceive(msg, 0, null);
        // Then
        assertThat(
                msg.getResponseHeader().getHeader("Cross-Origin-Opener-Policy"),
                containsString(ReplacerParam.REPORT_TO_REPLACEMENT));
        assertThat(
                msg.getResponseHeader().getHeader("Cross-Origin-Opener-Policy"),
                not(containsString("report-to")));
        assertThat(
                msg.getResponseHeader().getHeader("Content-Security-Policy-Report-Only"),
                containsString(ReplacerParam.REPORT_TO_REPLACEMENT));
        assertThat(
                msg.getResponseHeader().getHeader("Content-Security-Policy-Report-Only"),
                not(containsString("report-to")));
        assertThat(msg.getResponseHeader().getHeader("Report-To"), is(nullValue()));
        assertThat(
                msg.getResponseHeader().getHeader(ReplacerParam.REPORT_TO_REPLACEMENT),
                is(not(nullValue())));
    }

    private static ExtensionReplacer givenATokenProcessingReplacementRuleFor(
            ReplacerParamRule.MatchType matchType, String match, String replacement)
            throws HttpMalformedHeaderException {
        ExtensionReplacer extensionReplacer = new ExtensionReplacer();

        ReplacerParamRule TokenProcessingReplacementRule =
                new ReplacerParamRule(
                        "", "", matchType, match, false, replacement, null, true, true);

        extensionReplacer.getParams().getRules().add(TokenProcessingReplacementRule);

        return extensionReplacer;
    }

    private static ExtensionReplacer givenANormalProcessingReplacementRuleFor(
            ReplacerParamRule.MatchType matchType, String match, String replacement) {

        ExtensionReplacer extensionReplacer = new ExtensionReplacer();

        ReplacerParamRule TokenProcessingReplacementRule =
                new ReplacerParamRule("", matchType, match, false, replacement, null, true);

        extensionReplacer.getParams().getRules().add(TokenProcessingReplacementRule);

        return extensionReplacer;
    }
}
