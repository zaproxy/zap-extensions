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
package org.zaproxy.addon.authhelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.AuthConstants;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.Pair;

/** Unit test for {@link VerificationDetectionScanRule}. */
class VerificationDetectionScanRuleUnitTest
        extends PassiveScannerTest<VerificationDetectionScanRule> {

    private static final Set<String> BASE_URLS =
            Set.of("https://www.example.com/%s", "ttps://www.example.com/?action=%s");

    @Override
    protected VerificationDetectionScanRule createScanner() {
        return new VerificationDetectionScanRule();
    }

    /* Provides URLs with poor candidate strings both as path components and query values */
    private static Stream<String> providePoorCandidates() {
        return BASE_URLS.stream()
                .flatMap(
                        url ->
                                Stream.concat(
                                                AuthConstants.getLogoutIndicators().stream(),
                                                AuthConstants.getRegistrationIndicators().stream())
                                        // Format the URL with the indicator
                                        .map(url::formatted));
    }

    @ParameterizedTest
    @MethodSource("providePoorCandidates")
    void shouldIgnorePoorCandidateUrl(String url) throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET %s HTTP/1.1".formatted(url));
        // When
        scanHttpResponseReceive(msg);
        // Then
        try (MockedStatic<AuthUtils> authUtilMock = mockStatic(AuthUtils.class)) {
            // Did not pass pre-conditions
            authUtilMock.verify(() -> AuthUtils.getRequestSessionTokens(any()), times(0));
        }
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "Blah",
                "text/css",
                "text/javascript",
                "image/png",
                "image/svg+xml",
                "font/ttf"
            })
    void shouldIgnoreUnknownOrUnwantedContentTypes(String contentType)
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/user/ HTTP/1.1");
        msg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, contentType);
        msg.getRequestHeader().setHeader(HttpHeader.REFERER, "https://www.example.com/");
        msg.setResponseBody("<html>User: jsmith</html>");
        msg.setResponseHeader(
                """
                HTTP/1.1 200 OK\r
                Server: Apache-Coyote/1.1\r
                Content-Type: text/html;charset=ISO-8859-1\r
                Content-Length: %s\r\n\r
                """
                        .formatted(msg.getResponseBody().length()));
        // When
        scanHttpResponseReceive(msg);
        // Then
        try (MockedStatic<AuthUtils> authUtilMock = mockStatic(AuthUtils.class)) {
            // Did not pass pre-conditions
            authUtilMock.verify(() -> AuthUtils.getRequestSessionTokens(any()), times(0));
        }
        assertThat(alertsRaised.size(), equalTo(0));
    }

    /* Provides URLs with misc candidate strings both as path components and query values */
    private static Stream<Arguments> providePotentialCandidates() {
        // Get a 'matrix' of the sets
        return BASE_URLS.stream()
                .flatMap(
                        url ->
                                Stream.concat(
                                                Set.of(
                                                                "query",
                                                                "update",
                                                                "1234",
                                                                "02a3f4ec-f3df-4aa0-a2bd-3fdcdb02aa55")
                                                        .stream()
                                                        .map(e -> new Pair<>(e, false)),
                                                // Low priority candidates
                                                AuthConstants.getLoginIndicators().stream()
                                                        .map(e -> new Pair<>(e, true)))
                                        // Format the URL with the component
                                        .map(e -> Arguments.of(url.formatted(e.first), e.second)));
    }

    @ParameterizedTest
    @MethodSource("providePotentialCandidates")
    void shouldVerifyPotentialCandidateUrl(String url, boolean lowPriority)
            throws HttpMalformedHeaderException {
        // Given
        String tokenName = "x-auth-header";
        String tokenValue = "fdb0f2d1-6f5c-4dd7-a829-e1cb7a114f23";
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET %s HTTP/1.1".formatted(url));
        msg.getRequestHeader().addHeader(tokenName, tokenValue);
        SessionToken testToken =
                new SessionToken(SessionToken.HEADER_SOURCE, tokenName, tokenValue);
        Context testContext = new Context(mock(Session.class), 1);
        testContext.setIncludeInContextRegexs(List.of("https?://www.example.com.*"));
        try (MockedStatic<AuthUtils> authUtilMock = mockStatic(AuthUtils.class)) {
            when(AuthUtils.isRelevantToAuth(any())).thenReturn(true);
            when(AuthUtils.getRequestSessionTokens(any())).thenReturn(Set.of(testToken));
            when(AuthUtils.getRelatedContexts(any())).thenReturn(List.of(testContext));
            when(AuthUtils.getVerificationDetailsForContext(testContext.getId()))
                    .thenReturn(new VerificationRequestDetails());
            // When
            scanHttpResponseReceive(msg);
            // Then
            ArgumentCaptor<Context> ctxCaptor = ArgumentCaptor.forClass(Context.class);
            ArgumentCaptor<VerificationRequestDetails> verifCaptor =
                    ArgumentCaptor.forClass(VerificationRequestDetails.class);
            ArgumentCaptor<VerificationDetectionScanRule> ruleCaptor =
                    ArgumentCaptor.forClass(VerificationDetectionScanRule.class);

            authUtilMock.verify(
                    () ->
                            AuthUtils.processVerificationDetails(
                                    ctxCaptor.capture(),
                                    verifCaptor.capture(),
                                    ruleCaptor.capture()),
                    times(1));
            assertThat(ctxCaptor.getValue(), is(sameInstance(testContext)));
            VerificationRequestDetails vrd = verifCaptor.getValue();
            assertThat(vrd.getContextId(), is(equalTo(1)));
            assertThat(vrd.getScore(), is(equalTo(2)));
            assertThat(vrd.getToken(), is(equalTo(tokenValue)));
            assertThat(vrd.isLowPriority(), is(equalTo(lowPriority)));
            assertThat(ruleCaptor.getValue(), is(sameInstance(rule)));
        }
    }
}
