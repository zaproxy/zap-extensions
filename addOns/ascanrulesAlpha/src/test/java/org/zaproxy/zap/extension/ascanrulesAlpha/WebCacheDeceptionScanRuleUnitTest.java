/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import fi.iki.elonen.NanoHTTPD;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

class WebCacheDeceptionScanRuleUnitTest extends ActiveScannerTest<WebCacheDeceptionScanRule> {

    private static final String RESPONSE_BODY =
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec mattis ex ac orci consectetur viverra. Aenean porttitor tincidunt ligula. Suspendisse et ornare justo. Fusce vel maximus est. Donec id arcu nec justo egestas hendrerit. Sed pulvinar ultrices ultricies. Mauris ultrices odio non tellus mattis, id pharetra justo porta. Donec venenatis ante ac nisi blandit gravida. Nunc tellus dolor, finibus nec placerat ac, ullamcorper sit amet tellus.";

    private static final String AUTHORISED_RESPONSE =
            String.format(
                    "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                            + "<html><head></head><body>%s</body></html>",
                    RESPONSE_BODY);

    private static final String LONG_AUTHORISED_RESPONSE =
            String.format(
                    "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                            + "<html><head></head><body>%s</body></html>",
                    StringUtils.repeat(RESPONSE_BODY, 100));

    private static final String UNAUTHORISED_RESPONSE =
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                    + "<html><head></head><body>Lorem ipsum</body></html>";

    private static final String NOT_FOUND_RESPONSE =
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                    + "<html><head></head><body>404 NOT FOUND</body></html>";

    @Override
    protected WebCacheDeceptionScanRule createScanner() {
        return new WebCacheDeceptionScanRule();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "/"})
    void shouldSendRequestsWithExpectedPath(String basePath) throws Exception {
        // Given
        HttpMessage message = this.getHttpMessage(basePath);
        HttpRequestHeader headers = message.getRequestHeader();
        headers.addHeader("authorization", "Basic YWxhZGRpbjpvcGVuc2VzYW1l");
        message.setRequestHeader(headers);
        nano.addHandler(new CachedTestResponse(basePath, "authorization"));
        rule.init(message, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(nano.getRequestedUris(), hasItems("/", "/test", "/test.css"));
    }

    @Test
    void shouldAlertIfResponseGetsCached() throws Exception {
        // Given
        HttpMessage message = this.getHttpMessage("/private");
        HttpRequestHeader headers = message.getRequestHeader();
        headers.addHeader("authorization", "Basic YWxhZGRpbjpvcGVuc2VzYW1l");
        message.setRequestHeader(headers);
        nano.addHandler(new CachedTestResponse("/private", "authorization"));
        rule.init(message, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals("/test.css,/test.js,/test.gif,/test.png,/test.svg,", alert.getAttack());
    }

    @ParameterizedTest
    @ValueSource(ints = {403, 404, 500})
    void shouldNotTestIfOriginalResponseWasError(int status) throws Exception {
        // Given
        HttpMessage message = this.getHttpMessage("/private");
        HttpRequestHeader headers = message.getRequestHeader();
        headers.addHeader("authorization", "Basic YWxhZGRpbjpvcGVuc2VzYW1l");
        message.setRequestHeader(headers);
        message.getResponseHeader().setStatusCode(status);
        nano.addHandler(new CachedTestResponse("/private", "authorization"));
        rule.init(message, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertThat(httpMessagesSent, hasSize(0));
    }

    @Test
    void shouldNotAlertIfInitialAuthorisedAndUnauthorisedResponseSame() throws Exception {
        // Given
        HttpMessage message = this.getHttpMessage("/private");
        nano.addHandler(new FirstInitialTestResponse("/private", AUTHORISED_RESPONSE));
        rule.init(message, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertEquals(1, httpMessagesSent.size());
    }

    @Test
    void shouldNotAlertIfStaticPathAppendedGives404() throws Exception {
        // Given
        HttpMessage message = this.getHttpMessage("/private");
        HttpRequestHeader headers = message.getRequestHeader();
        headers.addHeader("authorization", "Basic YWxhZGRpbjpvcGVuc2VzYW1l");
        message.setRequestHeader(headers);
        nano.addHandler(new SecondInitialTestResponse("/private", "authorization"));
        rule.init(message, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertEquals(2, httpMessagesSent.size());
    }

    @Test
    void shouldNotAlertIfResponseDoesNotGetsCached() throws Exception {
        // Given
        HttpMessage message = this.getHttpMessage("/private");
        HttpRequestHeader headers = message.getRequestHeader();
        headers.addHeader("authorization", "Basic YWxhZGRpbjpvcGVuc2VzYW1l");
        message.setRequestHeader(headers);
        nano.addHandler(new NotCachedTestResponse("/private", "authorization"));
        rule.init(message, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertEquals(15, httpMessagesSent.size());
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_ATHN_06_CACHE_WEAKNESS.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_ATHN_06_CACHE_WEAKNESS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_ATHN_06_CACHE_WEAKNESS.getValue())));
    }

    @Test
    @Timeout(value = 1, unit = TimeUnit.SECONDS)
    void shouldDetectSimilarMessagesWithoutDelayOnLongResponse() throws Exception {
        // Given
        HttpMessage message = this.getHttpMessage("/private");
        nano.addHandler(new FirstInitialTestResponse("/private", LONG_AUTHORISED_RESPONSE));
        rule.init(message, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertEquals(1, httpMessagesSent.size());
    }

    private static class CachedTestResponse extends NanoServerHandler {

        private final String header;

        CachedTestResponse(String path, String header) {
            super(path);
            this.header = header;
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            Pattern pattern =
                    Pattern.compile("/test.(css|js|gif|png|svg)", Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(session.getUri());
            boolean matchFound = matcher.find();
            if (matchFound) {
                return newFixedLengthResponse(
                        NanoHTTPD.Response.Status.OK, "text/html", AUTHORISED_RESPONSE);
            }
            if (session.getHeaders().get(header) != null) {
                return newFixedLengthResponse(
                        NanoHTTPD.Response.Status.OK, "text/html", AUTHORISED_RESPONSE);
            }
            return newFixedLengthResponse(
                    NanoHTTPD.Response.Status.UNAUTHORIZED, "text/html", UNAUTHORISED_RESPONSE);
        }
    }

    private static class NotCachedTestResponse extends NanoServerHandler {

        private final String header;

        NotCachedTestResponse(String path, String header) {
            super(path);
            this.header = header;
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            if (session.getHeaders().get(header) != null) {
                return newFixedLengthResponse(
                        NanoHTTPD.Response.Status.OK, "text/html", AUTHORISED_RESPONSE);
            }
            return newFixedLengthResponse(
                    NanoHTTPD.Response.Status.UNAUTHORIZED, "text/html", UNAUTHORISED_RESPONSE);
        }
    }

    private static class FirstInitialTestResponse extends NanoServerHandler {

        private final String body;

        FirstInitialTestResponse(String path, String body) {
            super(path);
            this.body = body;
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            return newFixedLengthResponse(NanoHTTPD.Response.Status.OK, "text/html", this.body);
        }
    }

    private static class SecondInitialTestResponse extends NanoServerHandler {

        private final String header;

        SecondInitialTestResponse(String path, String header) {
            super(path);
            this.header = header;
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            Pattern pattern = Pattern.compile("/test", Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(session.getUri());
            boolean matchFound = matcher.find();
            if (matchFound) {
                return newFixedLengthResponse(
                        NanoHTTPD.Response.Status.NOT_FOUND, "text/html", NOT_FOUND_RESPONSE);
            }
            if (session.getHeaders().get(header) != null) {
                return newFixedLengthResponse(
                        NanoHTTPD.Response.Status.OK, "text/html", AUTHORISED_RESPONSE);
            }
            return newFixedLengthResponse(
                    NanoHTTPD.Response.Status.UNAUTHORIZED, "text/html", UNAUTHORISED_RESPONSE);
        }
    }
}
