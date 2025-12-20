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

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import fi.iki.elonen.NanoHTTPD.Response.Status;
import io.github.bonigarcia.seljup.BrowsersTemplate.Browser;
import io.github.bonigarcia.seljup.SeleniumJupiter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.Supplier;
import lombok.Setter;
import org.apache.commons.httpclient.URI;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.EnumSource.Mode;
import org.junit.jupiter.params.provider.ValueSource;
import org.openqa.selenium.By;
import org.openqa.selenium.Dimension;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.Point;
import org.openqa.selenium.Rectangle;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethod.AuthCheckingStrategy;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.Pair;
import org.zaproxy.zest.core.v1.ZestActionSleep;
import org.zaproxy.zest.core.v1.ZestClientElementClick;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestScript;

class AuthUtilsUnitTest extends TestUtils {

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();

        mockMessages(new ExtensionAuthhelper());
        AuthUtils.setHistoryProvider(new TestHistoryProvider());
    }

    @AfterEach
    void cleanUp() {
        AuthUtils.clean();
    }

    @Test
    void shouldCheckContainsSessionTokenWhileAddingAndRemoving() throws Exception {
        // Given
        AtomicBoolean concurrentModification = new AtomicBoolean();
        CountDownLatch cdl = new CountDownLatch(2500);
        ScheduledExecutorService executor = Executors.newScheduledThreadPool(3);
        SessionToken token = new SessionToken("source", "key", "value");
        executor.scheduleAtFixedRate(
                () -> AuthUtils.recordSessionToken(token), 0, 1, TimeUnit.MILLISECONDS);
        executor.scheduleAtFixedRate(
                () -> AuthUtils.removeSessionToken(token), 0, 1, TimeUnit.MILLISECONDS);
        // When
        executor.scheduleAtFixedRate(
                () -> {
                    try {
                        AuthUtils.containsSessionToken(token.getValue());
                    } catch (Exception e) {
                        concurrentModification.set(true);
                    }
                    cdl.countDown();
                },
                0,
                1,
                TimeUnit.MILLISECONDS);
        // Then
        cdl.await(5000, TimeUnit.SECONDS);
        executor.shutdownNow();
        assertThat(concurrentModification.get(), is(equalTo(false)));
    }

    @Test
    void shouldReturnUserTextField() {
        // Given
        List<WebElement> inputElements = new ArrayList<>();
        inputElements.add(new TestWebElement("input", "password"));
        inputElements.add(new TestWebElement("input", "text"));
        inputElements.add(new TestWebElement("input", "checkbox"));

        // When
        WebElement field = AuthUtils.getUserField(null, inputElements, null);

        // Then
        assertThat(field, is(notNullValue()));
        assertThat(field.getAttribute("type"), is(equalTo("text")));
    }

    @Test
    void shouldReturnUserTextFieldIgnoringNonDisplayedFields() throws Exception {
        // Given
        List<WebElement> inputElements = new ArrayList<>();
        // Registration form, not displayed.
        TestWebElement inputField = new TestWebElement("input", "text");
        inputField.setDisplayed(false);
        inputElements.add(inputField);
        inputField = new TestWebElement("input", "password");
        inputField.setDisplayed(false);
        inputElements.add(inputField);
        // Login form, displayed.
        inputElements.add(new TestWebElement("input", "text"));
        inputElements.add(new TestWebElement("input", "password"));

        // When
        WebElement field = AuthUtils.getUserField(null, inputElements, null);

        // Then
        assertThat(field, is(notNullValue()));
        assertThat(field.getAttribute("type"), is(equalTo("text")));
        assertThat(field.isDisplayed(), is(equalTo(true)));
    }

    @Test
    void shouldReturnSingleFieldAsUserField() {
        // Given
        List<WebElement> inputElements = new ArrayList<>();
        // Starting form with just username with custom input type.
        inputElements.add(new TestWebElement("input", "customtype"));

        // When
        WebElement field = AuthUtils.getUserField(null, inputElements, null);

        // Then
        assertThat(field, is(notNullValue()));
        assertThat(field.getAttribute("type"), is(equalTo("customtype")));
        assertThat(field.isDisplayed(), is(equalTo(true)));
    }

    @Test
    void shouldReturnDisplayedSingleFieldAsUserField() throws Exception {
        // Given
        List<WebElement> inputElements = new ArrayList<>();
        // Some other form, not displayed.
        TestWebElement inputField = new TestWebElement("input", "text");
        inputField.setDisplayed(false);
        inputElements.add(inputField);
        // Starting form with just username with custom input type, displayed.
        inputElements.add(new TestWebElement("input", "customtype"));

        // When
        WebElement field = AuthUtils.getUserField(null, inputElements, null);

        // Then
        assertThat(field, is(notNullValue()));
        assertThat(field.getAttribute("type"), is(equalTo("customtype")));
        assertThat(field.isDisplayed(), is(equalTo(true)));
    }

    @Test
    void shouldReturnUserEmailField() {
        // Given
        List<WebElement> inputElements = new ArrayList<>();
        inputElements.add(new TestWebElement("input", "password"));
        inputElements.add(new TestWebElement("input", "email"));
        inputElements.add(new TestWebElement("input", "checkbox"));

        // When
        WebElement field = AuthUtils.getUserField(null, inputElements, null);

        // Then
        assertThat(field, is(notNullValue()));
        assertThat(field.getAttribute("type"), is(equalTo("email")));
    }

    @Test
    void shouldReturnUserEmailFieldById() {
        // Given
        List<WebElement> inputElements = new ArrayList<>();
        inputElements.add(new TestWebElement("input", "password"));
        inputElements.add(new TestWebElement("input", "text", "search", "s"));
        inputElements.add(new TestWebElement("input", "text", "email", "e"));
        inputElements.add(new TestWebElement("input", "checkbox"));

        // When
        WebElement field = AuthUtils.getUserField(null, inputElements, null);

        // Then
        assertThat(field, is(notNullValue()));
        assertThat(field.getAttribute("id"), is(equalTo("email")));
    }

    @Test
    void shouldReturnUserEmailFieldByName() {
        // Given
        List<WebElement> inputElements = new ArrayList<>();
        inputElements.add(new TestWebElement("input", "password"));
        inputElements.add(new TestWebElement("input", "text", "search", "s"));
        inputElements.add(new TestWebElement("input", "text", "x", "username"));
        inputElements.add(new TestWebElement("input", "checkbox"));

        // When
        WebElement field = AuthUtils.getUserField(null, inputElements, null);

        // Then
        assertThat(field, is(notNullValue()));
        assertThat(field.getAttribute("name"), is(equalTo("username")));
    }

    @Test
    void shouldReturnNoUserField() {
        // Given
        List<WebElement> inputElements = new ArrayList<>();
        inputElements.add(new TestWebElement("input", "password"));
        inputElements.add(new TestWebElement("input", "hidden"));
        inputElements.add(new TestWebElement("input", "checkbox"));

        // When
        WebElement field = AuthUtils.getUserField(null, inputElements, null);

        // Then
        assertThat(field, is(nullValue()));
    }

    @Test
    void shouldReturnPasswordField() {
        // Given
        List<WebElement> inputElements = new ArrayList<>();
        inputElements.add(new TestWebElement("input", "email"));
        inputElements.add(new TestWebElement("input", "checkbox"));
        inputElements.add(new TestWebElement("input", "password"));

        // When
        WebElement field = AuthUtils.getPasswordField(inputElements);

        // Then
        assertThat(field, is(notNullValue()));
        assertThat(field.getAttribute("type"), is(equalTo("password")));
    }

    @Test
    void shouldReturnPasswordFieldIgnoringNonDisplayedFields() throws Exception {
        // Given
        List<WebElement> inputElements = new ArrayList<>();
        // Registration form, not displayed.
        TestWebElement inputField = new TestWebElement("input", "email");
        inputField.setDisplayed(false);
        inputElements.add(inputField);
        inputField = new TestWebElement("input", "password");
        inputField.setDisplayed(false);
        inputElements.add(inputField);
        // Login form, displayed.
        inputElements.add(new TestWebElement("input", "email"));
        inputElements.add(new TestWebElement("input", "password"));

        // When
        WebElement field = AuthUtils.getPasswordField(inputElements);

        // Then
        assertThat(field, is(notNullValue()));
        assertThat(field.getAttribute("type"), is(equalTo("password")));
        assertThat(field.isDisplayed(), is(equalTo(true)));
    }

    @Test
    void shouldReturnNoPasswordField() {
        // Given
        List<WebElement> inputElements = new ArrayList<>();
        inputElements.add(new TestWebElement("input", "email"));
        inputElements.add(new TestWebElement("input", "hidden"));
        inputElements.add(new TestWebElement("input", "checkbox"));

        // When
        WebElement field = AuthUtils.getPasswordField(inputElements);

        // Then
        assertThat(field, is(nullValue()));
    }

    @Test
    void shouldReturnNoSessionTokens() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage(new URI("https://example.com/test", true));

        // When
        Map<String, SessionToken> tokens = AuthUtils.getResponseSessionTokens(msg);

        // Then
        assertThat(tokens.size(), is(equalTo(0)));
    }

    @Test
    void shouldExtractHeaderSessionTokens() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage(new URI("https://example.com/test", true));
        msg.getResponseHeader().addHeader("CustomHeader", "example-session-token");
        msg.getResponseHeader().addHeader(HttpHeader.AUTHORIZATION, "example-session-token");

        // When
        Map<String, SessionToken> tokens = AuthUtils.getResponseSessionTokens(msg);

        // Then
        assertThat(tokens.size(), is(equalTo(1)));

        assertThat(tokens.get("header:authorization"), is(notNullValue()));
        assertThat(
                tokens.get("header:authorization").getSource(),
                is(equalTo(SessionToken.HEADER_SOURCE)));
        assertThat(
                tokens.get("header:authorization").getKey(), is(equalTo(HttpHeader.AUTHORIZATION)));
    }

    @Test
    void shouldExtractJsonSessionTokensInObject() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage(new URI("https://example.com/test", true));
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "blah-blah-json");
        msg.getResponseBody()
                .setBody("{'auth': {'test': '123', accessToken: 'example-session-token'}}");

        // When
        Map<String, SessionToken> tokens = AuthUtils.getResponseSessionTokens(msg);

        // Then
        assertThat(tokens.size(), is(equalTo(1)));
        assertThat(
                tokens.get("json:auth.accessToken").getSource(),
                is(equalTo(SessionToken.JSON_SOURCE)));
        assertThat(tokens.get("json:auth.accessToken").getKey(), is(equalTo("auth.accessToken")));
        assertThat(
                tokens.get("json:auth.accessToken").getValue(),
                is(equalTo("example-session-token")));
    }

    @Test
    void shouldExtractJsonSessionTokenInString() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage(new URI("https://example.com/test", true));
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "blah-blah-json");
        msg.getResponseBody().setBody("\"example-session-token\"");

        // When
        Map<String, SessionToken> tokens = AuthUtils.getResponseSessionTokens(msg);

        // Then
        assertThat(tokens.size(), is(equalTo(1)));
        assertSessionToken(
                tokens.get("json:"), SessionToken.JSON_SOURCE, "", "example-session-token");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "  ", " \t", "\n"})
    void shouldNotExtractJsonSessionTokenInBlankString(String value) throws Exception {
        // Given
        HttpMessage msg = new HttpMessage(new URI("https://example.com/test", true));
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "blah-blah-json");
        msg.getResponseBody().setBody("\"" + value + "\"");

        // When
        Map<String, SessionToken> tokens = AuthUtils.getResponseSessionTokens(msg);

        // Then
        assertThat(tokens.size(), is(equalTo(0)));
    }

    private static void assertSessionToken(
            SessionToken token, String source, String key, String value) {
        assertThat(token, is(notNullValue()));
        assertThat(token.getSource(), is(equalTo(source)));
        assertThat(token.getKey(), is(equalTo(key)));
        assertThat(token.getValue(), is(equalTo(value)));
    }

    @Test
    void shouldExtractCookieSessionTokens() throws Exception {
        HttpMessage msg = new HttpMessage(new URI("https://example.com/test", true));
        msg.getResponseHeader().addHeader(HttpHeader.SET_COOKIE, "too_short=123456789");
        msg.getResponseHeader().addHeader(HttpHeader.SET_COOKIE, "long_enough=12345678901");

        // When
        Map<String, SessionToken> tokens = AuthUtils.getResponseSessionTokens(msg);

        // Then
        assertThat(tokens.size(), is(equalTo(1)));

        assertThat(tokens.get("cookie:long_enough"), is(notNullValue()));
        assertThat(
                tokens.get("cookie:long_enough").getSource(),
                is(equalTo(SessionToken.COOKIE_SOURCE)));
        assertThat(tokens.get("cookie:long_enough").getKey(), is(equalTo("long_enough")));
    }

    @Test
    void shouldDefaultToNoTokens() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                """
                                GET / HTTP/1.1\r
                                Header1: Value1\r
                                Header2: Value2\r
                                Host: example.com\r\n\r\n"""),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody("Response Body"));
        // When
        Map<String, SessionToken> tokens = AuthUtils.getResponseSessionTokens(msg);

        // Then
        assertThat(tokens.size(), is(equalTo(0)));
    }

    @Test
    void shouldExtractHeaderTokens() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader(
                                """
                                HTTP/1.1 200 OK\r
                                Header1: Value1\r
                                Header2: Value2\r\n"""),
                        new HttpResponseBody("Response Body"));
        // When
        Map<String, SessionToken> tokens = AuthUtils.getAllTokens(msg, false);

        // Then
        assertThat(tokens.size(), is(equalTo(2)));
        assertThat(tokens.get("header:Header1").getValue(), is(equalTo("Value1")));
        assertThat(tokens.get("header:Header2").getValue(), is(equalTo("Value2")));
    }

    @Test
    void shouldExtractUrlParams() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET https://example.com/?att1=val1&att2=val2 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody("Response Body"));
        // When
        Map<String, SessionToken> tokens = AuthUtils.getAllTokens(msg, false);

        // Then
        assertThat(tokens.size(), is(equalTo(2)));
        assertThat(tokens.get("url:att1").getValue(), is(equalTo("val1")));
        assertThat(tokens.get("url:att2").getValue(), is(equalTo("val2")));
    }

    @Test
    void shouldExtractJsonTokens() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader(
                                "HTTP/1.1 200 OK\r\n" + "Content-Type: application/json"),
                        new HttpResponseBody(
                                """
                                {"wrapper1": {
                                  "att1": "val1",
                                  "att2": "val2",
                                  "wrapper2": {
                                    "att1": "val3",
                                    "array": [
                                      {"att1": "val4", "att2": "val5"},
                                      {"att3": "val6", "att4": "val7"}
                                    ]
                                  }
                                }}"""));
        // When
        Map<String, SessionToken> tokens = AuthUtils.getAllTokens(msg, false);

        // Then
        assertThat(tokens.size(), is(equalTo(8)));
        assertThat(tokens.get("json:wrapper1.att1").getValue(), is(equalTo("val1")));
        assertThat(tokens.get("json:wrapper1.att2").getValue(), is(equalTo("val2")));
        assertThat(tokens.get("json:wrapper1.wrapper2.att1").getValue(), is(equalTo("val3")));
        assertThat(
                tokens.get("json:wrapper1.wrapper2.array[0].att1").getValue(), is(equalTo("val4")));
        assertThat(
                tokens.get("json:wrapper1.wrapper2.array[0].att2").getValue(), is(equalTo("val5")));
        assertThat(
                tokens.get("json:wrapper1.wrapper2.array[1].att3").getValue(), is(equalTo("val6")));
        assertThat(
                tokens.get("json:wrapper1.wrapper2.array[1].att4").getValue(), is(equalTo("val7")));
        assertThat(tokens.get("header:Content-Type").getValue(), is(equalTo("application/json")));
    }

    @Test
    void shouldExtractAllCookies() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                """
                                GET https://example.com/ HTTP/1.1\r
                                Host: example.com\r
                                Cookie: aaa=bbb\r\n\r\n"""),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader(
                                "HTTP/1.1 200 OK\r\n" + "Set-Cookie: ccc=ddd; HttpOnly; Secure"),
                        new HttpResponseBody("Response Body"));
        // When
        Map<String, SessionToken> tokens = AuthUtils.getAllTokens(msg, true);

        // Then
        assertThat(tokens.size(), is(equalTo(3)));
        assertThat(tokens.get("cookie:aaa").getValue(), is(equalTo("bbb")));
        assertThat(tokens.get("cookie:ccc").getValue(), is(equalTo("ddd")));
        assertThat(
                tokens.get("header:Set-Cookie").getValue(),
                is(equalTo("ccc=ddd; HttpOnly; Secure")));
    }

    @Test
    void shouldExtractResponseCookies() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                """
                                GET https://example.com/ HTTP/1.1\r
                                Host: example.com\r
                                Cookie: aaa=bbb\r\n\r\n"""),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader(
                                "HTTP/1.1 200 OK\r\n" + "Set-Cookie: ccc=ddd; HttpOnly; Secure"),
                        new HttpResponseBody("Response Body"));
        // When
        Map<String, SessionToken> tokens = AuthUtils.getAllTokens(msg, false);

        // Then
        assertThat(tokens.size(), is(equalTo(2)));
        assertThat(tokens.get("cookie:ccc").getValue(), is(equalTo("ddd")));
        assertThat(
                tokens.get("header:Set-Cookie").getValue(),
                is(equalTo("ccc=ddd; HttpOnly; Secure")));
    }

    @Test
    void shouldGetEmptyHeaderTokens() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET https://example.com/?att1=val1&att2=val2 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody("Response Body"));

        // When
        List<Pair<String, String>> headerTokens =
                AuthUtils.getHeaderTokens(msg, new ArrayList<>(), true);

        // Then
        assertThat(headerTokens.size(), is(equalTo(0)));
    }

    @Test
    void shouldGetHeaderTokensWithCookies() throws Exception {
        // Given
        String token1 = "96438673498764398";
        String token2 = "bndkdfsojhgkdshgk";
        String token3 = "89jdhf9834herg03s";

        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET https://example.com/?att1=val1&att2=val2 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody("Response Body"));
        msg.getRequestHeader().addHeader(HttpHeader.AUTHORIZATION, "Bearer " + token1);
        msg.getRequestHeader().addHeader(HttpHeader.COOKIE, "test=" + token2 + "; SameSite=Strict");
        msg.getRequestHeader().addHeader(HttpHeader.AUTHORIZATION, token3);
        List<SessionToken> tokens = new ArrayList<>();
        tokens.add(new SessionToken(SessionToken.HEADER_SOURCE, HttpHeader.AUTHORIZATION, token1));
        tokens.add(new SessionToken(SessionToken.JSON_SOURCE, "set.cookie", token2));

        // When
        List<Pair<String, String>> headerTokens = AuthUtils.getHeaderTokens(msg, tokens, true);

        // Then
        assertThat(headerTokens.size(), is(equalTo(2)));
        assertThat(headerTokens.get(0).first, is(equalTo(HttpHeader.AUTHORIZATION)));
        assertThat(headerTokens.get(0).second, is(equalTo("Bearer {%header:authorization%}")));
        assertThat(headerTokens.get(1).first, is(equalTo(HttpHeader.COOKIE)));
        assertThat(headerTokens.get(1).second, is(equalTo("test={%json:set.cookie%}")));
    }

    @Test
    void shouldGetHeaderTokensWithoutCookies() throws Exception {
        // Given
        String token1 = "96438673498764398";
        String token2 = "bndkdfsojhgkdshgk";
        String token3 = "89jdhf9834herg03s";

        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET https://example.com/?att1=val1&att2=val2 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody("Response Body"));
        msg.getRequestHeader().addHeader(HttpHeader.AUTHORIZATION, "Bearer " + token1);
        msg.getRequestHeader().addHeader(HttpHeader.COOKIE, token2 + "; SameSite=Strict");
        msg.getRequestHeader().addHeader(HttpHeader.AUTHORIZATION, token3);
        List<SessionToken> tokens = new ArrayList<>();
        tokens.add(new SessionToken(SessionToken.HEADER_SOURCE, HttpHeader.AUTHORIZATION, token1));
        tokens.add(new SessionToken(SessionToken.JSON_SOURCE, "set.cookie", token2));

        // When
        List<Pair<String, String>> headerTokens = AuthUtils.getHeaderTokens(msg, tokens, false);

        // Then
        assertThat(headerTokens.size(), is(equalTo(1)));
        assertThat(headerTokens.get(0).first, is(equalTo(HttpHeader.AUTHORIZATION)));
        assertThat(headerTokens.get(0).second, is(equalTo("Bearer {%header:authorization%}")));
    }

    @Test
    void shouldGetHeaderTokensIgnoringIrrelevantCookies() throws Exception {
        // Given
        String token1 = "96438673498764398";
        String token2 = "bndkdfsojhgkdshgk";
        String token3 = "89jdhf9834herg03s";
        String token4 = "h6qb79djz02mgy12n";

        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET https://example.com/?att1=val1&att2=val2 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody("Response Body"));
        msg.getRequestHeader()
                .addHeader(
                        HttpHeader.COOKIE,
                        "test1="
                                + token1
                                + "; test2="
                                + token2
                                + "; test3="
                                + token3
                                + "; test4="
                                + token4);
        List<SessionToken> tokens = new ArrayList<>();
        tokens.add(new SessionToken(SessionToken.JSON_SOURCE, "set.cookie", token2));
        tokens.add(new SessionToken(SessionToken.COOKIE_SOURCE, "test4", token4));

        // When
        List<Pair<String, String>> headerTokens = AuthUtils.getHeaderTokens(msg, tokens, true);

        // Then
        assertThat(headerTokens.size(), is(equalTo(1)));
        assertThat(headerTokens.get(0).first, is(equalTo(HttpHeader.COOKIE)));
        assertThat(headerTokens.get(0).second, is(equalTo("test2={%json:set.cookie%}")));
    }

    @Test
    void shouldGetNoRequestSessionTokens() throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET https://example.com/?att1=val1&att2=val2 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody("Response Body"));

        // When
        Set<SessionToken> tokens = AuthUtils.getRequestSessionTokens(msg);

        // Then
        assertThat(tokens.size(), is(equalTo(0)));
    }

    @Test
    void shouldGetRequestSessionTokens() throws Exception {
        // Given
        String token1 = "96438673498764398";
        String token2 = "bndkdfsojhgkdshgk";
        String token3 = "89jdhf9834herg03s";
        String token4 = "3ys96hdtr28f6gsjr";

        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET https://example.com/?att1=val1&att2=val2 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody("Response Body"));
        msg.getRequestHeader().addHeader(HttpFieldsNames.AUTHORIZATION, "Bearer " + token1);
        msg.getRequestHeader()
                .addHeader(HttpFieldsNames.COOKIE, "id=" + token2 + "; SameSite=Strict");
        msg.getRequestHeader().addHeader(HttpFieldsNames.AUTHORIZATION, token3);
        msg.getRequestHeader().addHeader("x-auth-token", token4);

        // When
        Set<SessionToken> tokens = AuthUtils.getRequestSessionTokens(msg);
        SessionToken[] stArray = new SessionToken[tokens.size()];
        stArray = tokens.toArray(stArray);
        Arrays.sort(
                stArray,
                (SessionToken a, SessionToken b) -> {
                    return (a.getToken() + ":" + a.getValue())
                            .compareTo(b.getToken() + ":" + b.getValue());
                });

        // Then
        assertThat(tokens.size(), is(equalTo(4)));
        assertThat(stArray[0].getSource(), is(equalTo(SessionToken.COOKIE_SOURCE)));
        assertThat(stArray[1].getSource(), is(equalTo(SessionToken.HEADER_SOURCE)));
        assertThat(stArray[2].getSource(), is(equalTo(SessionToken.HEADER_SOURCE)));
        assertThat(stArray[3].getSource(), is(equalTo(SessionToken.HEADER_SOURCE)));

        assertThat(stArray[0].getToken(), is(equalTo("cookie:id")));
        assertThat(stArray[1].getToken(), is(equalTo("header:authorization")));
        assertThat(stArray[2].getToken(), is(equalTo("header:authorization")));
        assertThat(stArray[3].getToken(), is(equalTo("header:x-auth-token")));

        assertThat(stArray[0].getValue(), is(equalTo(token2)));
        assertThat(stArray[1].getValue(), is(equalTo(token3)));
        assertThat(stArray[2].getValue(), is(equalTo(token1)));
        assertThat(stArray[3].getValue(), is(equalTo(token4)));

        assertThat(stArray[0].getFullValue(), is(equalTo(token2)));
        assertThat(stArray[1].getFullValue(), is(equalTo(token3)));
        assertThat(stArray[2].getFullValue(), is(equalTo("Bearer " + token1)));
        assertThat(stArray[3].getFullValue(), is(equalTo(token4)));
    }

    @Test
    void shouldGetRequestSessionTokensUsingHeaderConfigs() throws Exception {
        // Given
        String token1 = "96438673498764398";
        String token2 = "bndkdfsojhgkdshgk";
        String token3 = "89jdhf9834herg03s";

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(
                """
                GET / HTTP/1.1
                authorization: Bearer %s
                cookie: id=%s; SameSite=Strict
                x-api: %s"""
                        .formatted(token1, token2, token3));
        List<Pair<String, String>> headerConfigs = List.of(new Pair<>("x-api", "{%header:x-api%}"));

        // When
        Set<SessionToken> tokens = AuthUtils.getRequestSessionTokens(msg, headerConfigs);

        // Then
        assertThat(
                tokens,
                containsInAnyOrder(
                        sessionTokenEqualTo(
                                SessionToken.HEADER_SOURCE,
                                "authorization",
                                token1,
                                "Bearer " + token1),
                        sessionTokenEqualTo(SessionToken.COOKIE_SOURCE, "id", token2, token2),
                        sessionTokenEqualTo(SessionToken.HEADER_SOURCE, "x-api", token3, token3)));
    }

    @Test
    void shouldReturnNoSessionToken() {
        // Given
        AuthUtils.recordSessionToken(
                new SessionToken(SessionToken.HEADER_SOURCE, HttpHeader.AUTHORIZATION, "456"));
        // When
        SessionToken st = AuthUtils.getSessionToken("123");
        // Then
        assertThat(st, is(nullValue()));
    }

    @Test
    void shouldReturnSessionToken() {
        // Given
        AuthUtils.recordSessionToken(
                new SessionToken(SessionToken.HEADER_SOURCE, "Header1", "123"));
        AuthUtils.recordSessionToken(
                new SessionToken(SessionToken.HEADER_SOURCE, "Header2", "456"));
        AuthUtils.recordSessionToken(
                new SessionToken(SessionToken.HEADER_SOURCE, "Header3", "789"));
        // When
        SessionToken st = AuthUtils.getSessionToken("789");
        // Then
        assertThat(st, is(notNullValue()));
        assertThat(st.getKey(), is("Header3"));
        assertThat(st.getValue(), is("789"));
        assertThat(st.getToken(), is("header:Header3"));
    }

    @Test
    void shouldRemoveSessionToken() {
        // Given
        AuthUtils.recordSessionToken(
                new SessionToken(SessionToken.HEADER_SOURCE, "Header1", "123"));
        AuthUtils.recordSessionToken(
                new SessionToken(SessionToken.HEADER_SOURCE, "Header2", "456"));
        AuthUtils.recordSessionToken(
                new SessionToken(SessionToken.HEADER_SOURCE, "Header3", "789"));
        // When
        SessionToken st1 = AuthUtils.getSessionToken("789");
        AuthUtils.removeSessionToken(st1);
        SessionToken st2 = AuthUtils.getSessionToken("789");
        // Then
        assertThat(st1, is(notNullValue()));
        assertThat(st2, is(nullValue()));
    }

    @ParameterizedTest
    @CsvSource({
        "text/html; charset=utf-8, true",
        "multipart/form-data; boundary=ExampleBoundaryString, true",
        "application/x-www-form-urlencoded, true",
        "application/json, true",
        "application/xhtml+xml, true",
        "application/xml, true",
        "text/xml, true",
        "application/x-font-ttf, false",
        "text/css, false",
        "text/javascript; charset=utf-8, false",
        "image/gif, false",
        "image/svg+xml, false",
    })
    void shouldReportIfRelevantToAuth(String contentType, String result) throws Exception {
        // Given
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                HttpRequestHeader.GET,
                                new URI("https://www.example.com", true),
                                HttpHeader.HTTP11),
                        new HttpRequestBody(),
                        new HttpResponseHeader(),
                        new HttpResponseBody());
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, contentType);

        // When
        boolean res = AuthUtils.isRelevantToAuth(msg);

        // Then
        assertThat(res, is(equalTo(Boolean.parseBoolean(result))));
    }

    @ParameterizedTest
    @CsvSource({
        "https://www.example.com, true",
        "https://www.example.com/page.html, true",
        "https://www.example.com/page.html?type=x.css, true",
        "https://www.example.com/page.css, false",
        "https://www.example.com/page.png, false",
        "https://www.example.com/page.jpg, false",
        "https://www.example.com/page.jpeg?aaa=bbb, false",
    })
    void shouldReportRelevantRequestHeaderUrlToAuthDiags(String url, String result)
            throws Exception {
        // Given
        HttpRequestHeader header = new HttpRequestHeader();
        header.setURI(new URI(url, true));
        HttpMessage msg = new HttpMessage(header, new HttpRequestBody());

        // When
        boolean res = AuthUtils.isRelevantToAuthDiags(msg);

        // Then
        assertThat(res, is(equalTo(Boolean.parseBoolean(result))));
    }

    @ParameterizedTest
    @CsvSource({
        "https://www.example.com, true",
        "https://www.clients2.google.com, false",
        "https://www.detectportal.firefox.com, false",
        "https://google-analytics.com, false",
        "https://www.mozilla.com, false",
        "https://www.safebrowsing-cache.co.uk, false",
    })
    void shouldReportRelevantHostsToAuthDiags(String url, String result) throws Exception {
        // Given
        HttpRequestHeader header = new HttpRequestHeader();
        header.setURI(new URI(url, true));
        HttpMessage msg = new HttpMessage(header, new HttpRequestBody());

        // When
        boolean res = AuthUtils.isRelevantToAuthDiags(msg);

        // Then
        assertThat(res, is(equalTo(Boolean.parseBoolean(result))));
    }

    @ParameterizedTest
    @CsvSource({
        "text/html, true",
        "app/random, true",
        "app/css, false",
        "app/Image, false",
        "app/JavaScript, false",
    })
    void shouldReportRelevantResponseHeaderTypeToAuthDiags(String type, String result)
            throws Exception {
        // Given
        HttpResponseHeader header = new HttpResponseHeader();
        header.setHeader(HttpHeader.CONTENT_TYPE, type);
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(),
                        new HttpRequestBody(),
                        header,
                        new HttpResponseBody());
        msg.getRequestHeader().setURI(new URI("https://www.example.com", true));

        // When
        boolean res = AuthUtils.isRelevantToAuthDiags(msg);

        // Then
        assertThat(res, is(equalTo(Boolean.parseBoolean(result))));
    }

    @Test
    void shouldSetMinWaitFor() {
        // Given
        ZestScript zs = new ZestScript();
        ZestClientElementClick el1 = new ZestClientElementClick();
        ZestClientElementClick el2 = new ZestClientElementClick();
        ZestClientElementClick el3 = new ZestClientElementClick();
        el1.setWaitForMsec(1000);
        el2.setWaitForMsec(5000);
        el3.setWaitForMsec(8000);
        zs.add(new ZestClientLaunch());
        zs.add(el1);
        zs.add(el2);
        zs.add(el3);
        zs.add(new ZestActionSleep());

        // When
        AuthUtils.setMinWaitFor(zs, 5000);

        // Then
        assertThat(el1.getWaitForMsec(), is(equalTo(5000)));
        assertThat(el2.getWaitForMsec(), is(equalTo(5000)));
        assertThat(el3.getWaitForMsec(), is(equalTo(8000)));
    }

    static class BrowserTest extends TestUtils {

        private static final String HTML_SHADOM_DOM =
                """
                    <div id="host-a"></div>
                    <input id="host-input-a" />
                    <div id="host-b"></div>
                    <div>
                        <input id="host-input-b" />
                    </div>

                    <script>
                        function addShadowInput(hostSelector, inputId, mode) {
                          const host = document.querySelector(hostSelector);
                          const shadow = host.attachShadow({ mode: mode });
                          const input = document.createElement("input");
                          input.id = inputId;
                          shadow.appendChild(input);
                        }

                        addShadowInput("#host-a", "shadow-input-open", "open" );
                        addShadowInput("#host-b", "shadow-input-closed", "closed" );
                    </script>
                """;

        private static final String FORM_SUBMIT_TIMEOUT =
                """
                    <script>
                        function remove() {
                            setTimeout(() => {
                              document.getElementsByTagName("input")[0].remove();
                            }, 1000);
                        }
                    </script>
                    <form action="javascript:remove()">
                        <input type="password" />
                    </form>
                    <button />
                """;

        @RegisterExtension static SeleniumJupiter seleniumJupiter = new SeleniumJupiter();

        private String url;
        private Supplier<String> pageContent = () -> "";

        @BeforeAll
        static void setup() {
            seleniumJupiter.addBrowsers(
                    new Browser(
                            "firefox",
                            null,
                            null,
                            new String[] {"-headless"},
                            new String[] {"remote.active-protocols=1"},
                            Map.of("webSocketUrl", true)));

            mockMessages(new ExtensionAuthhelper());
        }

        @BeforeEach
        void setupEach() throws IOException {
            startServer();

            String path = "/test";
            url = "http://localhost:" + nano.getListeningPort() + path;
            nano.addHandler(
                    new NanoServerHandler(path) {
                        @Override
                        protected Response serve(IHTTPSession session) {
                            return newFixedLengthResponse(pageContent.get());
                        }
                    });
        }

        @AfterEach
        void cleanupEach() {
            stopServer();
        }

        @TestTemplate
        void shouldReturnUserFieldCommonToPasswordForm(WebDriver wd) {
            // Given
            pageContent =
                    () ->
                            """
                                <input type="text" name="randomA" />
                                <form>
                                <input type="text" name="randomB">
                                <input type="password" name="passw">
                                <input type="text" name="user">
                                </form>
                             """;
            wd.get(url);
            List<WebElement> inputElements = AuthUtils.getInputElements(wd, false);
            WebElement pwdField = AuthUtils.getPasswordField(inputElements);
            // When
            WebElement field = AuthUtils.getUserField(wd, inputElements, pwdField);

            // Then
            assertThat(field, is(notNullValue()));
            assertThat(field.getDomAttribute("name"), is(equalTo("user")));
        }

        @TestTemplate
        void shouldReturnOnlyFieldCommonToPasswordForm(WebDriver wd) {
            // Given
            pageContent =
                    () ->
                            """
                                <input type="text" name="randomA" />
                                <form>
                                <input type="text" name="randomB">
                                <input type="password" name="passw">
                                </form>
                             """;
            wd.get(url);
            List<WebElement> inputElements = AuthUtils.getInputElements(wd, false);
            WebElement pwdField = AuthUtils.getPasswordField(inputElements);
            // When
            WebElement field = AuthUtils.getUserField(wd, inputElements, pwdField);

            // Then
            assertThat(field, is(notNullValue()));
            assertThat(field.getDomAttribute("name"), is(equalTo("randomB")));
        }

        @TestTemplate
        void shouldReturnFirstOfManyFieldsCommonToPasswordForm(WebDriver wd) {
            // Given
            pageContent =
                    () ->
                            """
                                <input type="text" name="randomA" />
                                <form>
                                <input type="password" name="passw">
                                <input type="text" name="randomB">
                                <input type="text" name="randomC">
                                </form>
                             """;
            wd.get(url);
            List<WebElement> inputElements = AuthUtils.getInputElements(wd, false);
            WebElement pwdField = AuthUtils.getPasswordField(inputElements);
            // When
            WebElement field = AuthUtils.getUserField(wd, inputElements, pwdField);

            // Then
            assertThat(field, is(notNullValue()));
            assertThat(field.getDomAttribute("name"), is(equalTo("randomB")));
        }

        @TestTemplate
        void shouldReturnUserTextFieldByDomProperty(WebDriver wd) {
            // Given
            pageContent =
                    () ->
                            """
                                <input type="password" />
                                <input id="id" />
                                <input type="checkbox" />
                                <script>
                                    document.getElementById("id").type = "text";
                                </script>
                             """;
            wd.get(url);
            List<WebElement> inputElements = AuthUtils.getInputElements(wd, false);

            // When
            WebElement field = AuthUtils.getUserField(null, inputElements, null);

            // Then
            assertThat(field, is(notNullValue()));
            assertThat(field.getDomProperty("type"), is(equalTo("text")));
        }

        @TestTemplate
        void shouldReturnPasswordFieldByDomProperty(WebDriver wd) {
            // Given
            pageContent =
                    () ->
                            """
                                <input type="email" />
                                <input type="checkbox" />
                                <input id="id" />
                                <script>
                                    document.getElementById("id").type = "password";
                                </script>
                             """;
            wd.get(url);
            List<WebElement> inputElements = AuthUtils.getInputElements(wd, false);

            // When
            WebElement field = AuthUtils.getPasswordField(inputElements);

            // Then
            assertThat(field, is(notNullValue()));
            assertThat(field.getDomProperty("type"), is(equalTo("password")));
        }

        @TestTemplate
        void shouldReturnPasswordFieldWithPasswordInName(WebDriver wd) {
            // Given
            pageContent =
                    () ->
                            """
                                <input type="text" name="IsPasswordField" />
                            """;
            wd.get(url);
            List<WebElement> inputElements = AuthUtils.getInputElements(wd, false);

            // When
            WebElement field = AuthUtils.getPasswordField(inputElements);

            // Then
            assertThat(field, is(notNullValue()));
        }

        @TestTemplate
        void shouldReturnPasswordFieldWithPasswordInId(WebDriver wd) {
            // Given
            pageContent =
                    () ->
                            """
                                <input type="text" id="IsPasswordField" />
                            """;
            wd.get(url);
            List<WebElement> inputElements = AuthUtils.getInputElements(wd, false);

            // When
            WebElement field = AuthUtils.getPasswordField(inputElements);

            // Then
            assertThat(field, is(notNullValue()));
        }

        @TestTemplate
        void shouldReturnPasswordFieldByTypeOverIdAndName(WebDriver wd) {
            // Given
            pageContent =
                    () ->
                            """
                                <input type="text" name="IsPasswordField" />
                                <input type="text" id="IsPasswordField" />
                                <input type="password" />
                            """;
            wd.get(url);
            List<WebElement> inputElements = AuthUtils.getInputElements(wd, false);

            // When
            WebElement field = AuthUtils.getPasswordField(inputElements);

            // Then
            assertThat(field, is(notNullValue()));
            assertThat(field.getDomProperty("type"), is(equalTo("password")));
        }

        @TestTemplate
        void shouldReturnInputElementsUnderShadowDom(WebDriver wd) {
            // Given
            pageContent = () -> HTML_SHADOM_DOM;
            wd.get(url);

            // When
            List<WebElement> inputElements = AuthUtils.getInputElements(wd, true);

            // Then
            assertThat(inputElements, hasSize(4));
            assertId(inputElements.get(0), "host-input-a");
            assertId(inputElements.get(1), "host-input-b");
            assertId(inputElements.get(2), "shadow-input-open");
            assertId(inputElements.get(3), "shadow-input-closed");
        }

        @TestTemplate
        void shouldNotReturnInputElementsUnderShadowDomIfNotWanted(WebDriver wd) {
            // Given
            pageContent = () -> HTML_SHADOM_DOM;
            wd.get(url);

            // When
            List<WebElement> inputElements = AuthUtils.getInputElements(wd, false);

            // Then
            assertThat(inputElements, hasSize(2));
            assertId(inputElements.get(0), "host-input-a");
            assertId(inputElements.get(1), "host-input-b");
        }

        @TestTemplate
        void shouldReturnOnFieldOnSubmit(WebDriver wd) {
            // Given
            pageContent =
                    () ->
                            """
                                <input type="password" />
                            """;
            wd.get(url);
            WebElement passwordField = wd.findElement(By.tagName("input"));
            AuthenticationDiagnostics diags = mock();

            // When
            AuthUtils.submit(diags, wd, passwordField, 0, 0);

            // Then
            verify(diags).recordStep(wd, "Auto Return");
            verifyNoMoreInteractions(diags);
        }

        @TestTemplate
        void shouldClickButtonIfReturnDoesNoActionOnFieldOnSubmit(WebDriver wd) {
            // Given
            pageContent = () -> FORM_SUBMIT_TIMEOUT;
            wd.get(url);
            WebElement passwordField = wd.findElement(By.tagName("input"));
            AuthenticationDiagnostics diags = mock();

            // When
            AuthUtils.submit(diags, wd, passwordField, 0, 0);

            // Then
            WebElement button = wd.findElement(By.tagName("button"));
            verify(diags).recordStep(wd, "Auto Return");
            verify(diags).recordStep(wd, "Click Button", button);
            verifyNoMoreInteractions(diags);
        }

        @TestTemplate
        void shouldClickLoginLikeButtonWhenMoreThanOneIfReturnDoesNoActionOnFieldOnSubmit(
                WebDriver wd) {
            // Given
            pageContent =
                    () ->
                            """
                                <input type="password" />
                                <button>
                                    <span>Show Password</span>
                                </button>
                                <button id="x">
                                    <span>Login</span>
                                </button>
                            """;
            wd.get(url);
            WebElement passwordField = wd.findElement(By.tagName("input"));
            AuthenticationDiagnostics diags = mock();

            // When
            AuthUtils.submit(diags, wd, passwordField, 0, 0);

            // Then
            WebElement button = wd.findElement(By.id("x"));
            verify(diags).recordStep(wd, "Auto Return");
            verify(diags).recordStep(wd, "Click Button", button);
            verifyNoMoreInteractions(diags);
        }

        @TestTemplate
        void shouldNotClickButtonIfReturnActionWorksUnderPageLoadWaitOnSubmit(WebDriver wd) {
            // Given
            pageContent = () -> FORM_SUBMIT_TIMEOUT;
            wd.get(url);
            WebElement passwordField = wd.findElement(By.tagName("input"));
            AuthenticationDiagnostics diags = mock();

            // When
            AuthUtils.submit(diags, wd, passwordField, 0, 2);

            // Then
            verify(diags).recordStep(wd, "Auto Return");
            verifyNoMoreInteractions(diags);
        }

        private static void assertId(WebElement element, String id) {
            assertThat(element.getAttribute("id"), is(equalTo(id)));
        }
    }

    static class LoginLinkVerification extends TestUtils {

        private String url;
        private Function<IHTTPSession, Response> handler;

        private HistoryProvider historyProvider;

        private HttpSender authSender;
        private User user;
        private Context context;
        private AuthenticationMethod authenticationMethod;

        @BeforeEach
        void setupEach() throws IOException {
            startServer();

            handler = session -> newFixedLengthResponse("");

            url = "http://localhost:" + nano.getListeningPort();
            nano.addHandler(
                    new NanoServerHandler("") {
                        @Override
                        protected Response serve(IHTTPSession session) {
                            return handler.apply(session);
                        }
                    });

            historyProvider = mock(HistoryProvider.class);
            AuthUtils.setHistoryProvider(historyProvider);

            authSender = mock(HttpSender.class);
            user = mock(User.class);
            context = mock(Context.class);
            given(user.getContext()).willReturn(context);
            authenticationMethod = mock(AuthenticationMethod.class);
            given(context.getAuthenticationMethod()).willReturn(authenticationMethod);
        }

        @AfterEach
        void cleanupEach() {
            stopServer();

            AuthUtils.setHistoryProvider(null);
        }

        @ParameterizedTest
        @EnumSource(value = AuthCheckingStrategy.class, mode = Mode.EXCLUDE, names = "AUTO_DETECT")
        void shouldNotCheckLoginLinkIfNotAutoDetectStrategy(
                AuthCheckingStrategy authCheckingStrategy) {
            // Given
            given(authenticationMethod.getAuthCheckingStrategy()).willReturn(authCheckingStrategy);
            // When
            AuthUtils.checkLoginLinkVerification(authSender, user, url);
            // Then
            verifyNoInteractions(authSender);
            verifyNoInteractions(historyProvider);
        }

        @Test
        void shouldNotFurtherCheckLoginLinkIfUnauthDoesNotHaveLoginLabels() {
            // Given
            given(authenticationMethod.getAuthCheckingStrategy())
                    .willReturn(AuthCheckingStrategy.AUTO_DETECT);
            // When
            AuthUtils.checkLoginLinkVerification(authSender, user, url);
            // Then
            verifyNoInteractions(authSender);
            verify(historyProvider).addAuthMessageToHistory(any(HttpMessage.class));
        }

        @Test
        void shouldFollowUpToMaxOfUnauthRedirections() {
            // Given
            handler =
                    session -> {
                        Response response =
                                newFixedLengthResponse(
                                        Status.TEMPORARY_REDIRECT, NanoHTTPD.MIME_HTML, "");
                        response.addHeader(HttpHeader.LOCATION, url);
                        return response;
                    };
            given(authenticationMethod.getAuthCheckingStrategy())
                    .willReturn(AuthCheckingStrategy.AUTO_DETECT);
            // When
            AuthUtils.checkLoginLinkVerification(authSender, user, url);
            // Then
            verifyNoInteractions(authSender);
            // First message sent is notified as well.
            verify(historyProvider, times(AuthUtils.MAX_UNAUTH_REDIRECTIONS + 1))
                    .addAuthMessageToHistory(any(HttpMessage.class));
        }

        @Test
        void shouldFollowRelativeUnauthRedirections() {
            // Given
            AtomicInteger redirCount = new AtomicInteger();
            handler =
                    session -> {
                        if (redirCount.compareAndSet(0, 1)) {
                            Response response =
                                    newFixedLengthResponse(
                                            Status.TEMPORARY_REDIRECT, NanoHTTPD.MIME_HTML, "");
                            response.addHeader(HttpHeader.LOCATION, "/path/");
                            return response;
                        }
                        return newFixedLengthResponse("");
                    };
            given(authenticationMethod.getAuthCheckingStrategy())
                    .willReturn(AuthCheckingStrategy.AUTO_DETECT);
            // When
            AuthUtils.checkLoginLinkVerification(authSender, user, url);
            // Then
            verifyNoInteractions(authSender);
            // First message sent is notified as well.
            verify(historyProvider, times(2)).addAuthMessageToHistory(any(HttpMessage.class));
        }
    }

    class TestWebElement implements WebElement {

        private String tag;
        private String type;
        private String id;
        private String name;
        @Setter private boolean displayed = true;

        TestWebElement(String tag, String type) {
            this.tag = tag;
            this.type = type;
        }

        TestWebElement(String tag, String type, String id, String name) {
            this(tag, type);
            this.id = id;
            this.name = name;
        }

        @Override
        public <X> X getScreenshotAs(OutputType<X> target) throws WebDriverException {
            return null;
        }

        @Override
        public void click() {}

        @Override
        public void submit() {}

        @Override
        public void sendKeys(CharSequence... keysToSend) {}

        @Override
        public void clear() {}

        @Override
        public String getTagName() {
            return tag;
        }

        @Override
        public String getAttribute(String name) {
            switch (name) {
                case "id":
                    return id;
                case "name":
                    return this.name;
                case "type":
                    return type;
                default:
                    return null;
            }
        }

        @Override
        public boolean isSelected() {
            return false;
        }

        @Override
        public boolean isEnabled() {
            return false;
        }

        @Override
        public String getText() {
            return null;
        }

        @Override
        public List<WebElement> findElements(By by) {
            return null;
        }

        @Override
        public WebElement findElement(By by) {
            return null;
        }

        @Override
        public boolean isDisplayed() {
            return displayed;
        }

        @Override
        public Point getLocation() {
            return null;
        }

        @Override
        public Dimension getSize() {
            return null;
        }

        @Override
        public Rectangle getRect() {
            return null;
        }

        @Override
        public String getCssValue(String propertyName) {
            return null;
        }
    }

    protected static Matcher<SessionToken> sessionTokenEqualTo(
            String source, String key, String value, String fullValue) {
        return new BaseMatcher<>() {

            @Override
            public boolean matches(Object actualValue) {
                SessionToken token = (SessionToken) actualValue;
                return source.equals(token.getSource())
                        && key.equals(token.getKey())
                        && value.equals(token.getValue())
                        && fullValue.equals(token.getFullValue());
            }

            @Override
            public void describeTo(Description description) {
                description
                        .appendText("SessionToken[source: ")
                        .appendValue(source)
                        .appendText(" key: ")
                        .appendValue(key)
                        .appendText(" value: ")
                        .appendValue(value)
                        .appendText(" full value: ")
                        .appendValue(fullValue)
                        .appendText("]");
            }

            @Override
            public void describeMismatch(Object item, Description description) {
                SessionToken token = (SessionToken) item;
                appendDifference(description, "source", source, token.getSource());
                appendDifference(description, "key", key, token.getKey());
                appendDifference(description, "value", value, token.getValue());
                appendDifference(description, "full value", fullValue, token.getFullValue());
            }

            private void appendDifference(
                    Description description, String field, String expected, String actual) {
                if (!expected.equals(actual)) {
                    description.appendText(field).appendText(" was ").appendValue(actual);
                }
            }
        };
    }
}
