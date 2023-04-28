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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.extension.users.ContextUserAuthManager;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.users.User;

class VerificationRequestDetailsUnitTest extends TestUtils {

    private ExtensionLoader extensionLoader;

    private Context context;
    private ContextUserAuthManager cuam;

    @BeforeEach
    public void setUp() throws Exception {
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        context = mock(Context.class);
        given(context.getId()).willReturn(1);
        cuam = mock(ContextUserAuthManager.class);

        ExtensionUserManagement extUser = mock(ExtensionUserManagement.class);
        given(extensionLoader.getExtension(ExtensionUserManagement.class)).willReturn(extUser);
        given(extUser.getContextUserAuthManager(anyInt())).willReturn(cuam);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
    }

    @Test
    void shouldReturnDataForBasicRequest() throws Exception {
        // Given
        String body = "Response Body";
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET / HTTP/1.1\r\n"
                                        + "Header1: Value1\r\n"
                                        + "Header2: Value2\r\n"
                                        + "Host: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 404 OK\r\n"),
                        new HttpResponseBody(body));

        // When
        VerificationRequestDetails vrd = new VerificationRequestDetails(msg, "aaa", context);

        // Then
        assertThat(vrd.getMsg(), is(equalTo(msg)));
        assertThat(vrd.getResponseCode(), is(equalTo(404)));
        assertThat(vrd.getContextId(), is(equalTo(1)));
        assertThat(vrd.isContainsUserDetails(), is(equalTo(false)));
        assertThat(vrd.isStructuredResponse(), is(equalTo(false)));
        assertThat(vrd.getEvidence(), is(""));
        assertThat(vrd.getResponseSize(), is(equalTo(body.length())));
        assertThat(vrd.getToken(), is(equalTo("aaa")));
        assertThat(vrd.getScore(), is(equalTo(2)));
        assertThat(vrd.getConfidence(), is(equalTo(1)));
    }

    @Test
    void shouldReturnDataForStructuredRequest() throws Exception {
        // Given
        String username = "user123@test.com";
        String body = "{'example': 'value1, 'user': '" + username + "'}";
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET / HTTP/1.1\r\n"
                                        + "Header1: Value1\r\n"
                                        + "Host: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader(
                                "HTTP/1.1 200 OK\r\n" + "Content-Type: application/json\r\n"),
                        new HttpResponseBody(body));
        List<User> users = new ArrayList<>();
        users.add(new User(1, username));
        given(cuam.getUsers()).willReturn(users);

        // When
        VerificationRequestDetails vrd = new VerificationRequestDetails(msg, "bbb", context);

        // Then
        assertThat(vrd.getMsg(), is(equalTo(msg)));
        assertThat(vrd.getResponseCode(), is(equalTo(200)));
        assertThat(vrd.getContextId(), is(equalTo(1)));
        assertThat(vrd.isContainsUserDetails(), is(equalTo(true)));
        assertThat(vrd.isStructuredResponse(), is(equalTo(true)));
        assertThat(vrd.getEvidence(), is(username));
        assertThat(vrd.getResponseSize(), is(equalTo(body.length())));
        assertThat(vrd.getToken(), is(equalTo("bbb")));
        assertThat(vrd.getScore(), is(equalTo(15)));
        assertThat(vrd.getConfidence(), is(equalTo(3)));
    }

    @Test
    void shouldReturnDataForStructuredRequestWithUsername() throws Exception {
        // Given
        String username = "user123@test.com";
        String body = "{'example': 'value1, 'user': '" + username + "'}";
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET / HTTP/1.1\r\n"
                                        + "Header1: Value1\r\n"
                                        + "Host: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader(
                                "HTTP/1.1 200 OK\r\n" + "Content-Type: application/json\r\n"),
                        new HttpResponseBody(body));
        List<User> users = new ArrayList<>();
        User user = new User(1, "test");
        user.setAuthenticationCredentials(
                new UsernamePasswordAuthenticationCredentials(username, "password123"));
        users.add(new User(1, username));
        given(cuam.getUsers()).willReturn(users);

        // When
        VerificationRequestDetails vrd = new VerificationRequestDetails(msg, "bbb", context);

        // Then
        assertThat(vrd.getMsg(), is(equalTo(msg)));
        assertThat(vrd.getResponseCode(), is(equalTo(200)));
        assertThat(vrd.getContextId(), is(equalTo(1)));
        assertThat(vrd.isContainsUserDetails(), is(equalTo(true)));
        assertThat(vrd.isStructuredResponse(), is(equalTo(true)));
        assertThat(vrd.getEvidence(), is(username));
        assertThat(vrd.getResponseSize(), is(equalTo(body.length())));
        assertThat(vrd.getToken(), is(equalTo("bbb")));
        assertThat(vrd.getScore(), is(equalTo(15)));
        assertThat(vrd.getConfidence(), is(equalTo(3)));
    }

    @Test
    void shouldReturnIsConsistant() throws Exception {
        // Given
        String body = "Response Body";
        HttpMessage msg1 =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 404 OK\r\n"),
                        new HttpResponseBody(body));
        HttpMessage msg2 =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 404 OK\r\n"),
                        new HttpResponseBody(body + "!"));

        // When
        VerificationRequestDetails vrd1 = new VerificationRequestDetails(msg1, "aaa", context);
        VerificationRequestDetails vrd2 = new VerificationRequestDetails(msg2, "aaa", context);

        // Then
        assertThat(vrd1.isConsistent(vrd2), is(equalTo(true)));
        assertThat(vrd1.isIdentifiablyDifferent(vrd2), is(equalTo(false)));
    }

    @Test
    void shouldReturnNotIsConsistantForDifferingBodies() throws Exception {
        // Given
        String body = "Response Body";
        HttpMessage msg1 =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 404 OK\r\n"),
                        new HttpResponseBody(body));
        HttpMessage msg2 =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 404 OK\r\n"),
                        new HttpResponseBody(body + " which is different"));

        // When
        VerificationRequestDetails vrd1 = new VerificationRequestDetails(msg1, "aaa", context);
        VerificationRequestDetails vrd2 = new VerificationRequestDetails(msg2, "aaa", context);

        // Then
        assertThat(vrd1.isConsistent(vrd2), is(equalTo(false)));
        assertThat(vrd1.isIdentifiablyDifferent(vrd2), is(equalTo(false)));
    }

    @Test
    void shouldReturnNotIsConsistantForDifferingResponseCodes() throws Exception {
        // Given
        String body = "Response Body";
        HttpMessage msg1 =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 404 OK\r\n"),
                        new HttpResponseBody(body));
        HttpMessage msg2 =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 401 OK\r\n"),
                        new HttpResponseBody(body));

        // When
        VerificationRequestDetails vrd1 = new VerificationRequestDetails(msg1, "aaa", context);
        VerificationRequestDetails vrd2 = new VerificationRequestDetails(msg2, "aaa", context);

        // Then
        assertThat(vrd1.isConsistent(vrd2), is(equalTo(false)));
        assertThat(vrd1.isIdentifiablyDifferent(vrd2), is(equalTo(true)));
    }

    @Test
    void shouldReturnNotIsConsistantForDifferingResponseTypes() throws Exception {
        // Given
        String stdBody = "Response Body ";
        String jsnBody = "{'aaa': 'bbb'}";
        HttpMessage msg1 =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader(
                                "HTTP/1.1 200 OK\r\n" + "Content-Type: application/text\r\n"),
                        new HttpResponseBody(stdBody));
        HttpMessage msg2 =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader(
                                "HTTP/1.1 200 OK\r\n" + "Content-Type: application/json\r\n"),
                        new HttpResponseBody(jsnBody));

        // When
        VerificationRequestDetails vrd1 = new VerificationRequestDetails(msg1, "aaa", context);
        VerificationRequestDetails vrd2 = new VerificationRequestDetails(msg2, "aaa", context);

        // Then
        assertThat(vrd1.isConsistent(vrd2), is(equalTo(false)));
    }

    @Test
    void shouldReturnNotIsConsistantForDifferingUserDetails() throws Exception {
        // Given
        String user1 = "user1@test.com";
        String user2 = "user2@test.com";
        String body1 = "{'example': 'value1, 'user': '" + user1 + "'}";
        String body2 = "{'example': 'value1, 'user': '" + user2 + "'}";

        List<User> users = new ArrayList<>();
        users.add(new User(1, user1));
        given(cuam.getUsers()).willReturn(users);

        HttpMessage msg1 =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET / HTTP/1.1\r\n"
                                        + "Header1: Value1\r\n"
                                        + "Host: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader(
                                "HTTP/1.1 200 OK\r\n" + "Content-Type: application/json\r\n"),
                        new HttpResponseBody(body1));

        HttpMessage msg2 =
                new HttpMessage(
                        new HttpRequestHeader("GET / HTTP/1.1\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader(
                                "HTTP/1.1 200 OK\r\n" + "Content-Type: application/json\r\n"),
                        new HttpResponseBody(body2));

        // When
        VerificationRequestDetails vrd1 = new VerificationRequestDetails(msg1, "aaa", context);
        VerificationRequestDetails vrd2 = new VerificationRequestDetails(msg2, "aaa", context);

        // Then
        assertThat(vrd1.isConsistent(vrd2), is(equalTo(false)));
        assertThat(vrd1.isIdentifiablyDifferent(vrd2), is(equalTo(true)));
    }
}
