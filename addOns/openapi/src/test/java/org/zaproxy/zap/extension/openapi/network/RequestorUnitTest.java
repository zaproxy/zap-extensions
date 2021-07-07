/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi.network;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import fi.iki.elonen.NanoHTTPD.Response.Status;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.openapi.AbstractServerTest;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link Requestor}. */
class RequestorUnitTest extends AbstractServerTest {

    static Stream<Arguments> requestMethods() {
        return Stream.of(
                arguments(RequestMethod.GET, "GET"),
                arguments(RequestMethod.POST, "POST"),
                arguments(RequestMethod.PUT, "PUT"),
                arguments(RequestMethod.OPTIONS, "OPTIONS"),
                arguments(RequestMethod.HEAD, "HEAD"),
                arguments(RequestMethod.DELETE, "DELETE"),
                arguments(RequestMethod.PATCH, "PATCH"));
    }

    @ParameterizedTest(name = "Request method: {0}")
    @MethodSource("requestMethods")
    void shouldUseCorrectRequestMethod(RequestMethod method, String expectedMethod) {
        // Given
        String baseUrl = "http://localhost:" + nano.getListeningPort() + "/";
        this.nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse("");
                    }
                });

        List<String> requestedMethods = new ArrayList<>();
        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        RequesterListener listener =
                (msg, initiator) -> requestedMethods.add(msg.getRequestHeader().getMethod());
        requestor.addListener(listener);
        // When
        List<String> errors = requestor.run(Arrays.asList(requestModel(method, baseUrl)));
        // Then
        assertThat(errors, is(empty()));
        assertThat(requestedMethods, hasSize(1));
        assertThat(requestedMethods.get(0), is(equalTo(expectedMethod)));
    }

    @Test
    void shouldNotifyAllRedirectsFollowed() {
        // Given
        String baseUrl = "http://localhost:" + nano.getListeningPort() + "/";
        this.nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        switch (session.getUri()) {
                            case "/":
                                return redirect("/a", "Root");
                            case "/a":
                                return redirect("/b", "A");
                            case "/b":
                                return redirect("/final", "B");
                            case "/final":
                                return newFixedLengthResponse("Final");
                            default:
                                return newFixedLengthResponse("");
                        }
                    }
                });

        List<String> messages = new ArrayList<>();
        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        RequesterListener listener =
                (msg, initiator) ->
                        messages.add(
                                msg.getRequestHeader().getMethod()
                                        + " "
                                        + msg.getRequestHeader().getURI().getEscapedPath()
                                        + " "
                                        + msg.getResponseBody().toString());
        requestor.addListener(listener);
        // When
        List<String> errors =
                requestor.run(Arrays.asList(requestModel(RequestMethod.GET, baseUrl)));
        // Then
        assertThat(errors, is(empty()));
        assertThat(messages.get(0), is(equalTo("GET / Root")));
        assertThat(messages.get(1), is(equalTo("GET /a A")));
        assertThat(messages.get(2), is(equalTo("GET /b B")));
        assertThat(messages.get(3), is(equalTo("GET /final Final")));
    }

    private static RequestModel requestModel(RequestMethod method, String url) {
        RequestModel request = new RequestModel();
        request.setMethod(method);
        request.setUrl(url);
        request.setHeaders(Collections.emptyList());
        request.setBody("");
        return request;
    }

    private static final Response redirect(String to, String responseContents) {
        Response response =
                newFixedLengthResponse(
                        Status.TEMPORARY_REDIRECT, NanoHTTPD.MIME_HTML, responseContents);
        response.addHeader("Location", to);
        return response;
    }
}
