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
package org.zaproxy.zap.extension.openapi.v3;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response.Status;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.openapi.AbstractServerTest;
import org.zaproxy.zap.extension.openapi.converter.Converter;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerConverter;
import org.zaproxy.zap.extension.openapi.network.RequesterListener;
import org.zaproxy.zap.extension.openapi.network.Requestor;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Test generated values for cookies. */
class OpenApiGeneratedCookieValuesTest extends AbstractServerTest {

    @Test
    void shouldUseDefaultValues() throws Exception {
        // Given
        this.nano.addHandler(new PlainResponseServerHandler());

        Converter converter =
                new SwaggerConverter(
                        getHtml(
                                "openapi_generated_cookie_values.yaml",
                                new String[][] {{"PORT", String.valueOf(nano.getListeningPort())}}),
                        null);
        List<HttpMessage> accessedMessages = new ArrayList<>();
        RequesterListener listener = (message, initiator) -> accessedMessages.add(message);

        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        requestor.addListener(listener);
        // When
        requestor.run(converter.getRequestModels());
        // Then
        HttpMessage message = accessedMessages.get(0);
        assertThat(message.getRequestHeader().getHeader("Cookie"), is(equalTo("Name=true")));

        message = accessedMessages.get(1);
        assertThat(message.getRequestHeader().getHeader("Cookie"), is(equalTo("Name=10")));

        message = accessedMessages.get(2);
        assertThat(message.getRequestHeader().getHeader("Cookie"), is(equalTo("Name=1.2")));

        message = accessedMessages.get(3);
        assertThat(message.getRequestHeader().getHeader("Cookie"), is(equalTo("Name=JohnDoe")));
    }

    private static class PlainResponseServerHandler extends NanoServerHandler {

        public PlainResponseServerHandler() {
            super("");
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            consumeBody(session);
            return newFixedLengthResponse(Status.OK, NanoHTTPD.MIME_PLAINTEXT, "");
        }
    }
}
