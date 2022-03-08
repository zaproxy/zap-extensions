/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.openapi.AbstractServerTest;
import org.zaproxy.zap.extension.openapi.converter.Converter;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerConverter;
import org.zaproxy.zap.extension.openapi.network.RequesterListener;
import org.zaproxy.zap.extension.openapi.network.Requestor;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Test that the value generator and formats are properly handled. */
class OpenApiValueGeneratorFormatsTest extends AbstractServerTest {

    @Test
    void shouldFormats() throws Exception {
        // Given
        this.nano.addHandler(new PlainResponseServerHandler());

        ValueGenerator vg =
                new ValueGenerator() {
                    @Override
                    public String getValue(
                            URI uri,
                            String url,
                            String fieldId,
                            String defaultValue,
                            List<String> definedValues,
                            Map<String, String> envAttributes,
                            Map<String, String> fieldAttributes) {
                        if (fieldId.equals("email")) {
                            return "fsmith@example.com";
                        }
                        return defaultValue;
                    }
                };

        Converter converter =
                new SwaggerConverter(
                        getHtml(
                                "openapi_formats.yaml",
                                new String[][] {{"PORT", String.valueOf(nano.getListeningPort())}}),
                        vg);
        List<HttpMessage> accessedMessages = new ArrayList<>();
        RequesterListener listener = (message, initiator) -> accessedMessages.add(message);

        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        requestor.addListener(listener);
        // When
        requestor.run(converter.getRequestModels());
        // Then
        HttpMessage message = accessedMessages.get(0);
        assertThat(
                message.getRequestBody().toString(),
                is(
                        equalTo(
                                "{\"email\":\"fsmith@example.com\",\"datetime\":\"1970-01-01T00:00:00.001Z\",\"duration\":\"John Doe\",\"uri\":\"John Doe\"}")));
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
