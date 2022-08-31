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
package org.zaproxy.zap.extension.openapi.spider;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.mockito.Mockito.mock;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.openapi.AbstractServerTest;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link OpenApiSpiderFunctionality}. */
class OpenApiSpiderFunctionalityUnitTest extends AbstractServerTest {

    private ValueGenerator valueGenerator;
    private OpenApiSpiderFunctionality spider;

    @BeforeEach
    void setupSpider() {
        valueGenerator = mock(ValueGenerator.class);
        spider = new OpenApiSpiderFunctionality(() -> valueGenerator);
    }

    @Test
    void shouldParseResource() throws Exception {
        // Given
        List<String> accessedUris = new ArrayList<>();
        this.nano.addHandler(
                new NanoServerHandler("") {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        accessedUris.add(session.getUri());
                        return newFixedLengthResponse("");
                    }
                });
        HttpMessage message = getHttpMessage("");
        message.setResponseBody(
                "openapi: 3.0.0\n"
                        + "servers:\n"
                        + "  - url: http://localhost:"
                        + nano.getListeningPort()
                        + "\n"
                        + "paths:\n"
                        + "  /path:\n"
                        + "    get:\n"
                        + "      responses:\n"
                        + "        200:\n"
                        + "          content:\n"
                        + "            application/json: {}");
        // When
        spider.parseResource(message);
        // Then
        assertThat(accessedUris, contains("/path"));
    }
}
