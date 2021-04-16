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
package org.zaproxy.addon.commonlib;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Collections;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.ActiveScannerTestUtils;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link AbstractHostFilePlugin}. */
public abstract class AbstractHostFilePluginUnitTest<T extends AbstractHostFilePlugin>
        extends ActiveScannerTestUtils<AbstractHostFilePlugin> {

    private String body;

    public AbstractHostFilePluginUnitTest() {
        this.body = "<html><head></head><H>Awesome Content</H1>Some text...<html>";
    }

    public void setBody(String body) {
        this.body = body;
    }

    @Test
    public void shouldCleanupOriginalRequestWhenMakingHostFileRequest()
            throws HttpMalformedHeaderException {
        // Given
        String path = "/";
        nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, body)));
        HttpMessage message = getHttpMessage(path);
        message.getRequestHeader().setMethod("POST");
        message.getRequestBody().setBody("foo=bar");
        message.getRequestHeader()
                .addHeader(HttpHeader.CONTENT_TYPE, "application/x-www-form-urlencoded");
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        HttpMessage sentMessage = httpMessagesSent.get(0);
        assertThat(sentMessage.getRequestHeader().getMethod(), is(equalTo("GET")));
        assertThat(
                sentMessage.getRequestHeader().getHeaderValues(HttpHeader.CONTENT_TYPE),
                is(equalTo(Collections.emptyList())));
        assertThat(sentMessage.getRequestBody().length(), is(equalTo(0)));
    }

    private static NanoServerHandler createHandler(String path, Response response) {
        return new NanoServerHandler(path) {
            @Override
            protected Response serve(IHTTPSession session) {
                return response;
            }
        };
    }
}
