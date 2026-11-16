/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.openapitest.simpletoken;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.ExtensionDev;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.ExtensionNetwork;

/** Unit test for {@link OpenApiTokenTestApiPage}. */
class OpenApiTokenTestApiPageUnitTest {

    private final OpenApiTokenTestApiPage page =
            new OpenApiTokenTestApiPage(
                    new TestProxyServer(mock(ExtensionDev.class), mock(ExtensionNetwork.class)));

    @Test
    void shouldAllowRequestWithToken() throws Exception {
        // Given
        HttpMessage msg = message(OpenApiSimpleTokenDir.TOKEN);
        // When
        page.handleMessage(null, msg);
        // Then
        assertThat(msg.getResponseHeader().getStatusCode(), is(200));
    }

    @Test
    void shouldForbidRequestWithWrongToken() throws Exception {
        // Given
        HttpMessage msg = message("wrong");
        // When
        page.handleMessage(null, msg);
        // Then
        assertThat(msg.getResponseHeader().getStatusCode(), is(403));
    }

    @Test
    void shouldForbidRequestWithoutToken() throws Exception {
        // Given
        HttpMessage msg = message(null);
        // When
        page.handleMessage(null, msg);
        // Then
        assertThat(msg.getResponseHeader().getStatusCode(), is(403));
    }

    private static HttpMessage message(String token) throws Exception {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://localhost/test-api HTTP/1.1");
        if (token != null) {
            msg.getRequestHeader().setHeader(OpenApiSimpleTokenDir.TOKEN_HEADER, token);
        }
        return msg;
    }
}
