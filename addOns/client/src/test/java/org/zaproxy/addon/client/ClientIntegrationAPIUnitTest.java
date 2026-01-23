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
package org.zaproxy.addon.client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ClientIntegrationAPI}. */
class ClientIntegrationAPIUnitTest extends TestUtils {

    private ClientIntegrationAPI api;

    @BeforeEach
    void setUp() {
        api = new ClientIntegrationAPI(null);
    }

    @Test
    void shouldRejectNullImplementorOnRegister() {
        // Given / When
        Exception e =
                assertThrows(NullPointerException.class, () -> api.registerClientCallBack(null));

        // Then
        assertThat(e.getMessage(), is("Parameter callback must not be null"));
    }

    @Test
    void shouldRejectNullImplementorOnUnRegister() {
        // Given / When
        Exception e =
                assertThrows(NullPointerException.class, () -> api.unregisterClientCallBack(null));

        // Then
        assertThat(e.getMessage(), is("Parameter callback must not be null"));
    }

    @Test
    void shouldRejectNullImplementorNameOnRegister() {
        // Given / When
        Exception e =
                assertThrows(
                        NullPointerException.class,
                        () -> api.registerClientCallBack(new CallBackImp(null)));

        // Then
        assertThat(e.getMessage(), is("Parameter callback implementor name must not be null"));
    }

    @Test
    void shouldRejectNullImplementorNameOnUnRegister() {
        // Given / When
        Exception e =
                assertThrows(
                        NullPointerException.class,
                        () -> api.unregisterClientCallBack(new CallBackImp(null)));

        // Then
        assertThat(e.getMessage(), is("Parameter callback implementor name must not be null"));
    }

    @Test
    void shouldUseTheRegisteredClientCallBack() throws Exception {
        // Given
        CallBackImp callback = new CallBackImp("test");
        api.registerClientCallBack(callback);

        // When
        String resp1 = api.handleCallBack(getMsg("GET", api.getCallbackUrl() + "/test"));
        String resp2 = api.handleCallBack(getMsg("POST", api.getCallbackUrl() + "/test/1/2/3"));
        String resp3 =
                api.handleCallBack(getMsg("OPTIONS", api.getCallbackUrl() + "/test?querystring"));

        // Then
        assertThat(callback.calls, is(3));
        assertThat(resp1, is("Test1"));
        assertThat(resp2, is("Test2"));
        assertThat(resp3, is("Test3"));
    }

    @Test
    void shouldNotUseUnregisteredClientCallBacks() throws Exception {
        // Given
        CallBackImp callback = new CallBackImp("test");
        api.registerClientCallBack(callback);
        api.unregisterClientCallBack(callback);

        // When
        String resp1 = api.handleCallBack(getMsg("GET", api.getCallbackUrl() + "/test"));
        String resp2 = api.handleCallBack(getMsg("POST", api.getCallbackUrl() + "/test/1/2/3"));
        String resp3 =
                api.handleCallBack(getMsg("OPTIONS", api.getCallbackUrl() + "/test?querystring"));

        // Then
        assertThat(callback.calls, is(0));
        assertThat(resp1, is(""));
        assertThat(resp2, is(""));
        assertThat(resp3, is(""));
    }

    @Test
    void shouldNotUseDifferentClientCallBacks() throws Exception {
        // Given
        CallBackImp callback = new CallBackImp("test");
        api.registerClientCallBack(callback);

        // When
        String resp1 = api.handleCallBack(getMsg("GET", api.getCallbackUrl()));
        String resp2 = api.handleCallBack(getMsg("GET", api.getCallbackUrl() + "test"));
        String resp3 = api.handleCallBack(getMsg("POST", api.getCallbackUrl() + "/tester/"));
        String resp4 =
                api.handleCallBack(getMsg("OPTIONS", api.getCallbackUrl() + "/1test?querystring"));

        // Then
        assertThat(callback.calls, is(0));
        assertThat(resp1, is(""));
        assertThat(resp2, is(""));
        assertThat(resp3, is(""));
        assertThat(resp4, is(""));
    }

    private HttpMessage getMsg(String method, String url) throws Exception {
        HttpMessage msg = new HttpMessage();
        URI uri = new URI(url, true);
        msg.setRequestHeader(new HttpRequestHeader(method, uri, HttpHeader.HTTP11));
        return msg;
    }

    static class CallBackImp implements ClientCallBackImplementor {

        private String name;
        int calls = 0;

        CallBackImp(String name) {
            this.name = name;
        }

        @Override
        public String getImplementorName() {
            return name;
        }

        @Override
        public String handleCallBack(HttpMessage msg) {
            this.calls++;
            return "Test" + this.calls;
        }
    }
}
