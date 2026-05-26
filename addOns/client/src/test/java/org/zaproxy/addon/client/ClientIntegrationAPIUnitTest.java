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
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.net.InetSocketAddress;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.client.internal.ClientMap;
import org.zaproxy.zap.extension.selenium.SeleniumScriptUtils;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ClientIntegrationAPI}. */
class ClientIntegrationAPIUnitTest extends TestUtils {

    private ExtensionClientIntegration extension;
    private ClientMap clientMap;
    private ClientIntegrationAPI api;

    @BeforeEach
    void setUp() {
        extension = mock(ExtensionClientIntegration.class);
        clientMap = mock(ClientMap.class);
        api = new ClientIntegrationAPI(extension, clientMap);
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
        InetSocketAddress addr = new InetSocketAddress(9999);

        // When
        String resp1 = api.handleCallBack(getMsg("GET", api.getCallbackUrl() + "/test", addr));
        String resp2 =
                api.handleCallBack(getMsg("POST", api.getCallbackUrl() + "/test/1/2/3", addr));
        String resp3 =
                api.handleCallBack(
                        getMsg("OPTIONS", api.getCallbackUrl() + "/test?querystring", addr));

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

    @Test
    void shouldCallBrowserLaunchedOnRegisteredCallbacks() {
        // Given
        BrowserEventCallBackImp callback = new BrowserEventCallBackImp("test");
        api.registerClientCallBack(callback);
        ClientCallBackUtils ccbu = createClientCallBackUtils();

        // When
        api.browserLaunched(ccbu);

        // Then
        assertThat(callback.launchedCcbu, is(sameInstance(ccbu)));
    }

    @Test
    void shouldNotCallBrowserLaunchedOnUnregisteredCallbacks() {
        // Given
        BrowserEventCallBackImp callback = new BrowserEventCallBackImp("test");
        api.registerClientCallBack(callback);
        api.unregisterClientCallBack(callback);
        ClientCallBackUtils ccbu = createClientCallBackUtils();

        // When
        api.browserLaunched(ccbu);

        // Then
        assertThat(callback.launchedCcbu, is(nullValue()));
    }

    @Test
    void shouldCallBrowserClosingOnRegisteredCallbacksWithSameCcbu() {
        // Given
        BrowserEventCallBackImp callback = new BrowserEventCallBackImp("test");
        api.registerClientCallBack(callback);
        ClientCallBackUtils ccbu = createClientCallBackUtils();
        api.browserLaunched(ccbu);

        // When
        api.browserClosing(ccbu.getWebDriver());

        // Then
        assertThat(callback.closingCcbu, is(sameInstance(ccbu)));
    }

    @Test
    void shouldNotCallBrowserClosingForUnknownWebDriver() {
        // Given
        BrowserEventCallBackImp callback = new BrowserEventCallBackImp("test");
        api.registerClientCallBack(callback);
        WebDriver unknownWd = mock(WebDriver.class);

        // When
        api.browserClosing(unknownWd);

        // Then
        assertThat(callback.closingCcbu, is(nullValue()));
    }

    @Test
    void shouldNotCallBrowserClosingTwiceForSameWebDriver() {
        // Given
        BrowserEventCallBackImp callback = new BrowserEventCallBackImp("test");
        api.registerClientCallBack(callback);
        ClientCallBackUtils ccbu = createClientCallBackUtils();
        api.browserLaunched(ccbu);
        api.browserClosing(ccbu.getWebDriver());
        callback.closingCcbu = null;

        // When
        api.browserClosing(ccbu.getWebDriver());

        // Then
        assertThat(callback.closingCcbu, is(nullValue()));
    }

    @Test
    void shouldNotCallBrowserClosingAfterClear() {
        // Given
        BrowserEventCallBackImp callback = new BrowserEventCallBackImp("test");
        api.registerClientCallBack(callback);
        ClientCallBackUtils ccbu = createClientCallBackUtils();
        api.browserLaunched(ccbu);

        // When
        api.clear();
        api.browserClosing(ccbu.getWebDriver());

        // Then
        assertThat(callback.closingCcbu, is(nullValue()));
    }

    @Test
    void shouldDelegateReportObject() throws Exception {
        // Given
        String reportedObject = "ReportedObject";
        JSONObject params = new JSONObject();
        params.put("objectJson", reportedObject);

        // When
        api.handleApiAction("reportObject", params);

        // Then
        verify(clientMap).handleReportObject(reportedObject);
    }

    @Test
    void shouldDelegateReportEvent() throws Exception {
        // Given
        String reportedEvent = "ReportedEvent";
        JSONObject params = new JSONObject();
        params.put("eventJson", reportedEvent);

        // When
        api.handleApiAction("reportEvent", params);

        // Then
        verify(clientMap).handleReportEvent(reportedEvent);
    }

    @Test
    void shouldPassInitiatorToClientCallBackWhenPortRegistered() throws Exception {
        // Given
        int proxyPort = 5678;
        InitiatorCallBackImp callback = new InitiatorCallBackImp("test");
        api.registerClientCallBack(callback);
        api.registerPortInitiator(proxyPort, HttpSender.CLIENT_SPIDER_INITIATOR);
        HttpMessage msg =
                getMsg("GET", api.getCallbackUrl() + "/test", new InetSocketAddress(proxyPort));

        // When
        api.handleCallBack(msg);

        // Then
        assertThat(callback.initiator, is(HttpSender.CLIENT_SPIDER_INITIATOR));
    }

    @Test
    void shouldPassUnknownInitiatorWhenPortUnknown() throws Exception {
        // Given
        InitiatorCallBackImp callback = new InitiatorCallBackImp("test");
        api.registerClientCallBack(callback);
        HttpMessage msg =
                getMsg("GET", api.getCallbackUrl() + "/test", new InetSocketAddress(9999));

        // When
        api.handleCallBack(msg);

        // Then
        assertThat(callback.initiator, is(-1));
    }

    @Test
    void shouldRemoveInitiatorMappingOnUnregisterPortInitiator() throws Exception {
        // Given
        int proxyPort = 5678;
        api.registerPortInitiator(proxyPort, HttpSender.CLIENT_SPIDER_INITIATOR);
        InitiatorCallBackImp callback = new InitiatorCallBackImp("test");
        api.registerClientCallBack(callback);

        // When
        api.unregisterPortInitiator(proxyPort);
        HttpMessage msg =
                getMsg("GET", api.getCallbackUrl() + "/test", new InetSocketAddress(proxyPort));
        api.handleCallBack(msg);

        // Then
        assertThat(callback.initiator, is(-1));
    }

    @Test
    void shouldDelegateReportObjectViaCallback() throws Exception {
        // Given
        String reportedObject = "ReportedObject";
        int localPort = 1234;
        HttpMessage msg =
                getPostMsg(
                        api.getCallbackUrl(),
                        "objectJson=" + URLEncoder.encode(reportedObject, StandardCharsets.UTF_8),
                        localPort);

        // When
        api.handleCallBack(msg);

        // Then
        verify(clientMap).handleReportObject(reportedObject, localPort);
    }

    @Test
    void shouldDelegateReportEventViaCallback() throws Exception {
        // Given
        String reportedEvent = "ReportedEvent";
        int localPort = 4321;
        HttpMessage msg =
                getPostMsg(
                        api.getCallbackUrl(),
                        "eventJson=" + URLEncoder.encode(reportedEvent, StandardCharsets.UTF_8),
                        localPort);

        // When
        api.handleCallBack(msg);

        // Then
        verify(clientMap).handleReportEvent(reportedEvent, localPort);
    }

    private static ClientCallBackUtils createClientCallBackUtils() {
        return createClientCallBackUtils(8080, 0);
    }

    private static ClientCallBackUtils createClientCallBackUtils(int proxyPort, int requester) {
        WebDriver wd = mock(WebDriver.class);
        SeleniumScriptUtils ssu =
                new SeleniumScriptUtils(wd, requester, "firefox", "localhost", proxyPort);
        return new ClientCallBackUtils(ssu, UUID.randomUUID());
    }

    private static HttpMessage getMsg(String method, String url) throws Exception {
        return getMsg(method, url, null);
    }

    private static HttpMessage getMsg(String method, String url, InetSocketAddress localAddress)
            throws Exception {
        HttpMessage msg = new HttpMessage();
        URI uri = new URI(url, true);
        msg.setRequestHeader(new HttpRequestHeader(method, uri, HttpHeader.HTTP11));
        if (localAddress != null) {
            msg.getRequestHeader().setLocalAddress(localAddress);
        }
        return msg;
    }

    private static HttpMessage getPostMsg(String url, String body, int localPort) throws Exception {
        HttpMessage msg = getMsg(HttpRequestHeader.POST, url);
        msg.getRequestHeader().setLocalAddress(new InetSocketAddress(localPort));
        msg.setRequestBody(body);
        return msg;
    }

    static class BrowserEventCallBackImp implements ClientCallBackImplementor {

        private final String name;
        ClientCallBackUtils launchedCcbu;
        ClientCallBackUtils closingCcbu;

        BrowserEventCallBackImp(String name) {
            this.name = name;
        }

        @Override
        public String getImplementorName() {
            return name;
        }

        @Override
        public String handleCallBack(HttpMessage msg) {
            return "";
        }

        @Override
        public void browserLaunched(ClientCallBackUtils ccbu) {
            this.launchedCcbu = ccbu;
        }

        @Override
        public void browserClosing(ClientCallBackUtils ccbu) {
            this.closingCcbu = ccbu;
        }
    }

    static class InitiatorCallBackImp implements ClientCallBackImplementor {

        private final String name;
        int initiator = -1;

        InitiatorCallBackImp(String name) {
            this.name = name;
        }

        @Override
        public String getImplementorName() {
            return name;
        }

        @Override
        public String handleCallBack(HttpMessage msg) {
            return "";
        }

        @Override
        public String handleCallBack(
                HttpMessage msg, ClientCallBackImplementor.ClientCallBackContext context) {
            this.initiator = context.initiator();
            return "";
        }
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
