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
package org.zaproxy.addon.oast.services.callback;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.io.IOException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.addon.oast.OastRequest;
import org.zaproxy.addon.oast.OastRequestHandler;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link CallbackService}. */
class CallbackServiceUnitTest extends TestUtils {

    private static ExtensionNetwork extensionNetwork;
    private int serverPort;
    private OastRequestHandler oastRequestHandler;
    private OastRequest oastRequest;
    private HttpSender httpSender;
    private CallbackService callbackService;

    @BeforeAll
    static void setupAll() {
        mockMessages(new ExtensionOast());
        extensionNetwork = new ExtensionNetwork();
        extensionNetwork.init();
    }

    @AfterAll
    static void tearDownAll() {
        extensionNetwork.stop();
    }

    @BeforeEach
    void setup() throws Exception {
        httpSender = new HttpSender(new ConnectionParam(), false, 0);

        oastRequest = mock(OastRequest.class);
        OastRequestFactory oastRequestFactory =
                mock(OastRequestFactory.class, withSettings().lenient());
        given(oastRequestFactory.create(any(), anyString(), anyString())).willReturn(oastRequest);
        oastRequestHandler = mock(OastRequestHandler.class);

        callbackService = new CallbackService(oastRequestFactory, extensionNetwork);
        callbackService.getParam().load(new ZapXmlConfiguration());
        serverPort = getRandomPort();
        callbackService.getParam().setPort(serverPort);
        callbackService.addOastRequestHandler(oastRequestHandler);
    }

    @AfterEach
    void tearDown() {
        this.callbackService.stopService();
    }

    @Test
    void shouldThrowForNullOastRequestFactory() throws Exception {
        // Given
        OastRequestFactory oastRequestFactory = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new CallbackService(oastRequestFactory, extensionNetwork));
    }

    @Test
    void shouldThrowForNullExtensionNetwork() throws Exception {
        // Given
        OastRequestFactory oastRequestFactory = mock(OastRequestFactory.class);
        ExtensionNetwork extensionNetwork = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new CallbackService(oastRequestFactory, extensionNetwork));
    }

    @Test
    void shouldStartServerOnSpecifiedPort() throws Exception {
        // Given
        callbackService.startService();
        HttpMessage serverRequest = createServerRequest("/");
        // When
        httpSender.sendAndReceive(serverRequest);
        // Then
        verify(oastRequestHandler).handle(oastRequest);
    }

    @Test
    void shouldStartServerOnRandomPort() throws Exception {
        // Given
        callbackService.getParam().setPort(0);
        callbackService.startService();
        serverPort = callbackService.getPort();
        HttpMessage serverRequest = createServerRequest("/");
        // When
        httpSender.sendAndReceive(serverRequest);
        // Then
        verify(oastRequestHandler).handle(oastRequest);
    }

    @Test
    void shouldStopServer() throws Exception {
        // Given
        callbackService.startService();
        HttpMessage serverRequest = createServerRequest("/");
        // When
        httpSender.sendAndReceive(serverRequest);
        callbackService.stopService();
        // Then
        assertThrows(IOException.class, () -> httpSender.sendAndReceive(serverRequest));
        verify(oastRequestHandler).handle(oastRequest);
    }

    @Test
    void shouldRestartServer() throws Exception {
        // Given
        callbackService.startService();
        HttpMessage serverRequest = createServerRequest("/");
        // When
        httpSender.sendAndReceive(serverRequest);
        callbackService.stopService();
        assertThrows(IOException.class, () -> httpSender.sendAndReceive(serverRequest));
        callbackService.startService();
        httpSender.sendAndReceive(serverRequest);
        // Then
        verify(oastRequestHandler, times(2)).handle(oastRequest);
    }

    @Test
    void shouldIncrementStatPayloadsGeneratedCorrectly() throws Exception {
        // Given
        callbackService.startService();
        InMemoryStats stats = new InMemoryStats();
        Stats.addListener(stats);
        // When
        callbackService.getNewPayload();
        // Then
        assertThat(stats.getStat("stats.oast.callback.payloadsGenerated"), is(1L));
    }

    private HttpMessage createServerRequest(String path) throws Exception {
        return new HttpMessage(
                new HttpRequestHeader(
                        "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1:" + serverPort));
    }
}
