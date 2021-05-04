/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package com.sittinglittleduck.DirBuster;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.testutils.HTTPDTestServer;

class EasySSLProtocolSocketFactoryUnitTest {

    private EasySSLProtocolSocketFactory socketFactory;

    private static HTTPDTestServer testServer;
    private static int serverPort;

    @BeforeAll
    static void startEmbeddedHttpServers() throws Exception {
        testServer = new HTTPDTestServer(0);
        testServer.start();
        serverPort = testServer.getListeningPort();
    }

    @AfterAll
    static void stopEmbeddedHttpServers() {
        testServer.stop();
    }

    @BeforeEach
    void resetSocketFactory() throws Exception {
        socketFactory = new EasySSLProtocolSocketFactory();
    }

    @Test
    void shouldCreateSocketForGivenHostAndPort() throws Exception {
        // Given
        String host = "localhost";
        int port = serverPort;
        // When
        Socket sslSocket = socketFactory.createSocket(host, port);
        // Then
        assertThat(sslSocket.getInetAddress().getHostName(), is(equalTo(host)));
        assertThat(sslSocket.getPort(), is(equalTo(port)));
    }

    // Note that on some platforms this gives a ConnectionException while on others it give a
    // UnknownHostException
    @Test
    void shouldFailCreatingSocketForUnknownHost() throws Exception {
        // Given
        String unknownHost = "localhorst";
        InetAddress localAddress = InetAddress.getLoopbackAddress();
        int localPort = 28080;
        HttpConnectionParams params = new HttpConnectionParams();
        params.setConnectionTimeout(60000);
        // When / Then
        assertThrows(
                IOException.class,
                () ->
                        socketFactory.createSocket(
                                unknownHost, serverPort, localAddress, localPort, params));
    }

    @Test
    void shouldFailCreatingSocketForUnknownPort() throws Exception {
        // Given
        int unknownPort = 12345;
        // When / Then
        assertThrows(
                ConnectException.class, () -> socketFactory.createSocket("localhost", unknownPort));
    }

    @Test
    void shouldFailCreatingSocketForMissingParameters() throws Exception {
        // Given
        HttpConnectionParams nullParams = null;
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        socketFactory.createSocket(
                                "localhost",
                                serverPort,
                                InetAddress.getLoopbackAddress(),
                                12345,
                                nullParams));
    }

    @Test
    void shouldCreateSocketWithGivenLocalAddressAndPort() throws Exception {
        // Given
        InetAddress localAddress = InetAddress.getLoopbackAddress();
        int localPort = 28080;
        // When
        Socket sslSocket =
                socketFactory.createSocket(
                        "localhost",
                        serverPort,
                        localAddress,
                        localPort,
                        new HttpConnectionParams());
        // Then
        assertThat(sslSocket.getLocalAddress(), is(equalTo(localAddress)));
        assertThat(sslSocket.getLocalPort(), is(equalTo(localPort)));
    }

    @Test
    @Disabled(value = "Requires a way to slow down connect process artificially")
    void shouldFailCreatingSocketWithInstantTimeout() throws Exception {
        // Given
        HttpConnectionParams params = new HttpConnectionParams();
        params.setConnectionTimeout(1);
        // When / Then
        assertThrows(
                SocketTimeoutException.class,
                () ->
                        socketFactory.createSocket(
                                "localhost",
                                serverPort,
                                InetAddress.getLoopbackAddress(),
                                38080,
                                params));
    }

    @Test
    void shouldSucceedCreatingSocketWithReasonableTimeout() throws Exception {
        // Given
        HttpConnectionParams params = new HttpConnectionParams();
        params.setConnectionTimeout(1000);
        // When
        Socket sslSocket =
                socketFactory.createSocket(
                        "localhost", serverPort, InetAddress.getLoopbackAddress(), 48080, params);
        // Then
        assertThat(sslSocket, is(notNullValue()));
    }
}
