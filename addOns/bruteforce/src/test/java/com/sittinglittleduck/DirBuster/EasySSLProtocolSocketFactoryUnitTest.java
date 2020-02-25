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

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.net.ConnectException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.zaproxy.zap.testutils.HTTPDTestServer;

public class EasySSLProtocolSocketFactoryUnitTest {

    private EasySSLProtocolSocketFactory socketFactory;

    private static HTTPDTestServer testServer;
    private static int serverPort;

    @BeforeClass
    public static void startEmbeddedHttpServers() throws Exception {
        testServer = new HTTPDTestServer(0);
        testServer.start();
        serverPort = testServer.getListeningPort();
    }

    @AfterClass
    public static void stopEmbeddedHttpServers() {
        testServer.stop();
    }

    @Before
    public void resetSocketFactory() throws Exception {
        socketFactory = new EasySSLProtocolSocketFactory();
    }

    @Test
    public void shouldCreateSocketForGivenHostAndPort() throws Exception {
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
    @Test(expected = java.io.IOException.class)
    public void shouldFailCreatingSocketForUnknownHost() throws Exception {
        // Given
        String unknownHost = "localhorst";
        InetAddress localAddress = InetAddress.getLoopbackAddress();
        int localPort = 28080;
        HttpConnectionParams params = new HttpConnectionParams();
        params.setConnectionTimeout(60000);
        // When
        socketFactory.createSocket(unknownHost, serverPort, localAddress, localPort, params);
        // Then = IOException
    }

    @Test(expected = ConnectException.class)
    public void shouldFailCreatingSocketForUnknownPort() throws Exception {
        // Given
        int unknownPort = 12345;
        // When
        socketFactory.createSocket("localhost", unknownPort);
        // Then = ConnectException
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailCreatingSocketForMissingParameters() throws Exception {
        // Given
        HttpConnectionParams nullParams = null;
        // When
        socketFactory.createSocket(
                "localhost", serverPort, InetAddress.getLoopbackAddress(), 12345, nullParams);
        // Then = IllegalArgumentException
    }

    @Test
    public void shouldCreateSocketWithGivenLocalAddressAndPort() throws Exception {
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

    @Test(expected = SocketTimeoutException.class)
    @Ignore // TODO Won't work unless we figure out a way to slow down connect process artificially
    public void shouldFailCreatingSocketWithInstantTimeout() throws Exception {
        // Given
        HttpConnectionParams params = new HttpConnectionParams();
        params.setConnectionTimeout(1);
        // When
        socketFactory.createSocket(
                "localhost", serverPort, InetAddress.getLoopbackAddress(), 38080, params);
        // Then = SocketTimeoutException
    }

    @Test
    public void shouldSucceedCreatingSocketWithReasonableTimeout() throws Exception {
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
