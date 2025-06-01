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
package org.zaproxy.addon.network.internal.server.http;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;

import io.netty.channel.Channel;
import io.netty.channel.embedded.EmbeddedChannel;
import java.net.InetSocketAddress;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.addon.network.internal.server.ServerConfig;

/** Unit test for {@link RecursiveRequestChecker}. */
class RecursiveRequestCheckerUnitTest {

    private static final int LOCAL_PORT = 8080;
    private static final InetSocketAddress LOCAL_ADDRESS =
            new InetSocketAddress("127.0.0.1", LOCAL_PORT);

    private ServerConfig serverConfig;
    private Channel channel;

    private RecursiveRequestChecker recursiveRequestChecker;

    @BeforeEach
    void setUp() {
        serverConfig = mock(ServerConfig.class);

        recursiveRequestChecker = RecursiveRequestChecker.getInstance();
        channel = new EmbeddedChannel();
        channel.attr(ChannelAttributes.SERVER_CONFIG).set(serverConfig);
        channel.attr(ChannelAttributes.LOCAL_ADDRESS).set(LOCAL_ADDRESS);
    }

    @Test
    void shouldHaveNonNullInstance() {
        assertThat(RecursiveRequestChecker.getInstance(), is(notNullValue()));
    }

    @Test
    void shouldNotBeRecursiveIfServerConfigAttributeNotPresent() throws Exception {
        // Given
        channel.attr(ChannelAttributes.SERVER_CONFIG).set(null);
        HttpMessage request = createRequest("GET / HTTP/1.1\r\n\r\n");
        // When
        boolean recursive = recursiveRequestChecker.isRecursive(channel, request);
        // Then
        assertThat(recursive, is(equalTo(false)));
    }

    @Test
    void shouldNotBeRecursiveIfLocalAddressAttributeNotPresent() throws Exception {
        // Given
        channel.attr(ChannelAttributes.LOCAL_ADDRESS).set(null);
        HttpMessage request = createRequest("GET / HTTP/1.1\r\n\r\n");
        // When
        boolean recursive = recursiveRequestChecker.isRecursive(channel, request);
        // Then
        assertThat(recursive, is(equalTo(false)));
    }

    @Test
    void shouldNotBeRecursiveIfNotRequestToItself() throws Exception {
        // Given
        HttpMessage request = createRequest("GET / HTTP/1.1\r\n\r\n");
        // When
        boolean recursive = recursiveRequestChecker.isRecursive(channel, request);
        // Then
        assertThat(recursive, is(equalTo(false)));
    }

    @Test
    void shouldNotBeRecursiveIfConnectRequestToItself() throws Exception {
        // Given
        HttpMessage request =
                createRequest("CONNECT 127.0.0.1:" + LOCAL_PORT + " HTTP/1.1\r\n\r\n");
        // When
        boolean recursive = recursiveRequestChecker.isRecursive(channel, request);
        // Then
        assertThat(recursive, is(equalTo(false)));
    }

    @Test
    void shouldNotBeRecursiveIfSameAddressButNotSamePort() throws Exception {
        // Given
        HttpMessage request =
                createRequest("GET / HTTP/1.1\r\nHost: 127.0.0.1:" + (LOCAL_PORT + 1) + "\r\n\r\n");
        // When
        boolean recursive = recursiveRequestChecker.isRecursive(channel, request);
        // Then
        assertThat(recursive, is(equalTo(false)));
    }

    @Test
    void shouldNotBeRecursiveIfSamePortButNotSameAddress() throws Exception {
        // Given
        HttpMessage request =
                createRequest("GET / HTTP/1.1\r\nHost: 127.0.0.2:" + LOCAL_PORT + "\r\n\r\n");
        // When
        boolean recursive = recursiveRequestChecker.isRecursive(channel, request);
        // Then
        assertThat(recursive, is(equalTo(false)));
    }

    @Test
    void shouldNotBeRecursiveIfAnyLocalAddressWithSamePortButNotSameAddress() throws Exception {
        // Given
        given(serverConfig.isAnyLocalAddress()).willReturn(true);
        HttpMessage request =
                createRequest("GET / HTTP/1.1\r\nHost: example.com:" + LOCAL_PORT + "\r\n\r\n");
        // When
        boolean recursive = recursiveRequestChecker.isRecursive(channel, request);
        // Then
        assertThat(recursive, is(equalTo(false)));
    }

    @Test
    void shouldBeRecursiveIfAnAlias() throws Exception {
        // Given
        given(serverConfig.isAlias(any())).willReturn(true);
        HttpMessage request = createRequest("GET / HTTP/1.1\r\nHost: zap\r\n\r\n");
        // When
        boolean recursive = recursiveRequestChecker.isRecursive(channel, request);
        // Then
        assertThat(recursive, is(equalTo(true)));
    }

    @Test
    void shouldBeRecursiveIfSameAddressAndPort() throws Exception {
        // Given
        HttpMessage request =
                createRequest("GET / HTTP/1.1\r\nHost: 127.0.0.1:" + LOCAL_PORT + "\r\n\r\n");
        // When
        boolean recursive = recursiveRequestChecker.isRecursive(channel, request);
        // Then
        assertThat(recursive, is(equalTo(true)));
    }

    @Test
    void shouldBeRecursiveIfAnyLocalAddressAndLocalAddressAndPort() throws Exception {
        // Given
        given(serverConfig.isAnyLocalAddress()).willReturn(true);
        HttpMessage request =
                createRequest("GET / HTTP/1.1\r\nHost: localhost:" + LOCAL_PORT + "\r\n\r\n");
        // When
        boolean recursive = recursiveRequestChecker.isRecursive(channel, request);
        // Then
        assertThat(recursive, is(equalTo(true)));
    }

    private static HttpMessage createRequest(String content) throws Exception {
        return new HttpMessage(new HttpRequestHeader(content));
    }
}
