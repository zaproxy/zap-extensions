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
package org.zaproxy.addon.network.internal.client.apachev5;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.net.PasswordAuthentication;
import org.apache.hc.core5.http.HttpHost;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.network.ConnectionOptions;
import org.zaproxy.addon.network.internal.client.HttpProxy;

/** Unit test for  {@link ProxyRoutePlanner}. */
class ProxyRoutePlannerUnitTest {

    private static final HttpProxy HTTP_PROXY =
            new HttpProxy(
                    "proxy.example.org",
                    443,
                    "Realm",
                    new PasswordAuthentication("UserName", "Password".toCharArray()));

    private ConnectionOptions connectionOptions;
    private ProxyRoutePlanner proxyRoutePlanner;

    @BeforeEach
    void setUp() {
        connectionOptions = mock(ConnectionOptions.class);
        given(connectionOptions.getHttpProxy()).willReturn(HTTP_PROXY);
        proxyRoutePlanner = new ProxyRoutePlanner(connectionOptions);
    }

    @Test
    void shouldProxyIfEnabledForHost() {
        // Given
        String schemeName = "http";
        String hostName = "localhost";
        HttpHost host = new HttpHost(schemeName, hostName, 8080);
        given(connectionOptions.isUseHttpProxy(hostName)).willReturn(true);
        // When
        HttpHost proxy = proxyRoutePlanner.determineProxy(host, null);
        // Then
        assertThat(proxy, is(notNullValue()));
        assertThat(proxy.getSchemeName(), is(equalTo(schemeName)));
        assertThat(proxy.getHostName(), is(equalTo(HTTP_PROXY.getHost())));
        assertThat(proxy.getPort(), is(equalTo(HTTP_PROXY.getPort())));
    }

    @Test
    void shouldNotProxyIfNotEnabledForHost() {
        // Given
        String schemeName = "http";
        String hostName = "localhost";
        HttpHost host = new HttpHost(schemeName, hostName, 8080);
        given(connectionOptions.isUseHttpProxy(hostName)).willReturn(false);
        // When
        HttpHost proxy = proxyRoutePlanner.determineProxy(host, null);
        // Then
        assertThat(proxy, is(nullValue()));
    }
}
