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
package org.zaproxy.addon.network;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.addon.network.LocalServersOptions.ServersChangedListener;
import org.zaproxy.addon.network.internal.TlsUtils;
import org.zaproxy.addon.network.internal.server.http.Alias;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig.ServerMode;
import org.zaproxy.addon.network.internal.server.http.PassThrough;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link LocalServersOptions}. */
class LocalServersOptionsUnitTest {

    private static final String ALIAS_KEY = "network.localServers.aliases.alias";
    private static final String PASS_THROUGH_KEY = "network.localServers.passThroughs.passThrough";
    private static final String MAIN_PROXY_KEY = "network.localServers.mainProxy";
    private static final String SERVER_KEY = "network.localServers.servers.server";
    private static final String CONFIG_WITH_VALID_SERVERS =
            "<network>\n"
                    + "  <localServers version=\"1\">\n"
                    + "    <servers>\n"
                    + "      <server>\n"
                    + "        <enabled>false</enabled>\n"
                    + "        <proxy>false</proxy>\n"
                    + "        <api>true</api>\n"
                    + "        <address>127.0.0.1</address>\n"
                    + "        <port>8080</port>\n"
                    + "        <tlsProtocols>\n"
                    + "          <protocol>TLSv1.3</protocol>\n"
                    + "          <protocol>TLSv1.2</protocol>\n"
                    + "          <protocol>TLSv1.1</protocol>\n"
                    + "        </tlsProtocols>\n"
                    + "        <behindNat>true</behindNat>\n"
                    + "        <removeAcceptEncoding>false</removeAcceptEncoding>\n"
                    + "        <decodeResponse>false</decodeResponse>\n"
                    + "      </server>\n"
                    + "      <server>\n"
                    + "        <enabled>true</enabled>\n"
                    + "        <proxy>true</proxy>\n"
                    + "        <api>false</api>\n"
                    + "        <address>localhost</address>\n"
                    + "        <port>8181</port>\n"
                    + "        <tlsProtocols>\n"
                    + "          <protocol>TLSv1.3</protocol>\n"
                    + "          <protocol>TLSv1.2</protocol>\n"
                    + "          <protocol>TLSv1.1</protocol>\n"
                    + "        </tlsProtocols>\n"
                    + "        <behindNat>false</behindNat>\n"
                    + "        <removeAcceptEncoding>true</removeAcceptEncoding>\n"
                    + "        <decodeResponse>true</decodeResponse>\n"
                    + "      </server>"
                    + "    </servers>\n"
                    + "  </localServers>\n"
                    + "</network>";

    private ZapXmlConfiguration config;
    private ServersChangedListener serversChangedlistener;
    private LocalServersOptions options;

    @BeforeEach
    void setUp() {
        options = new LocalServersOptions();
        serversChangedlistener = mock(ServersChangedListener.class);
        options.addServersChangedListener(serversChangedlistener);
        config = new ZapXmlConfiguration();
        options.load(config);
    }

    @Test
    void shouldHaveConfigVersionKey() {
        assertThat(options.getConfigVersionKey(), is(equalTo("network.localServers[@version]")));
    }

    @Test
    void shouldHaveDefaultValues() {
        // Given
        options = new LocalServersOptions();
        // When / Then
        assertDefaultValues();
    }

    private void assertDefaultValues() {
        assertThat(options.getPassThroughs(), is(empty()));
        assertThat(options.isConfirmRemovePassThrough(), is(equalTo(true)));
        assertThat(options.getAliases(), is(empty()));
        assertThat(options.isConfirmRemoveAlias(), is(equalTo(true)));
        assertThat(options.getServers(), is(empty()));
        assertThat(options.isConfirmRemoveServer(), is(equalTo(true)));
        LocalServerConfig mainProxy = options.getMainProxy();
        assertThat(mainProxy, is(notNullValue()));
        assertThat(mainProxy.getAddress(), is(equalTo(LocalServerConfig.DEFAULT_ADDRESS)));
        assertThat(mainProxy.getPort(), is(equalTo(LocalServerConfig.DEFAULT_PORT)));
        assertThat(mainProxy.getMode(), is(equalTo(LocalServerConfig.ServerMode.API_AND_PROXY)));
        assertThat(mainProxy.getTlsProtocols(), is(equalTo(TlsUtils.getSupportedProtocols())));
        assertThat(mainProxy.isBehindNat(), is(equalTo(false)));
        assertThat(mainProxy.isRemoveAcceptEncoding(), is(equalTo(true)));
        assertThat(mainProxy.isDecodeResponse(), is(equalTo(true)));
        assertThat(mainProxy.isEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldLoadEmptyConfig() {
        // Given
        ZapXmlConfiguration emptyConfig = new ZapXmlConfiguration();
        // When
        options.load(emptyConfig);
        // Then
        assertDefaultValues();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithConfirmRemoveServer(boolean value) {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <servers>\n"
                                + "      <confirmRemove>"
                                + value
                                + "</confirmRemove>\n"
                                + "    </servers>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemoveServer(), is(equalTo(value)));
    }

    @Test
    void shouldLoadConfigWithInvalidConfirmRemoveServer() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <servers>\n"
                                + "      <confirmRemove>not boolean</confirmRemove>\n"
                                + "    </servers>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemoveAlias(), is(equalTo(true)));
    }

    static Stream<Arguments> serverPersistenceData() {
        return Stream.of(
                arguments(
                        "127.0.0.1",
                        1001,
                        ServerMode.API_AND_PROXY,
                        true,
                        true,
                        true,
                        true,
                        true,
                        true),
                arguments("127.0.0.2", 1002, ServerMode.API, true, false, true, true, true, true),
                arguments("127.0.0.3", 1003, ServerMode.PROXY, false, true, true, true, true, true),
                arguments(
                        "127.0.0.4",
                        1004,
                        ServerMode.API_AND_PROXY,
                        true,
                        true,
                        false,
                        true,
                        true,
                        true),
                arguments(
                        "127.0.0.5",
                        1005,
                        ServerMode.API_AND_PROXY,
                        true,
                        true,
                        true,
                        false,
                        true,
                        true),
                arguments(
                        "127.0.0.6",
                        1006,
                        ServerMode.API_AND_PROXY,
                        true,
                        true,
                        true,
                        true,
                        false,
                        true),
                arguments(
                        "127.0.0.7",
                        1007,
                        ServerMode.API_AND_PROXY,
                        true,
                        true,
                        true,
                        true,
                        true,
                        false));
    }

    @ParameterizedTest
    @MethodSource("serverPersistenceData")
    void shouldSetMainProxy(
            String address,
            int port,
            ServerMode mode,
            boolean api,
            boolean proxy,
            boolean behindNat,
            boolean removeAcceptEncoding,
            boolean decodeResponse,
            boolean enabled) {
        // Given
        LocalServerConfig server = new LocalServerConfig();
        server.setAddress(address);
        server.setPort(port);
        server.setMode(mode);
        server.setBehindNat(behindNat);
        server.setRemoveAcceptEncoding(removeAcceptEncoding);
        server.setDecodeResponse(decodeResponse);
        server.setEnabled(enabled);
        // When
        options.setMainProxy(server);
        // Then
        assertThat(options.getServers(), hasSize(0));
        assertThat(config.getProperty(MAIN_PROXY_KEY + ".address"), is(equalTo(address)));
        assertThat(config.getProperty(MAIN_PROXY_KEY + ".port"), is(equalTo(port)));
        assertThat(config.getProperty(MAIN_PROXY_KEY + ".proxy"), is(equalTo(true)));
        assertThat(config.getProperty(MAIN_PROXY_KEY + ".api"), is(equalTo(api)));
        assertThat(
                config.getProperty(MAIN_PROXY_KEY + ".tlsProtocols.protocol(0)"),
                is(notNullValue()));
        assertThat(config.getProperty(MAIN_PROXY_KEY + ".behindNat"), is(equalTo(behindNat)));
        assertThat(
                config.getProperty(MAIN_PROXY_KEY + ".removeAcceptEncoding"),
                is(equalTo(removeAcceptEncoding)));
        assertThat(
                config.getProperty(MAIN_PROXY_KEY + ".decodeResponse"),
                is(equalTo(decodeResponse)));
        assertThat(config.getProperty(MAIN_PROXY_KEY + ".enabled"), is(equalTo(true)));
        verify(serversChangedlistener).mainProxySet(server);
    }

    @Test
    void shouldThrowIfSettingNullMainProxy() {
        // Given
        LocalServerConfig mainProxy = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.setMainProxy(mainProxy));
    }

    @ParameterizedTest
    @MethodSource("serverPersistenceData")
    void shouldAddServer(
            String address,
            int port,
            ServerMode mode,
            boolean api,
            boolean proxy,
            boolean behindNat,
            boolean removeAcceptEncoding,
            boolean decodeResponse,
            boolean enabled) {
        // Given
        LocalServerConfig server = new LocalServerConfig();
        server.setAddress(address);
        server.setPort(port);
        server.setMode(mode);
        server.setBehindNat(behindNat);
        server.setRemoveAcceptEncoding(removeAcceptEncoding);
        server.setDecodeResponse(decodeResponse);
        server.setEnabled(enabled);
        // When
        options.addServer(server);
        // Then
        assertThat(options.getServers(), hasSize(1));
        assertThat(config.getProperty(SERVER_KEY + ".address"), is(equalTo(address)));
        assertThat(config.getProperty(SERVER_KEY + ".port"), is(equalTo(port)));
        assertThat(config.getProperty(SERVER_KEY + ".proxy"), is(equalTo(proxy)));
        assertThat(config.getProperty(SERVER_KEY + ".api"), is(equalTo(api)));
        assertThat(
                config.getProperty(SERVER_KEY + ".tlsProtocols.protocol(0)"), is(notNullValue()));
        assertThat(config.getProperty(SERVER_KEY + ".behindNat"), is(equalTo(behindNat)));
        assertThat(
                config.getProperty(SERVER_KEY + ".removeAcceptEncoding"),
                is(equalTo(removeAcceptEncoding)));
        assertThat(config.getProperty(SERVER_KEY + ".decodeResponse"), is(equalTo(decodeResponse)));
        assertThat(config.getProperty(SERVER_KEY + ".enabled"), is(equalTo(enabled)));
        verify(serversChangedlistener).serverAdded(server);
    }

    @Test
    void shouldThrowIfAddingNullServer() {
        // Given
        LocalServerConfig server = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.addServer(server));
        assertThat(options.getServers(), hasSize(0));
    }

    @Test
    void shouldRemoveServer() {
        // Given
        options.addServer(newDefaultServer("192.168.0.1", 8080));
        LocalServerConfig server = newDefaultServer("localhost", 8080);
        options.addServer(server);
        options.addServer(newDefaultServer("127.0.0.1", 8181));
        // When
        boolean removed = options.removeServer("localhost", 8080);
        // Then
        assertThat(removed, is(equalTo(true)));
        assertThat(options.getServers(), hasSize(2));
        assertThat(config.getProperty(SERVER_KEY + "(0).address"), is(equalTo("192.168.0.1")));
        assertThat(config.getProperty(SERVER_KEY + "(0).port"), is(equalTo(8080)));
        assertServerFieldsPresent(0, true);
        assertThat(config.getProperty(SERVER_KEY + "(1).address"), is(equalTo("127.0.0.1")));
        assertThat(config.getProperty(SERVER_KEY + "(1).port"), is(equalTo(8181)));
        assertServerFieldsPresent(1, true);
        assertThat(config.getProperty(SERVER_KEY + "(2).address"), is(nullValue()));
        assertThat(config.getProperty(SERVER_KEY + "(2.port"), is(nullValue()));
        assertServerFieldsPresent(2, false);
        verify(serversChangedlistener).serverRemoved(server);
    }

    private static LocalServerConfig newDefaultServer(String address, int port) {
        LocalServerConfig server = new LocalServerConfig();
        server.setAddress(address);
        server.setPort(port);
        return server;
    }

    @Test
    void shouldReturnFalseIfServerNotRemoved() {
        // Given
        options.addServer(newDefaultServer("localhost", 8080));
        options.addServer(newDefaultServer("127.0.0.1", 8181));
        // When
        boolean removed = options.removeServer("127.0.0.1", 8282);
        // Then
        assertThat(removed, is(equalTo(false)));
        assertThat(options.getServers(), hasSize(2));
        assertThat(config.getProperty(SERVER_KEY + "(0).address"), is(equalTo("localhost")));
        assertThat(config.getProperty(SERVER_KEY + "(0).port"), is(equalTo(8080)));
        assertServerFieldsPresent(0, true);
        assertThat(config.getProperty(SERVER_KEY + "(1).address"), is(equalTo("127.0.0.1")));
        assertThat(config.getProperty(SERVER_KEY + "(1).port"), is(equalTo(8181)));
        assertServerFieldsPresent(1, true);
        verify(serversChangedlistener, times(0)).serverRemoved(any());
    }

    private void assertServerFieldsPresent(int pos, boolean present) {
        String baseKey = SERVER_KEY + "(" + pos + ").";
        Matcher<Object> matcher = present ? is(notNullValue()) : is(nullValue());
        assertThat(config.getProperty(baseKey + "address"), matcher);
        assertThat(config.getProperty(baseKey + "port"), matcher);
        assertThat(config.getProperty(baseKey + "proxy"), matcher);
        assertThat(config.getProperty(baseKey + "api"), matcher);
        assertThat(config.getProperty(baseKey + "tlsProtocols.protocol(0)"), matcher);
        assertThat(config.getProperty(baseKey + "behindNat"), matcher);
        assertThat(config.getProperty(baseKey + "removeAcceptEncoding"), matcher);
        assertThat(config.getProperty(baseKey + "decodeResponse"), matcher);
        assertThat(config.getProperty(baseKey + "enabled"), matcher);
    }

    @Test
    void shouldThrowIfRemovingServerWithNullAddress() {
        // Given
        String address = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.removeServer(address, 8080));
        assertThat(options.getServers(), hasSize(0));
    }

    @Test
    void shouldSetAndPersistConfirmRemoveServer() throws Exception {
        // Given / When
        options.setConfirmRemoveServer(false);
        // Then
        assertThat(options.isConfirmRemoveServer(), is(equalTo(false)));
        assertThat(
                config.getBoolean("network.localServers.servers.confirmRemove"),
                is(equalTo(false)));
    }

    @Test
    void shouldLoadMainProxy() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <mainProxy>\n"
                                + "      <proxy>true</proxy>\n"
                                + "      <api>false</api>\n"
                                + "      <address>192.168.0.1</address>\n"
                                + "      <port>8765</port>\n"
                                + "      <tlsProtocols>\n"
                                + "        <protocol>TLSv1.3</protocol>\n"
                                + "        <protocol>TLSv1.2</protocol>\n"
                                + "        <protocol>TLSv1.1</protocol>\n"
                                + "      </tlsProtocols>"
                                + "      <behindNat>true</behindNat>\n"
                                + "      <removeAcceptEncoding>false</removeAcceptEncoding>\n"
                                + "      <decodeResponse>false</decodeResponse>\n"
                                + "      <enabled>true</enabled>\n"
                                + "    </mainProxy>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getServers(), hasSize(0));
        assertServerFields(
                options.getMainProxy(),
                "192.168.0.1",
                8765,
                ServerMode.PROXY,
                true,
                false,
                false,
                true);
    }

    @Test
    void shouldUseDefaultProtocolsOnErrorForMainProxy() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <mainProxy>\n"
                                + "      <address>192.168.0.1</address>\n"
                                + "      <tlsProtocols>\n"
                                + "           <protocol>not something supported</protocol>\n"
                                + "      </tlsProtocols>\n"
                                + "    </mainProxy>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getMainProxy().getTlsProtocols(), is(not(empty())));
        assertThat(options.getMainProxy().getTlsConfig(), is(notNullValue()));
    }

    @Test
    void shouldFallbackToDefaultsIfMainProxyMalformed() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <mainProxy>\n"
                                + "      <address/>\n"
                                + "      <proxy>not a boolean</proxy>\n"
                                + "    </mainProxy>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getServers(), hasSize(0));
        assertServerFields(
                options.getMainProxy(),
                "localhost",
                8080,
                ServerMode.API_AND_PROXY,
                false,
                true,
                true,
                true);
    }

    @Test
    void shouldUseDefaultsIfMainProxyHasNoAddress() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <mainProxy>\n"
                                + "    </mainProxy>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getServers(), hasSize(0));
        assertServerFields(
                options.getMainProxy(),
                "localhost",
                8080,
                ServerMode.API_AND_PROXY,
                false,
                true,
                true,
                true);
    }

    @Test
    void shouldDefaultToEnabledForMainProxy() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <mainProxy>\n"
                                + "      <address>localhost</address>\n"
                                + "      <enabled>false</enabled>\n"
                                + "    </mainProxy>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getServers(), hasSize(0));
        assertThat(options.getMainProxy().isEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldDefaultToApiAndProxyIfNoProxyForMainProxy() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <mainProxy>\n"
                                + "      <address>localhost</address>\n"
                                + "      <proxy>false</proxy>\n"
                                + "    </mainProxy>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getServers(), hasSize(0));
        assertThat(options.getMainProxy().getMode(), is(equalTo(ServerMode.API_AND_PROXY)));
    }

    @Test
    void shouldLoadConfigWithServers() {
        // Given
        ZapXmlConfiguration config = configWith(CONFIG_WITH_VALID_SERVERS);
        // When
        options.load(config);
        // Then
        assertThat(options.getServers(), hasSize(2));
        assertServerFields(
                options.getServers().get(0),
                "127.0.0.1",
                8080,
                ServerMode.API,
                true,
                false,
                false,
                false);
        assertServerFields(
                options.getServers().get(1),
                "localhost",
                8181,
                ServerMode.PROXY,
                false,
                true,
                true,
                true);
    }

    @Test
    void shouldUseDefaultProtocolsOnErrorForServer() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <servers>\n"
                                + "      <server>\n"
                                + "        <address>192.168.0.1</address>\n"
                                + "        <tlsProtocols>\n"
                                + "           <protocol>not something supported</protocol>\n"
                                + "        </tlsProtocols>\n"
                                + "      </server>\n"
                                + "    </servers>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getMainProxy().getTlsProtocols(), is(not(empty())));
        assertThat(options.getMainProxy().getTlsConfig(), is(notNullValue()));
    }

    private static void assertServerFields(
            LocalServerConfig server,
            String address,
            int port,
            ServerMode mode,
            boolean behindNat,
            boolean removeAcceptEncoding,
            boolean decodeResponse,
            boolean enabled) {
        assertThat(server.getAddress(), is(equalTo(address)));
        assertThat(server.getPort(), is(equalTo(port)));
        assertThat(server.getMode(), is(equalTo(mode)));
        assertThat(server.getTlsProtocols(), is(not(empty())));
        assertThat(server.getTlsConfig(), is(notNullValue()));
        assertThat(server.isBehindNat(), is(equalTo(behindNat)));
        assertThat(server.isRemoveAcceptEncoding(), is(equalTo(removeAcceptEncoding)));
        assertThat(server.isDecodeResponse(), is(equalTo(decodeResponse)));
        assertThat(server.isEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldSetAndPersistServers() {
        // Given
        ZapXmlConfiguration config = configWith(CONFIG_WITH_VALID_SERVERS);
        options.load(config);
        List<LocalServerConfig> servers = options.getServers();
        options.load(new ZapXmlConfiguration());
        // When
        options.setServers(servers);
        // Then
        assertThat(options.getServers(), hasSize(2));
        assertServerFields(
                options.getServers().get(0),
                "127.0.0.1",
                8080,
                ServerMode.API,
                true,
                false,
                false,
                false);
        assertServerFields(
                options.getServers().get(1),
                "localhost",
                8181,
                ServerMode.PROXY,
                false,
                true,
                true,
                true);
        verify(serversChangedlistener).serversSet(servers);
    }

    @Test
    void shouldLoadConfigWhileIgnoringInvalidServer() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <servers>\n"
                                + "      <server>\n"
                                + "        <enabled>not a boolean</enabled>\n"
                                + "      </server>\n"
                                + "      <server>\n"
                                + "        <address>127.0.0.1</address>\n"
                                + "      </server>\n"
                                + "    </servers>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getServers(), hasSize(1));
        assertServerFields(
                options.getServers().get(0),
                "127.0.0.1",
                8080,
                ServerMode.API_AND_PROXY,
                false,
                true,
                true,
                true);
    }

    @Test
    void shouldLoadServerWithDefaultsIfEmpty() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <mainProxy>\n"
                                + "      <address>192.168.0.1</address>\n"
                                + "    </mainProxy>"
                                + "    <servers>\n"
                                + "      <server/>\n"
                                + "    </servers>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getServers(), hasSize(1));
        assertServerFields(
                options.getServers().get(0),
                "localhost",
                8080,
                ServerMode.API_AND_PROXY,
                false,
                true,
                true,
                true);
    }

    @Test
    void shouldDiscardServersWithDuplicatedAddressAndPort() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <mainProxy>\n"
                                + "      <address>localhost</address>\n"
                                + "      <port>8080</port>\n"
                                + "    </mainProxy>"
                                + "    <servers>\n"
                                + "      <server>\n"
                                + "        <address>localhost</address>\n"
                                + "        <port>8080</port>\n"
                                + "      </server>\n"
                                + "      <server>\n"
                                + "        <address>127.0.0.1</address>\n"
                                + "        <port>8080</port>\n"
                                + "      </server>\n"
                                + "      <server>\n"
                                + "        <address>127.0.0.1</address>\n"
                                + "        <port>8080</port>\n"
                                + "      </server>\n"
                                + "    </servers>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getServers(), hasSize(1));
        assertServerFields(
                options.getServers().get(0),
                "127.0.0.1",
                8080,
                ServerMode.API_AND_PROXY,
                false,
                true,
                true,
                true);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithConfirmRemoveAlias(boolean value) {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <aliases>\n"
                                + "      <confirmRemove>"
                                + value
                                + "</confirmRemove>\n"
                                + "    </aliases>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemoveAlias(), is(equalTo(value)));
    }

    @Test
    void shouldLoadConfigWithInvalidConfirmRemoveAlias() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <aliases>\n"
                                + "      <confirmRemove>not boolean</confirmRemove>\n"
                                + "    </aliases>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemoveAlias(), is(equalTo(true)));
    }

    @Test
    void shouldAddAlias() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        Alias alias = new Alias("example.org", true);
        // When
        options.addAlias(alias);
        // Then
        assertThat(options.getAliases(), hasSize(1));
        assertThat(config.getProperty(ALIAS_KEY + ".name"), is(equalTo("example.org")));
        assertThat(config.getProperty(ALIAS_KEY + ".enabled"), is(equalTo(true)));
    }

    @Test
    void shouldThrowIfAddingNullAlias() {
        // Given
        Alias alias = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.addAlias(alias));
        assertThat(options.getAliases(), hasSize(0));
    }

    @Test
    void shouldSetAliasEnabled() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addAlias(new Alias("example.org", true));
        options.addAlias(new Alias("example.com", true));
        // When
        boolean removed = options.setAliasEnabled("example.org", false);
        // Then
        assertThat(removed, is(equalTo(true)));
        assertThat(options.getAliases(), hasSize(2));
        assertThat(config.getProperty(ALIAS_KEY + "(0).name"), is(equalTo("example.org")));
        assertThat(config.getProperty(ALIAS_KEY + "(0).enabled"), is(equalTo(false)));
        assertThat(config.getProperty(ALIAS_KEY + "(1).name"), is(equalTo("example.com")));
        assertThat(config.getProperty(ALIAS_KEY + "(1).enabled"), is(equalTo(true)));
    }

    @Test
    void shouldReturnFalseIfAliasNotChanged() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addAlias(new Alias("example.org", true));
        options.addAlias(new Alias("example.com", true));
        // When
        boolean removed = options.setAliasEnabled("other.example.org", false);
        // Then
        assertThat(removed, is(equalTo(false)));
        assertThat(options.getAliases(), hasSize(2));
        assertThat(config.getProperty(ALIAS_KEY + "(0).name"), is(equalTo("example.org")));
        assertThat(config.getProperty(ALIAS_KEY + "(0).enabled"), is(equalTo(true)));
        assertThat(config.getProperty(ALIAS_KEY + "(1).name"), is(equalTo("example.com")));
        assertThat(config.getProperty(ALIAS_KEY + "(1).enabled"), is(equalTo(true)));
    }

    @Test
    void shouldThrowIfSettingNullNameEnabled() {
        // Given
        String name = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.setAliasEnabled(name, true));
        assertThat(options.getAliases(), hasSize(0));
    }

    @Test
    void shouldRemoveAlias() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addAlias(new Alias("example.org", true));
        options.addAlias(new Alias("example.com", true));
        // When
        boolean removed = options.removeAlias("example.org");
        // Then
        assertThat(removed, is(equalTo(true)));
        assertThat(options.getAliases(), hasSize(1));
        assertThat(config.getProperty(ALIAS_KEY + "(0).name"), is(equalTo("example.com")));
        assertThat(config.getProperty(ALIAS_KEY + "(0).enabled"), is(equalTo(true)));
        assertThat(config.getProperty(ALIAS_KEY + "(1).name"), is(nullValue()));
        assertThat(config.getProperty(ALIAS_KEY + "(1).enabled"), is(nullValue()));
    }

    @Test
    void shouldReturnFalseIfAliasNotRemoved() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addAlias(new Alias("example.org", true));
        options.addAlias(new Alias("example.com", true));
        // When
        boolean removed = options.removeAlias("other.example.org");
        // Then
        assertThat(removed, is(equalTo(false)));
        assertThat(options.getAliases(), hasSize(2));
        assertThat(config.getProperty(ALIAS_KEY + "(0).name"), is(equalTo("example.org")));
        assertThat(config.getProperty(ALIAS_KEY + "(0).enabled"), is(equalTo(true)));
        assertThat(config.getProperty(ALIAS_KEY + "(1).name"), is(equalTo("example.com")));
        assertThat(config.getProperty(ALIAS_KEY + "(1).enabled"), is(equalTo(true)));
    }

    @Test
    void shouldThrowIfRemovingNullName() {
        // Given
        String name = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.removeAlias(name));
        assertThat(options.getAliases(), hasSize(0));
    }

    @Test
    void shouldSetAndPersistConfirmRemoveAlias() throws Exception {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        // When
        options.setConfirmRemoveAlias(false);
        // Then
        assertThat(options.isConfirmRemoveAlias(), is(equalTo(false)));
        assertThat(
                config.getBoolean("network.localServers.aliases.confirmRemove"),
                is(equalTo(false)));
    }

    @Test
    void shouldLoadConfigWithAliases() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <aliases>\n"
                                + "      <alias>\n"
                                + "        <name>example.org</name>\n"
                                + "        <enabled>true</enabled>\n"
                                + "      </alias>\n"
                                + "      <alias>\n"
                                + "        <name>example.com</name>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </alias>\n"
                                + "    </aliases>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getAliases(), hasSize(2));
        assertThat(options.getAliases().get(0).getName(), is(equalTo("example.org")));
        assertThat(options.getAliases().get(0).isEnabled(), is(equalTo(true)));
        assertThat(options.getAliases().get(1).getName(), is(equalTo("example.com")));
        assertThat(options.getAliases().get(1).isEnabled(), is(equalTo(false)));
    }

    @Test
    void shouldSetAndPersistAliases() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <aliases>\n"
                                + "      <alias>\n"
                                + "        <name>example.org</name>\n"
                                + "        <enabled>true</enabled>\n"
                                + "      </alias>\n"
                                + "      <alias>\n"
                                + "        <name>example.com</name>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </alias>\n"
                                + "    </aliases>\n"
                                + "  </localServers>\n"
                                + "</network>");
        options.load(config);
        List<Alias> aliases = options.getAliases();
        options.load(new ZapXmlConfiguration());
        // When
        options.setAliases(aliases);
        // Then
        assertThat(options.getAliases(), hasSize(2));
        assertThat(options.getAliases().get(0).getName(), is(equalTo("example.org")));
        assertThat(options.getAliases().get(0).isEnabled(), is(equalTo(true)));
        assertThat(options.getAliases().get(1).getName(), is(equalTo("example.com")));
        assertThat(options.getAliases().get(1).isEnabled(), is(equalTo(false)));
    }

    @Test
    void shouldLoadConfigWhileIgnoringInvalidAliases() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <aliases>\n"
                                + "      <alias>\n"
                                + "        <name></name>\n"
                                + "        <enabled>true</enabled>\n"
                                + "      </alias>\n"
                                + "      <alias>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </alias>\n"
                                + "      <alias>\n"
                                + "        <name>example.com</name>\n"
                                + "        <enabled>not a boolean</enabled>\n"
                                + "      </alias>\n"
                                + "      <alias>\n"
                                + "        <name>valid.example.com</name>\n"
                                + "      </alias>\n"
                                + "    </aliases>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getAliases(), hasSize(1));
        assertThat(options.getAliases().get(0).getName(), is(equalTo("valid.example.com")));
        assertThat(options.getAliases().get(0).isEnabled(), is(equalTo(true)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithConfirmRemovePassThrough(boolean value) {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <passThroughs>\n"
                                + "      <confirmRemove>"
                                + value
                                + "</confirmRemove>\n"
                                + "    </passThroughs>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemovePassThrough(), is(equalTo(value)));
    }

    @Test
    void shouldLoadConfigWithInvalidConfirmRemovePassThrough() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <passThroughs>\n"
                                + "      <confirmRemove>not boolean</confirmRemove>\n"
                                + "    </passThroughs>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemovePassThrough(), is(equalTo(true)));
    }

    @Test
    void shouldAddPassThrough() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        PassThrough passThrough = new PassThrough(Pattern.compile("example.org"), true);
        // When
        options.addPassThrough(passThrough);
        // Then
        assertThat(options.getPassThroughs(), hasSize(1));

        assertThat(config.getProperty(PASS_THROUGH_KEY + ".authority"), is(equalTo("example.org")));
        assertThat(config.getProperty(PASS_THROUGH_KEY + ".enabled"), is(equalTo(true)));
    }

    @Test
    void shouldThrowIfAddingNullPassThrough() {
        // Given
        PassThrough passThrough = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.addPassThrough(passThrough));
        assertThat(options.getPassThroughs(), hasSize(0));
    }

    @Test
    void shouldSetPassThroughEnabled() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addPassThrough(new PassThrough(Pattern.compile("example.org"), true));
        options.addPassThrough(new PassThrough(Pattern.compile("example.com"), true));
        // When
        boolean removed = options.setPassThroughEnabled("example.org", false);
        // Then
        assertThat(removed, is(equalTo(true)));
        assertThat(options.getPassThroughs(), hasSize(2));
        assertThat(
                config.getProperty(PASS_THROUGH_KEY + "(0).authority"), is(equalTo("example.org")));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(0).enabled"), is(equalTo(false)));
        assertThat(
                config.getProperty(PASS_THROUGH_KEY + "(1).authority"), is(equalTo("example.com")));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(1).enabled"), is(equalTo(true)));
    }

    @Test
    void shouldReturnFalseIfPassThroughNotChanged() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addPassThrough(new PassThrough(Pattern.compile("example.org"), true));
        options.addPassThrough(new PassThrough(Pattern.compile("example.com"), true));
        // When
        boolean removed = options.setPassThroughEnabled("other.example.org", false);
        // Then
        assertThat(removed, is(equalTo(false)));
        assertThat(options.getPassThroughs(), hasSize(2));
        assertThat(
                config.getProperty(PASS_THROUGH_KEY + "(0).authority"), is(equalTo("example.org")));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(0).enabled"), is(equalTo(true)));
        assertThat(
                config.getProperty(PASS_THROUGH_KEY + "(1).authority"), is(equalTo("example.com")));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(1).enabled"), is(equalTo(true)));
    }

    @Test
    void shouldThrowIfSettingNullAuthorityEnabled() {
        // Given
        String authority = null;
        // When / Then
        assertThrows(
                NullPointerException.class, () -> options.setPassThroughEnabled(authority, true));
        assertThat(options.getPassThroughs(), hasSize(0));
    }

    @Test
    void shouldRemovePassThrough() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addPassThrough(new PassThrough(Pattern.compile("example.org"), true));
        options.addPassThrough(new PassThrough(Pattern.compile("example.com"), true));
        // When
        boolean removed = options.removePassThrough("example.org");
        // Then
        assertThat(removed, is(equalTo(true)));
        assertThat(options.getPassThroughs(), hasSize(1));
        assertThat(
                config.getProperty(PASS_THROUGH_KEY + "(0).authority"), is(equalTo("example.com")));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(0).enabled"), is(equalTo(true)));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(1).authority"), is(nullValue()));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(1).enabled"), is(nullValue()));
    }

    @Test
    void shouldReturnFalseIfPassThroughNotRemoved() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addPassThrough(new PassThrough(Pattern.compile("example.org"), true));
        options.addPassThrough(new PassThrough(Pattern.compile("example.com"), true));
        // When
        boolean removed = options.removePassThrough("other.example.org");
        // Then
        assertThat(removed, is(equalTo(false)));
        assertThat(options.getPassThroughs(), hasSize(2));
        assertThat(
                config.getProperty(PASS_THROUGH_KEY + "(0).authority"), is(equalTo("example.org")));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(0).enabled"), is(equalTo(true)));
        assertThat(
                config.getProperty(PASS_THROUGH_KEY + "(1).authority"), is(equalTo("example.com")));
        assertThat(config.getProperty(PASS_THROUGH_KEY + "(1).enabled"), is(equalTo(true)));
    }

    @Test
    void shouldThrowIfRemovingNullAuthority() {
        // Given
        String authority = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.removePassThrough(authority));
        assertThat(options.getPassThroughs(), hasSize(0));
    }

    @Test
    void shouldSetAndPersistConfirmRemovePassThrough() throws Exception {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        // When
        options.setConfirmRemovePassThrough(false);
        // Then
        assertThat(options.isConfirmRemovePassThrough(), is(equalTo(false)));
        assertThat(
                config.getBoolean("network.localServers.passThroughs.confirmRemove"),
                is(equalTo(false)));
    }

    @Test
    void shouldLoadConfigWithPassThroughs() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <passThroughs>\n"
                                + "      <passThrough>\n"
                                + "        <authority>example.org</authority>\n"
                                + "        <enabled>true</enabled>\n"
                                + "      </passThrough>\n"
                                + "      <passThrough>\n"
                                + "        <authority>example.com</authority>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </passThrough>\n"
                                + "    </passThroughs>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getPassThroughs(), hasSize(2));
        assertThat(
                options.getPassThroughs().get(0).getAuthority().pattern(),
                is(equalTo("example.org")));
        assertThat(options.getPassThroughs().get(0).isEnabled(), is(equalTo(true)));
        assertThat(
                options.getPassThroughs().get(1).getAuthority().pattern(),
                is(equalTo("example.com")));
        assertThat(options.getPassThroughs().get(1).isEnabled(), is(equalTo(false)));
    }

    @Test
    void shouldSetAndPersistPassThroughs() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <passThroughs>\n"
                                + "      <passThrough>\n"
                                + "        <authority>example.org</authority>\n"
                                + "        <enabled>true</enabled>\n"
                                + "      </passThrough>\n"
                                + "      <passThrough>\n"
                                + "        <authority>example.com</authority>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </passThrough>\n"
                                + "    </passThroughs>\n"
                                + "  </localServers>\n"
                                + "</network>");
        options.load(config);
        List<PassThrough> passThroughs = options.getPassThroughs();
        options.load(new ZapXmlConfiguration());
        // When
        options.setPassThroughs(passThroughs);
        // Then
        assertThat(options.getPassThroughs(), hasSize(2));
        assertThat(
                options.getPassThroughs().get(0).getAuthority().pattern(),
                is(equalTo("example.org")));
        assertThat(options.getPassThroughs().get(0).isEnabled(), is(equalTo(true)));
        assertThat(
                options.getPassThroughs().get(1).getAuthority().pattern(),
                is(equalTo("example.com")));
        assertThat(options.getPassThroughs().get(1).isEnabled(), is(equalTo(false)));
    }

    @Test
    void shouldLoadConfigWhileIgnoringInvalidPassThroughs() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<network>\n"
                                + "  <localServers version=\"1\">\n"
                                + "    <passThroughs>\n"
                                + "      <passThrough>\n"
                                + "        <authority></authority>\n"
                                + "        <enabled>true</enabled>\n"
                                + "      </passThrough>\n"
                                + "      <passThrough>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </passThrough>\n"
                                + "      <passThrough>\n"
                                + "        <authority>*</authority>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </passThrough>\n"
                                + "      <passThrough>\n"
                                + "        <authority>example.com</authority>\n"
                                + "        <enabled>not a boolean</enabled>\n"
                                + "      </passThrough>\n"
                                + "      <passThrough>\n"
                                + "        <authority>valid.example.com</authority>\n"
                                + "      </passThrough>\n"
                                + "    </passThroughs>\n"
                                + "  </localServers>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getPassThroughs(), hasSize(1));
        assertThat(
                options.getPassThroughs().get(0).getAuthority().pattern(),
                is(equalTo("valid.example.com")));
        assertThat(options.getPassThroughs().get(0).isEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldMigrateCoreProxy() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<proxy>\n"
                                + "  <port>1234</port>\n"
                                + "  <decodeGzip>false</decodeGzip>\n"
                                + "  <behindnat>true</behindnat>\n"
                                + "  <removeUnsupportedEncodings>false</removeUnsupportedEncodings>\n"
                                + "  <ip>127.0.0.2</ip>\n"
                                + "  <securityProtocolsEnabled>\n"
                                + "    <protocol>SSLv3</protocol>\n"
                                + "    <protocol>TLSv1</protocol>\n"
                                + "    <protocol>TLSv1.3</protocol>\n"
                                + "    <protocol>TLSv1.2</protocol>\n"
                                + "    <protocol>TLSv1.1</protocol>\n"
                                + "  </securityProtocolsEnabled>\n"
                                + "</proxy>");
        // When
        options.load(config);
        // Then
        assertServerFields(
                options.getMainProxy(),
                "127.0.0.2",
                1234,
                ServerMode.API_AND_PROXY,
                true,
                false,
                false,
                true);
        assertThat(config.getProperty("proxy.ip"), is(nullValue()));
    }

    @Test
    void shouldMigrateCoreProxyWithJustPort() {
        // Given
        ZapXmlConfiguration config = configWith("<proxy><port>1234</port></proxy>");
        // When
        options.load(config);
        // Then
        assertServerFields(
                options.getMainProxy(),
                "localhost",
                1234,
                ServerMode.API_AND_PROXY,
                false,
                true,
                true,
                true);
        assertThat(config.getProperty("proxy.port"), is(nullValue()));
    }

    @Test
    void shouldUseDefaultsIfCoreProxyDataNotPresent() {
        // Given
        ZapXmlConfiguration config = configWith("<proxy></proxy>");
        // When
        options.load(config);
        // Then
        assertDefaultValues();
        assertThat(config.getProperty("proxy.ip"), is(nullValue()));
    }

    @Test
    void shouldUseDefaultsIfFailedToMigrateCoreProxy() {
        // Given
        ZapXmlConfiguration config = configWith("<proxy><ip/></proxy>");
        // When
        options.load(config);
        // Then
        assertDefaultValues();
        assertThat(config.getProperty("proxy.ip"), is(nullValue()));
    }

    @Test
    void shouldMigrateAdditionalProxies() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<proxies>\n"
                                + "  <confirmRemoveProxy>false</confirmRemoveProxy>\n"
                                + "  <all>\n"
                                + "    <address>localhost</address>\n"
                                + "    <port>8123</port>\n"
                                + "    <enabled>true</enabled>\n"
                                + "    <anylocal>false</anylocal>\n"
                                + "    <remunsupported>true</remunsupported>\n"
                                + "    <decode>true</decode>\n"
                                + "    <behindnat>false</behindnat>\n"
                                + "  </all>\n"
                                + "  <all>\n"
                                + "    <address>0.0.0.0</address>\n"
                                + "    <port>8234</port>\n"
                                + "    <enabled>false</enabled>\n"
                                + "    <anylocal>false</anylocal>\n"
                                + "    <remunsupported>false</remunsupported>\n"
                                + "    <decode>false</decode>\n"
                                + "    <behindnat>true</behindnat>\n"
                                + "  </all>\n"
                                + "</proxies>");
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemoveServer(), is(equalTo(false)));
        assertThat(options.getServers(), hasSize(2));
        assertServerFields(
                options.getServers().get(0),
                "localhost",
                8123,
                ServerMode.API_AND_PROXY,
                false,
                true,
                true,
                true);
        assertServerFields(
                options.getServers().get(1),
                "0.0.0.0",
                8234,
                ServerMode.API_AND_PROXY,
                true,
                false,
                false,
                false);
        assertThat(config.getProperty("proxies.confirmRemoveProxy"), is(nullValue()));
        assertThat(config.getProperty("proxies.all"), is(nullValue()));
    }

    @Test
    void shouldSkipIfAdditionalProxyDataNotPresent() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<proxies><confirmRemoveProxy>true</confirmRemoveProxy><all/></proxies>");
        // When
        options.load(config);
        // Then
        assertDefaultValues();
        assertThat(options.getServers(), hasSize(0));
        assertThat(config.getProperty("proxies.confirmRemoveProxy"), is(nullValue()));
        assertThat(config.getProperty("proxies.all"), is(nullValue()));
    }

    @Test
    void shouldUseDefaultsIfFailedToMigrateAdditionalProxies() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<proxies>\n"
                                + "  <confirmRemoveProxy>true</confirmRemoveProxy>\n"
                                + "  <all>\n"
                                + "    <address>localhost</address>\n"
                                + "    <port>not a port</port>\n"
                                + "  </all>\n"
                                + "</proxies>");
        // When
        options.load(config);
        // Then
        assertDefaultValues();
        assertThat(options.getServers(), hasSize(0));
        assertThat(config.getProperty("proxies.confirmRemoveProxy"), is(nullValue()));
        assertThat(config.getProperty("proxies.all"), is(nullValue()));
    }

    private static ZapXmlConfiguration configWith(String value) {
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        String contents =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
                        + "<config>\n"
                        + value
                        + "\n</config>";
        try {
            config.load(new ByteArrayInputStream(contents.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return config;
    }
}
