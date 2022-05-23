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
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.zaproxy.addon.network.ConnectionOptions.DEFAULT_DEFAULT_USER_AGENT;
import static org.zaproxy.addon.network.ConnectionOptions.DEFAULT_TIMEOUT;
import static org.zaproxy.addon.network.ConnectionOptions.DNS_DEFAULT_TTL_SUCCESSFUL_QUERIES;

import java.io.ByteArrayInputStream;
import java.net.PasswordAuthentication;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.internal.TlsUtils;
import org.zaproxy.addon.network.internal.client.HttpProxy;
import org.zaproxy.addon.network.internal.client.HttpProxyExclusion;
import org.zaproxy.addon.network.internal.client.SocksProxy;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link ConnectionOptions}. */
class ConnectionOptionsUnitTest {

    private static final String TIMEOUT_KEY = "network.connection.timeoutInSecs";
    private static final String DEFAULT_USER_AGENT_KEY = "network.connection.defaultUserAgent";
    private static final String GLOBAL_HTTP_STATE_ENABLED_KEY =
            "network.connection.useGlobalHttpState";
    private static final String DNS_TTL_SUCCESSFUL_QUERIES_KEY =
            "network.connection.dnsTtlSuccessfulQueries";

    private static final String TLS_PROTOCOL_KEY = "network.connection.tlsProtocols.protocol";
    private static final String TLS_ALLOW_UNSAFE_RENEGOTIATION =
            "network.connection.tlsProtocols.allowUnsafeRenegotiation";

    private static final String HTTP_PROXY_KEY = "network.connection.httpProxy";
    private static final String HTTP_PROXY_PASSWORD_KEY = HTTP_PROXY_KEY + ".password";
    private static final String HTTP_PROXY_ENABLED_KEY = HTTP_PROXY_KEY + ".enabled";
    private static final String HTTP_PROXY_AUTH_ENABLED_KEY = HTTP_PROXY_KEY + ".authEnabled";
    private static final String STORE_HTTP_PROXY_PASS_KEY = HTTP_PROXY_KEY + ".storePass";

    private static final String HTTP_PROXY_EXCLUSION_KEY =
            "network.connection.httpProxy.exclusions.exclusion";
    private static final String HTTP_PROXY_EXCLUSIONS_CONFIRM_REMOVE =
            "network.connection.httpProxy.exclusions.confirmRemove";

    private static final String SOCKS_PROXY_KEY = "network.connection.socksProxy";
    private static final String SOCKS_PROXY_ENABLED_KEY = SOCKS_PROXY_KEY + ".enabled";

    private static final PasswordAuthentication EMPTY_CREDENTIALS =
            new PasswordAuthentication("", "".toCharArray());

    private ZapXmlConfiguration config;
    private ConnectionOptions options;

    @BeforeEach
    void setUp() {
        cleanUp();

        options = new ConnectionOptions();
        config = new ZapXmlConfiguration();
        options.load(config);
    }

    @AfterEach
    void cleanUp() {
        HttpRequestHeader.setDefaultUserAgent("");
        System.setProperty("socksProxyHost", "");
    }

    @Test
    void shouldHaveConfigVersionKey() {
        assertThat(options.getConfigVersionKey(), is(equalTo("network.connection[@version]")));
    }

    @Test
    void shouldHaveDefaultValues() {
        // Given
        options = new ConnectionOptions();
        // When / Then
        assertDefaultValues();
    }

    private void assertDefaultValues() {
        assertThat(options.getTimeoutInSecs(), is(equalTo(ConnectionOptions.DEFAULT_TIMEOUT)));
        assertThat(
                options.getDefaultUserAgent(),
                is(equalTo(ConnectionOptions.DEFAULT_DEFAULT_USER_AGENT)));
        assertThat(
                HttpRequestHeader.getDefaultUserAgent(),
                is(equalTo(ConnectionOptions.DEFAULT_DEFAULT_USER_AGENT)));
        assertThat(options.isUseGlobalHttpState(), is(equalTo(false)));
        assertThat(
                options.getDnsTtlSuccessfulQueries(),
                is(equalTo(ConnectionOptions.DNS_DEFAULT_TTL_SUCCESSFUL_QUERIES)));
        assertThat(options.getTlsProtocols(), is(equalTo(TlsUtils.getSupportedProtocols())));
        assertThat(options.isAllowUnsafeRenegotiation(), is(equalTo(false)));

        HttpProxy httpProxy = options.getHttpProxy();
        assertThat(options.isHttpProxyEnabled(), is(equalTo(false)));
        assertThat(options.isHttpProxyAuthEnabled(), is(equalTo(false)));
        assertThat(options.isStoreHttpProxyPass(), is(equalTo(true)));
        assertHttpProxyFields(httpProxy, "localhost", 8090, "", "", "");
        assertThat(httpProxy, is(equalTo(ConnectionOptions.DEFAULT_HTTP_PROXY)));
        assertThat(options.getHttpProxyExclusions(), is(empty()));
        assertThat(options.isConfirmRemoveHttpProxyExclusion(), is(equalTo(true)));

        SocksProxy socksProxy = options.getSocksProxy();
        assertThat(options.isSocksProxyEnabled(), is(equalTo(false)));
        assertSocksProxyFields(
                socksProxy, "localhost", 1080, SocksProxy.Version.SOCKS5, true, "", "");
        assertThat(socksProxy, is(equalTo(ConnectionOptions.DEFAULT_SOCKS_PROXY)));
    }

    private static void assertHttpProxyFields(
            HttpProxy httpProxy,
            String host,
            int port,
            String realm,
            String userName,
            String password) {
        assertThat(httpProxy.getHost(), is(equalTo(host)));
        assertThat(httpProxy.getPort(), is(equalTo(port)));
        assertThat(httpProxy.getRealm(), is(equalTo(realm)));
        assertThat(httpProxy.getPasswordAuthentication().getUserName(), is(equalTo(userName)));
        assertThat(
                httpProxy.getPasswordAuthentication().getPassword(),
                is(equalTo(password.toCharArray())));
    }

    private static void assertSocksProxyFields(
            SocksProxy socksProxy,
            String host,
            int port,
            SocksProxy.Version version,
            boolean useDns,
            String userName,
            String password) {
        assertThat(socksProxy.getHost(), is(equalTo(host)));
        assertThat(socksProxy.getPort(), is(equalTo(port)));
        assertThat(socksProxy.getVersion(), is(equalTo(version)));
        assertThat(socksProxy.isUseDns(), is(equalTo(useDns)));
        assertThat(socksProxy.getPasswordAuthentication().getUserName(), is(equalTo(userName)));
        assertThat(
                socksProxy.getPasswordAuthentication().getPassword(),
                is(equalTo(password.toCharArray())));
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

    @Test
    void shouldLoadConfigWithTimeoutInSecs() {
        // Given
        config.setProperty(TIMEOUT_KEY, "60");
        // When
        options.load(config);
        // Then
        assertThat(options.getTimeoutInSecs(), is(equalTo(60)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"-1", "" + Long.MAX_VALUE, "A", ""})
    void shouldUseDefaultWithInvalidTimeoutInSecs(String timeout) {
        // Given
        config.setProperty(TIMEOUT_KEY, timeout);
        // When
        options.load(config);
        // Then
        assertThat(options.getTimeoutInSecs(), is(equalTo(DEFAULT_TIMEOUT)));
    }

    @ParameterizedTest
    @CsvSource({"-1, " + DEFAULT_TIMEOUT, "0, 0", "10, 10"})
    void shouldSetAndPersistTimeoutInSecs(int value, int expected) throws Exception {
        // Given / When
        options.setTimeoutInSecs(value);
        // Then
        assertThat(options.getTimeoutInSecs(), is(equalTo(expected)));
        assertThat(config.getInt(TIMEOUT_KEY), is(equalTo(expected)));
    }

    @Test
    void shouldLoadConfigWithDefaultUserAgent() {
        // Given
        String userAgent = "user-agent";
        config.setProperty(DEFAULT_USER_AGENT_KEY, userAgent);
        // When
        options.load(config);
        // Then
        assertThat(options.getDefaultUserAgent(), is(equalTo(userAgent)));
        assertThat(HttpRequestHeader.getDefaultUserAgent(), is(equalTo(userAgent)));
    }

    @Test
    void shouldUseDefaultWithNoDefaultUserAgent() {
        // Given
        config.setProperty(DEFAULT_USER_AGENT_KEY, null);
        // When
        options.load(config);
        // Then
        assertThat(options.getDefaultUserAgent(), is(equalTo(DEFAULT_DEFAULT_USER_AGENT)));
        assertThat(
                HttpRequestHeader.getDefaultUserAgent(), is(equalTo(DEFAULT_DEFAULT_USER_AGENT)));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"user-agent"})
    void shouldSetAndPersistDefaultUserAgent(String userAgent) throws Exception {
        // Given / When
        options.setDefaultUserAgent(userAgent);
        // Then
        assertThat(options.getDefaultUserAgent(), is(equalTo(userAgent)));
        assertThat(config.getString(DEFAULT_USER_AGENT_KEY), is(equalTo(userAgent)));
        assertThat(HttpRequestHeader.getDefaultUserAgent(), is(equalTo(userAgent)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithUseGlobalHttpState(boolean enabled) {
        // Given
        config.setProperty(GLOBAL_HTTP_STATE_ENABLED_KEY, enabled);
        // When
        options.load(config);
        // Then
        assertThat(options.isUseGlobalHttpState(), is(equalTo(enabled)));
    }

    @Test
    void shouldUseDefaultWithInvalidUseGlobalHttpState() {
        // Given
        config.setProperty(GLOBAL_HTTP_STATE_ENABLED_KEY, "not boolean");
        // When
        options.load(config);
        // Then
        assertThat(options.isUseGlobalHttpState(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetAndPersistUseGlobalHttpState(boolean enabled) throws Exception {
        // Given / When
        options.setUseGlobalHttpState(enabled);
        // Then
        assertThat(options.isUseGlobalHttpState(), is(equalTo(enabled)));
        assertThat(config.getBoolean(GLOBAL_HTTP_STATE_ENABLED_KEY), is(equalTo(enabled)));
    }

    @Test
    void shouldLoadConfigWithDnsTtlSuccessfulQueries() {
        // Given
        config.setProperty(DNS_TTL_SUCCESSFUL_QUERIES_KEY, "60");
        // When
        options.load(config);
        // Then
        assertThat(options.getDnsTtlSuccessfulQueries(), is(equalTo(60)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"" + Long.MAX_VALUE, "A", ""})
    void shouldUseDefaultWithInvalidDnsTtlSuccessfulQueries(String ttl) {
        // Given
        config.setProperty(DNS_TTL_SUCCESSFUL_QUERIES_KEY, ttl);
        // When
        options.load(config);
        // Then
        assertThat(
                options.getDnsTtlSuccessfulQueries(),
                is(equalTo(DNS_DEFAULT_TTL_SUCCESSFUL_QUERIES)));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0, 10})
    void shouldSetAndPersistDnsTtlSuccessfulQueries(int value) throws Exception {
        // Given / When
        options.setDnsTtlSuccessfulQueries(value);
        // Then
        assertThat(options.getDnsTtlSuccessfulQueries(), is(equalTo(value)));
        assertThat(config.getInt(DNS_TTL_SUCCESSFUL_QUERIES_KEY), is(equalTo(value)));
    }

    @Test
    void shouldLoadConfigWithTlsProtocols() {
        // Given
        config.setProperty(TLS_PROTOCOL_KEY + "(0)", TlsUtils.getSupportedProtocols().get(0));
        // When
        options.load(config);
        // Then
        assertThat(options.getTlsProtocols(), contains(TlsUtils.getSupportedProtocols().get(0)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "Not Supported"})
    void shouldUseDefaultWithInvalidTlsProtocols(String tlsProtocol) {
        // Given
        config.setProperty(TLS_PROTOCOL_KEY + "(0)", tlsProtocol);
        // When
        options.load(config);
        // Then
        assertThat(options.getTlsProtocols(), is(equalTo(TlsUtils.getSupportedProtocols())));
    }

    @Test
    void shouldSetAndPersistTlsProtocols() throws Exception {
        // Given
        List<String> tlsProtocols =
                Collections.singletonList(TlsUtils.getSupportedProtocols().get(0));
        // When
        options.setTlsProtocols(tlsProtocols);
        // Then
        assertThat(options.getTlsProtocols(), is(equalTo(tlsProtocols)));
        assertThat(
                config.getString(TLS_PROTOCOL_KEY + "(0)"),
                is(equalTo(TlsUtils.getSupportedProtocols().get(0))));
    }

    @Test
    void shouldThrowIfSettingInvalidTlsProtocols() throws Exception {
        // Given
        List<String> tlsProtocols = Collections.singletonList("");
        // When / Then
        assertThrows(IllegalArgumentException.class, () -> options.setTlsProtocols(tlsProtocols));
        assertThat(config.getString(TLS_PROTOCOL_KEY + "(0)"), is(nullValue()));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithAllowUnsafeRenegotiation(boolean allow) {
        // Given
        config.setProperty(TLS_ALLOW_UNSAFE_RENEGOTIATION, allow);
        // When
        options.load(config);
        // Then
        assertThat(options.isAllowUnsafeRenegotiation(), is(equalTo(allow)));
        assertAllowUnsafeRenegotiationProperties(allow);
    }

    @Test
    void shouldUseDefaultWithInvalidAllowUnsafeRenegotiation() {
        // Given
        config.setProperty(TLS_ALLOW_UNSAFE_RENEGOTIATION, "not a boolean");
        // When
        options.load(config);
        // Then
        assertThat(options.isAllowUnsafeRenegotiation(), is(equalTo(false)));
        assertAllowUnsafeRenegotiationProperties(false);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetAndPersistAllowUnsafeRenegotiation(boolean allow) throws Exception {
        // Given
        options.setAllowUnsafeRenegotiation(!allow);
        // When
        options.setAllowUnsafeRenegotiation(allow);
        // Then
        assertThat(options.isAllowUnsafeRenegotiation(), is(equalTo(allow)));
        assertThat(config.getBoolean(TLS_ALLOW_UNSAFE_RENEGOTIATION), is(equalTo(allow)));
        assertAllowUnsafeRenegotiationProperties(allow);
    }

    private static void assertAllowUnsafeRenegotiationProperties(boolean allow) {
        assertThat(
                System.getProperty("sun.security.ssl.allowUnsafeRenegotiation"),
                is(equalTo(String.valueOf(allow))));
        assertThat(
                System.getProperty("com.ibm.jsse2.renegotiate"),
                is(equalTo(allow ? "ALL" : "NONE")));
    }

    @Test
    void shouldLoadConfigWithHttpProxy() {
        // Given
        config =
                configWith(
                        "<network>\n"
                                + "  <connection version=\"1\">\n"
                                + "    <httpProxy>\n"
                                + "      <host>example.com</host>\n"
                                + "      <port>1234</port>\n"
                                + "      <realm>Realm</realm>\n"
                                + "      <username>UserName</username>\n"
                                + "      <password>Password</password>\n"
                                + "    </httpProxy>\n"
                                + "  </connection>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertHttpProxyFields(
                options.getHttpProxy(), "example.com", 1234, "Realm", "UserName", "Password");
    }

    @Test
    void shouldLoadConfigWithEmptyHttpProxyHost() {
        // Given
        config =
                configWith(
                        "<network>\n"
                                + "  <connection version=\"1\">\n"
                                + "    <httpProxy>\n"
                                + "      <host></host>\n"
                                + "    </httpProxy>\n"
                                + "  </connection>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(
                options.getHttpProxy().getHost(),
                is(equalTo(ConnectionOptions.DEFAULT_HTTP_PROXY.getHost())));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "not an int", "-1", "0", "65536"})
    void shouldLoadConfigWithInvalidHttpProxyPort(String port) {
        // Given
        config =
                configWith(
                        "<network>\n"
                                + "  <connection version=\"1\">\n"
                                + "    <httpProxy>\n"
                                + "      <port>"
                                + port
                                + "</port>\n"
                                + "    </httpProxy>\n"
                                + "  </connection>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(
                options.getHttpProxy().getPort(),
                is(equalTo(ConnectionOptions.DEFAULT_HTTP_PROXY.getPort())));
    }

    static Stream<Arguments> httpProxyPersistenceData() {
        return Stream.of(
                arguments("127.0.0.1", 1001, "Realm 1", "UserName 1", "Password 1"),
                arguments("127.0.0.2", 1002, "", "UserName 2", "Password 2"),
                arguments("127.0.0.3", 1003, "", "", "Password 3"),
                arguments("127.0.0.4", 1004, "", "", ""));
    }

    @ParameterizedTest
    @MethodSource("httpProxyPersistenceData")
    void shouldSetAndPersistHttpProxy(
            String host, int port, String realm, String userName, String password) {

        // Given
        HttpProxy httpProxy =
                new HttpProxy(
                        host,
                        port,
                        realm,
                        new PasswordAuthentication(userName, password.toCharArray()));
        // When
        options.setHttpProxy(httpProxy);
        // Then
        assertThat(config.getProperty(HTTP_PROXY_KEY + ".host"), is(equalTo(host)));
        assertThat(config.getProperty(HTTP_PROXY_KEY + ".port"), is(equalTo(port)));
        assertThat(config.getProperty(HTTP_PROXY_KEY + ".realm"), is(equalTo(realm)));
        assertThat(config.getProperty(HTTP_PROXY_KEY + ".username"), is(equalTo(userName)));
        assertThat(config.getProperty(HTTP_PROXY_PASSWORD_KEY), is(equalTo(password)));
    }

    @Test
    void shouldNotSetAndPersistSameHttpProxy() {
        // Given
        HttpProxy httpProxy = ConnectionOptions.DEFAULT_HTTP_PROXY;
        // When
        options.setHttpProxy(httpProxy);
        // Then
        assertThat(config.getProperty(HTTP_PROXY_KEY + ".host"), is(nullValue()));
        assertThat(config.getProperty(HTTP_PROXY_KEY + ".port"), is(nullValue()));
        assertThat(config.getProperty(HTTP_PROXY_KEY + ".realm"), is(nullValue()));
        assertThat(config.getProperty(HTTP_PROXY_KEY + ".username"), is(nullValue()));
        assertThat(config.getProperty(HTTP_PROXY_PASSWORD_KEY), is(nullValue()));
    }

    @ParameterizedTest
    @MethodSource("httpProxyPersistenceData")
    void shouldNotStorePasswordIfStoreHttpProxyPassNotSet(
            String host, int port, String realm, String userName, String password) {
        // Given
        options.setStoreHttpProxyPass(false);
        HttpProxy httpProxy =
                new HttpProxy(
                        host,
                        port,
                        realm,
                        new PasswordAuthentication(userName, password.toCharArray()));
        // When
        options.setHttpProxy(httpProxy);
        // Then
        assertThat(config.getProperty(HTTP_PROXY_PASSWORD_KEY), is(equalTo("")));
    }

    @Test
    void shouldThrowIfSettingNullHttpProxy() {
        // Given
        HttpProxy httpProxy = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.setHttpProxy(httpProxy));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithHttpProxyEnabled(boolean enabled) {
        // Given
        config.setProperty(HTTP_PROXY_ENABLED_KEY, enabled);
        // When
        options.load(config);
        // Then
        assertThat(options.isHttpProxyEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldUseDefaultWithNoHttpProxyEnabled() {
        // Given
        config.setProperty(HTTP_PROXY_ENABLED_KEY, null);
        // When
        options.load(config);
        // Then
        assertThat(options.isHttpProxyEnabled(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetAndPersistHttpProxyEnabled(boolean enabled) throws Exception {
        // Given / When
        options.setHttpProxyEnabled(enabled);
        // Then
        assertThat(options.isHttpProxyEnabled(), is(equalTo(enabled)));
        assertThat(config.getBoolean(HTTP_PROXY_ENABLED_KEY), is(equalTo(enabled)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithHttpProxyAuthEnabled(boolean enabled) {
        // Given
        config.setProperty(HTTP_PROXY_AUTH_ENABLED_KEY, enabled);
        // When
        options.load(config);
        // Then
        assertThat(options.isHttpProxyAuthEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldUseDefaultWithNoHttpProxyAuthEnabled() {
        // Given
        config.setProperty(HTTP_PROXY_AUTH_ENABLED_KEY, null);
        // When
        options.load(config);
        // Then
        assertThat(options.isHttpProxyAuthEnabled(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetAndPersistHttpProxyAuthEnabled(boolean enabled) throws Exception {
        // Given / When
        options.setHttpProxyAuthEnabled(enabled);
        // Then
        assertThat(options.isHttpProxyAuthEnabled(), is(equalTo(enabled)));
        assertThat(config.getBoolean(HTTP_PROXY_AUTH_ENABLED_KEY), is(equalTo(enabled)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithStoreHttpProxyPass(boolean store) {
        // Given
        config.setProperty(STORE_HTTP_PROXY_PASS_KEY, store);
        // When
        options.load(config);
        // Then
        assertThat(options.isStoreHttpProxyPass(), is(equalTo(store)));
    }

    @Test
    void shouldUseDefaultWithNoStoreHttpProxyPass() {
        // Given
        config.setProperty(STORE_HTTP_PROXY_PASS_KEY, null);
        // When
        options.load(config);
        // Then
        assertThat(options.isStoreHttpProxyPass(), is(equalTo(true)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetAndPersistStoreHttpProxyPass(boolean store) throws Exception {
        // Given / When
        options.setStoreHttpProxyPass(store);
        // Then
        assertThat(options.isStoreHttpProxyPass(), is(equalTo(store)));
        assertThat(config.getBoolean(STORE_HTTP_PROXY_PASS_KEY), is(equalTo(store)));
    }

    @Test
    void shouldClearStoredPassIfSettingToNotStoreHttpProxyPass() throws Exception {
        // Given
        config.setProperty(HTTP_PROXY_PASSWORD_KEY, "password");
        options.load(config);
        // When
        options.setStoreHttpProxyPass(false);
        // Then
        assertThat(config.getString(HTTP_PROXY_PASSWORD_KEY), is(equalTo("")));
    }

    @Test
    void shouldNotClearStoredPassIfSettingToStoreHttpProxyPass() throws Exception {
        // Given
        config.setProperty(HTTP_PROXY_PASSWORD_KEY, "password");
        options.load(config);
        // When
        options.setStoreHttpProxyPass(true);
        // Then
        assertThat(config.getString(HTTP_PROXY_PASSWORD_KEY), is(equalTo("password")));
    }

    @Test
    void shouldUseHttpProxyForHostIfProxyEnabledAndHostNotExcluded() throws Exception {
        // Given
        String host = "example.org";
        options.setHttpProxyEnabled(true);
        options.addHttpProxyExclusion(exclusion("other.example.com", true));
        options.addHttpProxyExclusion(exclusion(Pattern.quote(host), false));
        // When
        boolean useProxy = options.isUseHttpProxy(host);
        // Then
        assertThat(useProxy, is(equalTo(true)));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldNotUseHttpProxyForHostIfProxyEnabledAndHostIsNullOrEmpty(String host)
            throws Exception {
        // Given
        options.setHttpProxyEnabled(true);
        // When
        boolean useProxy = options.isUseHttpProxy(host);
        // Then
        assertThat(useProxy, is(equalTo(false)));
    }

    @Test
    void shouldNotUseHttpProxyForHostIfProxyNotEnabled() throws Exception {
        // Given
        String host = "example.org";
        options.setHttpProxyEnabled(false);
        // When
        boolean useProxy = options.isUseHttpProxy(host);
        // Then
        assertThat(useProxy, is(equalTo(false)));
    }

    @Test
    void shouldNotUseHttpProxyForHostIfProxyEnabledAndHostExcluded() throws Exception {
        // Given
        String host = "example.org";
        options.setHttpProxyEnabled(true);
        options.addHttpProxyExclusion(exclusion(Pattern.quote(host), true));
        // When
        boolean useProxy = options.isUseHttpProxy(host);
        // Then
        assertThat(useProxy, is(equalTo(false)));
    }

    @Test
    void shouldAddHttpProxyExclusion() {
        // Given
        HttpProxyExclusion exclusion = exclusion("example.org", true);
        // When
        options.addHttpProxyExclusion(exclusion);
        // Then
        assertThat(options.getHttpProxyExclusions(), hasSize(1));
        assertPersistedExclusion(0, "example.org", true);
    }

    @Test
    void shouldThrowIfAddingNullHttpProxyExclusion() {
        // Given
        HttpProxyExclusion exclusion = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.addHttpProxyExclusion(exclusion));
        assertThat(options.getHttpProxyExclusions(), hasSize(0));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetHttpProxyExclusionEnabled(boolean enabled) {
        // Given
        options.addHttpProxyExclusion(exclusion("example.org", !enabled));
        options.addHttpProxyExclusion(exclusion("example.com", true));
        // When
        boolean changed = options.setHttpProxyExclusionEnabled("example.org", enabled);
        // Then
        assertThat(changed, is(equalTo(true)));
        assertThat(options.getHttpProxyExclusions(), hasSize(2));
        assertPersistedExclusion(0, "example.org", enabled);
        assertPersistedExclusion(1, "example.com", true);
    }

    @Test
    void shouldReturnFalseIfHttpProxyExclusionNotChanged() {
        // Given
        options.addHttpProxyExclusion(exclusion("example.org", true));
        options.addHttpProxyExclusion(exclusion("example.com", true));
        // When
        boolean changed = options.setHttpProxyExclusionEnabled("other.example.org", false);
        // Then
        assertThat(changed, is(equalTo(false)));
        assertThat(options.getHttpProxyExclusions(), hasSize(2));
        assertPersistedExclusion(0, "example.org", true);
        assertPersistedExclusion(1, "example.com", true);
    }

    @Test
    void shouldThrowIfSettingNullHttpProxyExclusionEnabled() {
        // Given
        String host = null;
        // When / Then
        assertThrows(
                NullPointerException.class, () -> options.setHttpProxyExclusionEnabled(host, true));
        assertThat(options.getHttpProxyExclusions(), hasSize(0));
    }

    @Test
    void shouldRemoveHttpProxyExclusion() {
        // Given
        options.addHttpProxyExclusion(exclusion("example.org", true));
        options.addHttpProxyExclusion(exclusion("example.com", true));
        // When
        boolean removed = options.removeHttpProxyExclusion("example.org");
        // Then
        assertThat(removed, is(equalTo(true)));
        assertThat(options.getHttpProxyExclusions(), hasSize(1));
        assertPersistedExclusion(0, "example.com", true);
        assertPersistedExclusion(1, null, null);
    }

    @Test
    void shouldReturnFalseIfHttpProxyExclusionNotRemoved() {
        // Given
        options.addHttpProxyExclusion(exclusion("example.org", true));
        options.addHttpProxyExclusion(exclusion("example.com", true));
        // When
        boolean removed = options.removeHttpProxyExclusion("other.example.org");
        // Then
        assertThat(removed, is(equalTo(false)));
        assertThat(options.getHttpProxyExclusions(), hasSize(2));
        assertPersistedExclusion(0, "example.org", true);
        assertPersistedExclusion(1, "example.com", true);
    }

    @Test
    void shouldThrowIfRemovingNullHostHttpProxyExclusion() {
        // Given
        String host = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.removeHttpProxyExclusion(host));
        assertThat(options.getHttpProxyExclusions(), hasSize(0));
    }

    @Test
    void shouldLoadConfigWithHttpProxyExclusions() {
        // Given
        config =
                configWith(
                        "<network>\n"
                                + "  <connection version=\"1\">\n"
                                + "    <httpProxy>\n"
                                + "      <exclusions>\n"
                                + "        <exclusion>\n"
                                + "          <host>example.org</host>\n"
                                + "          <enabled>true</enabled>\n"
                                + "        </exclusion>\n"
                                + "        <exclusion>\n"
                                + "          <host>example.com</host>\n"
                                + "          <enabled>false</enabled>\n"
                                + "        </exclusion>\n"
                                + "      </exclusions>\n"
                                + "    </httpProxy>\n"
                                + "  </connection>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getHttpProxyExclusions(), hasSize(2));
        assertExclusion(0, "example.org", true);
        assertExclusion(1, "example.com", false);
    }

    @Test
    void shouldSetAndPersistHttpProxyExclusions() {
        // Given
        List<HttpProxyExclusion> exclusions =
                Arrays.asList(exclusion("example.org", true), exclusion("example.com", false));
        // When
        options.setHttpProxyExclusions(exclusions);
        // Then
        assertThat(options.getHttpProxyExclusions(), hasSize(2));
        assertExclusion(0, "example.org", true);
        assertExclusion(1, "example.com", false);
    }

    @Test
    void shouldLoadConfigWhileIgnoringInvalidHttpProxyExclusions() {
        // Given
        config =
                configWith(
                        "<network>\n"
                                + "  <connection version=\"1\">\n"
                                + "    <httpProxy>\n"
                                + "      <exclusions>\n"
                                + "        <exclusion>\n"
                                + "          <host></host>\n"
                                + "          <enabled>true</enabled>\n"
                                + "        </exclusion>\n"
                                + "        <exclusion>\n"
                                + "          <enabled>false</enabled>\n"
                                + "        </exclusion>\n"
                                + "        <exclusion>\n"
                                + "          <host>*</host>\n"
                                + "          <enabled>false</enabled>\n"
                                + "        </exclusion>\n"
                                + "        <exclusion>\n"
                                + "          <host>example.com</host>\n"
                                + "          <enabled>not a boolean</enabled>\n"
                                + "        </exclusion>\n"
                                + "        <exclusion>\n"
                                + "          <host>valid.example.com</host>\n"
                                + "        </exclusion>\n"
                                + "      </exclusions>\n"
                                + "    </httpProxy>\n"
                                + "  </connection>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getHttpProxyExclusions(), hasSize(1));
        assertExclusion(0, "valid.example.com", true);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithConfirmRemoveHttpProxyExclusion(boolean value) {
        // Given
        config.setProperty(HTTP_PROXY_EXCLUSIONS_CONFIRM_REMOVE, value);
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemoveHttpProxyExclusion(), is(equalTo(value)));
    }

    @Test
    void shouldLoadConfigWithInvalidConfirmRemoveHttpProxyExclusion() {
        // Given
        config.setProperty(HTTP_PROXY_EXCLUSIONS_CONFIRM_REMOVE, "not boolean");
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemoveHttpProxyExclusion(), is(equalTo(true)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetAndPersistConfirmRemoveHttpProxyExclusion(boolean confirm) throws Exception {
        // Given / When
        options.setConfirmRemoveHttpProxyExclusion(confirm);
        // Then
        assertThat(options.isConfirmRemoveHttpProxyExclusion(), is(equalTo(confirm)));
        assertThat(config.getBoolean(HTTP_PROXY_EXCLUSIONS_CONFIRM_REMOVE), is(equalTo(confirm)));
    }

    @Test
    void shouldLoadConfigWithSocksProxy() {
        // Given
        config =
                configWith(
                        "<network>\n"
                                + "  <connection version=\"1\">\n"
                                + "    <socksProxy>\n"
                                + "      <host>example.com</host>\n"
                                + "      <port>1234</port>\n"
                                + "      <version>4</version>\n"
                                + "      <dns>false</dns>\n"
                                + "      <username>UserName</username>\n"
                                + "      <password>Password</password>\n"
                                + "    </socksProxy>\n"
                                + "  </connection>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertSocksProxyFields(
                options.getSocksProxy(),
                "example.com",
                1234,
                SocksProxy.Version.SOCKS4A,
                false,
                "UserName",
                "Password");
    }

    @Test
    void shouldLoadConfigWithEmptySocksProxyHost() {
        // Given
        config =
                configWith(
                        "<network>\n"
                                + "  <connection version=\"1\">\n"
                                + "    <socksProxy>\n"
                                + "      <host></host>\n"
                                + "    </socksProxy>\n"
                                + "  </connection>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(
                options.getSocksProxy().getHost(),
                is(equalTo(ConnectionOptions.DEFAULT_SOCKS_PROXY.getHost())));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "not an int", "-1", "0", "65536"})
    void shouldLoadConfigWithInvalidSocksProxyPort(String port) {
        // Given
        config =
                configWith(
                        "<network>\n"
                                + "  <connection version=\"1\">\n"
                                + "    <socksProxy>\n"
                                + "      <port>"
                                + port
                                + "</port>\n"
                                + "    </socksProxy>\n"
                                + "  </connection>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(
                options.getSocksProxy().getPort(),
                is(equalTo(ConnectionOptions.DEFAULT_SOCKS_PROXY.getPort())));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "not a version", "0"})
    void shouldLoadConfigWithInvalidSocksProxyVersion(String version) {
        // Given
        config =
                configWith(
                        "<network>\n"
                                + "  <connection version=\"1\">\n"
                                + "    <socksProxy>\n"
                                + "      <version>"
                                + version
                                + "</version>\n"
                                + "    </socksProxy>\n"
                                + "  </connection>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(
                options.getSocksProxy().getVersion(),
                is(equalTo(ConnectionOptions.DEFAULT_SOCKS_PROXY.getVersion())));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "not a boolean"})
    void shouldLoadConfigWithInvalidSocksProxyDns(String dns) {
        // Given
        config =
                configWith(
                        "<network>\n"
                                + "  <connection version=\"1\">\n"
                                + "    <socksProxy>\n"
                                + "      <dns>"
                                + dns
                                + "</dns>\n"
                                + "    </socksProxy>\n"
                                + "  </connection>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(
                options.getSocksProxy().isUseDns(),
                is(equalTo(ConnectionOptions.DEFAULT_SOCKS_PROXY.isUseDns())));
    }

    static Stream<Arguments> socksProxyPersistenceData() {
        return Stream.of(
                arguments(
                        "127.0.0.1",
                        1001,
                        SocksProxy.Version.SOCKS5,
                        true,
                        "UserName 1",
                        "Password 1"),
                arguments(
                        "127.0.0.2",
                        1002,
                        SocksProxy.Version.SOCKS5,
                        false,
                        "UserName 2",
                        "Password 2"),
                arguments("127.0.0.3", 1003, SocksProxy.Version.SOCKS4A, true, "", "Password 3"),
                arguments("127.0.0.4", 1004, SocksProxy.Version.SOCKS4A, false, "", ""));
    }

    @ParameterizedTest
    @MethodSource("socksProxyPersistenceData")
    void shouldSetAndPersistSocksProxy(
            String host,
            int port,
            SocksProxy.Version version,
            boolean useDns,
            String userName,
            String password) {

        // Given
        SocksProxy socksProxy =
                new SocksProxy(
                        host,
                        port,
                        version,
                        useDns,
                        new PasswordAuthentication(userName, password.toCharArray()));
        // When
        options.setSocksProxy(socksProxy);
        // Then
        assertThat(config.getProperty(SOCKS_PROXY_KEY + ".host"), is(equalTo(host)));
        assertThat(config.getProperty(SOCKS_PROXY_KEY + ".port"), is(equalTo(port)));
        assertThat(config.getProperty(SOCKS_PROXY_KEY + ".version"), is(equalTo(version.number())));
        assertThat(config.getProperty(SOCKS_PROXY_KEY + ".dns"), is(equalTo(useDns)));
        assertThat(config.getProperty(SOCKS_PROXY_KEY + ".username"), is(equalTo(userName)));
        assertThat(config.getProperty(SOCKS_PROXY_KEY + ".password"), is(equalTo(password)));
    }

    @Test
    void shouldNotSetAndPersistSameSocksProxy() {
        // Given
        SocksProxy socksProxy = ConnectionOptions.DEFAULT_SOCKS_PROXY;
        // When
        options.setSocksProxy(socksProxy);
        // Then
        assertThat(config.getProperty(SOCKS_PROXY_KEY + ".host"), is(nullValue()));
        assertThat(config.getProperty(SOCKS_PROXY_KEY + ".port"), is(nullValue()));
        assertThat(config.getProperty(SOCKS_PROXY_KEY + ".version"), is(nullValue()));
        assertThat(config.getProperty(SOCKS_PROXY_KEY + ".dns"), is(nullValue()));
        assertThat(config.getProperty(SOCKS_PROXY_KEY + ".username"), is(nullValue()));
        assertThat(config.getProperty(SOCKS_PROXY_KEY + ".password"), is(nullValue()));
    }

    @Test
    void shouldThrowIfSettingNullSocksProxy() {
        // Given
        SocksProxy socksProxy = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.setSocksProxy(socksProxy));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithSocksProxyEnabled(boolean enabled) {
        // Given
        config.setProperty(SOCKS_PROXY_ENABLED_KEY, enabled);
        // When
        options.load(config);
        // Then
        assertThat(options.isSocksProxyEnabled(), is(equalTo(enabled)));
    }

    @Test
    void shouldUseDefaultWithNoSocksProxyEnabled() {
        // Given
        config.setProperty(SOCKS_PROXY_ENABLED_KEY, null);
        // When
        options.load(config);
        // Then
        assertThat(options.isSocksProxyEnabled(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetAndPersistSocksProxyEnabled(boolean enabled) throws Exception {
        // Given / When
        options.setSocksProxyEnabled(enabled);
        // Then
        assertThat(options.isSocksProxyEnabled(), is(equalTo(enabled)));
        assertThat(config.getBoolean(SOCKS_PROXY_ENABLED_KEY), is(equalTo(enabled)));
    }

    @Test
    void shouldApplySocksProxySystemPropertiesWhenEnabled() throws Exception {
        // Given
        SocksProxy socksProxy = ConnectionOptions.DEFAULT_SOCKS_PROXY;
        // When
        options.setSocksProxyEnabled(true);
        // Then
        assertThat(System.getProperty("socksProxyHost"), is(equalTo(socksProxy.getHost())));
        assertThat(
                System.getProperty("socksProxyPort"),
                is(equalTo(String.valueOf(socksProxy.getPort()))));
        assertThat(
                System.getProperty("socksProxyVersion"),
                is(equalTo(String.valueOf(socksProxy.getVersion().number()))));
    }

    @Test
    void shouldClearSocksProxySystemPropertiesWhenNotEnabled() throws Exception {
        // Given
        options.setSocksProxyEnabled(true);
        // When
        options.setSocksProxyEnabled(false);
        // Then
        assertThat(System.getProperty("socksProxyHost"), is(equalTo("")));
        assertThat(System.getProperty("socksProxyPort"), is(equalTo("")));
        assertThat(System.getProperty("socksProxyVersion"), is(equalTo("")));
    }

    @Test
    void shouldApplySocksProxySystemPropertiesWhenSettingEnabledSocksProxy() throws Exception {
        // Given
        options.setSocksProxyEnabled(true);
        SocksProxy socksProxy =
                new SocksProxy(
                        "example.com", 1234, SocksProxy.Version.SOCKS4A, false, EMPTY_CREDENTIALS);
        // When
        options.setSocksProxy(socksProxy);
        // Then
        assertThat(System.getProperty("socksProxyHost"), is(equalTo(socksProxy.getHost())));
        assertThat(
                System.getProperty("socksProxyPort"),
                is(equalTo(String.valueOf(socksProxy.getPort()))));
        assertThat(
                System.getProperty("socksProxyVersion"),
                is(equalTo(String.valueOf(socksProxy.getVersion().number()))));
    }

    @Test
    void shouldClearSocksProxySystemPropertiesWhenSettingNotEnabledSocksProxy() throws Exception {
        // Given
        options.setSocksProxyEnabled(false);
        SocksProxy socksProxy =
                new SocksProxy(
                        "example.com", 1234, SocksProxy.Version.SOCKS4A, false, EMPTY_CREDENTIALS);
        // When
        options.setSocksProxy(socksProxy);
        // Then
        assertThat(System.getProperty("socksProxyHost"), is(equalTo("")));
        assertThat(System.getProperty("socksProxyPort"), is(equalTo("")));
        assertThat(System.getProperty("socksProxyVersion"), is(equalTo("")));
    }

    @Test
    void shouldApplySocksProxySystemPropertiesOnLoadifSocksProxyEnabled() throws Exception {
        // Given
        options.setSocksProxyEnabled(true);
        SocksProxy socksProxy =
                new SocksProxy(
                        "example.com", 1234, SocksProxy.Version.SOCKS4A, false, EMPTY_CREDENTIALS);
        // When
        options.setSocksProxy(socksProxy);
        // Then
        assertThat(System.getProperty("socksProxyHost"), is(equalTo(socksProxy.getHost())));
        assertThat(
                System.getProperty("socksProxyPort"),
                is(equalTo(String.valueOf(socksProxy.getPort()))));
        assertThat(
                System.getProperty("socksProxyVersion"),
                is(equalTo(String.valueOf(socksProxy.getVersion().number()))));
    }

    @Test
    void shouldUseSocksProxySystemPropertiesOnLoadIfPresent() throws Exception {
        // Given
        String host = "example.org";
        int port = 443;
        SocksProxy.Version version = SocksProxy.Version.SOCKS4A;
        System.setProperty("socksProxyHost", host);
        System.setProperty("socksProxyPort", String.valueOf(port));
        System.setProperty("socksProxyVersion", String.valueOf(version.number()));
        // When
        options.load(config);
        // Then
        SocksProxy socksProxy = options.getSocksProxy();
        assertSocksProxyFields(
                socksProxy,
                host,
                port,
                version,
                ConnectionOptions.DEFAULT_SOCKS_PROXY.isUseDns(),
                "",
                "");
        assertThat(System.getProperty("socksProxyHost"), is(equalTo(host)));
        assertThat(System.getProperty("socksProxyPort"), is(equalTo(String.valueOf(port))));
        assertThat(
                System.getProperty("socksProxyVersion"),
                is(equalTo(String.valueOf(version.number()))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "not an int", "-1", "0", "65536"})
    void shouldUseDefaultPortForSocksProxySystemPropertiesOnLoadIfInvalidOrMissing(String port)
            throws Exception {
        // Given
        String host = "example.org";
        SocksProxy.Version version = SocksProxy.Version.SOCKS4A;
        System.setProperty("socksProxyHost", host);
        System.setProperty("socksProxyPort", port);
        System.setProperty("socksProxyVersion", String.valueOf(version.number()));
        // When
        options.load(config);
        // Then
        SocksProxy socksProxy = options.getSocksProxy();
        assertSocksProxyFields(
                socksProxy,
                host,
                ConnectionOptions.DEFAULT_SOCKS_PROXY.getPort(),
                version,
                ConnectionOptions.DEFAULT_SOCKS_PROXY.isUseDns(),
                "",
                "");
        assertThat(
                System.getProperty("socksProxyPort"),
                is(equalTo(String.valueOf(ConnectionOptions.DEFAULT_SOCKS_PROXY.getPort()))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "not a version", "0"})
    void shouldUseDefaultVersionForSocksProxySystemPropertiesOnLoadIfMissing(String version)
            throws Exception {
        // Given
        String host = "example.org";
        int port = 443;
        System.setProperty("socksProxyHost", host);
        System.setProperty("socksProxyPort", String.valueOf(port));
        System.setProperty("socksProxyVersion", version);
        // When
        options.load(config);
        // Then
        SocksProxy socksProxy = options.getSocksProxy();
        assertSocksProxyFields(
                socksProxy,
                host,
                port,
                ConnectionOptions.DEFAULT_SOCKS_PROXY.getVersion(),
                ConnectionOptions.DEFAULT_SOCKS_PROXY.isUseDns(),
                "",
                "");
        assertThat(
                System.getProperty("socksProxyVersion"),
                is(
                        equalTo(
                                String.valueOf(
                                        ConnectionOptions.DEFAULT_SOCKS_PROXY
                                                .getVersion()
                                                .number()))));
    }

    @Test
    void shouldNotResolveRemoteHostnameWithSocksProxyEnabledUseDnsAndVersion5() {
        // Given
        options.setSocksProxyEnabled(true);
        SocksProxy socksProxy =
                new SocksProxy(
                        "example.com", 1234, SocksProxy.Version.SOCKS5, true, EMPTY_CREDENTIALS);
        options.setSocksProxy(socksProxy);
        String host = "example.org";
        // When
        boolean resolve = options.shouldResolveRemoteHostname(host);
        // Then
        assertThat(resolve, is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "127.0.0.1", "[::1]", "[::0]"})
    void shouldNResolveRemoteHostnameWithSocksProxyEnabledUseDnsAndVersion5IfLooback(String host) {
        // Given
        options.setSocksProxyEnabled(true);
        SocksProxy socksProxy =
                new SocksProxy(
                        "example.com", 1234, SocksProxy.Version.SOCKS5, true, EMPTY_CREDENTIALS);
        options.setSocksProxy(socksProxy);
        // When
        boolean resolve = options.shouldResolveRemoteHostname(host);
        // Then
        assertThat(resolve, is(equalTo(true)));
    }

    @Test
    void shouldResolveRemoteHostnameIfSocksProxyNotEnabled() {
        // Given
        options.setSocksProxyEnabled(false);
        String host = "example.org";
        // When
        boolean resolve = options.shouldResolveRemoteHostname(host);
        // Then
        assertThat(resolve, is(equalTo(true)));
    }

    @Test
    void shouldResolveRemoteHostnameIfSocksProxyNotUseDns() {
        // Given
        options.setSocksProxyEnabled(true);
        SocksProxy socksProxy =
                new SocksProxy(
                        "example.com", 1234, SocksProxy.Version.SOCKS5, false, EMPTY_CREDENTIALS);
        options.setSocksProxy(socksProxy);
        String host = "example.org";
        // When
        boolean resolve = options.shouldResolveRemoteHostname(host);
        // Then
        assertThat(resolve, is(equalTo(true)));
    }

    @Test
    void shouldResolveRemoteHostnameIfSocksProxyNotVersion5() {
        // Given
        options.setSocksProxyEnabled(true);
        SocksProxy socksProxy =
                new SocksProxy(
                        "example.com", 1234, SocksProxy.Version.SOCKS4A, true, EMPTY_CREDENTIALS);
        options.setSocksProxy(socksProxy);
        String host = "example.org";
        // When
        boolean resolve = options.shouldResolveRemoteHostname(host);
        // Then
        assertThat(resolve, is(equalTo(true)));
    }

    @Test
    void shouldMigrateGeneralOptions() {
        // Given
        config =
                configWith(
                        "<connection>\n"
                                + "  <timeoutInSecs>123</timeoutInSecs>\n"
                                + "  <defaultUserAgent>User-Agent</defaultUserAgent>\n"
                                + "  <httpStateEnabled>true</httpStateEnabled>\n"
                                + "  <dnsTtlSuccessfulQueries>321</dnsTtlSuccessfulQueries>\n"
                                + "  <securityProtocolsEnabled>\n"
                                + "    <protocol>SSLv3</protocol>\n"
                                + "    <protocol>TLSv1</protocol>\n"
                                + "    <protocol>TLSv1.1</protocol>\n"
                                + "    <protocol>TLSv1.2</protocol>\n"
                                + "    <protocol>TLSv1.3</protocol>\n"
                                + "  </securityProtocolsEnabled>\n"
                                + "</connection>"
                                + "<certificate>\n"
                                + "  <allowUnsafeSslRenegotiation>true</allowUnsafeSslRenegotiation>\n"
                                + "</certificate>");
        // When
        options.load(config);
        // Then
        assertThat(options.getTimeoutInSecs(), is(equalTo(123)));
        assertThat(options.getDefaultUserAgent(), is(equalTo("User-Agent")));
        assertThat(options.isUseGlobalHttpState(), is(equalTo(true)));
        assertThat(options.getDnsTtlSuccessfulQueries(), is(equalTo(321)));
        assertThat(options.getTlsProtocols(), is(equalTo(TlsUtils.getSupportedProtocols())));
        assertThat(options.isAllowUnsafeRenegotiation(), is(equalTo(true)));
        assertThat(config.getKeys("connection").hasNext(), is(equalTo(false)));
        assertThat(config.getKeys("certificate").hasNext(), is(equalTo(false)));
    }

    @Test
    void shouldIgnoreUnsuppportedTlsProtocolsWhileMigrating() {
        // Given
        config =
                configWith(
                        "<connection>\n"
                                + "  <securityProtocolsEnabled>\n"
                                + "    <protocol>Not known</protocol>\n"
                                + "    <protocol></protocol>\n"
                                + "    <protocol>SSLv3</protocol>\n"
                                + "    <protocol>TLSv1</protocol>\n"
                                + "    <protocol>TLSv1.1</protocol>\n"
                                + "    <protocol>TLSv1.2</protocol>\n"
                                + "    <protocol>TLSv1.3</protocol>\n"
                                + "  </securityProtocolsEnabled>\n"
                                + "</connection>");
        // When
        options.load(config);
        // Then
        assertThat(options.getTlsProtocols(), is(equalTo(TlsUtils.getSupportedProtocols())));
        assertThat(config.getKeys("connection").hasNext(), is(equalTo(false)));
    }

    @Test
    void shouldUseAllTlsProtocolsIfNoneWhileMigrating() {
        // Given
        config =
                configWith(
                        "<connection><securityProtocolsEnabled></securityProtocolsEnabled></connection>");
        // When
        options.load(config);
        // Then
        assertThat(options.getTlsProtocols(), is(equalTo(TlsUtils.getSupportedProtocols())));
        assertThat(config.getKeys("connection").hasNext(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldMigrateHttpProxy(boolean prompt) {
        // Given
        config =
                configWith(
                        "<connection>\n"
                                + "  <proxyChain>\n"
                                + "    <enabled>true</enabled>\n"
                                + "    <hostName>example.org</hostName>\n"
                                + "    <port>1234</port>\n"
                                + "    <realm>Realm</realm>\n"
                                + "    <userName>User Name</userName>\n"
                                + "    <prompt>"
                                + prompt
                                + "</prompt>\n"
                                + "    <password>Password</password>\n"
                                + "    <authEnabled>true</authEnabled>\n"
                                + "  </proxyChain>\n"
                                + "</connection>");
        // When
        options.load(config);
        // Then
        assertThat(options.isHttpProxyEnabled(), is(equalTo(true)));
        assertThat(options.isHttpProxyAuthEnabled(), is(equalTo(true)));
        assertThat(options.isStoreHttpProxyPass(), is(equalTo(!prompt)));
        assertHttpProxyFields(
                options.getHttpProxy(), "example.org", 1234, "Realm", "User Name", "Password");
        assertThat(config.getKeys("connection").hasNext(), is(equalTo(false)));
    }

    @Test
    void shouldMigrateHttpProxyExclusions() {
        // Given
        config =
                configWith(
                        "<connection>\n"
                                + "  <proxyChain>\n"
                                + "    <confirmRemoveExcludedDomain>false</confirmRemoveExcludedDomain>\n"
                                + "    <exclusions>\n"
                                + "      <exclusion>\n"
                                + "        <name>localhost</name>\n"
                                + "        <enabled>true</enabled>\n"
                                + "        <regex>false</regex>\n"
                                + "      </exclusion>\n"
                                + "      <exclusion>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </exclusion>\n"
                                + "      <exclusion>\n"
                                + "        <name>*</name>\n"
                                + "        <regex>true</regex>\n"
                                + "      </exclusion>\n"
                                + "      <exclusion>\n"
                                + "        <name>127\\.0\\.0.*</name>\n"
                                + "        <enabled>true</enabled>\n"
                                + "        <regex>true</regex>\n"
                                + "      </exclusion>\n"
                                + "      <exclusion>\n"
                                + "        <name>example.org</name>\n"
                                + "      </exclusion>\n"
                                + "    </exclusions>\n"
                                + "  </proxyChain>\n"
                                + "</connection>");
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemoveHttpProxyExclusion(), is(equalTo(false)));
        assertThat(options.getHttpProxyExclusions(), hasSize(3));
        assertExclusion(0, "\\Qlocalhost\\E", true);
        assertExclusion(1, "127\\.0\\.0.*", true);
        assertExclusion(2, "\\Qexample.org\\E", true);
        assertThat(config.getKeys("connection").hasNext(), is(equalTo(false)));
    }

    @Test
    void shouldMigrateSocksProxy() {
        // Given
        config =
                configWith(
                        "<connection>\n"
                                + "  <socksProxy>\n"
                                + "    <enabled>true</enabled>\n"
                                + "    <host>example.org</host>\n"
                                + "    <port>1234</port>\n"
                                + "    <version>4</version>\n"
                                + "    <dns>false</dns>\n"
                                + "    <username>User Name</username>\n"
                                + "    <password>Password</password>\n"
                                + "  </socksProxy>\n"
                                + "</connection>");
        // When
        options.load(config);
        // Then
        assertThat(options.isSocksProxyEnabled(), is(equalTo(true)));
        assertSocksProxyFields(
                options.getSocksProxy(),
                "example.org",
                1234,
                SocksProxy.Version.SOCKS4A,
                false,
                "User Name",
                "Password");
        assertThat(config.getKeys("connection").hasNext(), is(equalTo(false)));
    }

    private static HttpProxyExclusion exclusion(String pattern, boolean enabled) {
        return new HttpProxyExclusion(Pattern.compile(pattern), enabled);
    }

    private void assertPersistedExclusion(int index, String host, Boolean enabled) {
        String indexKey = "(" + index + ")";
        assertThat(
                config.getProperty(HTTP_PROXY_EXCLUSION_KEY + indexKey + ".host"),
                is(equalTo(host)));
        assertThat(
                config.getProperty(HTTP_PROXY_EXCLUSION_KEY + indexKey + ".enabled"),
                is(equalTo(enabled)));
    }

    private void assertExclusion(int index, String host, boolean enabled) {
        HttpProxyExclusion exclusion = options.getHttpProxyExclusions().get(index);
        assertThat(exclusion.getHost().pattern(), is(equalTo(host)));
        assertThat(exclusion.isEnabled(), is(equalTo(enabled)));
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
