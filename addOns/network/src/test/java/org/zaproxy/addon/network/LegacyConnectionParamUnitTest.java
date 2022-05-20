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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.net.PasswordAuthentication;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.HttpState;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.zaproxy.addon.network.internal.client.HttpProxy;
import org.zaproxy.addon.network.internal.client.HttpProxyExclusion;
import org.zaproxy.zap.network.DomainMatcher;

/** Unit test for {@link LegacyConnectionParam}. */
@ExtendWith(MockitoExtension.class)
class LegacyConnectionParamUnitTest {

    private static final String PASSWORD = "Password";
    private static final HttpProxy HTTP_PROXY =
            new HttpProxy(
                    "example.org",
                    443,
                    "Realm",
                    new PasswordAuthentication("UserName", PASSWORD.toCharArray()));

    private static final HttpProxyExclusion EXCLUSION_A =
            new HttpProxyExclusion(Pattern.compile("A"), false);
    private static final HttpProxyExclusion EXCLUSION_B =
            new HttpProxyExclusion(Pattern.compile("\\QB\\E"), true);
    private static final List<HttpProxyExclusion> EXCLUSIONS =
            Collections.unmodifiableList(Arrays.asList(EXCLUSION_A, EXCLUSION_B));

    private ConnectionOptions connectionOptions;
    private LegacyConnectionParam legacyConnectionParam;

    @Captor private ArgumentCaptor<List<HttpProxyExclusion>> exclusionsCaptor;

    @BeforeEach
    void setUp() {
        connectionOptions = mock(ConnectionOptions.class);
        legacyConnectionParam = new LegacyConnectionParam(() -> null, connectionOptions);
    }

    @Test
    void shouldGetDefaultUserAgentFromConnectionOptions() {
        // Given
        String defaultUserAgent = "user-agent";
        given(connectionOptions.getDefaultUserAgent()).willReturn(defaultUserAgent);
        // When
        String obtainedDefaultUserAgent = legacyConnectionParam.getDefaultUserAgent();
        // Then
        assertThat(obtainedDefaultUserAgent, is(equalTo(defaultUserAgent)));
        verify(connectionOptions).getDefaultUserAgent();
    }

    @Test
    void shouldSetDefaultUserAgentToConnectionOptions() {
        // Given
        String defaultUserAgent = "user-agent";
        // When
        legacyConnectionParam.setDefaultUserAgent(defaultUserAgent);
        // Then
        verify(connectionOptions).setDefaultUserAgent(defaultUserAgent);
    }

    @Test
    void shouldGetDnsTtlSuccessfulQueriesFromConnectionOptions() {
        // Given
        int ttl = 30;
        given(connectionOptions.getDnsTtlSuccessfulQueries()).willReturn(ttl);
        // When
        int obtainedTtl = legacyConnectionParam.getDnsTtlSuccessfulQueries();
        // Then
        assertThat(obtainedTtl, is(equalTo(ttl)));
        verify(connectionOptions).getDnsTtlSuccessfulQueries();
    }

    @Test
    void shouldSetDnsTtlSuccessfulQueriesToConnectionOptions() {
        // Given
        int ttl = 30;
        // When
        legacyConnectionParam.setDnsTtlSuccessfulQueries(ttl);
        // Then
        verify(connectionOptions).setDnsTtlSuccessfulQueries(ttl);
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldGetHttpStateFromSupplier() {
        // Given
        HttpState httpState = new HttpState();
        Supplier<HttpState> httpStateSupplier = mock(Supplier.class);
        given(httpStateSupplier.get()).willReturn(httpState);
        legacyConnectionParam = new LegacyConnectionParam(httpStateSupplier, connectionOptions);
        // When
        HttpState obtainedHttpState = legacyConnectionParam.getHttpState();
        // Then
        assertThat(obtainedHttpState, is(sameInstance(httpState)));
        verify(httpStateSupplier).get();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldObtainIsHttpStateEnabledFromConnectionOptions(boolean httpStateEnabled) {
        // Given
        given(connectionOptions.isUseGlobalHttpState()).willReturn(httpStateEnabled);
        // When
        boolean obtainedHttpStateEnabled = legacyConnectionParam.isHttpStateEnabled();
        // Then
        assertThat(obtainedHttpStateEnabled, is(equalTo(httpStateEnabled)));
        verify(connectionOptions).isUseGlobalHttpState();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetHttpStateEnabledToConnectionOptions(boolean httpStateEnabled) {
        // Given / When
        legacyConnectionParam.setHttpStateEnabled(httpStateEnabled);
        // Then
        verify(connectionOptions).setUseGlobalHttpState(httpStateEnabled);
    }

    @Test
    void shouldGetProxyChainNameFromConnectionOptions() {
        // Given
        given(connectionOptions.getHttpProxy()).willReturn(HTTP_PROXY);
        // When
        String host = legacyConnectionParam.getProxyChainName();
        // Then
        assertThat(host, is(equalTo(HTTP_PROXY.getHost())));
        verify(connectionOptions).getHttpProxy();
    }

    @Test
    void shouldSetProxyChainNameToConnectionOptions() {
        // Given
        given(connectionOptions.getHttpProxy()).willReturn(HTTP_PROXY);
        String host = "other.example.org";
        // When
        legacyConnectionParam.setProxyChainName(host);
        // Then
        verify(connectionOptions)
                .setHttpProxy(
                        new HttpProxy(
                                host,
                                HTTP_PROXY.getPort(),
                                HTTP_PROXY.getRealm(),
                                HTTP_PROXY.getPasswordAuthentication()));
    }

    @Test
    void shouldGetProxyChainPasswordFromConnectionOptions() {
        // Given
        given(connectionOptions.getHttpProxy()).willReturn(HTTP_PROXY);
        // When
        String password = legacyConnectionParam.getProxyChainPassword();
        // Then
        assertThat(password, is(equalTo(PASSWORD)));
        verify(connectionOptions).getHttpProxy();
    }

    @Test
    void shouldSetProxyChainPasswordToConnectionOptions() {
        // Given
        given(connectionOptions.getHttpProxy()).willReturn(HTTP_PROXY);
        String password = "Other Password";
        // When
        legacyConnectionParam.setProxyChainPassword(password);
        // Then
        verify(connectionOptions)
                .setHttpProxy(
                        new HttpProxy(
                                HTTP_PROXY.getHost(),
                                HTTP_PROXY.getPort(),
                                HTTP_PROXY.getRealm(),
                                new PasswordAuthentication(
                                        HTTP_PROXY.getPasswordAuthentication().getUserName(),
                                        password.toCharArray())));
    }

    @Test
    @SuppressWarnings("deprecation")
    void shouldSetProxyChainSkipName() {
        // Given
        String proxyChainSkipName = "example.org;example.com";
        // When
        legacyConnectionParam.setProxyChainSkipName(proxyChainSkipName);
        // Then
        verify(connectionOptions).setHttpProxyExclusions(exclusionsCaptor.capture());
        List<HttpProxyExclusion> exclusions = exclusionsCaptor.getValue();
        assertExclusion(exclusions.get(0), "\\Qexample.org\\E", true);
        assertExclusion(exclusions.get(1), "\\Qexample.com\\E", true);
    }

    @Test
    void shouldGetProxyChainPortFromConnectionOptions() {
        // Given
        given(connectionOptions.getHttpProxy()).willReturn(HTTP_PROXY);
        // When
        int port = legacyConnectionParam.getProxyChainPort();
        // Then
        assertThat(port, is(equalTo(HTTP_PROXY.getPort())));
        verify(connectionOptions).getHttpProxy();
    }

    @Test
    void shouldSetProxyChainPortToConnectionOptions() {
        // Given
        given(connectionOptions.getHttpProxy()).willReturn(HTTP_PROXY);
        int proxyChainPort = 1234;
        // When
        legacyConnectionParam.setProxyChainPort(proxyChainPort);
        // Then
        verify(connectionOptions)
                .setHttpProxy(
                        new HttpProxy(
                                HTTP_PROXY.getHost(),
                                proxyChainPort,
                                HTTP_PROXY.getRealm(),
                                HTTP_PROXY.getPasswordAuthentication()));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldObtainIsProxyChainPromptFromConnectionOptions(boolean proxyPrompt) {
        // Given
        given(connectionOptions.isStoreHttpProxyPass()).willReturn(!proxyPrompt);
        // When
        boolean obtainedProxyPrompt = legacyConnectionParam.isProxyChainPrompt();
        // Then
        assertThat(obtainedProxyPrompt, is(equalTo(proxyPrompt)));
        verify(connectionOptions).isStoreHttpProxyPass();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetProxyChainPromptToConnectionOptions(boolean proxyPrompt) {
        // Given / When
        legacyConnectionParam.setProxyChainPrompt(proxyPrompt);
        // Then
        verify(connectionOptions).setStoreHttpProxyPass(!proxyPrompt);
    }

    @Test
    void shouldGetProxyChainRealmFromConnectionOptions() {
        // Given
        given(connectionOptions.getHttpProxy()).willReturn(HTTP_PROXY);
        // When
        String realm = legacyConnectionParam.getProxyChainRealm();
        // Then
        assertThat(realm, is(equalTo(HTTP_PROXY.getRealm())));
        verify(connectionOptions).getHttpProxy();
    }

    @Test
    void shouldSetProxyChainRealmToConnectionOptions() {
        // Given
        given(connectionOptions.getHttpProxy()).willReturn(HTTP_PROXY);
        String realm = "Other Realm";
        // When
        legacyConnectionParam.setProxyChainRealm(realm);
        // Then
        verify(connectionOptions)
                .setHttpProxy(
                        new HttpProxy(
                                HTTP_PROXY.getHost(),
                                HTTP_PROXY.getPort(),
                                realm,
                                HTTP_PROXY.getPasswordAuthentication()));
    }

    @Test
    void shouldGetProxyChainUserNameFromConnectionOptions() {
        // Given
        given(connectionOptions.getHttpProxy()).willReturn(HTTP_PROXY);
        // When
        String userName = legacyConnectionParam.getProxyChainUserName();
        // Then
        assertThat(userName, is(equalTo(HTTP_PROXY.getPasswordAuthentication().getUserName())));
        verify(connectionOptions).getHttpProxy();
    }

    @Test
    void shouldSetProxyChainUserNameToConnectionOptions() {
        // Given
        given(connectionOptions.getHttpProxy()).willReturn(HTTP_PROXY);
        String userName = "Other UserName";
        // When
        legacyConnectionParam.setProxyChainUserName(userName);
        // Then
        verify(connectionOptions)
                .setHttpProxy(
                        new HttpProxy(
                                HTTP_PROXY.getHost(),
                                HTTP_PROXY.getPort(),
                                HTTP_PROXY.getRealm(),
                                new PasswordAuthentication(
                                        userName,
                                        HTTP_PROXY.getPasswordAuthentication().getPassword())));
    }

    @ParameterizedTest
    @SuppressWarnings("deprecation")
    @ValueSource(booleans = {true, false})
    void shouldHaveSingleCookieRequestHeaderAsTrueAlways(boolean singleCookie) {
        // Given / When
        legacyConnectionParam.setSingleCookieRequestHeader(singleCookie);
        // Then
        assertThat(legacyConnectionParam.isSingleCookieRequestHeader(), is(equalTo(true)));
        verifyNoInteractions(connectionOptions);
    }

    @Test
    void shouldGetTimeoutInSecsFromConnectionOptions() {
        // Given
        int timeoutInSecs = 20;
        given(connectionOptions.getTimeoutInSecs()).willReturn(timeoutInSecs);
        // When
        int obtainedTimeoutInSecs = legacyConnectionParam.getTimeoutInSecs();
        // Then
        assertThat(obtainedTimeoutInSecs, is(equalTo(timeoutInSecs)));
        verify(connectionOptions).getTimeoutInSecs();
    }

    @Test
    void shouldSetTimeoutInSecsToConnectionOptions() {
        // Given
        int timeoutInSecs = 20;
        // When
        legacyConnectionParam.setTimeoutInSecs(timeoutInSecs);
        // Then
        verify(connectionOptions).setTimeoutInSecs(timeoutInSecs);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldObtainIsUseProxyChainFromConnectionOptions(boolean useProxyChain) {
        // Given
        given(connectionOptions.isHttpProxyEnabled()).willReturn(useProxyChain);
        // When
        boolean obtainedUseProxyChain = legacyConnectionParam.isUseProxyChain();
        // Then
        assertThat(obtainedUseProxyChain, is(equalTo(useProxyChain)));
        verify(connectionOptions).isHttpProxyEnabled();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetUseProxyChainToConnectionOptions(boolean useProxyChain) {
        // Given / When
        legacyConnectionParam.setUseProxyChain(useProxyChain);
        // Then
        verify(connectionOptions).setHttpProxyEnabled(useProxyChain);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldObtainIsUseProxyChainAuthFromConnectionOptions(boolean useProxyChainAuth) {
        // Given
        given(connectionOptions.isHttpProxyAuthEnabled()).willReturn(useProxyChainAuth);
        // When
        boolean obtainedUseProxyChainAuth = legacyConnectionParam.isUseProxyChainAuth();
        // Then
        assertThat(obtainedUseProxyChainAuth, is(equalTo(useProxyChainAuth)));
        verify(connectionOptions).isHttpProxyAuthEnabled();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetUseProxyChainAuthToConnectionOptions(boolean useProxyChainAuth) {
        // Given / When
        legacyConnectionParam.setUseProxyChainAuth(useProxyChainAuth);
        // Then
        verify(connectionOptions).setHttpProxyAuthEnabled(useProxyChainAuth);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldObtainIsUseSocksProxyFromConnectionOptions(boolean useSocksProxy) {
        // Given
        given(connectionOptions.isSocksProxyEnabled()).willReturn(useSocksProxy);
        // When
        boolean obtainedUseSocksProxy = legacyConnectionParam.isUseSocksProxy();
        // Then
        assertThat(obtainedUseSocksProxy, is(equalTo(useSocksProxy)));
        verify(connectionOptions).isSocksProxyEnabled();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetUseSocksProxyToConnectionOptions(boolean useSocksProxy) {
        // Given / When
        legacyConnectionParam.setUseSocksProxy(useSocksProxy);
        // Then
        verify(connectionOptions).setSocksProxyEnabled(useSocksProxy);
    }

    @ParameterizedTest
    @CsvSource({"example.org, true", "example.com, false"})
    void shouldUseProxyFromConnectionOptions(String hostname, boolean result) {
        // Given
        given(connectionOptions.isUseHttpProxy(any())).willReturn(result);
        // When
        boolean obtainedResult = legacyConnectionParam.isUseProxy(hostname);
        // Then
        assertThat(obtainedResult, is(equalTo(result)));
        verify(connectionOptions).isUseHttpProxy(hostname);
    }

    @ParameterizedTest
    @CsvSource({"example.org, true", "example.com, false"})
    void shouldResolveRemoteHostnameWithConnectionOptions(String hostname, boolean result) {
        // Given
        given(connectionOptions.shouldResolveRemoteHostname(any())).willReturn(result);
        // When
        boolean obtainedResult = legacyConnectionParam.shouldResolveRemoteHostname(hostname);
        // Then
        assertThat(obtainedResult, is(equalTo(result)));
        verify(connectionOptions).shouldResolveRemoteHostname(hostname);
    }

    @Test
    void shouldGetProxyExcludedDomainsFromConnectionOptions() {

        // Given
        given(connectionOptions.getHttpProxyExclusions()).willReturn(EXCLUSIONS);
        // When
        List<DomainMatcher> excludedDomains = legacyConnectionParam.getProxyExcludedDomains();
        // Then
        assertThat(
                excludedDomains,
                contains(domainMatcher("A", false), domainMatcher("\\QB\\E", true)));
    }

    @Test
    void shouldSetProxyExcludedDomainsToConnectionOptions() {
        // Given
        List<DomainMatcher> excludedDomains =
                Arrays.asList(domainMatcher("A", false), new DomainMatcher("B"));
        // When
        legacyConnectionParam.setProxyExcludedDomains(excludedDomains);
        // Then
        verify(connectionOptions).setHttpProxyExclusions(EXCLUSIONS);
    }

    private static void assertExclusion(
            HttpProxyExclusion exclusion, String host, boolean enabled) {
        assertThat(exclusion.getHost().pattern(), is(equalTo(host)));
        assertThat(exclusion.isEnabled(), is(equalTo(enabled)));
    }

    private static DomainMatcher domainMatcher(String regex, boolean enabled) {
        DomainMatcher domainMatcher = new DomainMatcher(Pattern.compile(regex));
        domainMatcher.setEnabled(enabled);
        return domainMatcher;
    }
}
