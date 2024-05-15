/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.withSettings;

import java.net.PasswordAuthentication;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.common.HttpProxy;
import org.zaproxy.addon.network.internal.cert.CertificateUtils;
import org.zaproxy.addon.network.internal.client.HttpProxyExclusion;
import org.zaproxy.addon.network.internal.client.SocksProxy;
import org.zaproxy.addon.network.internal.ratelimit.RateLimitOptions;
import org.zaproxy.addon.network.internal.ratelimit.RateLimitRule;
import org.zaproxy.addon.network.internal.server.http.Alias;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig.ServerMode;
import org.zaproxy.addon.network.internal.server.http.PassThrough;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.API.RequestType;
import org.zaproxy.zap.extension.api.ApiElement;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiParameter;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;

/** Unit test for {@link NetworkApi}. */
class NetworkApiUnitTest extends TestUtils {

    private NetworkApi networkApi;
    private ServerCertificatesOptions serverCertificatesOptions;
    private LocalServersOptions localServersOptions;
    private ConnectionOptions connectionOptions;
    private ClientCertificatesOptions clientCertificatesOptions;
    private RateLimitOptions rateLimitOptions;
    private ExtensionNetwork extensionNetwork;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionNetwork());
        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        Model.setSingletonForTesting(model);
        OptionsParam optionsParam =
                mock(OptionsParam.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getOptionsParam()).willReturn(optionsParam);
        extensionNetwork =
                mock(ExtensionNetwork.class, withSettings().strictness(Strictness.LENIENT));
        serverCertificatesOptions =
                mock(
                        ServerCertificatesOptions.class,
                        withSettings().strictness(Strictness.LENIENT));
        given(extensionNetwork.getServerCertificatesOptions())
                .willReturn(serverCertificatesOptions);
        localServersOptions =
                mock(LocalServersOptions.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionNetwork.getLocalServersOptions()).willReturn(localServersOptions);
        connectionOptions =
                mock(ConnectionOptions.class, withSettings().strictness(Strictness.LENIENT));
        given(connectionOptions.getHttpProxy()).willReturn(ConnectionOptions.DEFAULT_HTTP_PROXY);
        given(extensionNetwork.getConnectionOptions()).willReturn(connectionOptions);
        clientCertificatesOptions = mock(ClientCertificatesOptions.class);
        given(extensionNetwork.getClientCertificatesOptions())
                .willReturn(clientCertificatesOptions);
        rateLimitOptions =
                mock(RateLimitOptions.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionNetwork.getRateLimitOptions()).willReturn(rateLimitOptions);
        networkApi = new NetworkApi(extensionNetwork);
    }

    @AfterAll
    static void cleanUp() {
        Constant.messages = null;
    }

    @Test
    void shouldHavePrefix() throws Exception {
        // Given / When
        String prefix = networkApi.getPrefix();
        // Then
        assertThat(prefix, is(equalTo("network")));
    }

    @Test
    void shouldAddApiElements() {
        // Given / When
        networkApi = new NetworkApi(extensionNetwork);
        // Then
        assertThat(networkApi.getApiActions(), hasSize(29));
        assertThat(networkApi.getApiViews(), hasSize(16));
        assertThat(networkApi.getApiOthers(), hasSize(3));
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"unknown", "something"})
    void shouldThrowApiExceptionForUnknownShortcut(String path) throws Exception {
        // Given
        HttpMessage message = new HttpMessage(new URI("http://zap/" + path, true));
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleShortcut(message));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.URL_NOT_FOUND)));
    }

    @Test
    void shouldReturnProxyPacFromShortcut() throws Exception {
        // Given
        String proxyPacContent = "Proxy PAC Content";
        given(extensionNetwork.getProxyPacContent(any())).willReturn(proxyPacContent);
        HttpMessage message = new HttpMessage(new URI("http://zap/proxy.pac", true));
        // When
        HttpMessage response = networkApi.handleShortcut(message);
        // Then
        assertThat(response.getResponseBody().toString(), is(equalTo(proxyPacContent)));
        verify(extensionNetwork).getProxyPacContent("zap");
    }

    @Test
    void shouldSetProxyWithShortcut() throws Exception {
        // Given
        HttpMessage message = new HttpMessage(new URI("http://zap/setproxy", true));
        message.setRequestBody(
                "{\"type\":1,\"http\":{\"host\":\"proxy.example.org\",\"port\":8090}}");
        // When
        HttpMessage response = networkApi.handleShortcut(message);
        // Then
        assertThat(response.getResponseBody().toString(), is(equalTo("OK")));
        verify(connectionOptions).getHttpProxy();
        verify(connectionOptions).setHttpProxy(newHttpProxy("proxy.example.org", 8090, "", "", ""));
        verifyNoMoreInteractions(connectionOptions);
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"unknown", "something"})
    void shouldThrowApiExceptionForUnknownAction(String name) throws Exception {
        // Given
        JSONObject params = new JSONObject();
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_ACTION)));
    }

    @Test
    void shouldReturnOkForGeneratedRootCaCert() throws Exception {
        // Given
        String name = "generateRootCaCert";
        JSONObject params = new JSONObject();
        given(extensionNetwork.generateRootCaCert()).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
    }

    @Test
    void shouldReturnFailForNonGeneratedRootCaCert() throws Exception {
        // Given
        String name = "generateRootCaCert";
        JSONObject params = new JSONObject();
        given(extensionNetwork.generateRootCaCert()).willReturn(false);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.FAIL)));
    }

    @Test
    void shouldReturnOkForImportedRootCaCert() throws Exception {
        // Given
        String name = "importRootCaCert";
        JSONObject params = new JSONObject();
        Path file = Paths.get("/dir/cert.pem");
        params.put("filePath", file.toString());
        given(extensionNetwork.importRootCaCert(file)).willReturn(null);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(extensionNetwork).importRootCaCert(file);
    }

    @Test
    void shouldThrowApiExceptionForNonImportedRootCaCert() throws Exception {
        // Given
        String name = "importRootCaCert";
        JSONObject params = new JSONObject();
        Path file = Paths.get("/dir/cert.pem");
        params.put("filePath", file.toString());
        given(extensionNetwork.importRootCaCert(file)).willReturn("Missing private key.");
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        assertThat(exception.toString(true), containsString("Missing private key."));
        verify(extensionNetwork).importRootCaCert(file);
    }

    @Test
    void shouldSetRootCaCertValidityIfHandlingServerCerts() throws Exception {
        // Given
        String name = "setRootCaCertValidity";
        JSONObject params = new JSONObject();
        params.put("validity", 123);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(serverCertificatesOptions).setRootCaCertValidity(Duration.ofDays(123));
    }

    @Test
    void shouldThrowApiExceptionForInvalidRootCaCertValidity() {
        // Given
        String name = "setRootCaCertValidity";
        JSONObject params = new JSONObject();
        params.put("validity", "not valid value");
        willThrow(IllegalArgumentException.class)
                .given(serverCertificatesOptions)
                .setRootCaCertValidity(any());
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
    }

    @Test
    void shouldSetServerCertValidityIfHandlingServerCerts() throws Exception {
        // Given
        String name = "setServerCertValidity";
        JSONObject params = new JSONObject();
        params.put("validity", 123);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(serverCertificatesOptions).setServerCertValidity(Duration.ofDays(123));
    }

    @Test
    void shouldThrowApiExceptionForInvalidServerCertValidity() {
        // Given
        String name = "setServerCertValidity";
        JSONObject params = new JSONObject();
        params.put("validity", "not valid value");
        willThrow(IllegalArgumentException.class)
                .given(serverCertificatesOptions)
                .setServerCertValidity(any());
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"unknown", "something"})
    void shouldThrowApiExceptionForUnknownOther(String name) throws Exception {
        // Given
        HttpMessage message = new HttpMessage();
        JSONObject params = new JSONObject();
        // When
        ApiException exception =
                assertThrows(
                        ApiException.class, () -> networkApi.handleApiOther(message, name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_OTHER)));
    }

    @Test
    void shouldReturnProxyPac() throws Exception {
        // Given
        String name = "proxy.pac";
        JSONObject params = new JSONObject();
        String proxyPacContent = "Proxy PAC Content";
        given(extensionNetwork.getProxyPacContent(any())).willReturn(proxyPacContent);
        HttpMessage message = new HttpMessage(new URI("http://zap/OTHER/network/proxy.pac", true));
        // When
        HttpMessage response = networkApi.handleApiOther(message, name, params);
        // Then
        assertThat(response.getResponseBody().toString(), is(equalTo(proxyPacContent)));
        verify(extensionNetwork).getProxyPacContent("zap");
    }

    @Test
    void shouldReturnPemForExistingRootCaCert() throws Exception {
        // Given
        HttpMessage message = new HttpMessage();
        String name = "rootCaCert";
        JSONObject params = new JSONObject();
        KeyStore keyStore =
                CertificateUtils.stringToKeystore(NetworkTestUtils.FISH_CERT_BASE64_STR);
        given(extensionNetwork.getRootCaKeyStore()).willReturn(keyStore);
        // When
        HttpMessage apiMessage = networkApi.handleApiOther(message, name, params);
        // Then
        assertThat(apiMessage, is(sameInstance(message)));
        assertThat(
                apiMessage.getResponseHeader().toString(),
                allOf(
                        containsString("Content-Type: application/pkix-cert;"),
                        containsString(
                                "Content-Disposition: attachment; filename=\"ZAPCACert.cer\"\r\n")));
        assertThat(
                apiMessage.getResponseBody().toString(),
                allOf(
                        containsString(CertificateUtils.BEGIN_CERTIFICATE_TOKEN),
                        containsString(
                                "MIIC9TCCAl6gAwIBAgIJANL8E4epRNznMA0GCSqGSIb3DQEBBQUAMFsxGDAWBgNV\n"),
                        containsString(CertificateUtils.END_CERTIFICATE_TOKEN),
                        not(containsString(CertificateUtils.BEGIN_PRIVATE_KEY_TOKEN))));
        assertThat(apiMessage, is(sameInstance(message)));
    }

    @Test
    void shouldThrowExceptionForMissingRootCaCert() throws Exception {
        // Given
        HttpMessage message = new HttpMessage();
        String name = "rootCaCert";
        JSONObject params = new JSONObject();
        given(extensionNetwork.getRootCaKeyStore()).willReturn(null);
        // When
        ApiException exception =
                assertThrows(
                        ApiException.class, () -> networkApi.handleApiOther(message, name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.DOES_NOT_EXIST)));
    }

    @Test
    void shouldThrowExceptionForIncorrectRootCaCert() throws Exception {
        // Given
        HttpMessage message = new HttpMessage();
        String name = "rootCaCert";
        JSONObject params = new JSONObject();
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        given(extensionNetwork.getRootCaKeyStore()).willReturn(keyStore);
        // When
        ApiException exception =
                assertThrows(
                        ApiException.class, () -> networkApi.handleApiOther(message, name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.INTERNAL_ERROR)));
    }

    @Test
    void shouldSetProxyWithOtherEndpoint() throws Exception {
        // Given
        HttpMessage message = new HttpMessage();
        String name = "setProxy";
        JSONObject params = new JSONObject();
        params.put("proxy", "{\"type\":1,\"http\":{\"host\":\"proxy.example.org\",\"port\":8090}}");
        // When
        HttpMessage response = networkApi.handleApiOther(message, name, params);
        // Then
        assertThat(response.getResponseBody().toString(), is(equalTo("OK")));
        verify(connectionOptions).getHttpProxy();
        verify(connectionOptions).setHttpProxy(newHttpProxy("proxy.example.org", 8090, "", "", ""));
        verifyNoMoreInteractions(connectionOptions);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "\"a\"", "[]"})
    void shouldNotSetProxyWithOtherEndpointIfTypeNotSupported(String type) throws Exception {
        // Given
        HttpMessage message = new HttpMessage();
        String name = "setProxy";
        JSONObject params = new JSONObject();
        params.put(
                "proxy",
                "{\"type\":" + type + ",\"http\":{\"host\":\"proxy.example.org\",\"port\":8090}}");
        // When
        HttpMessage response = networkApi.handleApiOther(message, name, params);
        // Then
        assertThat(response.getResponseBody().toString(), is(equalTo("OK")));
        verifyNoInteractions(connectionOptions);
    }

    @ParameterizedTest
    @ValueSource(strings = {"\"host\":\"\",", ""})
    void shouldNotSetProxyWithOtherEndpointIfHostNotValid(String host) throws Exception {
        // Given
        HttpMessage message = new HttpMessage();
        String name = "setProxy";
        JSONObject params = new JSONObject();
        params.put("proxy", "{\"type\":1,\"http\":{" + host + "\"port\":8080}}");
        // When
        HttpMessage response = networkApi.handleApiOther(message, name, params);
        // Then
        assertThat(response.getResponseBody().toString(), is(equalTo("OK")));
        verifyNoInteractions(connectionOptions);
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "\"a\"", "[]"})
    void shouldNotSetProxyWithOtherEndpointIfPortNotValid(String port) throws Exception {
        // Given
        HttpMessage message = new HttpMessage();
        String name = "setProxy";
        JSONObject params = new JSONObject();
        params.put(
                "proxy",
                "{\"type\":1,\"http\":{\"host\":\"proxy.example.org\",\"port\":" + port + "}}");
        // When
        HttpMessage response = networkApi.handleApiOther(message, name, params);
        // Then
        assertThat(response.getResponseBody().toString(), is(equalTo("OK")));
        verifyNoInteractions(connectionOptions);
    }

    @Test
    void shouldThrowApiExceptionWhenSettingProxyWithOtherEndpointIfMalformedJson()
            throws Exception {
        // Given
        HttpMessage message = new HttpMessage();
        String name = "setProxy";
        JSONObject params = new JSONObject();
        params.put("proxy", "...");
        // When
        ApiException exception =
                assertThrows(
                        ApiException.class, () -> networkApi.handleApiOther(message, name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        verifyNoInteractions(connectionOptions);
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"unknown", "something"})
    void shouldThrowApiExceptionForUnknownView(String name) throws Exception {
        // Given
        JSONObject params = new JSONObject();
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiView(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_VIEW)));
    }

    @Test
    void shouldReturnRootCaCertValidityIfHandlingServerCerts() throws Exception {
        // Given
        String name = "getRootCaCertValidity";
        JSONObject params = new JSONObject();
        given(serverCertificatesOptions.getRootCaCertValidity()).willReturn(Duration.ofDays(123));
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(response.getName(), is(equalTo(name)));
        assertThat(response, is(instanceOf(ApiResponseElement.class)));
        assertThat(((ApiResponseElement) response).getValue(), is(equalTo("123")));
    }

    @Test
    void shouldReturnServerCertValidityIfHandlingServerCerts() throws Exception {
        // Given
        String name = "getServerCertValidity";
        JSONObject params = new JSONObject();
        given(serverCertificatesOptions.getServerCertValidity()).willReturn(Duration.ofDays(123));
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(response.getName(), is(equalTo(name)));
        assertThat(response, is(instanceOf(ApiResponseElement.class)));
        assertThat(((ApiResponseElement) response).getValue(), is(equalTo("123")));
    }

    @Test
    void shouldReturnOkForAddedAlias() throws Exception {
        // Given
        String name = "addAlias";
        JSONObject params = new JSONObject();
        params.put("name", "example.org");
        params.put("enabled", "false");
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(localServersOptions).addAlias(new Alias("example.org", false));
    }

    @Test
    void shouldDefaultToEnabledForAddedAlias() throws Exception {
        // Given
        String name = "addAlias";
        JSONObject params = new JSONObject();
        params.put("name", "example.org");
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(localServersOptions).addAlias(new Alias("example.org", true));
    }

    @Test
    void shouldReturnOkForRemovedAlias() throws Exception {
        // Given
        String name = "removeAlias";
        JSONObject params = new JSONObject();
        params.put("name", "example.org");
        given(localServersOptions.removeAlias(any())).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(localServersOptions).removeAlias("example.org");
    }

    @Test
    void shouldThrowApiExceptionForMissingRemovedAlias() throws Exception {
        // Given
        String name = "removeAlias";
        JSONObject params = new JSONObject();
        params.put("name", "example.org");
        given(localServersOptions.removeAlias(any())).willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.DOES_NOT_EXIST)));
        verify(localServersOptions).removeAlias("example.org");
    }

    @Test
    void shouldReturnOkForChangedAlias() throws Exception {
        // Given
        String name = "setAliasEnabled";
        JSONObject params = new JSONObject();
        params.put("name", "example.org");
        params.put("enabled", "false");
        given(localServersOptions.setAliasEnabled(any(), anyBoolean())).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(localServersOptions).setAliasEnabled("example.org", false);
    }

    @Test
    void shouldThrowApiExceptionForMissingChangedAlias() throws Exception {
        // Given
        String name = "setAliasEnabled";
        JSONObject params = new JSONObject();
        params.put("name", "example.org");
        params.put("enabled", "true");
        given(localServersOptions.setAliasEnabled(any(), anyBoolean())).willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.DOES_NOT_EXIST)));
        verify(localServersOptions).setAliasEnabled("example.org", true);
    }

    @Test
    void shouldGetAliases() throws Exception {
        // Given
        String name = "getAliases";
        JSONObject params = new JSONObject();
        given(localServersOptions.getAliases())
                .willReturn(
                        Arrays.asList(
                                new Alias("example.org", true), new Alias("example.com", false)));
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(response.getName(), is(equalTo(name)));
        assertThat(
                response.toJSON().toString(),
                is(
                        equalTo(
                                "{\"getAliases\":[{\"name\":\"example.org\",\"enabled\":true},"
                                        + "{\"name\":\"example.com\",\"enabled\":false}]}")));
    }

    @Test
    void shouldReturnOkForAddedHttpProxyExclusion() throws Exception {
        // Given
        String name = "addHttpProxyExclusion";
        JSONObject params = new JSONObject();
        params.put("host", "example.org");
        params.put("enabled", "false");
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(connectionOptions)
                .addHttpProxyExclusion(newHttpProxyExclusion("example.org", false));
    }

    @Test
    void shouldThrowApiExceptionForInvalidAddedHttpProxyExclusion() throws Exception {
        // Given
        String name = "addHttpProxyExclusion";
        JSONObject params = new JSONObject();
        params.put("host", "*");
        params.put("enabled", "true");
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
    }

    @Test
    void shouldDefaultToEnabledForAddedHttpProxyExclusion() throws Exception {
        // Given
        String name = "addHttpProxyExclusion";
        JSONObject params = new JSONObject();
        params.put("host", "example.org");
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(connectionOptions).addHttpProxyExclusion(newHttpProxyExclusion("example.org", true));
    }

    @Test
    void shouldReturnOkForRemovedHttpProxyExclusion() throws Exception {
        // Given
        String name = "removeHttpProxyExclusion";
        JSONObject params = new JSONObject();
        params.put("host", "example.org");
        given(connectionOptions.removeHttpProxyExclusion(any())).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(connectionOptions).removeHttpProxyExclusion("example.org");
    }

    @Test
    void shouldThrowApiExceptionForMissingRemovedHttpProxyExclusion() throws Exception {
        // Given
        String name = "removeHttpProxyExclusion";
        JSONObject params = new JSONObject();
        params.put("host", "example.org");
        given(connectionOptions.removeHttpProxyExclusion(any())).willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.DOES_NOT_EXIST)));
        verify(connectionOptions).removeHttpProxyExclusion("example.org");
    }

    @Test
    void shouldReturnOkForChangedHttpProxyExclusion() throws Exception {
        // Given
        String name = "setHttpProxyExclusionEnabled";
        JSONObject params = new JSONObject();
        params.put("host", "example.org");
        params.put("enabled", "false");
        given(connectionOptions.setHttpProxyExclusionEnabled(any(), anyBoolean())).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(connectionOptions).setHttpProxyExclusionEnabled("example.org", false);
    }

    @Test
    void shouldThrowApiExceptionForMissingChangedHttpProxyExclusion() throws Exception {
        // Given
        String name = "setHttpProxyExclusionEnabled";
        JSONObject params = new JSONObject();
        params.put("host", "example.org");
        params.put("enabled", "true");
        given(connectionOptions.setHttpProxyExclusionEnabled(any(), anyBoolean()))
                .willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.DOES_NOT_EXIST)));
        verify(connectionOptions).setHttpProxyExclusionEnabled("example.org", true);
    }

    @Test
    void shouldGetHttpProxyExclusions() throws Exception {
        // Given
        String name = "getHttpProxyExclusions";
        JSONObject params = new JSONObject();
        given(connectionOptions.getHttpProxyExclusions())
                .willReturn(
                        Arrays.asList(
                                newHttpProxyExclusion("example.org", true),
                                newHttpProxyExclusion("example.com", false)));
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(response.getName(), is(equalTo(name)));
        assertThat(
                response.toJSON().toString(),
                is(
                        equalTo(
                                "{\"getHttpProxyExclusions\":[{\"host\":\"example.org\",\"enabled\":true},"
                                        + "{\"host\":\"example.com\",\"enabled\":false}]}")));
    }

    @Test
    void shouldReturnOkForSetHttpProxy() throws Exception {
        // Given
        String name = "setHttpProxy";
        JSONObject params = new JSONObject();
        String host = "example.org";
        params.put("host", host);
        int port = 443;
        params.put("port", port);
        String realm = "realm";
        params.put("realm", realm);
        String username = "username";
        params.put("username", username);
        String password = "password";
        params.put("password", password);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(connectionOptions).setHttpProxy(newHttpProxy(host, port, realm, username, password));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "not an int", "-1", "0", "65536"})
    void shouldThrowApiExceptionForInvalidHttpProxyPort(String port) throws Exception {
        // Given
        String name = "setHttpProxy";
        JSONObject params = new JSONObject();
        params.put("host", "host");
        params.put("port", port);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        verifyNoInteractions(connectionOptions);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldGetIsHttpProxyAuthEnabled(boolean enabled) throws Exception {
        // Given
        String name = "isHttpProxyAuthEnabled";
        JSONObject params = new JSONObject();
        given(connectionOptions.isHttpProxyAuthEnabled()).willReturn(enabled);
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(
                response.toJSON().toString(),
                is(equalTo("{\"isHttpProxyAuthEnabled\":\"" + enabled + "\"}")));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldGetIsHttpProxyEnabled(boolean enabled) throws Exception {
        // Given
        String name = "isHttpProxyEnabled";
        JSONObject params = new JSONObject();
        given(connectionOptions.isHttpProxyEnabled()).willReturn(enabled);
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(
                response.toJSON().toString(),
                is(equalTo("{\"isHttpProxyEnabled\":\"" + enabled + "\"}")));
    }

    @ParameterizedTest
    @CsvSource({"true, true", "false, false", "invalid, false"})
    void shouldSetHttpProxyAuthEnabled(String enabled, boolean expected) throws Exception {
        // Given
        String name = "setHttpProxyAuthEnabled";
        JSONObject params = new JSONObject();
        params.put("enabled", enabled);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(connectionOptions).setHttpProxyAuthEnabled(expected);
    }

    @ParameterizedTest
    @CsvSource({"true, true", "false, false", "invalid, false"})
    void shouldSetHttpProxyEnabled(String enabled, boolean expected) throws Exception {
        // Given
        String name = "setHttpProxyEnabled";
        JSONObject params = new JSONObject();
        params.put("enabled", enabled);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(connectionOptions).setHttpProxyEnabled(expected);
    }

    @Test
    void shouldGetHttpProxy() throws Exception {
        // Given
        String name = "getHttpProxy";
        JSONObject params = new JSONObject();

        given(connectionOptions.getHttpProxy())
                .willReturn(newHttpProxy("example.com", 443, "realm", "username", "password"));
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(response.getName(), is(equalTo(name)));
        assertThat(
                response.toJSON().toString(),
                is(
                        equalTo(
                                "{\"getHttpProxy\":{\"host\":\"example.com\",\"port\":443,\"realm\":\"realm\",\"username\":\"username\",\"password\":\"password\"}}")));
    }

    @Test
    void shouldReturnOkForSetSocksProxy() throws Exception {
        // Given
        String name = "setSocksProxy";
        JSONObject params = new JSONObject();
        String host = "example.org";
        params.put("host", host);
        int port = 1080;
        params.put("port", port);
        SocksProxy.Version version = SocksProxy.Version.SOCKS4A;
        params.put("version", version.number());
        boolean useDns = true;
        params.put("useDns", useDns);
        String username = "username";
        params.put("username", username);
        String password = "password";
        params.put("password", password);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(connectionOptions)
                .setSocksProxy(newSocksProxy(host, port, version, useDns, username, password));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "not an int", "-1", "0", "65536"})
    void shouldThrowApiExceptionForInvalidSocksProxyPort(String port) throws Exception {
        // Given
        String name = "setSocksProxy";
        JSONObject params = new JSONObject();
        params.put("host", "host");
        params.put("port", port);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        verifyNoInteractions(connectionOptions);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldGetIsSocksProxyEnabled(boolean enabled) throws Exception {
        // Given
        String name = "isSocksProxyEnabled";
        JSONObject params = new JSONObject();
        given(connectionOptions.isSocksProxyEnabled()).willReturn(enabled);
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(
                response.toJSON().toString(),
                is(equalTo("{\"isSocksProxyEnabled\":\"" + enabled + "\"}")));
    }

    @Test
    void shouldGetSocksProxy() throws Exception {
        // Given
        String name = "getSocksProxy";
        JSONObject params = new JSONObject();

        given(connectionOptions.getSocksProxy())
                .willReturn(
                        newSocksProxy(
                                "example.com",
                                443,
                                SocksProxy.Version.SOCKS4A,
                                false,
                                "username",
                                "password"));
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(response.getName(), is(equalTo(name)));
        assertThat(
                response.toJSON().toString(),
                is(
                        equalTo(
                                "{\"getSocksProxy\":{\"host\":\"example.com\",\"port\":443,\"version\":\"4\",\"useDns\":false,\"username\":\"username\",\"password\":\"password\"}}")));
    }

    @Test
    void shouldReturnOkForAddedPassThrough() throws Exception {
        // Given
        String name = "addPassThrough";
        JSONObject params = new JSONObject();
        params.put("authority", "example.org");
        params.put("enabled", "false");
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(localServersOptions).addPassThrough(newPassThrough("example.org", false));
    }

    @Test
    void shouldThrowApiExceptionForInvalidAddedPassThrough() throws Exception {
        // Given
        String name = "addPassThrough";
        JSONObject params = new JSONObject();
        params.put("authority", "*");
        params.put("enabled", "true");
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
    }

    @Test
    void shouldDefaultToEnabledForAddedPassThrough() throws Exception {
        // Given
        String name = "addPassThrough";
        JSONObject params = new JSONObject();
        params.put("authority", "example.org");
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(localServersOptions).addPassThrough(newPassThrough("example.org", true));
    }

    @Test
    void shouldReturnOkForRemovedPassThrough() throws Exception {
        // Given
        String name = "removePassThrough";
        JSONObject params = new JSONObject();
        params.put("authority", "example.org");
        given(localServersOptions.removePassThrough(any())).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(localServersOptions).removePassThrough("example.org");
    }

    @Test
    void shouldThrowApiExceptionForMissingRemovedPassThrough() throws Exception {
        // Given
        String name = "removePassThrough";
        JSONObject params = new JSONObject();
        params.put("authority", "example.org");
        given(localServersOptions.removePassThrough(any())).willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.DOES_NOT_EXIST)));
        verify(localServersOptions).removePassThrough("example.org");
    }

    @Test
    void shouldReturnOkForChangedPassThrough() throws Exception {
        // Given
        String name = "setPassThroughEnabled";
        JSONObject params = new JSONObject();
        params.put("authority", "example.org");
        params.put("enabled", "false");
        given(localServersOptions.setPassThroughEnabled(any(), anyBoolean())).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(localServersOptions).setPassThroughEnabled("example.org", false);
    }

    @Test
    void shouldThrowApiExceptionForMissingChangedPassThrough() throws Exception {
        // Given
        String name = "setPassThroughEnabled";
        JSONObject params = new JSONObject();
        params.put("authority", "example.org");
        params.put("enabled", "true");
        given(localServersOptions.setPassThroughEnabled(any(), anyBoolean())).willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.DOES_NOT_EXIST)));
        verify(localServersOptions).setPassThroughEnabled("example.org", true);
    }

    @Test
    void shouldGetPassThroughs() throws Exception {
        // Given
        String name = "getPassThroughs";
        JSONObject params = new JSONObject();
        given(localServersOptions.getPassThroughs())
                .willReturn(
                        Arrays.asList(
                                newPassThrough("example.org", true),
                                newPassThrough("example.com", false)));
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(response.getName(), is(equalTo(name)));
        assertThat(
                response.toJSON().toString(),
                is(
                        equalTo(
                                "{\"getPassThroughs\":[{\"authority\":\"example.org\",\"enabled\":true},"
                                        + "{\"authority\":\"example.com\",\"enabled\":false}]}")));
    }

    @Test
    void shouldReturnOkForAddedLocalServer() throws Exception {
        // Given
        String name = "addLocalServer";
        JSONObject params = new JSONObject();
        params.put("address", "localhost");
        int port = getRandomPort();
        params.put("port", port);
        given(localServersOptions.getMainProxy()).willReturn(newLocalServer("localhost", 8080));
        given(localServersOptions.getServers()).willReturn(Collections.emptyList());
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(localServersOptions).addServer(newLocalServer("localhost", port));
    }

    @Test
    void shouldThrowApiExceptionIfDuplicatedWithMainProxyForAddedLocalServer() throws Exception {
        // Given
        String name = "addLocalServer";
        JSONObject params = new JSONObject();
        params.put("address", "localhost");
        params.put("port", "8080");
        given(localServersOptions.getMainProxy()).willReturn(newLocalServer("localhost", 8080));
        given(localServersOptions.getServers()).willReturn(Collections.emptyList());
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        assertThat(exception.toString(true), containsString("already defined"));
    }

    @Test
    void shouldThrowApiExceptionIfDuplicatedWithOtherLocalServerForAddedLocalServer()
            throws Exception {
        // Given
        String name = "addLocalServer";
        JSONObject params = new JSONObject();
        params.put("address", "localhost");
        params.put("port", "8080");
        given(localServersOptions.getMainProxy()).willReturn(newLocalServer("localhost", 8081));
        given(localServersOptions.getServers())
                .willReturn(Arrays.asList(newLocalServer("localhost", 8080)));
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        assertThat(exception.toString(true), containsString("already defined"));
    }

    @Test
    void shouldThrowApiExceptionIfUnableToListenForAddedLocalServer() throws Exception {
        // Given
        String name = "addLocalServer";
        JSONObject params = new JSONObject();
        params.put("address", "localhost");
        params.put("port", "80");
        given(localServersOptions.getMainProxy()).willReturn(newLocalServer("localhost", 8080));
        given(localServersOptions.getServers())
                .willReturn(Arrays.asList(newLocalServer("localhost", 8081)));
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        assertThat(exception.toString(true), containsString("listen on"));
    }

    @Test
    void shouldThrowApiExceptionIfInvalidPortForAddedLocalServer() throws Exception {
        // Given
        String name = "addLocalServer";
        JSONObject params = new JSONObject();
        params.put("address", "localhost");
        params.put("port", "808080808");
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        assertThat(exception.toString(true), containsString("port"));
    }

    @Test
    void shouldUseOptionalParamsForAddedLocalServer() throws Exception {
        // Given
        String name = "addLocalServer";
        JSONObject params = new JSONObject();
        params.put("address", "localhost");
        int port = getRandomPort();
        params.put("port", port);
        params.put("proxy", "true");
        params.put("api", "false");
        params.put("behindNat", "true");
        params.put("removeAcceptEncoding", "false");
        params.put("decodeResponse", "false");
        LocalServerConfig server = newLocalServer("localhost", port);
        server.setMode(ServerMode.PROXY);
        server.setBehindNat(true);
        server.setRemoveAcceptEncoding(false);
        server.setDecodeResponse(false);
        given(localServersOptions.getMainProxy()).willReturn(newLocalServer("localhost", 8080));
        given(localServersOptions.getServers()).willReturn(Collections.emptyList());
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(localServersOptions).addServer(server);
    }

    @Test
    void shouldReturnOkForRemovedLocalServer() throws Exception {
        // Given
        String name = "removeLocalServer";
        JSONObject params = new JSONObject();
        params.put("address", "localhost");
        params.put("port", "8080");
        given(localServersOptions.removeServer(any(), anyInt())).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(localServersOptions).removeServer("localhost", 8080);
    }

    @Test
    void shouldThrowApiExceptionForMissingRemovedLocalServer() throws Exception {
        // Given
        String name = "removeLocalServer";
        JSONObject params = new JSONObject();
        params.put("address", "localhost");
        params.put("port", "8080");
        given(localServersOptions.removeServer(any(), anyInt())).willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.DOES_NOT_EXIST)));
        verify(localServersOptions).removeServer("localhost", 8080);
    }

    @Test
    void shouldGetLocalServers() throws Exception {
        // Given
        String name = "getLocalServers";
        JSONObject params = new JSONObject();
        given(localServersOptions.getServers())
                .willReturn(
                        Arrays.asList(
                                newLocalServer("localhost", 8080),
                                newLocalServer("192.168.0.1", 8081)));
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(response.getName(), is(equalTo(name)));
        assertThat(
                response.toJSON().toString(),
                is(
                        equalTo(
                                "{\"getLocalServers\":[{\"proxy\":true,\"address\":\"localhost\",\"port\":8080,\"api\":true,\"behindNat\":false,\"removeAcceptEncoding\":true,\"decodeResponse\":true,\"enabled\":true},"
                                        + "{\"proxy\":true,\"address\":\"192.168.0.1\",\"port\":8081,\"api\":true,\"behindNat\":false,\"removeAcceptEncoding\":true,\"decodeResponse\":true,\"enabled\":true}]}")));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0, 123})
    void shouldSetConnectionTimeout(int timeout) throws Exception {
        // Given
        String name = "setConnectionTimeout";
        JSONObject params = new JSONObject();
        params.put("timeout", timeout);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(connectionOptions).setTimeoutInSecs(timeout);
    }

    @Test
    void shouldThrowApiExceptionForInvalidConnectionTimeout() throws Exception {
        // Given
        String name = "setConnectionTimeout";
        JSONObject params = new JSONObject();
        params.put("timeout", "a");
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        verifyNoInteractions(connectionOptions);
    }

    @Test
    void shouldGetConnectionTimeout() throws Exception {
        // Given
        String name = "getConnectionTimeout";
        JSONObject params = new JSONObject();
        given(connectionOptions.getTimeoutInSecs()).willReturn(123);
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(response.getName(), is(equalTo(name)));
        assertThat(response.toJSON().toString(), is(equalTo("{\"getConnectionTimeout\":\"123\"}")));
    }

    @Test
    void shouldSetDefaultUserAgent() throws Exception {
        // Given
        String name = "setDefaultUserAgent";
        JSONObject params = new JSONObject();
        String userAgent = "User-Agent";
        params.put("userAgent", userAgent);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(connectionOptions).setDefaultUserAgent(userAgent);
    }

    @Test
    void shouldGetDefaultUserAgent() throws Exception {
        // Given
        String name = "getDefaultUserAgent";
        JSONObject params = new JSONObject();
        given(connectionOptions.getDefaultUserAgent()).willReturn("User-Agent");
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(response.getName(), is(equalTo(name)));
        assertThat(
                response.toJSON().toString(),
                is(equalTo("{\"getDefaultUserAgent\":\"User-Agent\"}")));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0, 1})
    void shouldSetDnsTtlSuccessfulQueries(int ttl) throws Exception {
        // Given
        String name = "setDnsTtlSuccessfulQueries";
        JSONObject params = new JSONObject();
        params.put("ttl", ttl);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(connectionOptions).setDnsTtlSuccessfulQueries(ttl);
    }

    @Test
    void shouldThrowApiExceptionForInvalidDnsTtlSuccessfulQueries() throws Exception {
        // Given
        String name = "setDnsTtlSuccessfulQueries";
        JSONObject params = new JSONObject();
        params.put("ttl", "a");
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        verifyNoInteractions(connectionOptions);
    }

    @Test
    void shouldGetDnsTtlSuccessfulQueries() throws Exception {
        // Given
        String name = "getDnsTtlSuccessfulQueries";
        JSONObject params = new JSONObject();
        given(connectionOptions.getDnsTtlSuccessfulQueries()).willReturn(123);
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(response.getName(), is(equalTo(name)));
        assertThat(
                response.toJSON().toString(),
                is(equalTo("{\"getDnsTtlSuccessfulQueries\":\"123\"}")));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetUseGlobalHttpState(boolean use) throws Exception {
        // Given
        String name = "setUseGlobalHttpState";
        JSONObject params = new JSONObject();
        params.put("use", use);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(connectionOptions).setUseGlobalHttpState(use);
    }

    @Test
    void shouldGetIsUseGlobalHttpState() throws Exception {
        // Given
        String name = "isUseGlobalHttpState";
        JSONObject params = new JSONObject();
        given(connectionOptions.isUseGlobalHttpState()).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(response.getName(), is(equalTo(name)));
        assertThat(
                response.toJSON().toString(), is(equalTo("{\"isUseGlobalHttpState\":\"true\"}")));
    }

    @Test
    void shouldAddPkcs12ClientCertificate() throws Exception {
        // Given
        String name = "addPkcs12ClientCertificate";
        JSONObject params = new JSONObject();
        String file = "/path/to/file";
        params.put("filePath", file);
        String password = "password";
        params.put("password", password);
        int index = 1234;
        params.put("index", index);
        given(clientCertificatesOptions.addPkcs12Certificate()).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(clientCertificatesOptions).setPkcs12File(file);
        verify(clientCertificatesOptions).setPkcs12Password(password);
        verify(clientCertificatesOptions).setPkcs12Index(index);
        verify(clientCertificatesOptions).addPkcs12Certificate();
        verify(clientCertificatesOptions).setUseCertificate(true);
    }

    @Test
    void shouldThrowApiExceptionIfNotAbleToAddPkcs12ClientCertificate() throws Exception {
        // Given
        String name = "addPkcs12ClientCertificate";
        JSONObject params = new JSONObject();
        String file = "/path/to/file";
        params.put("filePath", file);
        String password = "password";
        params.put("password", password);
        int index = 1234;
        params.put("index", index);
        given(clientCertificatesOptions.addPkcs12Certificate()).willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_EXTERNAL_DATA)));
        verify(clientCertificatesOptions).setPkcs12File(file);
        verify(clientCertificatesOptions).setPkcs12Password(password);
        verify(clientCertificatesOptions).setPkcs12Index(index);
        verify(clientCertificatesOptions).addPkcs12Certificate();
        verify(clientCertificatesOptions, times(0)).setUseCertificate(true);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetUseClientCertificate(boolean use) throws Exception {
        // Given
        String name = "setUseClientCertificate";
        JSONObject params = new JSONObject();
        params.put("use", use);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(clientCertificatesOptions).setUseCertificate(use);
    }

    @Test
    void shouldHaveDescriptionsForAllApiElements() {
        networkApi = new NetworkApi(extensionNetwork);
        List<String> missingKeys = new ArrayList<>();
        checkKey(networkApi.getDescriptionKey(), missingKeys);
        checkApiElements(
                networkApi, networkApi.getApiActions(), API.RequestType.action, missingKeys);
        checkApiElements(networkApi, networkApi.getApiOthers(), API.RequestType.other, missingKeys);
        checkApiElements(networkApi, networkApi.getApiViews(), API.RequestType.view, missingKeys);
        assertThat(missingKeys, is(empty()));
    }

    @Test
    void shouldReturnOkForAddedRateLimitRule() throws Exception {
        // Given
        String name = "addRateLimitRule";
        JSONObject params = new JSONObject();
        params.put("description", "limit example.org");
        params.put("matchString", "example.org");
        params.put("enabled", "false");
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(rateLimitOptions)
                .addRule(new RateLimitRule("limit example.org", "example.org", false));
    }

    @Test
    // Should not happen as it's mandatory but test expected behaviour anyway.
    void shouldAcceptEmptyGroupByForRateLimitRule() throws Exception {
        // Given
        String name = "addRateLimitRule";
        JSONObject params = new JSONObject();
        params.put("description", "limit example.org");
        params.put("matchString", "example.org");
        params.put("enabled", "false");
        params.put("groupBy", "");
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(rateLimitOptions)
                .addRule(
                        new RateLimitRule(
                                "limit example.org",
                                "example.org",
                                false,
                                1,
                                RateLimitRule.GroupBy.RULE,
                                false));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "rule", "Rule", "RULE", "host", "Host", "HOST",
            })
    void shouldAcceptGroupByInAnyCaseForRateLimitRule(String groupBy) throws Exception {
        // Given
        String name = "addRateLimitRule";
        JSONObject params = new JSONObject();
        params.put("description", "limit example.org");
        params.put("matchString", "example.org");
        params.put("enabled", "false");
        params.put("groupBy", groupBy);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(rateLimitOptions)
                .addRule(
                        new RateLimitRule(
                                "limit example.org",
                                "example.org",
                                false,
                                1,
                                toGroupByEnum(groupBy),
                                false));
    }

    private static RateLimitRule.GroupBy toGroupByEnum(String groupBy) {
        return RateLimitRule.GroupBy.valueOf(groupBy.toUpperCase(Locale.ROOT));
    }

    @Test
    void shouldRejectInvalidGroupByForRateLimitRule() throws Exception {
        // Given
        String name = "addRateLimitRule";
        JSONObject params = new JSONObject();
        params.put("description", "limit example.org");
        params.put("matchString", "example.org");
        params.put("enabled", "false");
        params.put("groupBy", "Not_GroupBy_");
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        assertThat(exception.getMessage(), containsString("groupBy"));
        verify(rateLimitOptions, times(0)).addRule(any());
    }

    @Test
    void shouldDefaultToEnabledForAddedRateLimitRule() throws Exception {
        // Given
        String name = "addRateLimitRule";
        JSONObject params = new JSONObject();
        params.put("description", "limit example.org");
        params.put("matchString", "example.org");
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(rateLimitOptions)
                .addRule(new RateLimitRule("limit example.org", "example.org", true));
    }

    @Test
    void shouldReturnOkForRemovedRateLimitRule() throws Exception {
        // Given
        String name = "removeRateLimitRule";
        JSONObject params = new JSONObject();
        params.put("description", "example.org");
        given(rateLimitOptions.removeRule(any())).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(rateLimitOptions).removeRule("example.org");
    }

    @Test
    void shouldThrowApiExceptionForMissingRemovedRateLimitRule() throws Exception {
        // Given
        String name = "removeRateLimitRule";
        JSONObject params = new JSONObject();
        params.put("description", "example.org");
        given(rateLimitOptions.removeRule(any())).willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.DOES_NOT_EXIST)));
        verify(rateLimitOptions).removeRule("example.org");
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldReturnOkForChangedRateLimitRule(boolean enabled) throws Exception {
        // Given
        String name = "setRateLimitRuleEnabled";
        JSONObject params = new JSONObject();
        params.put("description", "example.org");
        params.put("enabled", enabled);
        given(rateLimitOptions.setEnabled(any(), anyBoolean())).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(rateLimitOptions).setEnabled("example.org", enabled);
    }

    @Test
    void shouldThrowApiExceptionForMissingChangedRateLimitRule() throws Exception {
        // Given
        String name = "setRateLimitRuleEnabled";
        JSONObject params = new JSONObject();
        params.put("description", "example.org");
        params.put("enabled", "true");
        given(rateLimitOptions.setEnabled(any(), anyBoolean())).willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.DOES_NOT_EXIST)));
        verify(rateLimitOptions).setEnabled("example.org", true);
    }

    @Test
    void shouldGetRateLimitRules() throws Exception {
        // Given
        String name = "getRateLimitRules";
        JSONObject params = new JSONObject();
        given(rateLimitOptions.getRules())
                .willReturn(
                        Arrays.asList(
                                new RateLimitRule("limit example.org", "example.org", true),
                                new RateLimitRule("limit example.com", "example.com", false)));
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(response.getName(), is(equalTo(name)));
        assertThat(
                response.toJSON().toString(),
                is(
                        equalTo(
                                "{\"getRateLimitRules\":[{\"description\":\"limit example.org\",\"matchString\":\"example.org\",\"requestsPerSecond\":1,\"groupBy\":\"RULE\",\"matchRegex\":false,\"enabled\":true},{\"description\":\"limit example.com\",\"matchString\":\"example.com\",\"requestsPerSecond\":1,\"groupBy\":\"RULE\",\"matchRegex\":false,\"enabled\":false}]}")));
    }

    private static void checkApiElements(
            ApiImplementor api,
            List<? extends ApiElement> elements,
            RequestType type,
            List<String> missingKeys) {
        elements.sort((a, b) -> a.getName().compareTo(b.getName()));
        for (ApiElement element : elements) {
            assertThat(
                    "API element: " + api.getPrefix() + "/" + element.getName(),
                    element.getDescriptionTag(),
                    is(not(emptyString())));
            checkKey(element.getDescriptionTag(), missingKeys);
            element.getParameters().stream()
                    .map(ApiParameter::getDescriptionKey)
                    .forEach(key -> checkKey(key, missingKeys));
        }
    }

    private static void checkKey(String key, List<String> missingKeys) {
        if (!Constant.messages.containsKey(key)) {
            missingKeys.add(key);
        }
    }

    private static PassThrough newPassThrough(String authority, boolean enabled) {
        return new PassThrough(Pattern.compile(authority), enabled);
    }

    private static HttpProxy newHttpProxy(
            String host, int port, String realm, String username, String password) {
        return new HttpProxy(
                host, port, realm, new PasswordAuthentication(username, password.toCharArray()));
    }

    private static SocksProxy newSocksProxy(
            String host,
            int port,
            SocksProxy.Version version,
            boolean useDns,
            String username,
            String password) {
        return new SocksProxy(
                host,
                port,
                version,
                useDns,
                new PasswordAuthentication(username, password.toCharArray()));
    }

    private static HttpProxyExclusion newHttpProxyExclusion(String pattern, boolean enabled) {
        return new HttpProxyExclusion(Pattern.compile(pattern), enabled);
    }

    private static LocalServerConfig newLocalServer(String address, int port) {
        LocalServerConfig server = new LocalServerConfig();
        server.setAddress(address);
        server.setPort(port);
        return server;
    }
}
