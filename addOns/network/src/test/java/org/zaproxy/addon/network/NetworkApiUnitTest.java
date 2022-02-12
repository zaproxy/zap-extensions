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
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyBoolean;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.internal.cert.CertificateUtils;
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
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link NetworkApi}. */
class NetworkApiUnitTest extends TestUtils {

    private NetworkApi networkApi;
    private ServerCertificatesOptions serverCertificatesOptions;
    private LocalServersOptions localServersOptions;
    private ExtensionNetwork extensionNetwork;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionNetwork());
        extensionNetwork = mock(ExtensionNetwork.class, withSettings().lenient());
        serverCertificatesOptions = mock(ServerCertificatesOptions.class, withSettings().lenient());
        given(extensionNetwork.getServerCertificatesOptions())
                .willReturn(serverCertificatesOptions);
        localServersOptions = mock(LocalServersOptions.class, withSettings().lenient());
        given(extensionNetwork.getLocalServersOptions()).willReturn(localServersOptions);
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
        // Given
        given(extensionNetwork.isHandleServerCerts()).willReturn(false);
        // When
        networkApi = new NetworkApi(extensionNetwork);
        // Then
        assertThat(networkApi.getApiActions(), hasSize(2));
        assertThat(networkApi.getApiViews(), hasSize(0));
        assertThat(networkApi.getApiOthers(), hasSize(1));
    }

    @Test
    void shouldAddAdditionalApiElementsWhenHandlingServerCerts() {
        // Given
        given(extensionNetwork.isHandleServerCerts()).willReturn(true);
        // When
        networkApi = new NetworkApi(extensionNetwork);
        // Then
        assertThat(networkApi.getApiActions(), hasSize(4));
        assertThat(networkApi.getApiViews(), hasSize(2));
        assertThat(networkApi.getApiOthers(), hasSize(1));
    }

    @Test
    void shouldAddAdditionalApiElementsWhenHandlingLocalServers() {
        // Given
        given(extensionNetwork.isHandleServerCerts()).willReturn(true);
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
        // When
        networkApi = new NetworkApi(extensionNetwork);
        // Then
        assertThat(networkApi.getApiActions(), hasSize(12));
        assertThat(networkApi.getApiViews(), hasSize(5));
        assertThat(networkApi.getApiOthers(), hasSize(1));
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
        given(extensionNetwork.isHandleServerCerts()).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(serverCertificatesOptions).setRootCaCertValidity(Duration.ofDays(123));
    }

    @Test
    void shouldThrowApiExceptionWhenSettingRootCaCertValidityIfNotHandlingServerCerts()
            throws Exception {
        // Given
        String name = "setRootCaCertValidity";
        JSONObject params = new JSONObject();
        params.put("validity", 123);
        given(extensionNetwork.isHandleServerCerts()).willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_ACTION)));
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
        given(extensionNetwork.isHandleServerCerts()).willReturn(true);
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
        given(extensionNetwork.isHandleServerCerts()).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(serverCertificatesOptions).setServerCertValidity(Duration.ofDays(123));
    }

    @Test
    void shouldThrowApiExceptionWhenSettingServerCertValidityIfNotHandlingServerCerts()
            throws Exception {
        // Given
        String name = "setServerCertValidity";
        JSONObject params = new JSONObject();
        params.put("validity", 123);
        given(extensionNetwork.isHandleServerCerts()).willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_ACTION)));
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
        given(extensionNetwork.isHandleServerCerts()).willReturn(true);
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
        given(extensionNetwork.isHandleServerCerts()).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(response.getName(), is(equalTo(name)));
        assertThat(response, is(instanceOf(ApiResponseElement.class)));
        assertThat(((ApiResponseElement) response).getValue(), is(equalTo("123")));
    }

    @Test
    void shouldThrowApiExceptionWhenGettingRootCaCertValidityIfNotHandlingServerCerts()
            throws Exception {
        // Given
        String name = "getRootCaCertValidity";
        JSONObject params = new JSONObject();
        given(serverCertificatesOptions.getRootCaCertValidity()).willReturn(Duration.ofDays(123));
        given(extensionNetwork.isHandleServerCerts()).willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiView(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_VIEW)));
    }

    @Test
    void shouldReturnServerCertValidityIfHandlingServerCerts() throws Exception {
        // Given
        String name = "getServerCertValidity";
        JSONObject params = new JSONObject();
        given(serverCertificatesOptions.getServerCertValidity()).willReturn(Duration.ofDays(123));
        given(extensionNetwork.isHandleServerCerts()).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiView(name, params);
        // Then
        assertThat(response.getName(), is(equalTo(name)));
        assertThat(response, is(instanceOf(ApiResponseElement.class)));
        assertThat(((ApiResponseElement) response).getValue(), is(equalTo("123")));
    }

    @Test
    void shouldThrowApiExceptionWhenGettingServerCertValidityIfNotHandlingServerCerts()
            throws Exception {
        // Given
        String name = "getServerCertValidity";
        JSONObject params = new JSONObject();
        given(serverCertificatesOptions.getServerCertValidity()).willReturn(Duration.ofDays(123));
        given(extensionNetwork.isHandleServerCerts()).willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiView(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_VIEW)));
    }

    @Test
    void shouldReturnOkForAddedAlias() throws Exception {
        // Given
        String name = "addAlias";
        JSONObject params = new JSONObject();
        params.put("name", "example.org");
        params.put("enabled", "false");
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
        given(localServersOptions.removeAlias(any())).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(localServersOptions).removeAlias("example.org");
    }

    @Test
    void shouldhrowApiExceptionForMissingRemovedAlias() throws Exception {
        // Given
        String name = "removeAlias";
        JSONObject params = new JSONObject();
        params.put("name", "example.org");
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
    void shouldReturnOkForAddedPassThrough() throws Exception {
        // Given
        String name = "addPassThrough";
        JSONObject params = new JSONObject();
        params.put("authority", "example.org");
        params.put("enabled", "false");
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
        given(localServersOptions.removePassThrough(any())).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(localServersOptions).removePassThrough("example.org");
    }

    @Test
    void shouldhrowApiExceptionForMissingRemovedPassThrough() throws Exception {
        // Given
        String name = "removePassThrough";
        JSONObject params = new JSONObject();
        params.put("authority", "example.org");
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
                                "{\"getPassThroughs\":[{\"name\":\"example.org\",\"enabled\":true},"
                                        + "{\"name\":\"example.com\",\"enabled\":false}]}")));
    }

    @Test
    void shouldReturnOkForAddedLocalServer() throws Exception {
        // Given
        String name = "addLocalServer";
        JSONObject params = new JSONObject();
        params.put("address", "localhost");
        int port = getRandomPort();
        params.put("port", port);
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
        given(localServersOptions.removeServer(any(), anyInt())).willReturn(true);
        // When
        ApiResponse response = networkApi.handleApiAction(name, params);
        // Then
        assertThat(response, is(equalTo(ApiResponseElement.OK)));
        verify(localServersOptions).removeServer("localhost", 8080);
    }

    @Test
    void shouldhrowApiExceptionForMissingRemovedLocalServer() throws Exception {
        // Given
        String name = "removeLocalServer";
        JSONObject params = new JSONObject();
        params.put("address", "localhost");
        params.put("port", "8080");
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
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
    @ValueSource(
            strings = {
                "addAlias",
                "removeAlias",
                "setAliasEnabled",
                "addPassThrough",
                "removePassThrough",
                "setPassThroughEnabled",
                "addLocalServer",
                "removeLocalServer"
            })
    void shouldThrowApiExceptionForUnsupportedActionsIfNotHandlingLocalServers(String name)
            throws Exception {
        // Given
        JSONObject params = new JSONObject();
        given(extensionNetwork.isHandleLocalServers()).willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_ACTION)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"getAliases", "getPassThroughs", "getLocalServers"})
    void shouldThrowApiExceptionForUnsupportedViewsIfNotHandlingLocalServers(String name)
            throws Exception {
        // Given
        JSONObject params = new JSONObject();
        given(extensionNetwork.isHandleLocalServers()).willReturn(false);
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> networkApi.handleApiView(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_VIEW)));
    }

    @Test
    void shouldHaveDescriptionsForAllApiElements() {
        given(extensionNetwork.isHandleServerCerts()).willReturn(true);
        given(extensionNetwork.isHandleLocalServers()).willReturn(true);
        networkApi = new NetworkApi(extensionNetwork);
        List<String> missingKeys = new ArrayList<>();
        checkKey(networkApi.getDescriptionKey(), missingKeys);
        checkApiElements(
                networkApi, networkApi.getApiActions(), API.RequestType.action, missingKeys);
        checkApiElements(networkApi, networkApi.getApiOthers(), API.RequestType.other, missingKeys);
        checkApiElements(networkApi, networkApi.getApiViews(), API.RequestType.view, missingKeys);
        assertThat(missingKeys, is(empty()));
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

    private static LocalServerConfig newLocalServer(String address, int port) {
        LocalServerConfig server = new LocalServerConfig();
        server.setAddress(address);
        server.setPort(port);
        return server;
    }
}
