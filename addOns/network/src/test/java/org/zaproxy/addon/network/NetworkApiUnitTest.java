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
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.API.RequestType;
import org.zaproxy.zap.extension.api.ApiElement;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiParameter;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.dynssl.SslCertificateUtils;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link NetworkApi}. */
class NetworkApiUnitTest extends TestUtils {

    private NetworkApi networkApi;
    private ExtensionNetwork extensionNetwork;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionNetwork());
        extensionNetwork = mock(ExtensionNetwork.class);
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
                SslCertificateUtils.string2Keystore(NetworkTestUtils.FISH_CERT_BASE64_STR);
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
                        containsString(SslCertificateUtils.BEGIN_CERTIFICATE_TOKEN),
                        containsString(
                                "MIIC9TCCAl6gAwIBAgIJANL8E4epRNznMA0GCSqGSIb3DQEBBQUAMFsxGDAWBgNV\n"),
                        containsString(SslCertificateUtils.END_CERTIFICATE_TOKEN),
                        not(containsString(SslCertificateUtils.BEGIN_PRIVATE_KEY_TOKEN))));
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
    void shouldHaveDescriptionsForAllApiElements() {
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
}
