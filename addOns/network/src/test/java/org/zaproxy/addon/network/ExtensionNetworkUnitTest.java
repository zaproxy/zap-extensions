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
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.dynssl.DynSSLParam;
import org.zaproxy.zap.extension.dynssl.ExtensionDynSSL;
import org.zaproxy.zap.extension.dynssl.SslCertificateUtils;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ExtensionNetwork}. */
class ExtensionNetworkUnitTest extends TestUtils {

    private Model model;
    private OptionsParam optionsParam;
    private ExtensionLoader extensionLoader;
    private ExtensionNetwork extension;

    @BeforeEach
    void setUp() {
        extension = new ExtensionNetwork();
        mockMessages(extension);
        model = mock(Model.class, withSettings().lenient());
        Model.setSingletonForTesting(model);
        optionsParam = mock(OptionsParam.class, withSettings().lenient());
        given(model.getOptionsParam()).willReturn(optionsParam);

        extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        Control.initSingletonForTesting(model, extensionLoader);
    }

    @Test
    void shouldHaveName() {
        assertThat(extension.getName(), is(equalTo("ExtensionNetwork")));
    }

    @Test
    void shouldHaveUiName() {
        assertThat(extension.getUIName(), is(not(emptyString())));
    }

    @Test
    void shouldHaveDescription() {
        assertThat(extension.getDescription(), is(not(emptyString())));
    }

    @Test
    void shouldAddNetworkApiOnHook() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        // When
        extension.hook(extensionHook);
        // Then
        ArgumentCaptor<ApiImplementor> argument = ArgumentCaptor.forClass(ApiImplementor.class);
        verify(extensionHook).addApiImplementor(argument.capture());
        assertThat(argument.getAllValues(), contains(instanceOf(NetworkApi.class)));
    }

    @Test
    void shouldBeUnloadable() {
        assertThat(extension.canUnload(), is(true));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"db1", "db2"})
    void shouldSupportAllDbs(String name) {
        assertThat(extension.supportsDb(name), is(true));
    }

    @Test
    void shouldWriteRootCaCertAsPem() throws Exception {
        // Given
        Path file = Files.createTempFile("rootca", ".cer");
        mockRootCaKeyStore();
        // When
        extension.writeRootCaCertAsPem(file);
        // Then
        String contents = new String(Files.readAllBytes(file), StandardCharsets.US_ASCII);
        assertThat(
                contents,
                allOf(
                        containsString(SslCertificateUtils.BEGIN_CERTIFICATE_TOKEN),
                        containsString(
                                "MIIC9TCCAl6gAwIBAgIJANL8E4epRNznMA0GCSqGSIb3DQEBBQUAMFsxGDAWBgNV\n"),
                        containsString(SslCertificateUtils.END_CERTIFICATE_TOKEN),
                        not(containsString(SslCertificateUtils.BEGIN_PRIVATE_KEY_TOKEN))));
    }

    @Test
    void shouldNotWriteRootCaCertAsPemIfRootCaKeyStoreMissing() throws Exception {
        // Given
        Path file = Files.createTempFile("rootca", ".cer");
        // When
        extension.writeRootCaCertAsPem(file);
        // Then
        String contents = new String(Files.readAllBytes(file), StandardCharsets.US_ASCII);
        assertThat(contents, not(containsString(SslCertificateUtils.BEGIN_CERTIFICATE_TOKEN)));
    }

    @Test
    void shouldGetRootCaKeyStoreFromDynSslParam() throws Exception {
        // Given
        mockRootCaKeyStore();
        // When
        KeyStore keyStore = extension.getRootCaKeyStore();
        // Then
        assertThat(keyStore, is(not(nullValue())));
    }

    @Test
    void shouldNotGetRootCaKeyStoreFromDynSslParamIfNotAvailable() throws Exception {
        // Given / When
        KeyStore keyStore = extension.getRootCaKeyStore();
        // Then
        assertThat(keyStore, is(nullValue()));
    }

    @Test
    void shouldGenerateRootCaCertWithExtensionDynSsl() throws Exception {
        // Given
        ExtensionDynSSL extensionDynSsl = mock(ExtensionDynSSL.class);
        given(extensionLoader.getExtension(ExtensionDynSSL.class)).willReturn(extensionDynSsl);
        // When
        boolean generated = extension.generateRootCaCert();
        // Then
        assertThat(generated, is(equalTo(true)));
        verify(extensionDynSsl).createNewRootCa();
    }

    @Test
    void shouldNotGenerateRootCaCertWithExtensionDynSslIfNotAvailable() throws Exception {
        // Given
        given(extensionLoader.getExtension(ExtensionDynSSL.class)).willReturn(null);
        // When
        boolean generated = extension.generateRootCaCert();
        // Then
        assertThat(generated, is(equalTo(false)));
    }

    @Test
    void shouldImportRootCaCertWithExtensionDynSsl() throws Exception {
        // Given
        Path file = Files.createTempFile("rootca", ".cer");
        ExtensionDynSSL extensionDynSsl = mock(ExtensionDynSSL.class);
        given(extensionLoader.getExtension(ExtensionDynSSL.class)).willReturn(extensionDynSsl);
        // When
        String result = extension.importRootCaCert(file);
        // Then
        assertThat(result, is(nullValue()));
        verify(extensionDynSsl).importRootCaCertificate(file.toFile());
    }

    @Test
    void shouldNotImportRootCaCertWithExtensionDynSslIfNotAvailable() throws Exception {
        // Given
        Path file = Files.createTempFile("rootca", ".cer");
        given(extensionLoader.getExtension(ExtensionDynSSL.class)).willReturn(null);
        // When
        String result = extension.importRootCaCert(file);
        // Then
        assertThat(result, is(equalTo("")));
    }

    private void mockRootCaKeyStore() throws Exception {
        KeyStore keyStore =
                SslCertificateUtils.string2Keystore(NetworkTestUtils.FISH_CERT_BASE64_STR);
        DynSSLParam dynSslParam = mock(DynSSLParam.class);
        given(optionsParam.getParamSet(DynSSLParam.class)).willReturn(dynSslParam);
        given(dynSslParam.getRootca()).willReturn(keyStore);
    }
}
