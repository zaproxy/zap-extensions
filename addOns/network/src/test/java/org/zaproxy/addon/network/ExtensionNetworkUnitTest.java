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
import static org.hamcrest.Matchers.arrayWithSize;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import io.netty.channel.Channel;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyStore;
import java.security.Security;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.parosproxy.paros.common.AbstractParam;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.proxy.ProxyServer;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.security.CertData;
import org.parosproxy.paros.security.SslCertificateService;
import org.zaproxy.addon.network.ExtensionNetwork.SslCertificateServiceImpl;
import org.zaproxy.addon.network.internal.cert.CertConfig;
import org.zaproxy.addon.network.internal.cert.CertificateUtils;
import org.zaproxy.addon.network.internal.codec.HttpClientCodec;
import org.zaproxy.addon.network.internal.server.http.handlers.LegacyProxyListenerHandler;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.addon.network.testutils.TestClient;
import org.zaproxy.addon.network.testutils.TextTestClient;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.dynssl.DynSSLParam;
import org.zaproxy.zap.extension.dynssl.ExtensionDynSSL;
import org.zaproxy.zap.extension.dynssl.SslCertificateUtils;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link ExtensionNetwork}. */
class ExtensionNetworkUnitTest extends TestUtils {

    private MockedStatic<ZAP> zap;
    private Consumer<SslCertificateService> setSslCertificateService;
    private Model model;
    private OptionsParam optionsParam;
    private ExtensionLoader extensionLoader;
    private ExtensionNetwork extension;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        extension = new ExtensionNetwork();
        extension.init();
        mockMessages(extension);
        setSslCertificateService = mock(Consumer.class);
        extension.setSslCertificateService = setSslCertificateService;
        model = mock(Model.class, withSettings().lenient());
        Model.setSingletonForTesting(model);
        optionsParam = mock(OptionsParam.class, withSettings().lenient());
        given(model.getOptionsParam()).willReturn(optionsParam);

        extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        Control.initSingletonForTesting(model, extensionLoader);

        zap = mockStatic(ZAP.class);
        zap.when(ZAP::getProcessType).thenReturn(ZAP.ProcessType.daemon);
    }

    private void extensionStarted() {
        extension.hook(mock(ExtensionHook.class));
        extension.getServerCertificatesOptions().load(new ZapXmlConfiguration());
        extension.start();
    }

    @AfterEach
    void cleanUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Configurator.reconfigure(getClass().getResource("/log4j2-test.properties").toURI());
        zap.close();
        extension.stop();
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
    void shouldCreateLegacyCertServiceOnInit() {
        // Given / When
        extension.init();
        // Then
        assertThat(extension.getSslCertificateService(), is(notNullValue()));
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
    void shouldAddLegacyProxiesApiOnHookIfHandlingLocalServers() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.handleServerCerts = true;
        extension.handleLocalServers = true;
        // When
        extension.hook(extensionHook);
        // Then
        ArgumentCaptor<LegacyProxiesApi> argument = ArgumentCaptor.forClass(LegacyProxiesApi.class);
        verify(extensionHook, times(2)).addApiImplementor(argument.capture());
        assertThat(argument.getAllValues(), hasItem(instanceOf(LegacyProxiesApi.class)));
    }

    @Test
    void shouldNotAddServerCertificatesOptionsOnHookIfNotHandlingServerCerts() throws Exception {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.handleServerCerts = false;
        // When
        extension.hook(extensionHook);
        // Then
        verify(extensionHook, times(0)).addOptionsParamSet(any());
        assertThat(extension.getServerCertificatesOptions(), is(nullValue()));
    }

    @Test
    void shouldAddServerCertificatesOptionsOnHookIfHandlingServerCerts() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.handleServerCerts = true;
        // When
        extension.hook(extensionHook);
        // Then
        ArgumentCaptor<AbstractParam> argument = ArgumentCaptor.forClass(AbstractParam.class);
        verify(extensionHook).addOptionsParamSet(argument.capture());
        assertThat(argument.getAllValues(), contains(instanceOf(ServerCertificatesOptions.class)));
        assertThat(
                extension.getServerCertificatesOptions(),
                is(equalTo(argument.getAllValues().get(0))));
    }

    @Test
    void shouldNotAddCommandLineArgsOnHookIfNotHandlingServerCerts() throws Exception {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.handleServerCerts = false;
        // When
        extension.hook(extensionHook);
        // Then
        verify(extensionHook, times(0)).addCommandLine(any());
        assertThat(extension.getServerCertificatesOptions(), is(nullValue()));
    }

    @Test
    void shouldAddCommandLineArgsOnHookIfHandlingServerCerts() throws Exception {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.handleServerCerts = true;
        // When
        extension.hook(extensionHook);
        // Then
        ArgumentCaptor<CommandLineArgument[]> argument =
                ArgumentCaptor.forClass(CommandLineArgument[].class);
        verify(extensionHook).addCommandLine(argument.capture());
        CommandLineArgument[] args = argument.getAllValues().get(0);
        assertThat(args, arrayWithSize(3));
        assertThat(args[0].getName(), is(equalTo("-certload")));
        assertThat(args[0].getNumOfArguments(), is(equalTo(1)));
        assertThat(args[0].getHelpMessage(), is(not(emptyString())));
        assertThat(args[1].getName(), is(equalTo("-certpubdump")));
        assertThat(args[1].getNumOfArguments(), is(equalTo(1)));
        assertThat(args[1].getHelpMessage(), is(not(emptyString())));
        assertThat(args[2].getName(), is(equalTo("-certfulldump")));
        assertThat(args[2].getNumOfArguments(), is(equalTo(1)));
        assertThat(args[2].getHelpMessage(), is(not(emptyString())));
    }

    @Test
    void shouldAddHostAndPortCommandLineArgsOnHookIfHandlingLocalServerServers() throws Exception {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.handleServerCerts = true;
        extension.handleLocalServers = true;
        // When
        extension.hook(extensionHook);
        // Then
        ArgumentCaptor<CommandLineArgument[]> argument =
                ArgumentCaptor.forClass(CommandLineArgument[].class);
        verify(extensionHook).addCommandLine(argument.capture());
        CommandLineArgument[] args = argument.getAllValues().get(0);
        assertThat(args, arrayWithSize(5));
        assertThat(args[3].getName(), is(equalTo("-host")));
        assertThat(args[3].getNumOfArguments(), is(equalTo(1)));
        assertThat(args[3].getHelpMessage(), is(not(emptyString())));
        assertThat(args[4].getName(), is(equalTo("-port")));
        assertThat(args[4].getNumOfArguments(), is(equalTo(1)));
        assertThat(args[4].getHelpMessage(), is(not(emptyString())));
    }

    @Test
    void shouldAddLegacyProxyListenerHandlerOnHookAlways() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        // When
        extension.hook(extensionHook);
        // Then
        ArgumentCaptor<ProxyServer> argument = ArgumentCaptor.forClass(ProxyServer.class);
        verify(extensionLoader).addProxyServer(argument.capture());
        assertThat(argument.getAllValues(), contains(instanceOf(LegacyProxyListenerHandler.class)));
        assertThat(
                extension.getLegacyProxyListenerHandler(),
                is(equalTo(argument.getAllValues().get(0))));
    }

    @Test
    void shouldAddLocalServersOptionsOnHookIfHandlingLocalServers() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.handleServerCerts = true;
        extension.handleLocalServers = true;
        // When
        extension.hook(extensionHook);
        // Then
        ArgumentCaptor<AbstractParam> argument = ArgumentCaptor.forClass(AbstractParam.class);
        verify(extensionHook, times(2)).addOptionsParamSet(argument.capture());
        assertThat(argument.getAllValues(), hasItem(instanceOf(LocalServersOptions.class)));
        assertThat(extension.getLocalServersOptions(), is(equalTo(argument.getAllValues().get(1))));
    }

    @Test
    void shouldNotAddLocalServersOptionsOnHookIfNotHandlingLocalServers() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.handleServerCerts = true;
        extension.handleLocalServers = false;
        // When
        extension.hook(extensionHook);
        // Then
        ArgumentCaptor<AbstractParam> argument = ArgumentCaptor.forClass(AbstractParam.class);
        verify(extensionHook).addOptionsParamSet(argument.capture());
        assertThat(argument.getAllValues(), not(contains(instanceOf(LocalServersOptions.class))));
        assertThat(extension.getLocalServersOptions(), is(nullValue()));
    }

    @Test
    void shouldCreatePassThroughHandlerOnHookIfHandlingLocalServers() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.handleServerCerts = true;
        extension.handleLocalServers = true;
        // When
        extension.hook(extensionHook);
        // Then
        assertThat(extension.getPassThroughHandler(), is(notNullValue()));
    }

    @Test
    void shouldNotCreatePassThroughHandlerOnHookIfNotHandlingLocalServers() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.handleServerCerts = true;
        extension.handleLocalServers = false;
        // When
        extension.hook(extensionHook);
        // Then
        assertThat(extension.getPassThroughHandler(), is(nullValue()));
    }

    @Test
    void shouldNotExecuteCommandLineArgsIfNotHandlingCerts() throws Exception {
        // Given
        CommandLineArgument[] args = mockedCmdLineArgs(3);
        Stream.of(args).forEach(arg -> given(arg.isEnabled()).willReturn(true));
        extension.handleServerCerts = false;
        // When
        extension.execute(args);
        // Then
        Stream.of(args).forEach(arg -> verify(arg, times(0)).isEnabled());
    }

    @Test
    void shouldLoadCertCommandLineArgIfHandlingCerts() throws Exception {
        // Given
        Path file = Files.createTempFile("rootca", ".pem");
        Files.write(file, NetworkTestUtils.FISH_CERT_PEM_BYTES);
        CommandLineArgument[] args = mockedCmdLineArgs(3);
        cmdLineArgEnabledWithFile(args, 0, file);
        extension.handleServerCerts = true;
        extensionStarted();
        List<String> logEvents = registerLogEvents();
        // When
        extension.execute(args);
        // Then
        Stream.of(args).forEach(arg -> verify(arg).isEnabled());
        assertThat(
                extension.getServerCertificatesOptions().getRootCaKeyStore(), is(notNullValue()));
        ArgumentCaptor<SslCertificateService> argument =
                ArgumentCaptor.forClass(SslCertificateService.class);
        verify(extension.setSslCertificateService, times(1)).accept(argument.capture());
        assertThat(argument.getAllValues(), contains(instanceOf(SslCertificateServiceImpl.class)));
        SslCertificateService service = argument.getAllValues().get(0);
        assertThat(service.createCertForHost(new CertData("example.org")), is(notNullValue()));
        assertThat(logEvents, contains(startsWith("Root CA certificate loaded from")));
    }

    @Test
    void shouldErrorIfLoadingUnreadableCertCommandLineArg() throws Exception {
        // Given
        Path file = Paths.get("/some/path/not/readable/rootca.pem");
        CommandLineArgument[] args = mockedCmdLineArgs(3);
        cmdLineArgEnabledWithFile(args, 0, file);
        extension.handleServerCerts = true;
        extensionStarted();
        List<String> logEvents = registerLogEvents();
        // When
        extension.execute(args);
        // Then
        Stream.of(args).forEach(arg -> verify(arg).isEnabled());
        assertThat(logEvents, contains(startsWith("Cannot read file")));
    }

    @Test
    void shouldErrorIfLoadingInvalidCertCommandLineArg() throws Exception {
        // Given
        Path file = Files.createTempDirectory("not-cert");
        CommandLineArgument[] args = mockedCmdLineArgs(3);
        cmdLineArgEnabledWithFile(args, 0, file);
        extension.handleServerCerts = true;
        extensionStarted();
        List<String> logEvents = registerLogEvents();
        // When
        extension.execute(args);
        // Then
        Stream.of(args).forEach(arg -> verify(arg).isEnabled());
        assertThat(logEvents, contains(startsWith("Failed to read the selected .pem file:")));
    }

    @Test
    void shouldDumpCertCommandLineArgIfHandlingCerts() throws Exception {
        // Given
        Path file = Files.createTempFile("dump", ".pem");
        CommandLineArgument[] args = mockedCmdLineArgs(3);
        cmdLineArgEnabledWithFile(args, 1, file);
        extension.handleServerCerts = true;
        extensionStarted();
        List<String> logEvents = registerLogEvents();
        // When
        extension.execute(args);
        // Then
        Stream.of(args).forEach(arg -> verify(arg).isEnabled());
        assertThat(
                contents(file),
                allOf(
                        containsString(SslCertificateUtils.BEGIN_CERTIFICATE_TOKEN),
                        containsString(SslCertificateUtils.END_CERTIFICATE_TOKEN),
                        not(containsString(SslCertificateUtils.BEGIN_PRIVATE_KEY_TOKEN))));
        assertThat(logEvents, contains(startsWith("Root CA certificate written to")));
    }

    @Test
    void shouldErrorWhenDumpingCertCommandLineArgIfNotWritable() throws Exception {
        // Given
        Path file = Files.createTempFile("dump", ".pem");
        notWritable(file);
        CommandLineArgument[] args = mockedCmdLineArgs(3);
        cmdLineArgEnabledWithFile(args, 1, file);
        extension.handleServerCerts = true;
        extensionStarted();
        List<String> logEvents = registerLogEvents();
        // When
        extension.execute(args);
        // Then
        Stream.of(args).forEach(arg -> verify(arg).isEnabled());
        assertThat(logEvents, contains(startsWith("Cannot write to file")));
    }

    @Test
    void shouldDumpCertAndKeyCommandLineArgIfHandlingCerts() throws Exception {
        // Given
        Path file = Files.createTempFile("dump", ".pem");
        CommandLineArgument[] args = mockedCmdLineArgs(3);
        cmdLineArgEnabledWithFile(args, 2, file);
        extension.handleServerCerts = true;
        extensionStarted();
        List<String> logEvents = registerLogEvents();
        // When
        extension.execute(args);
        // Then
        Stream.of(args).forEach(arg -> verify(arg).isEnabled());
        assertThat(
                contents(file),
                allOf(
                        containsString(SslCertificateUtils.BEGIN_CERTIFICATE_TOKEN),
                        containsString(SslCertificateUtils.END_CERTIFICATE_TOKEN),
                        containsString(SslCertificateUtils.BEGIN_PRIVATE_KEY_TOKEN),
                        containsString(SslCertificateUtils.END_PRIVATE_KEY_TOKEN)));
        assertThat(logEvents, contains(startsWith("Root CA certificate written to")));
    }

    @Test
    void shouldErrorWhenDumpingCertAndKeyCommandLineArgIfNotWritable() throws Exception {
        // Given
        Path file = Files.createTempFile("dump", ".pem");
        notWritable(file);
        CommandLineArgument[] args = mockedCmdLineArgs(3);
        cmdLineArgEnabledWithFile(args, 2, file);
        extension.handleServerCerts = true;
        extensionStarted();
        List<String> logEvents = registerLogEvents();
        // When
        extension.execute(args);
        // Then
        Stream.of(args).forEach(arg -> verify(arg).isEnabled());
        assertThat(logEvents, contains(startsWith("Cannot write to file")));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"/path/a/", "/path/b"})
    void shouldNoHandleFiles(String path) throws Exception {
        // Given
        File file = path != null ? Paths.get(path).toFile() : null;
        // When
        boolean handleFile = extension.handleFile(file);
        // Then
        assertThat(handleFile, is(equalTo(false)));
    }

    @Test
    void shouldNoHandleExtensions() throws Exception {
        // Given / When
        List<String> handledExtensions = extension.getHandledExtensions();
        // Then
        assertThat(handledExtensions, is(empty()));
    }

    @Test
    void shouldNotSetSslCertificateServiceOnStartIfNotHandlingServerCerts() {
        // Given
        extension.handleServerCerts = false;
        // When
        extension.start();
        // Then
        verify(extension.setSslCertificateService, times(0)).accept(any());
    }

    @Test
    void shouldGenerateRootCaCertAndSetSslCertificateServiceOnStartIfHandlingServerCerts()
            throws Exception {
        // Given
        extension.handleServerCerts = true;
        extension.hook(mock(ExtensionHook.class));
        extension.getServerCertificatesOptions().load(new ZapXmlConfiguration());
        // When
        extension.start();
        // Then
        ArgumentCaptor<SslCertificateService> argument =
                ArgumentCaptor.forClass(SslCertificateService.class);
        verify(extension.setSslCertificateService, times(1)).accept(argument.capture());
        assertThat(argument.getAllValues(), contains(instanceOf(SslCertificateServiceImpl.class)));
        SslCertificateService service = argument.getAllValues().get(0);
        assertThat(service.createCertForHost(new CertData("example.org")), is(notNullValue()));
    }

    @Test
    void shouldLoadRootCaCertAndSetSslCertificateServiceOnStartIfHandlingServerCerts()
            throws Exception {
        // Given
        extension.handleServerCerts = true;
        extension.hook(mock(ExtensionHook.class));
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        config.setProperty(
                "network.serverCertificates.rootCa.ks", NetworkTestUtils.FISH_CERT_BASE64_STR);
        extension.getServerCertificatesOptions().load(config);
        // When
        extension.start();
        // Then
        ArgumentCaptor<SslCertificateService> argument =
                ArgumentCaptor.forClass(SslCertificateService.class);
        verify(extension.setSslCertificateService, times(1)).accept(argument.capture());
        assertThat(argument.getAllValues(), contains(instanceOf(SslCertificateServiceImpl.class)));
        SslCertificateService service = argument.getAllValues().get(0);
        assertThat(service.createCertForHost(new CertData("example.org")), is(notNullValue()));
    }

    @Test
    void shouldNotSetSslCertificateServiceOnStartIfHandlingServerCertsAndNotAbleToLoadRootCaCert() {
        // Given
        extension.handleServerCerts = true;
        extension.hook(mock(ExtensionHook.class));
        // No configuration loaded in the options will lead to exception later.
        // When
        extension.start();
        // Then
        verify(extension.setSslCertificateService, times(0)).accept(any());
    }

    @Test
    void shouldWarnOfExpiredRootCaCertOnStartIfHandlingServerCerts() throws Exception {
        // Given
        extension.handleServerCerts = true;
        extension.hook(mock(ExtensionHook.class));
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        KeyStore expiredRootCaKeyStore =
                CertificateUtils.createRootCaKeyStore(new CertConfig(Duration.ofDays(-90)));
        config.setProperty(
                "network.serverCertificates.rootCa.ks",
                CertificateUtils.keyStoreToString(expiredRootCaKeyStore));
        extension.getServerCertificatesOptions().load(config);
        List<String> logEvents = registerLogEvents();
        // When
        extension.start();
        // Then
        assertThat(logEvents, hasSize(1));
        assertThat(logEvents.get(0), startsWith("ZAP's Root CA certificate has expired"));
    }

    @Test
    void shouldBeUnloadable() {
        assertThat(extension.canUnload(), is(true));
    }

    @Test
    void shouldNotUnloadAnyComponentsIfNotHandlingServerCerts() {
        // Given
        extension.handleServerCerts = false;
        // When
        extension.unload();
        // Then
        verify(extension.setSslCertificateService, times(0)).accept(any());
        assertThat(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME), is(notNullValue()));
    }

    @Test
    void shouldUnloadIfHandlingServerCerts() {
        // Given
        extension.handleServerCerts = true;
        // When
        extension.unload();
        // Then
        verify(extension.setSslCertificateService, times(1)).accept(null);
        assertThat(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME), is(nullValue()));
    }

    @Test
    void shouldUnloadLegacyProxyListenerHandlerAlways() {
        // Given
        extension.hook(mock(ExtensionHook.class));
        LegacyProxyListenerHandler handler = extension.getLegacyProxyListenerHandler();
        // When
        extension.unload();
        // Then
        verify(extensionLoader).removeProxyServer(handler);
        assertThat(extension.getLegacyProxyListenerHandler(), is(nullValue()));
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
        assertThat(
                contents(file),
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
        assertThat(
                contents(file), not(containsString(SslCertificateUtils.BEGIN_CERTIFICATE_TOKEN)));
    }

    @Test
    void shouldGetRootCaKeyStoreFromDynSslParam() throws Exception {
        // Given
        mockRootCaKeyStore();
        // When
        KeyStore keyStore = extension.getRootCaKeyStore();
        // Then
        assertThat(keyStore, is(notNullValue()));
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

    @Test
    void shouldImportRootCaCertWhenHandlingServerCerts() throws Exception {
        // Given
        extension.handleServerCerts = true;
        Path file = Files.createTempFile("rootca", ".cer");
        Files.write(file, NetworkTestUtils.FISH_CERT_PEM_BYTES);
        extensionStarted();
        // When
        String result = extension.importRootCaCert(file);
        // Then
        assertThat(result, is(nullValue()));
        assertThat(
                extension.getServerCertificatesOptions().getRootCaKeyStore(), is(notNullValue()));
        ArgumentCaptor<SslCertificateService> argument =
                ArgumentCaptor.forClass(SslCertificateService.class);
        verify(extension.setSslCertificateService, times(1)).accept(argument.capture());
        assertThat(argument.getAllValues(), contains(instanceOf(SslCertificateServiceImpl.class)));
        SslCertificateService service = argument.getAllValues().get(0);
        assertThat(service.createCertForHost(new CertData("example.org")), is(notNullValue()));
    }

    @Test
    void shouldFailToImportRootCaCertIfUnableToCreateKeyStoreWhenHandlingServerCerts()
            throws Exception {
        // Given
        extension.handleServerCerts = true;
        Path file = Files.createTempFile("rootca", ".cer");
        Files.write(file, NetworkTestUtils.FISH_CERT_PEM_BYTES);
        // No options instance will lead to exception later.
        // When
        String result = extension.importRootCaCert(file);
        // Then
        assertThat(result, is(startsWith("Failed to create the KeyStore from the .pem file:")));
    }

    @Test
    void shouldFailToImportRootCaCertIfFileDoesNotExistWhenHandlingServerCerts() throws Exception {
        // Given
        extension.handleServerCerts = true;
        Path file = Paths.get("/not/a/file.pem");
        // When
        String result = extension.importRootCaCert(file);
        // Then
        assertThat(result, is(startsWith("Failed to read the selected .pem file:")));
    }

    @Test
    void shouldFailToImportRootCaCertIfFileDoesNotContainCertWhenHandlingServerCerts()
            throws Exception {
        // Given
        extension.handleServerCerts = true;
        Path file = Files.createTempFile("rootca", ".cer");
        // When
        String result = extension.importRootCaCert(file);
        // Then
        assertThat(result, is(startsWith("No certificate section found in the .pem file.")));
    }

    @Test
    void shouldFailToImportRootCaCertIfFileHasInvalidBase64CertWhenHandlingServerCerts()
            throws Exception {
        // Given
        extension.handleServerCerts = true;
        Path file = Files.createTempFile("rootca", ".cer");
        Files.write(
                file,
                (CertificateUtils.BEGIN_CERTIFICATE_TOKEN
                                + "\nNotBase64Cert\n"
                                + CertificateUtils.END_CERTIFICATE_TOKEN)
                        .getBytes(StandardCharsets.US_ASCII));
        // When
        String result = extension.importRootCaCert(file);
        // Then
        assertThat(result, is(startsWith("The certificate is not properly base64 encoded.")));
    }

    @Test
    void shouldFailToImportRootCaCertIfFileDoesNotContainPrivateKeyWhenHandlingServerCerts()
            throws Exception {
        // Given
        extension.handleServerCerts = true;
        Path file = Files.createTempFile("rootca", ".cer");
        Files.write(
                file,
                (CertificateUtils.BEGIN_CERTIFICATE_TOKEN
                                + "\n"
                                + NetworkTestUtils.FISH_CERT_BASE64
                                + CertificateUtils.END_CERTIFICATE_TOKEN)
                        .getBytes(StandardCharsets.US_ASCII));
        // When
        String result = extension.importRootCaCert(file);
        // Then
        assertThat(result, is(startsWith("No private key section found in the .pem file.")));
    }

    @Test
    void shouldFailToImportRootCaCertIfFileHasInvalidBase64PrivateKeyWhenHandlingServerCerts()
            throws Exception {
        // Given
        extension.handleServerCerts = true;
        Path file = Files.createTempFile("rootca", ".cer");
        Files.write(
                file,
                (CertificateUtils.BEGIN_CERTIFICATE_TOKEN
                                + "\n"
                                + NetworkTestUtils.FISH_CERT_BASE64
                                + CertificateUtils.END_CERTIFICATE_TOKEN
                                + "\n"
                                + CertificateUtils.BEGIN_PRIVATE_KEY_TOKEN
                                + "\nNotBase64Cert\n"
                                + CertificateUtils.END_PRIVATE_KEY_TOKEN)
                        .getBytes(StandardCharsets.US_ASCII));
        // When
        String result = extension.importRootCaCert(file);
        // Then
        assertThat(result, is(startsWith("The private key is not properly base64 encoded.")));
    }

    @Test
    void shouldCreateHttpServerWithProvidedHandler() throws Exception {
        // Given
        HttpMessageHandler handler =
                (ctx, msg) -> {
                    if (!ctx.isFromClient()) {
                        return;
                    }
                    try {
                        msg.setResponseHeader("HTTP/1.1 200 OK\r\nConnection: close");
                    } catch (HttpMalformedHeaderException ignore) {
                        // Valid header.
                    }
                };
        extension.handleServerCerts = true;
        extension.hook(mock(ExtensionHook.class));
        HttpMessage msg = new HttpMessage(new HttpRequestHeader("GET / HTTP/1.1"));
        TestClient client =
                new TextTestClient(
                        "127.0.0.1",
                        ch -> ch.pipeline().addFirst("http.client", new HttpClientCodec()));
        // When
        try (Server server = extension.createHttpServer(handler)) {
            int port = server.start(Server.ANY_PORT);
            Channel channel = client.connect(port, null);
            channel.writeAndFlush(msg).sync();
            msg = (HttpMessage) TextTestClient.waitForResponse(channel);
            // Then
            assertThat(
                    msg.getResponseHeader().toString(),
                    is(equalTo("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")));
        } finally {
            client.close();
        }
    }

    @Test
    void shouldCreateHttpProxyWithProvidedInitiatorAndHandler() throws Exception {
        // Given
        HttpMessageHandler handler =
                (ctx, msg) -> {
                    ctx.overridden();
                    try {
                        msg.setResponseHeader("HTTP/1.1 200 OK\r\nConnection: close");
                    } catch (HttpMalformedHeaderException ignore) {
                        // Valid header.
                    }
                };
        extension.handleServerCerts = true;
        extension.hook(mock(ExtensionHook.class));
        HttpMessage msg = new HttpMessage(new HttpRequestHeader("GET / HTTP/1.1"));
        TestClient client =
                new TextTestClient(
                        "127.0.0.1",
                        ch -> ch.pipeline().addFirst("http.client", new HttpClientCodec()));
        given(optionsParam.getConnectionParam()).willReturn(new ConnectionParam());
        extension.initModel(model);
        // When
        try (Server server = extension.createHttpProxy(1, handler)) {
            int port = server.start(Server.ANY_PORT);
            Channel channel = client.connect(port, null);
            channel.writeAndFlush(msg).sync();
            msg = (HttpMessage) TextTestClient.waitForResponse(channel);
            // Then
            assertThat(
                    msg.getResponseHeader().toString(),
                    is(equalTo("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")));
        } finally {
            client.close();
        }
    }

    @Test
    void shouldCreateHttpProxyWithProvidedHttpSenderAndHandler() throws Exception {
        // Given
        HttpMessageHandler handler =
                (ctx, msg) -> {
                    ctx.overridden();
                    try {
                        msg.setResponseHeader("HTTP/1.1 200 OK\r\nConnection: close");
                    } catch (HttpMalformedHeaderException ignore) {
                        // Valid header.
                    }
                };
        extension.handleServerCerts = true;
        extension.hook(mock(ExtensionHook.class));
        HttpMessage msg = new HttpMessage(new HttpRequestHeader("GET / HTTP/1.1"));
        TestClient client =
                new TextTestClient(
                        "127.0.0.1",
                        ch -> ch.pipeline().addFirst("http.client", new HttpClientCodec()));
        ConnectionParam connectionParam = new ConnectionParam();
        given(optionsParam.getConnectionParam()).willReturn(connectionParam);
        extension.initModel(model);
        // When
        try (Server server =
                extension.createHttpProxy(new HttpSender(connectionParam, true, 1), handler)) {
            int port = server.start(Server.ANY_PORT);
            Channel channel = client.connect(port, null);
            channel.writeAndFlush(msg).sync();
            msg = (HttpMessage) TextTestClient.waitForResponse(channel);
            // Then
            assertThat(
                    msg.getResponseHeader().toString(),
                    is(equalTo("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")));
        } finally {
            client.close();
        }
    }

    @Test
    void shouldThrowIfCreatingHttpServerWithNullHandler() throws Exception {
        // Given
        extension.handleServerCerts = true;
        extension.hook(mock(ExtensionHook.class));
        HttpMessageHandler handler = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> extension.createHttpServer(handler));
    }

    private void mockRootCaKeyStore() throws Exception {
        KeyStore keyStore =
                SslCertificateUtils.string2Keystore(NetworkTestUtils.FISH_CERT_BASE64_STR);
        DynSSLParam dynSslParam = mock(DynSSLParam.class);
        given(optionsParam.getParamSet(DynSSLParam.class)).willReturn(dynSslParam);
        given(dynSslParam.getRootca()).willReturn(keyStore);
    }

    private static List<String> registerLogEvents() {
        List<String> logEvents = new ArrayList<>();
        TestLogAppender logAppender = new TestLogAppender(logEvents::add);
        LoggerContext context = LoggerContext.getContext();
        LoggerConfig rootLoggerconfig = context.getConfiguration().getRootLogger();
        rootLoggerconfig.getAppenders().values().forEach(context.getRootLogger()::removeAppender);
        rootLoggerconfig.addAppender(logAppender, null, null);
        rootLoggerconfig.setLevel(Level.ALL);
        context.updateLoggers();
        return logEvents;
    }

    private static CommandLineArgument[] mockedCmdLineArgs(int size) {
        CommandLineArgument[] args = new CommandLineArgument[size];
        for (int i = 0; i < size; i++) {
            args[i] = mock(CommandLineArgument.class, withSettings().lenient());
        }
        return args;
    }

    private static void cmdLineArgEnabledWithFile(
            CommandLineArgument[] args, int index, Path file) {
        given(args[index].isEnabled()).willReturn(true);
        Vector<String> values = new Vector<>();
        values.add(file.toString());
        given(args[index].getArguments()).willReturn(values);
    }

    private static String contents(Path file) throws IOException {
        return new String(Files.readAllBytes(file), StandardCharsets.US_ASCII);
    }

    private static void notWritable(Path file) throws IOException {
        assumeTrue(
                Files.getFileStore(file).supportsFileAttributeView(PosixFileAttributeView.class),
                "Test requires support for POSIX file attributes.");
        Set<PosixFilePermission> perms =
                Files.readAttributes(file, PosixFileAttributes.class).permissions();
        perms.remove(PosixFilePermission.OWNER_WRITE);
        Files.setPosixFilePermissions(file, perms);
    }
}
