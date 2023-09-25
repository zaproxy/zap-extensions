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
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.apache.commons.httpclient.HttpState;
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
import org.mockito.quality.Strictness;
import org.parosproxy.paros.common.AbstractParam;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.network.internal.cert.CertConfig;
import org.zaproxy.addon.network.internal.cert.CertData;
import org.zaproxy.addon.network.internal.cert.CertificateUtils;
import org.zaproxy.addon.network.internal.cert.GenerationException;
import org.zaproxy.addon.network.internal.cert.ServerCertificateService;
import org.zaproxy.addon.network.internal.codec.HttpClientCodec;
import org.zaproxy.addon.network.internal.server.AliasChecker;
import org.zaproxy.addon.network.internal.server.http.Alias;
import org.zaproxy.addon.network.internal.server.http.PassThrough;
import org.zaproxy.addon.network.internal.server.http.handlers.LegacyProxyListenerHandler;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpServerConfig;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.addon.network.server.ServerInfo;
import org.zaproxy.addon.network.testutils.TestClient;
import org.zaproxy.addon.network.testutils.TextTestClient;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiElement;
import org.zaproxy.zap.extension.api.CoreAPI;
import org.zaproxy.zap.extension.api.OptionsParamApi;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link ExtensionNetwork}. */
@SuppressWarnings("deprecation")
class ExtensionNetworkUnitTest extends TestUtils {

    private MockedStatic<ZAP> zap;
    private Session session;
    private Model model;
    private OptionsParam optionsParam;
    private ExtensionLoader extensionLoader;
    private ExtensionNetwork extension;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());

        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(model, extensionLoader);

        model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        Model.setSingletonForTesting(model);
        optionsParam = mock(OptionsParam.class, withSettings().strictness(Strictness.LENIENT));
        given(optionsParam.getConnectionParam())
                .willReturn(new org.parosproxy.paros.network.ConnectionParam());
        given(optionsParam.getProxyParam())
                .willReturn(mock(org.parosproxy.paros.core.proxy.ProxyParam.class));
        given(model.getOptionsParam()).willReturn(optionsParam);
        session = mock(Session.class);
        given(model.getSession()).willReturn(session);

        extension = new ExtensionNetwork();
        extension.init();
        extension.initModel(model);
        mockMessages(extension);

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
        extension.destroy();
        try {
            API.getInstance().removeApiImplementor(new CoreApiTest());
        } catch (Exception e) {
        }
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
    void shouldAddLegacyConnectionOptionsOnInstantiation() {
        ArgumentCaptor<org.parosproxy.paros.network.ConnectionParam> argument =
                ArgumentCaptor.forClass(org.parosproxy.paros.network.ConnectionParam.class);
        verify(optionsParam).setConnectionParam(argument.capture());
        assertThat(argument.getValue(), is(instanceOf(LegacyConnectionParam.class)));
    }

    @Test
    void shouldCreateMainProxyServerInfoOnInitModel() {
        // Given
        String address = "address";
        int port = 1234;
        org.parosproxy.paros.core.proxy.ProxyParam proxyParam =
                mock(org.parosproxy.paros.core.proxy.ProxyParam.class);
        given(proxyParam.getProxyIp()).willReturn(address);
        given(proxyParam.getProxyPort()).willReturn(port);
        given(optionsParam.getProxyParam()).willReturn(proxyParam);
        // When
        extension.initModel(model);
        // Then
        ServerInfo serverInfo = extension.getMainProxyServerInfo();
        assertThat(serverInfo, is(notNullValue()));
        assertThat(serverInfo.getAddress(), is(equalTo(address)));
        assertThat(serverInfo.getPort(), is(equalTo(port)));
        verify(proxyParam).getProxyIp();
        verify(proxyParam).getProxyPort();
    }

    @Test
    void shouldAddNetworkApiOnHook() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        // When
        extension.hook(extensionHook);
        // Then
        verify(extensionHook).addApiImplementor(any(NetworkApi.class));
    }

    @Test
    void shouldAddSessionChangedListenerOnHook() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        // When
        extension.hook(extensionHook);
        // Then
        ArgumentCaptor<SessionChangedListener> argument =
                ArgumentCaptor.forClass(SessionChangedListener.class);
        verify(extensionHook).addSessionListener(argument.capture());
        assertThat(argument.getValue(), is(notNullValue()));
    }

    @Test
    void shouldResetHttpStateIfSessionChanged() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.hook(extensionHook);
        ArgumentCaptor<SessionChangedListener> argument =
                ArgumentCaptor.forClass(SessionChangedListener.class);
        verify(extensionHook).addSessionListener(argument.capture());
        SessionChangedListener sessionChangedListener = argument.getValue();
        org.parosproxy.paros.network.ConnectionParam connectionParam =
                mock(org.parosproxy.paros.network.ConnectionParam.class);
        given(optionsParam.getConnectionParam()).willReturn(connectionParam);
        extension.initModel(model);
        // When
        sessionChangedListener.sessionChanged(null);
        // Then
        verify(connectionParam).setHttpState(any(HttpState.class));
    }

    @Test
    void shouldAddLegacyProxiesApiOnHook() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        // When
        extension.hook(extensionHook);
        // Then
        verify(extensionHook).addApiImplementor(any((LegacyProxiesApi.class)));
    }

    @Test
    void shouldCreateAliasCheckerOnHook() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        // When
        extension.hook(extensionHook);
        // Then
        assertThat(extension.getAliasChecker(), is(notNullValue()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://zap/", "https://zap/", "http://zap:8090/", "https://zap:1234/"})
    void shouldBeAliasIfZapDomain(String requestTarget) throws Exception {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.hook(extensionHook);
        AliasChecker aliasChecker = extension.getAliasChecker();
        HttpRequestHeader requestHeader =
                new HttpRequestHeader("GET " + requestTarget + " HTTP/1.1");
        // When
        boolean alias = aliasChecker.isAlias(requestHeader);
        // Then
        assertThat(alias, is(equalTo(true)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldCheckAliasDefinedInOptions(boolean expectedAlias) throws Exception {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.hook(extensionHook);
        Alias optionAlias = mock(Alias.class);
        HttpRequestHeader requestHeader = new HttpRequestHeader("GET http://not.zap/ HTTP/1.1");
        given(optionAlias.test(requestHeader)).willReturn(expectedAlias);
        extension.getLocalServersOptions().load(new ZapXmlConfiguration());
        extension.getLocalServersOptions().addAlias(optionAlias);
        AliasChecker aliasChecker = extension.getAliasChecker();
        // When
        boolean alias = aliasChecker.isAlias(requestHeader);
        // Then
        assertThat(alias, is(equalTo(expectedAlias)));
        verify(optionAlias).test(requestHeader);
    }

    @Test
    void shouldAddServerCertificatesOptionsOnHook() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        // When
        extension.hook(extensionHook);
        // Then
        ArgumentCaptor<AbstractParam> argument = ArgumentCaptor.forClass(AbstractParam.class);
        verify(extensionHook, times(6)).addOptionsParamSet(argument.capture());
        assertThat(argument.getAllValues(), hasItem(instanceOf(ServerCertificatesOptions.class)));
        assertThat(
                extension.getServerCertificatesOptions(),
                is(equalTo(argument.getAllValues().get(0))));
    }

    @Test
    void shouldAddCommandLineArgsOnHook() throws Exception {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        // When
        extension.hook(extensionHook);
        // Then
        ArgumentCaptor<CommandLineArgument[]> argument =
                ArgumentCaptor.forClass(CommandLineArgument[].class);
        verify(extensionHook).addCommandLine(argument.capture());
        CommandLineArgument[] args = argument.getAllValues().get(0);
        assertThat(args, arrayWithSize(5));
        assertThat(args[0].getName(), is(equalTo("-certload")));
        assertThat(args[0].getNumOfArguments(), is(equalTo(1)));
        assertThat(args[0].getHelpMessage(), is(not(emptyString())));
        assertThat(args[1].getName(), is(equalTo("-certpubdump")));
        assertThat(args[1].getNumOfArguments(), is(equalTo(1)));
        assertThat(args[1].getHelpMessage(), is(not(emptyString())));
        assertThat(args[2].getName(), is(equalTo("-certfulldump")));
        assertThat(args[2].getNumOfArguments(), is(equalTo(1)));
        assertThat(args[2].getHelpMessage(), is(not(emptyString())));
        assertThat(args[3].getName(), is(equalTo("-host")));
        assertThat(args[3].getNumOfArguments(), is(equalTo(1)));
        assertThat(args[3].getHelpMessage(), is(not(emptyString())));
        assertThat(args[4].getName(), is(equalTo("-port")));
        assertThat(args[4].getNumOfArguments(), is(equalTo(1)));
        assertThat(args[4].getHelpMessage(), is(not(emptyString())));
    }

    @Test
    @SuppressWarnings("removal")
    void shouldAddLegacyProxyListenerHandlerOnHookAlways() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        // When
        extension.hook(extensionHook);
        // Then
        ArgumentCaptor<org.parosproxy.paros.core.proxy.ProxyServer> argument =
                ArgumentCaptor.forClass(org.parosproxy.paros.core.proxy.ProxyServer.class);
        verify(extensionLoader).addProxyServer(argument.capture());
        assertThat(argument.getAllValues(), contains(instanceOf(LegacyProxyListenerHandler.class)));
        assertThat(
                extension.getLegacyProxyListenerHandler(),
                is(equalTo(argument.getAllValues().get(0))));
    }

    @Test
    void shouldAddLocalServersOptionsOnHook() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        // When
        extension.hook(extensionHook);
        // Then
        ArgumentCaptor<AbstractParam> argument = ArgumentCaptor.forClass(AbstractParam.class);
        verify(extensionHook, times(6)).addOptionsParamSet(argument.capture());
        assertThat(argument.getAllValues(), hasItem(instanceOf(LocalServersOptions.class)));
        assertThat(extension.getLocalServersOptions(), is(equalTo(argument.getAllValues().get(1))));
    }

    @Test
    void shouldCreatePassThroughHandlerOnHook() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        // When
        extension.hook(extensionHook);
        // Then
        assertThat(extension.getPassThroughHandler(), is(notNullValue()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"example.com", "example.org", "subdomain.example.org"})
    void shouldNotPassThroughByDefault(String domain) throws Exception {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.hook(extensionHook);
        HttpRequestHeader requestHeader =
                new HttpRequestHeader("GET / HTTP/1.1\r\nHost: " + domain);
        // When
        boolean passThrough = extension.shouldPassThrough(requestHeader);
        // Then
        assertThat(passThrough, is(equalTo(false)));
    }

    @Test
    void shouldNotPassThroughIfZapDomain() throws Exception {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.hook(extensionHook);
        String domain = "zap";
        HttpRequestHeader requestHeader =
                new HttpRequestHeader("GET / HTTP/1.1\r\nHost: " + domain);
        addPassThrough(domain, true);
        // When
        boolean passThrough = extension.shouldPassThrough(requestHeader);
        // Then
        assertThat(passThrough, is(equalTo(false)));
    }

    private void addPassThrough(String domain, boolean enabled) {
        extension.getLocalServersOptions().load(new ZapXmlConfiguration());
        extension
                .getLocalServersOptions()
                .addPassThrough(new PassThrough(Pattern.compile(Pattern.quote(domain)), enabled));
    }

    @Test
    void shouldNotPassThroughIfAlias() throws Exception {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.hook(extensionHook);
        String domain = "alias.example.com";
        HttpRequestHeader requestHeader =
                new HttpRequestHeader("GET / HTTP/1.1\r\nHost: " + domain);
        addPassThrough(domain, true);
        extension.getLocalServersOptions().addAlias(new Alias(domain, true));
        // When
        boolean passThrough = extension.shouldPassThrough(requestHeader);
        // Then
        assertThat(passThrough, is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldPassThroughBasedOnPassThroughEnabledState(boolean enabled) throws Exception {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.hook(extensionHook);
        String domain = "alias.example.com";
        addPassThrough(domain, enabled);
        HttpRequestHeader requestHeader =
                new HttpRequestHeader("GET / HTTP/1.1\r\nHost: " + domain);
        // When
        boolean passThrough = extension.shouldPassThrough(requestHeader);
        // Then
        assertThat(passThrough, is(equalTo(enabled)));
    }

    @Test
    void shouldAddConnectionOptionsOnHook() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        // When
        extension.hook(extensionHook);
        // Then
        ArgumentCaptor<AbstractParam> argument = ArgumentCaptor.forClass(AbstractParam.class);
        verify(extensionHook, times(6)).addOptionsParamSet(argument.capture());
        assertThat(argument.getAllValues(), hasItem(instanceOf(ConnectionOptions.class)));
    }

    @Test
    void shouldAddOptionsChangedListenerOnHook() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        // When
        extension.hook(extensionHook);
        // Then
        verify(extensionHook).addOptionsChangedListener(any());
    }

    @Test
    void shouldAddClientCertificatesOptionsOnHook() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        // When
        extension.hook(extensionHook);
        // Then
        ArgumentCaptor<AbstractParam> argument = ArgumentCaptor.forClass(AbstractParam.class);
        verify(extensionHook, times(6)).addOptionsParamSet(argument.capture());
        assertThat(argument.getAllValues(), hasItem(instanceOf(ClientCertificatesOptions.class)));
        assertThat(extension.getClientCertificatesOptions(), is(notNullValue()));
    }

    @Test
    void shouldCreateGlobalHttpStateOnOptionsChangedIfUsingGlobalHttpState() {
        // Given
        OptionsChangedListener optionsChangedListener = setupOptionsChangedListener();
        extension.getConnectionOptions().setUseGlobalHttpState(true);
        // When
        optionsChangedListener.optionsChanged(null);
        // Then
        assertThat(extension.getGlobalHttpState(), is(notNullValue()));
    }

    private OptionsChangedListener setupOptionsChangedListener() {
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        extension.hook(extensionHook);
        extension.getConnectionOptions().load(new ZapXmlConfiguration());
        ArgumentCaptor<OptionsChangedListener> argument =
                ArgumentCaptor.forClass(OptionsChangedListener.class);
        verify(extensionHook).addOptionsChangedListener(argument.capture());
        return argument.getValue();
    }

    @Test
    void shouldKeepSameGlobalHttpStateOnOptionsChangedIfStillUsingGlobalHttpState() {
        // Given
        OptionsChangedListener optionsChangedListener = setupOptionsChangedListener();
        extension.getConnectionOptions().setUseGlobalHttpState(true);
        optionsChangedListener.optionsChanged(null);
        HttpState httpState = extension.getGlobalHttpState();
        // When
        optionsChangedListener.optionsChanged(null);
        // Then
        assertThat(extension.getGlobalHttpState(), is(sameInstance(httpState)));
    }

    @Test
    void shouldNotCreateGlobalHttpStateOnOptionsChangedIfNotUsingGlobalHttpState() {
        // Given
        OptionsChangedListener optionsChangedListener = setupOptionsChangedListener();
        extension.getConnectionOptions().setUseGlobalHttpState(false);
        // When
        optionsChangedListener.optionsChanged(null);
        // Then
        assertThat(extension.getGlobalHttpState(), is(nullValue()));
    }

    @Test
    void shouldAddLegacyConnectionParamToCoreApiOnHook() {
        // Given
        ExtensionHook extensionHook = mock(ExtensionHook.class);
        CoreApiTest coreApi = new CoreApiTest();
        API.getInstance().registerApiImplementor(coreApi);
        // When
        extension.hook(extensionHook);
        // Then
        assertThat(coreApi.getLastAddedParam(), is(instanceOf(LegacyConnectionParam.class)));
        assertThat(
                coreApi.getApiViews().stream()
                        .map(ApiElement::getName)
                        .sorted()
                        .filter(e -> e.startsWith("option"))
                        .count(),
                is(equalTo(21L)));
        assertThat(
                coreApi.getApiActions().stream()
                        .map(ApiElement::getName)
                        .sorted()
                        .filter(e -> e.startsWith("setOption"))
                        .count(),
                is(equalTo(18L)));
    }

    @Test
    void shouldLoadCertCommandLineArg() throws Exception {
        // Given
        Path file = Files.createTempFile("rootca", ".pem");
        Files.write(file, NetworkTestUtils.FISH_CERT_PEM_BYTES);
        CommandLineArgument[] args = mockedCmdLineArgs(5);
        cmdLineArgEnabledWithFile(args, 0, file);
        extensionStarted();
        List<String> logEvents = registerLogEvents();
        // When
        extension.execute(args);
        // Then
        Stream.of(args).forEach(arg -> verify(arg).isEnabled());
        assertThat(
                extension.getServerCertificatesOptions().getRootCaKeyStore(), is(notNullValue()));
        ServerCertificateService certificateService = extension.getServerCertificateService();
        assertThat(
                certificateService.createCertificate(new CertData("example.org")),
                is(notNullValue()));
        assertThat(logEvents, hasItem(startsWith("Root CA certificate loaded from")));
    }

    @Test
    void shouldErrorIfLoadingUnreadableCertCommandLineArg() throws Exception {
        // Given
        Path file = Paths.get("/some/path/not/readable/rootca.pem");
        CommandLineArgument[] args = mockedCmdLineArgs(5);
        cmdLineArgEnabledWithFile(args, 0, file);
        extensionStarted();
        List<String> logEvents = registerLogEvents();
        // When
        extension.execute(args);
        // Then
        Stream.of(args).forEach(arg -> verify(arg).isEnabled());
        assertThat(logEvents, hasItem(startsWith("Cannot read file")));
    }

    @Test
    void shouldErrorIfLoadingInvalidCertCommandLineArg() throws Exception {
        // Given
        Path file = Files.createTempDirectory("not-cert");
        CommandLineArgument[] args = mockedCmdLineArgs(5);
        cmdLineArgEnabledWithFile(args, 0, file);
        extensionStarted();
        List<String> logEvents = registerLogEvents();
        // When
        extension.execute(args);
        // Then
        Stream.of(args).forEach(arg -> verify(arg).isEnabled());
        assertThat(logEvents, hasItem(startsWith("Failed to read the selected .pem file:")));
    }

    @Test
    void shouldDumpCertCommandLineArg() throws Exception {
        // Given
        Path file = Files.createTempFile("dump", ".pem");
        CommandLineArgument[] args = mockedCmdLineArgs(5);
        cmdLineArgEnabledWithFile(args, 1, file);
        extensionStarted();
        List<String> logEvents = registerLogEvents();
        // When
        extension.execute(args);
        // Then
        Stream.of(args).forEach(arg -> verify(arg).isEnabled());
        assertThat(
                contents(file),
                allOf(
                        containsString(CertificateUtils.BEGIN_CERTIFICATE_TOKEN),
                        containsString(CertificateUtils.END_CERTIFICATE_TOKEN),
                        not(containsString(CertificateUtils.BEGIN_PRIVATE_KEY_TOKEN))));
        assertThat(logEvents, hasItem(startsWith("Root CA certificate written to")));
    }

    @Test
    void shouldErrorWhenDumpingCertCommandLineArgIfNotWritable() throws Exception {
        // Given
        Path file = Files.createTempFile("dump", ".pem");
        notWritable(file);
        CommandLineArgument[] args = mockedCmdLineArgs(5);
        cmdLineArgEnabledWithFile(args, 1, file);
        extensionStarted();
        List<String> logEvents = registerLogEvents();
        // When
        extension.execute(args);
        // Then
        Stream.of(args).forEach(arg -> verify(arg).isEnabled());
        assertThat(logEvents, hasItem(startsWith("Cannot write to file")));
    }

    @Test
    void shouldDumpCertAndKeyCommandLineArg() throws Exception {
        // Given
        Path file = Files.createTempFile("dump", ".pem");
        CommandLineArgument[] args = mockedCmdLineArgs(5);
        cmdLineArgEnabledWithFile(args, 2, file);
        extensionStarted();
        List<String> logEvents = registerLogEvents();
        // When
        extension.execute(args);
        // Then
        Stream.of(args).forEach(arg -> verify(arg).isEnabled());
        assertThat(
                contents(file),
                allOf(
                        containsString(CertificateUtils.BEGIN_CERTIFICATE_TOKEN),
                        containsString(CertificateUtils.END_CERTIFICATE_TOKEN),
                        containsString(CertificateUtils.BEGIN_PRIVATE_KEY_TOKEN),
                        containsString(CertificateUtils.END_PRIVATE_KEY_TOKEN)));
        assertThat(logEvents, hasItem(startsWith("Root CA certificate written to")));
    }

    @Test
    void shouldErrorWhenDumpingCertAndKeyCommandLineArgIfNotWritable() throws Exception {
        // Given
        Path file = Files.createTempFile("dump", ".pem");
        notWritable(file);
        CommandLineArgument[] args = mockedCmdLineArgs(5);
        cmdLineArgEnabledWithFile(args, 2, file);
        extensionStarted();
        List<String> logEvents = registerLogEvents();
        // When
        extension.execute(args);
        // Then
        Stream.of(args).forEach(arg -> verify(arg).isEnabled());
        assertThat(logEvents, hasItem(startsWith("Cannot write to file")));
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
    void shouldGenerateAndSetRootCaCertOnStart() throws Exception {
        // Given
        extension.hook(mock(ExtensionHook.class));
        extension.getServerCertificatesOptions().load(new ZapXmlConfiguration());
        // When
        extension.start();
        // Then
        ServerCertificateService certificateService = extension.getServerCertificateService();
        assertThat(
                certificateService.createCertificate(new CertData("example.org")),
                is(notNullValue()));
    }

    @Test
    void shouldSetRootCaCertOnStartIfAbleToLoadRootCaCert() throws Exception {
        // Given
        extension.hook(mock(ExtensionHook.class));
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        config.setProperty(
                "network.serverCertificates.rootCa.ks", NetworkTestUtils.FISH_CERT_BASE64_STR);
        extension.getServerCertificatesOptions().load(config);
        // When
        extension.start();
        // Then
        ServerCertificateService certificateService = extension.getServerCertificateService();
        assertThat(
                certificateService.createCertificate(new CertData("example.org")),
                is(notNullValue()));
    }

    @Test
    void shouldNotSetRootCaCertOnStartIfNotAbleToLoadRootCaCert() {
        // Given
        extension.hook(mock(ExtensionHook.class));
        // No configuration loaded in the options will lead to exception later.
        // When
        extension.start();
        // Then
        ServerCertificateService certificateService = extension.getServerCertificateService();
        GenerationException exception =
                assertThrows(
                        GenerationException.class,
                        () -> certificateService.createCertificate(null));
        assertThat(exception.getMessage(), is(equalTo("The root CA certificate was not set.")));
    }

    @Test
    void shouldWarnOfExpiredRootCaCertOnStart() throws Exception {
        // Given
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
        assertThat(logEvents, hasItem(startsWith("ZAP's Root CA certificate has expired")));
    }

    @Test
    void shouldNotBeUnloadable() {
        assertThat(extension.canUnload(), is(true));
    }

    @Test
    void shouldUnload() {
        // Given
        extension.initModel(model);
        // When
        extension.unload();
        // Then
        assertThat(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME), is(nullValue()));
        verify(session).setGlobalExcludedUrlRegexsSupplier(null);
    }

    @Test
    @SuppressWarnings("removal")
    void shouldUnloadLegacyProxyListenerHandlerAlways() {
        // Given
        extension.hook(mock(ExtensionHook.class));
        extension.initModel(model);
        LegacyProxyListenerHandler handler = extension.getLegacyProxyListenerHandler();
        // When
        extension.unload();
        // Then
        verify(extensionLoader).removeProxyServer(handler);
        assertThat(extension.getLegacyProxyListenerHandler(), is(nullValue()));
    }

    @Test
    void shouldUnloadLegacyConnectionParam() {
        // Given
        extension.initModel(model);
        CoreApiTest coreApi = new CoreApiTest();
        API.getInstance().registerApiImplementor(coreApi);
        // When
        extension.unload();
        // Then
        ArgumentCaptor<org.parosproxy.paros.network.ConnectionParam> argument =
                ArgumentCaptor.forClass(org.parosproxy.paros.network.ConnectionParam.class);
        verify(optionsParam, times(2)).setConnectionParam(argument.capture());
        assertThat(argument.getValue(), not(instanceOf(LegacyConnectionParam.class)));
        assertThat(coreApi.getLastAddedParam(), is(not(instanceOf(LegacyConnectionParam.class))));
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
        extension.hook(mock(ExtensionHook.class));
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        config.setProperty(
                "network.serverCertificates.rootCa.ks", NetworkTestUtils.FISH_CERT_BASE64_STR);
        extension.getServerCertificatesOptions().load(config);
        // When
        extension.writeRootCaCertAsPem(file);
        // Then
        assertThat(
                contents(file),
                allOf(
                        containsString(CertificateUtils.BEGIN_CERTIFICATE_TOKEN),
                        containsString(
                                "MIIC9TCCAl6gAwIBAgIJANL8E4epRNznMA0GCSqGSIb3DQEBBQUAMFsxGDAWBgNV\n"),
                        containsString(CertificateUtils.END_CERTIFICATE_TOKEN),
                        not(containsString(CertificateUtils.BEGIN_PRIVATE_KEY_TOKEN))));
    }

    @Test
    void shouldNotWriteRootCaCertAsPemIfRootCaKeyStoreMissing() throws Exception {
        // Given
        Path file = Files.createTempFile("rootca", ".cer");
        extension.hook(mock(ExtensionHook.class));
        // When
        extension.writeRootCaCertAsPem(file);
        // Then
        assertThat(contents(file), not(containsString(CertificateUtils.BEGIN_CERTIFICATE_TOKEN)));
    }

    @Test
    void shouldImportRootCaCert() throws Exception {
        // Given
        Path file = Files.createTempFile("rootca", ".cer");
        Files.write(file, NetworkTestUtils.FISH_CERT_PEM_BYTES);
        extensionStarted();
        // When
        String result = extension.importRootCaCert(file);
        // Then
        assertThat(result, is(nullValue()));
        assertThat(
                extension.getServerCertificatesOptions().getRootCaKeyStore(), is(notNullValue()));
        ServerCertificateService service = extension.getServerCertificateService();
        assertThat(service.createCertificate(new CertData("example.org")), is(notNullValue()));
    }

    @Test
    void shouldFailToImportRootCaCertIfUnableToCreateKeyStore() throws Exception {
        // Given
        Path file = Files.createTempFile("rootca", ".cer");
        Files.write(file, NetworkTestUtils.FISH_CERT_PEM_BYTES);
        // No options instance will lead to exception later.
        // When
        String result = extension.importRootCaCert(file);
        // Then
        assertThat(result, is(startsWith("Failed to create the KeyStore from the .pem file:")));
    }

    @Test
    void shouldFailToImportRootCaCertIfFileDoesNotExist() throws Exception {
        // Given
        Path file = Paths.get("/not/a/file.pem");
        // When
        String result = extension.importRootCaCert(file);
        // Then
        assertThat(result, is(startsWith("Failed to read the selected .pem file:")));
    }

    @Test
    void shouldFailToImportRootCaCertIfFileDoesNotContainCert() throws Exception {
        // Given
        Path file = Files.createTempFile("rootca", ".cer");
        // When
        String result = extension.importRootCaCert(file);
        // Then
        assertThat(result, is(startsWith("No certificate section found in the .pem file.")));
    }

    @Test
    void shouldFailToImportRootCaCertIfFileHasInvalidBase64Cert() throws Exception {
        // Given
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
    void shouldFailToImportRootCaCertIfFileDoesNotContainPrivateKey() throws Exception {
        // Given
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
    void shouldFailToImportRootCaCertIfFileHasInvalidBase64PrivateKey() throws Exception {
        // Given
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
        extension.hook(mock(ExtensionHook.class));
        HttpMessage msg = new HttpMessage(new HttpRequestHeader("GET / HTTP/1.1"));
        TestClient client =
                new TextTestClient(
                        "127.0.0.1",
                        ch -> ch.pipeline().addFirst("http.client", new HttpClientCodec()));
        given(optionsParam.getConnectionParam())
                .willReturn(new org.parosproxy.paros.network.ConnectionParam());
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
        extension.hook(mock(ExtensionHook.class));
        HttpMessage msg = new HttpMessage(new HttpRequestHeader("GET / HTTP/1.1"));
        TestClient client =
                new TextTestClient(
                        "127.0.0.1",
                        ch -> ch.pipeline().addFirst("http.client", new HttpClientCodec()));
        org.parosproxy.paros.network.ConnectionParam connectionParam =
                new org.parosproxy.paros.network.ConnectionParam();
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
        extension.hook(mock(ExtensionHook.class));
        HttpMessageHandler handler = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> extension.createHttpServer(handler));
    }

    @Test
    void shouldThrowIfCreatingHttpServerWithNullConfig() throws Exception {
        // Given
        extension.hook(mock(ExtensionHook.class));
        HttpServerConfig config = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> extension.createHttpServer(config));
    }

    @Test
    void shouldCreateHttpServerWithZapApi() throws Exception {
        // Given
        AtomicBoolean requestReachedHandler = new AtomicBoolean();
        HttpMessageHandler handler = (ctx, msg) -> requestReachedHandler.set(true);
        extension.hook(mock(ExtensionHook.class));
        HttpMessage msg = new HttpMessage(new HttpRequestHeader("GET http://zap/ HTTP/1.1"));
        TestClient client =
                new TextTestClient(
                        "127.0.0.1",
                        ch -> ch.pipeline().addFirst("http.client", new HttpClientCodec()));
        HttpServerConfig config =
                HttpServerConfig.builder()
                        .setHttpMessageHandler(handler)
                        .setServeZapApi(true)
                        .build();
        given(optionsParam.getApiParam()).willReturn(mock(OptionsParamApi.class));
        // When
        try (Server server = extension.createHttpServer(config)) {
            int port = server.start(Server.ANY_PORT);
            Channel channel = client.connect(port, null);
            channel.writeAndFlush(msg).sync();
            TextTestClient.waitForResponse(channel);
            // Then
            assertThat(requestReachedHandler.get(), is(equalTo(false)));
        } finally {
            client.close();
        }
    }

    @Test
    void shouldCreateHttpProxyWithZapApi() throws Exception {
        // Given
        AtomicBoolean requestReachedHandler = new AtomicBoolean();
        HttpMessageHandler handler = (ctx, msg) -> requestReachedHandler.set(true);
        extension.hook(mock(ExtensionHook.class));
        HttpMessage msg = new HttpMessage(new HttpRequestHeader("GET http://zap/ HTTP/1.1"));
        TestClient client =
                new TextTestClient(
                        "127.0.0.1",
                        ch -> ch.pipeline().addFirst("http.client", new HttpClientCodec()));
        HttpServerConfig config =
                HttpServerConfig.builder()
                        .setHttpMessageHandler(handler)
                        .setHttpSender(new HttpSender(1))
                        .setServeZapApi(true)
                        .build();
        given(optionsParam.getApiParam()).willReturn(mock(OptionsParamApi.class));
        // When
        try (Server server = extension.createHttpServer(config)) {
            int port = server.start(Server.ANY_PORT);
            Channel channel = client.connect(port, null);
            channel.writeAndFlush(msg).sync();
            TextTestClient.waitForResponse(channel);
            // Then
            assertThat(requestReachedHandler.get(), is(equalTo(false)));
        } finally {
            client.close();
        }
    }

    @Test
    void shouldGetProxyPacContent() {
        // Given
        extension.hook(mock(ExtensionHook.class));
        String domain = "X";
        // When
        String proxyPacContent = extension.getProxyPacContent(domain);
        // Then
        assertThat(
                proxyPacContent,
                is(
                        equalTo(
                                "function FindProxyForURL(url, host) {\n  return \"PROXY localhost:8080\";\n} // End of function\n")));
    }

    @Test
    void shouldGetProxyPacContentWithAccessedDomainIfProxyAnyAddressAndNotZapDomain() {
        // Given
        extension.hook(mock(ExtensionHook.class));
        extension.getLocalServersOptions().load(new ZapXmlConfiguration());
        extension.getLocalServersOptions().getMainProxy().setAddress("0.0.0.0");
        String domain = "127.0.0.1";
        // When
        String proxyPacContent = extension.getProxyPacContent(domain);
        // Then
        assertThat(
                proxyPacContent,
                is(
                        equalTo(
                                "function FindProxyForURL(url, host) {\n  return \"PROXY 127.0.0.1:8080\";\n} // End of function\n")));
    }

    @Test
    void shouldGetProxyPacContentWithAnyAddressIfNoAddressKnown() {
        // Given
        extension.hook(mock(ExtensionHook.class));
        extension.getLocalServersOptions().load(new ZapXmlConfiguration());
        extension.getLocalServersOptions().getMainProxy().setAddress("0.0.0.0");
        String domain = "zap";
        // When
        String proxyPacContent = extension.getProxyPacContent(domain);
        // Then
        assertThat(
                proxyPacContent,
                is(
                        equalTo(
                                "function FindProxyForURL(url, host) {\n  return \"PROXY 0.0.0.0:8080\";\n} // End of function\n")));
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
            args[i] =
                    mock(CommandLineArgument.class, withSettings().strictness(Strictness.LENIENT));
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

    private static class CoreApiTest extends CoreAPI {

        private AbstractParam param;

        CoreApiTest() {
            super(new org.parosproxy.paros.network.ConnectionParam());
        }

        AbstractParam getLastAddedParam() {
            return param;
        }

        @Override
        public void addApiOptions(AbstractParam param) {
            this.param = param;
            super.addApiOptions(param);
        }
    }
}
