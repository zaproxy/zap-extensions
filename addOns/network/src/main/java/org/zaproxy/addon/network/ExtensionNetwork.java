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

import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.util.NettyRuntime;
import io.netty.util.concurrent.DefaultEventExecutorGroup;
import io.netty.util.concurrent.DefaultThreadFactory;
import io.netty.util.concurrent.EventExecutorGroup;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.Authenticator;
import java.net.BindException;
import java.net.InetAddress;
import java.net.PasswordAuthentication;
import java.net.ProxySelector;
import java.net.ServerSocket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.channels.UnresolvedAddressException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.swing.GroupLayout;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import org.apache.commons.httpclient.HttpState;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.cookie.CookieStore;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.OptionsDialog;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.network.LocalServersOptions.ServersChangedListener;
import org.zaproxy.addon.network.internal.TlsUtils;
import org.zaproxy.addon.network.internal.cert.CertData;
import org.zaproxy.addon.network.internal.cert.CertificateUtils;
import org.zaproxy.addon.network.internal.cert.GenerationException;
import org.zaproxy.addon.network.internal.cert.ServerCertificateGenerator;
import org.zaproxy.addon.network.internal.cert.ServerCertificateService;
import org.zaproxy.addon.network.internal.client.CloseableHttpSenderImpl;
import org.zaproxy.addon.network.internal.client.HttpProxy;
import org.zaproxy.addon.network.internal.client.LegacyUtils;
import org.zaproxy.addon.network.internal.client.ZapAuthenticator;
import org.zaproxy.addon.network.internal.client.ZapProxySelector;
import org.zaproxy.addon.network.internal.client.apachev5.HttpSenderApache;
import org.zaproxy.addon.network.internal.handlers.PassThroughHandler;
import org.zaproxy.addon.network.internal.server.AliasChecker;
import org.zaproxy.addon.network.internal.server.http.HttpServer;
import org.zaproxy.addon.network.internal.server.http.LocalServer;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig.ServerMode;
import org.zaproxy.addon.network.internal.server.http.LocalServerHandler;
import org.zaproxy.addon.network.internal.server.http.MainProxyHandler;
import org.zaproxy.addon.network.internal.server.http.MainServerHandler;
import org.zaproxy.addon.network.internal.server.http.handlers.CloseOnRecursiveRequestHandler;
import org.zaproxy.addon.network.internal.server.http.handlers.ConnectReceivedHandler;
import org.zaproxy.addon.network.internal.server.http.handlers.DecodeResponseHandler;
import org.zaproxy.addon.network.internal.server.http.handlers.HttpSenderHandler;
import org.zaproxy.addon.network.internal.server.http.handlers.LegacyProxyListenerHandler;
import org.zaproxy.addon.network.internal.server.http.handlers.RemoveAcceptEncodingHandler;
import org.zaproxy.addon.network.internal.ui.LocalServerInfoLabel;
import org.zaproxy.addon.network.internal.ui.PromptHttpProxyPasswordDialog;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.addon.network.server.ServerInfo;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiElement;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.brk.ExtensionBreak;
import org.zaproxy.zap.utils.ZapPortNumberSpinner;

public class ExtensionNetwork extends ExtensionAdaptor implements CommandLineListener {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionNetwork.class);

    static {
        ProxySelector.setDefault(ZapProxySelector.getSingleton());
        Authenticator.setDefault(ZapAuthenticator.getSingleton());
    }

    private static final int NO_PORT_OVERRIDE = -1;
    private static final int INVALID_PORT = -2;

    private static final String I18N_PREFIX = "network";

    private static final int ARG_CERT_LOAD = 0;
    private static final int ARG_CERT_PUB_DUMP = 1;
    private static final int ARG_CERT_FULL_DUMP = 2;

    private static final int ARG_HOST_IDX = 3;
    private static final int ARG_PORT_IDX = 4;

    private CloseableHttpSenderImpl<?> httpSenderNetwork;

    @SuppressWarnings("deprecation")
    private org.parosproxy.paros.network.ConnectionParam legacyConnectionOptions;

    private LegacyProxyListenerHandler legacyProxyListenerHandler;
    private Object syncGroups = new Object();
    private boolean groupsInitiated;
    private NioEventLoopGroup mainEventLoopGroup;
    private EventExecutorGroup mainEventExecutorGroup;

    private ClientCertificatesOptions clientCertificatesOptions;
    private ClientCertificatesOptionsPanel clientCertificatesOptionsPanel;

    private ServerCertificatesOptions serverCertificatesOptions;
    private ServerCertificatesOptionsPanel serverCertificatesOptionsPanel;

    private ServerCertificateServiceImpl serverCertificateService;

    private LocalServersOptions localServersOptions;
    private LocalServersOptionsPanel localServersOptionsPanel;

    private ConnectionOptions connectionOptions;
    private ConnectionOptionsPanel connectionOptionsPanel;

    private HttpSender proxyHttpSender;
    private HttpSenderHandler httpSenderHandler;
    private PassThroughHandler passThroughHandler;
    private AliasChecker aliasChecker;
    private Map<String, LocalServer> localServers;
    private LocalServer mainProxyServer;
    private ServerInfo mainProxyServerInfo;
    private LocalServerHandler.SerialiseState serialiseForBreak;
    private ExtensionBreak extensionBreak;
    private Method addBreakListenerMethod;
    private Method removeBreakListenerMethod;

    private LocalServerInfoLabel localServerInfoLabel;

    private CookieStore globalCookieStore;
    private HttpState globalHttpState;

    @SuppressWarnings("deprecation")
    public ExtensionNetwork() {
        super(ExtensionNetwork.class.getSimpleName());

        setI18nPrefix(I18N_PREFIX);

        // Let the servers start after everything has been initialised.
        setOrder(Integer.MAX_VALUE);

        // Force initialisation.
        TlsUtils.getSupportedTlsProtocols();

        connectionOptions = new ConnectionOptions();
        legacyConnectionOptions =
                new LegacyConnectionParam(
                        () -> {
                            LegacyUtils.updateHttpState(globalHttpState, globalCookieStore);
                            return globalHttpState;
                        },
                        connectionOptions);
        Model.getSingleton().getOptionsParam().setConnectionParam(legacyConnectionOptions);

        clientCertificatesOptions = new ClientCertificatesOptions();

        try {
            httpSenderNetwork =
                    new HttpSenderApache(
                            this::getGlobalCookieStore,
                            connectionOptions,
                            clientCertificatesOptions,
                            () -> legacyProxyListenerHandler);
            HttpSender.setImpl(httpSenderNetwork);
        } catch (Exception e) {
            LOGGER.error("An error occurred while creating the sender:", e);
        }
    }

    /**
     * Gets the global cookie store.
     *
     * @return the global cookie store, might be {@code null}.
     */
    CookieStore getGlobalCookieStore() {
        return globalCookieStore;
    }

    /**
     * Gets the global HTTP state.
     *
     * @return the global HTTP state, might be {@code null}.
     */
    HttpState getGlobalHttpState() {
        return globalHttpState;
    }

    ConnectionOptions getConnectionOptions() {
        return connectionOptions;
    }

    ClientCertificatesOptions getClientCertificatesOptions() {
        return clientCertificatesOptions;
    }

    AliasChecker getAliasChecker() {
        return aliasChecker;
    }

    @Override
    public void init() {
        localServers = Collections.synchronizedMap(new HashMap<>());

        extensionBreak =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionBreak.class);
        if (extensionBreak != null) {
            try {
                addBreakListenerMethod =
                        extensionBreak
                                .getClass()
                                .getDeclaredMethod(
                                        "addSerialisationRequiredListener", Consumer.class);
                removeBreakListenerMethod =
                        extensionBreak
                                .getClass()
                                .getDeclaredMethod(
                                        "removeSerialisationRequiredListener", Consumer.class);
            } catch (Exception e) {
                LOGGER.error("An error occurred while getting the break methods:", e);
            }
        }
    }

    @Override
    public void initModel(Model model) {
        super.initModel(model);

        mainProxyServerInfo =
                new ServerInfo() {

                    @Override
                    @SuppressWarnings("deprecation")
                    public String getAddress() {
                        return getModel().getOptionsParam().getProxyParam().getProxyIp();
                    }

                    @Override
                    @SuppressWarnings("deprecation")
                    public int getPort() {
                        return getModel().getOptionsParam().getProxyParam().getProxyPort();
                    }
                };

        proxyHttpSender = new HttpSender(HttpSender.PROXY_INITIATOR);
        httpSenderHandler = new HttpSenderHandler(proxyHttpSender);
    }

    private NioEventLoopGroup getMainEventLoopGroup() {
        if (!groupsInitiated) {
            initEventGroups();
        }
        return mainEventLoopGroup;
    }

    private EventExecutorGroup getMainEventExecutorGroup() {
        if (!groupsInitiated) {
            initEventGroups();
        }
        return mainEventExecutorGroup;
    }

    private void initEventGroups() {
        synchronized (syncGroups) {
            if (groupsInitiated) {
                return;
            }

            if (mainEventLoopGroup == null) {
                mainEventLoopGroup =
                        new NioEventLoopGroup(
                                NettyRuntime.availableProcessors(),
                                new DefaultThreadFactory("ZAP-IO", Thread.MAX_PRIORITY));
            }

            if (mainEventExecutorGroup == null) {
                mainEventExecutorGroup =
                        new DefaultEventExecutorGroup(
                                NettyRuntime.availableProcessors(),
                                new DefaultThreadFactory(
                                        "ZAP-IO-EventExecutor", Thread.MAX_PRIORITY));
            }

            groupsInitiated = true;
        }
    }

    private void shutdownEventGroups() {
        synchronized (syncGroups) {
            if (mainEventLoopGroup != null) {
                try {
                    mainEventLoopGroup.shutdownGracefully().sync();
                } catch (InterruptedException e) {
                    LOGGER.warn(
                            "Interrupted while waiting for the main event loop group to shutdown.");
                    Thread.currentThread().interrupt();
                    return;
                }
                mainEventLoopGroup = null;
            }

            if (mainEventExecutorGroup != null) {
                try {
                    mainEventExecutorGroup.shutdownGracefully().sync();
                } catch (InterruptedException e) {
                    LOGGER.warn(
                            "Interrupted while waiting for the main event executor group to shutdown.");
                    Thread.currentThread().interrupt();
                }
            }

            groupsInitiated = false;
        }
    }

    /**
     * Creates an HTTP server.
     *
     * <p>The CONNECT requests are automatically handled as is the possible TLS upgrade.
     *
     * @param handler the message handler.
     * @return the server.
     * @throws NullPointerException if the given handler is {@code null}.
     * @since 0.1.0
     */
    public Server createHttpServer(HttpMessageHandler handler) {
        Objects.requireNonNull(handler);
        List<HttpMessageHandler> handlers =
                Arrays.asList(ConnectReceivedHandler.getSetAndOverrideInstance(), handler);
        return createHttpServer(() -> new MainServerHandler(handlers));
    }

    private Server createHttpServer(Supplier<MainServerHandler> handler) {
        return new HttpServer(
                getMainEventLoopGroup(),
                getMainEventExecutorGroup(),
                serverCertificateService,
                handler);
    }

    /**
     * Gets the server info of the main proxy.
     *
     * @return the server info.
     * @since 0.2.0
     */
    public ServerInfo getMainProxyServerInfo() {
        return mainProxyServerInfo;
    }

    /**
     * Creates an HTTP proxy.
     *
     * <p>The CONNECT requests are automatically handled as is the possible TLS upgrade. The
     * connection is automatically closed on recursive requests.
     *
     * @param initiator the initiator used for the {@code HttpSender}.
     * @param handler the message handler.
     * @return the server.
     * @throws NullPointerException if the given handler is {@code null}.
     * @since 0.1.0
     */
    public Server createHttpProxy(int initiator, HttpMessageHandler handler) {
        Objects.requireNonNull(handler);
        HttpSender httpSender = new HttpSender(initiator);
        return createHttpProxy(httpSender, handler);
    }

    /**
     * Creates an HTTP proxy using an existing {@code HttpSender}.
     *
     * <p>The CONNECT requests are automatically handled as is the possible TLS upgrade. The
     * connection is automatically closed on recursive requests.
     *
     * @param httpSender the HTTP sender.
     * @param handler the message handler.
     * @return the server.
     * @throws NullPointerException if the HTTP sender and given handler are {@code null}.
     * @since 0.1.0
     */
    public Server createHttpProxy(HttpSender httpSender, HttpMessageHandler handler) {
        Objects.requireNonNull(handler);
        Objects.requireNonNull(httpSender);
        List<HttpMessageHandler> handlers =
                Arrays.asList(
                        ConnectReceivedHandler.getSetAndOverrideInstance(),
                        CloseOnRecursiveRequestHandler.getInstance(),
                        RemoveAcceptEncodingHandler.getEnabledInstance(),
                        DecodeResponseHandler.getEnabledInstance(),
                        handler,
                        new HttpSenderHandler(httpSender));
        return createHttpServer(() -> new MainProxyHandler(legacyProxyListenerHandler, handlers));
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("network.ext.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("network.ext.desc");
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        extensionHook.addApiImplementor(new NetworkApi(this));
        extensionHook.addSessionListener(new SessionChangedListenerImpl());

        legacyProxyListenerHandler = new LegacyProxyListenerHandler();
        Control.getSingleton().getExtensionLoader().addProxyServer(legacyProxyListenerHandler);

        extensionHook.addCommandLine(createCommandLineArgs());

        serverCertificateService = new ServerCertificateServiceImpl();

        serverCertificatesOptions = new ServerCertificatesOptions();
        extensionHook.addOptionsParamSet(serverCertificatesOptions);

        localServersOptions = new LocalServersOptions();
        localServersOptions.addServersChangedListener(new ServersChangedListenerImpl());
        extensionHook.addOptionsParamSet(localServersOptions);

        passThroughHandler =
                new PassThroughHandler(
                        requestHeader ->
                                localServersOptions.getPassThroughs().stream()
                                        .anyMatch(e -> e.test(requestHeader)));

        aliasChecker =
                requestHeader -> {
                    if (API.API_DOMAIN.equals(requestHeader.getHostName())) {
                        return true;
                    }

                    return localServersOptions.getAliases().stream()
                            .anyMatch(e -> e.test(requestHeader));
                };

        extensionHook.addApiImplementor(new LegacyProxiesApi(this));

        ApiImplementor coreApi = API.getInstance().getImplementors().get("core");
        if (coreApi != null) {
            updateOldCoreApiEndpoints(coreApi, legacyConnectionOptions);
        }

        extensionHook.addOptionsParamSet(connectionOptions);
        extensionHook.addOptionsChangedListener(new OptionsChangedListenerImpl());

        extensionHook.addOptionsParamSet(clientCertificatesOptions);

        if (hasView()) {
            ExtensionHookView hookView = extensionHook.getHookView();
            OptionsDialog optionsDialog = View.getSingleton().getOptionsDialog("");
            String[] networkNode = {Constant.messages.getString("network.ui.options.name")};
            serverCertificatesOptionsPanel = new ServerCertificatesOptionsPanel(this);
            optionsDialog.addParamPanel(networkNode, serverCertificatesOptionsPanel, true);

            localServersOptionsPanel = new LocalServersOptionsPanel(this);
            optionsDialog.addParamPanel(networkNode, localServersOptionsPanel, true);

            localServerInfoLabel =
                    new LocalServerInfoLabel(
                            getView().getMainFrame().getMainFooterPanel(), localServersOptions);

            hookView.addOptionPanel(
                    new LegacyOptionsPanel("dynssl", serverCertificatesOptionsPanel));
            hookView.addOptionPanel(new LegacyOptionsPanel("proxies", localServersOptionsPanel));

            connectionOptionsPanel = new ConnectionOptionsPanel();
            optionsDialog.addParamPanel(networkNode, connectionOptionsPanel, true);
            hookView.addOptionPanel(new LegacyOptionsPanel("connection", connectionOptionsPanel));

            clientCertificatesOptionsPanel =
                    new ClientCertificatesOptionsPanel(View.getSingleton());
            optionsDialog.addParamPanel(networkNode, clientCertificatesOptionsPanel, true);
            hookView.addOptionPanel(
                    new LegacyOptionsPanel("clientcerts", clientCertificatesOptionsPanel));
        }
    }

    private static void updateOldCoreApiEndpoints(
            ApiImplementor coreApi,
            @SuppressWarnings("deprecation")
                    org.parosproxy.paros.network.ConnectionParam connectionParam) {
        List<String> views =
                Arrays.asList(
                        "optionDefaultUserAgent",
                        "optionDnsTtlSuccessfulQueries",
                        "optionHttpState",
                        "optionHttpStateEnabled",
                        "optionProxyChainName",
                        "optionProxyChainPassword",
                        "optionProxyChainPort",
                        "optionProxyChainPrompt",
                        "optionProxyChainRealm",
                        "optionProxyChainUserName",
                        "optionSingleCookieRequestHeader",
                        "optionTimeoutInSecs",
                        "optionUseProxyChain",
                        "optionUseProxyChainAuth",
                        "optionUseSocksProxy");
        coreApi.getApiViews().removeIf(view -> views.contains(view.getName()));

        List<String> actions =
                Arrays.asList(
                        "setOptionDefaultUserAgent",
                        "setOptionDnsTtlSuccessfulQueries",
                        "setOptionHttpStateEnabled",
                        "setOptionProxyChainName",
                        "setOptionProxyChainPassword",
                        "setOptionProxyChainPort",
                        "setOptionProxyChainPrompt",
                        "setOptionProxyChainRealm",
                        "setOptionProxyChainUserName",
                        "setOptionSingleCookieRequestHeader",
                        "setOptionTimeoutInSecs",
                        "setOptionUseProxyChain",
                        "setOptionUseProxyChainAuth",
                        "setOptionUseSocksProxy");
        coreApi.getApiActions().removeIf(action -> actions.contains(action.getName()));

        coreApi.addApiOptions(connectionParam);

        deprecateApiElements(views, coreApi::getApiView);
        deprecateApiElements(actions, coreApi::getApiAction);

        coreApi.getApiView("optionSingleCookieRequestHeader")
                .setDeprecatedDescription(
                        Constant.messages.getString("api.deprecated.option.endpoint"));
        coreApi.getApiAction("setOptionSingleCookieRequestHeader")
                .setDeprecatedDescription(
                        Constant.messages.getString("api.deprecated.option.endpoint"));
    }

    private static <T extends ApiElement> void deprecateApiElements(
            List<String> names, Function<String, T> method) {
        names.forEach(
                name -> {
                    T element = method.apply(name);
                    element.setDeprecated(true);
                    element.setDeprecatedDescription(
                            Constant.messages.getString("network.api.legacy.deprecated.network"));
                });
    }

    private class ServersChangedListenerImpl implements ServersChangedListener {

        @Override
        public void mainProxySet(LocalServerConfig mainProxyConfig) {
            if (mainProxyServer == null) {
                return;
            }

            if (mainProxyServer.getConfig().updateFrom(mainProxyConfig)) {
                try {
                    mainProxyServer.start();
                    updateCoreProxy(mainProxyConfig);
                } catch (IOException e) {
                    LOGGER.warn("An error occurred while restarting the main proxy:", e);
                }
            }
        }

        @Override
        public void serverAdded(LocalServerConfig serverConfig) {
            if (serverConfig.isEnabled()) {
                startAdditionalLocalServer(createLocalServer(serverConfig));
            }
        }

        @Override
        public void serverRemoved(LocalServerConfig serverConfig) {
            stopAdditionalLocalServer(localServers.remove(keyLocalServer(serverConfig)));
        }

        @Override
        public void serversSet(List<LocalServerConfig> configs) {
            localServers.values().removeIf(server -> checkLocalServerChange(server, configs));

            configs.parallelStream()
                    .filter(LocalServerConfig::isEnabled)
                    .filter(e -> !localServers.containsKey(keyLocalServer(e)))
                    .forEach(e -> startAdditionalLocalServer(createLocalServer(e)));
        }
    }

    private boolean checkLocalServerChange(LocalServer server, List<LocalServerConfig> configs) {
        Optional<LocalServerConfig> result =
                configs.parallelStream()
                        .filter(
                                config -> {
                                    if (config.getPort() != server.getConfig().getPort()) {
                                        return false;
                                    }
                                    return config.getAddress()
                                            .equals(server.getConfig().getAddress());
                                })
                        .findAny();

        if (result.isPresent()) {
            LocalServerConfig newConfig = result.get();
            if (!newConfig.isEnabled()) {
                stopAdditionalLocalServer(server);
                return true;
            }

            if (server.getConfig().updateFrom(newConfig)) {
                startAdditionalLocalServer(server);
            }
            return false;
        }

        stopAdditionalLocalServer(server);
        return true;
    }

    @Override
    public void optionsLoaded() {
        if (hasView() && !connectionOptions.isStoreHttpProxyPass()) {
            char[] password = new PromptHttpProxyPasswordDialog().getPassword();
            if (password.length != 0) {
                HttpProxy oldProxy = connectionOptions.getHttpProxy();
                HttpProxy httpProxy =
                        new HttpProxy(
                                oldProxy.getHost(),
                                oldProxy.getPort(),
                                oldProxy.getRealm(),
                                new PasswordAuthentication(
                                        oldProxy.getPasswordAuthentication().getUserName(),
                                        password));
                connectionOptions.setHttpProxy(httpProxy);
            }
        }
    }

    @Override
    public void postInit() {
        serialiseForBreak = new BreakSerialiseState();
        if (addBreakListenerMethod != null) {
            try {
                addBreakListenerMethod.invoke(extensionBreak, serialiseForBreak);
            } catch (Exception e) {
                LOGGER.error("An error occurred while adding the break listener:", e);
            }
        }

        if (hasView()) {
            localServerInfoLabel.update();
        }
    }

    private static class BreakSerialiseState
            implements LocalServerHandler.SerialiseState, Consumer<Boolean> {

        private volatile boolean serialise;

        @Override
        public void accept(Boolean serialise) {
            this.serialise = serialise;
        }

        @Override
        public boolean isSerialise() {
            return serialise;
        }
    }

    @Override
    public void postInstall() {
        startLocalServers(null, NO_PORT_OVERRIDE, true);
    }

    private void startAdditionalLocalServer(LocalServer server) {
        if (server == null) {
            return;
        }

        String key = keyLocalServer(server.getConfig());
        try {
            server.start();
            localServers.put(key, server);
            LOGGER.info("Started additional server: {}", key);
        } catch (IOException e) {
            LOGGER.warn("Failed to start additional server {} reason: {}", key, e.getMessage());
        }
    }

    private static boolean stopLocalServer(LocalServer server) {
        if (server == null) {
            return false;
        }

        try {
            server.close();
        } catch (IOException e) {
            LOGGER.debug("An error occurred while stopping the server:", e);
        }
        return true;
    }

    private static boolean stopAdditionalLocalServer(LocalServer server) {
        if (stopLocalServer(server)) {
            LOGGER.info("Stopped additional server: {}", () -> keyLocalServer(server.getConfig()));
        }
        return true;
    }

    private LocalServer createLocalServer(LocalServerConfig config) {
        return new LocalServer(
                getMainEventLoopGroup(),
                getMainEventExecutorGroup(),
                serverCertificateService,
                legacyProxyListenerHandler,
                passThroughHandler,
                httpSenderHandler,
                new LocalServerConfig(config, aliasChecker),
                serialiseForBreak,
                getModel());
    }

    private void startLocalServers(String overrideAddress, int overridePort, boolean install) {
        boolean commandLineMode = ZAP.getProcessType() == ZAP.ProcessType.cmdline;
        boolean daemonMode = ZAP.getProcessType() == ZAP.ProcessType.daemon;

        if (!commandLineMode) {
            localServersOptions.getServers().stream()
                    .filter(LocalServerConfig::isEnabled)
                    .map(this::createLocalServer)
                    .forEach(this::startAdditionalLocalServer);
        }

        LocalServerConfig serverConfig = localServersOptions.getMainProxy();
        boolean overrides = false;
        String address = serverConfig.getAddress();
        if (overrideAddress != null) {
            address = overrideAddress;
            serverConfig.setAddress(address);
            overrides = true;
        }

        int port = serverConfig.getPort();
        if (overridePort > 0) {
            port = overridePort;
            serverConfig.setPort(port);
            overrides = true;
        }

        if (overrides) {
            localServersOptions.setMainProxy(serverConfig);
        }

        updateCoreProxy(serverConfig);

        if (commandLineMode) {
            serverConfig.setMode(ServerMode.PROXY);
        }

        mainProxyServer = createLocalServer(serverConfig);
        if (overridePort == INVALID_PORT) {
            return;
        }

        try {
            mainProxyServer.start();

            if (daemonMode) {
                LOGGER.info("ZAP is now listening on {}:{}", address, port);
            }
        } catch (Exception e) {

            if (!install && (daemonMode || commandLineMode)) {
                String message =
                        "Failed to start the main proxy: "
                                + e.getClass().getName()
                                + " "
                                + e.getMessage();
                LOGGER.warn(message);
                if (commandLineMode) {
                    System.err.println(message);
                }

                shutdownZap("Terminating ZAP, unable to start the main proxy.");
            }

            String detailedError = null;
            if (e instanceof UnresolvedAddressException) {
                detailedError =
                        Constant.messages.getString(
                                "network.cmdline.proxy.error.host.unknown", address);
            } else if (e instanceof BindException || e instanceof SocketException) {
                if (containsMessage(e, "requested address")) {
                    detailedError =
                            Constant.messages.getString(
                                    "network.cmdline.proxy.error.host.assign", address);
                } else if (containsMessage(e, "denied") || containsMessage(e, "in use")) {
                    if (promptUserMainProxyPort()) {
                        return;
                    }

                    detailedError =
                            Constant.messages.getString(
                                    "network.cmdline.proxy.error.port",
                                    address,
                                    String.valueOf(port));
                }
            }

            if (detailedError == null) {
                detailedError =
                        Constant.messages.getString(
                                "network.cmdline.proxy.error.generic", e.getMessage());
                LOGGER.warn("Failed to start the main proxy: {}", e.getMessage());
            }

            JOptionPane.showMessageDialog(
                    getView().getMainFrame(),
                    Constant.messages.getString(
                            "network.cmdline.proxy.error.message", detailedError),
                    Constant.messages.getString("network.cmdline.proxy.error.title"),
                    JOptionPane.WARNING_MESSAGE);
        }
    }

    @SuppressWarnings("deprecation")
    private void updateCoreProxy(LocalServerConfig serverConfig) {
        org.parosproxy.paros.core.proxy.ProxyParam proxyParam =
                getModel().getOptionsParam().getProxyParam();
        proxyParam.setProxyIp(
                serverConfig.isAnyLocalAddress()
                        ? getLocalhostAddress()
                        : serverConfig.getAddress());
        proxyParam.setProxyPort(serverConfig.getPort());
    }

    private static String getLocalhostAddress() {
        try {
            return InetAddress.getLocalHost().getHostAddress();
        } catch (UnknownHostException ex) {
            return LocalServerConfig.DEFAULT_ADDRESS;
        }
    }

    @SuppressWarnings("deprecation")
    private boolean promptUserMainProxyPort() {
        LocalServerConfig serverConfig = mainProxyServer.getConfig();
        PromptPortPanel prompt =
                new PromptPortPanel(serverConfig.getAddress(), serverConfig.getPort());
        do {
            int result =
                    JOptionPane.showConfirmDialog(
                            getView().getMainFrame(),
                            prompt,
                            Constant.messages.getString("network.cmdline.proxy.error.title"),
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.WARNING_MESSAGE,
                            null);
            if (result != JOptionPane.YES_OPTION) {
                return false;
            }

            mainProxyServer.getConfig().setPort(prompt.getPort());
            try {
                mainProxyServer.start();
                break;
            } catch (Exception ignore) {
                // Keep trying.
            }

            prompt.retry();

        } while (true);

        org.parosproxy.paros.core.proxy.ProxyParam proxyParam =
                getModel().getOptionsParam().getProxyParam();
        proxyParam.setProxyPort(prompt.getPort());

        LocalServer currentProxyServer = mainProxyServer;
        mainProxyServer = null;
        localServersOptions.setMainProxy(serverConfig);
        mainProxyServer = currentProxyServer;
        return true;
    }

    private static class PromptPortPanel extends JPanel {

        private static final long serialVersionUID = 1L;

        private static final int MAX_PORT_RETRIES = 50;

        private final String address;
        private final JLabel label;
        private final ZapPortNumberSpinner portSpinner;

        public PromptPortPanel(String address, int port) {
            this.address = address;

            label = new JLabel();
            portSpinner = new ZapPortNumberSpinner(port);

            GroupLayout layout = new GroupLayout(this);
            setLayout(layout);
            layout.setAutoCreateGaps(true);
            layout.setAutoCreateContainerGaps(true);

            layout.setHorizontalGroup(
                    layout.createSequentialGroup().addComponent(label).addComponent(portSpinner));
            layout.setVerticalGroup(
                    layout.createParallelGroup().addComponent(label).addComponent(portSpinner));

            retry();
        }

        void retry() {
            int port = portSpinner.getValue();
            label.setText(
                    Constant.messages.getString(
                            "network.cmdline.proxy.error.port.retry", String.valueOf(port)));
            if (port < 1024 || port > Server.MAX_PORT - MAX_PORT_RETRIES) {
                port = 1024;
            }

            int maxPort = port + MAX_PORT_RETRIES;
            for (; port <= maxPort; port++) {
                try (ServerSocket server =
                        new ServerSocket(port, 0, InetAddress.getByName(address))) {
                    port = server.getLocalPort();
                    break;
                } catch (IOException ignore) {
                    // Just trying to get a free port.
                }
            }

            portSpinner.setValue(port);
        }

        int getPort() {
            return portSpinner.getValue();
        }
    }

    private static boolean containsMessage(Exception e, String contents) {
        String message = e.getMessage();
        if (message == null) {
            return false;
        }
        return message.contains(contents);
    }

    private static String keyLocalServer(LocalServerConfig serverConfig) {
        return serverConfig.getAddress() + ":" + serverConfig.getPort();
    }

    /**
     * Removes the configurations of the started local servers.
     *
     * @param serverConfigs the server configurations to filter.
     */
    void removeStartedLocalServers(Set<LocalServerConfig> serverConfigs) {
        if (mainProxyServer.isStarted()) {
            serverConfigs.remove(mainProxyServer.getConfig());
        }
        localServers.values().stream()
                .filter(LocalServer::isStarted)
                .map(LocalServer::getConfig)
                .forEach(serverConfigs::remove);
    }

    LegacyProxyListenerHandler getLegacyProxyListenerHandler() {
        return legacyProxyListenerHandler;
    }

    PassThroughHandler getPassThroughHandler() {
        return passThroughHandler;
    }

    private static CommandLineArgument[] createCommandLineArgs() {
        CommandLineArgument[] arguments = new CommandLineArgument[5];
        arguments[ARG_CERT_LOAD] =
                new CommandLineArgument(
                        "-certload",
                        1,
                        null,
                        "",
                        "-certload <path>         "
                                + Constant.messages.getString("network.cmdline.certload"));
        arguments[ARG_CERT_PUB_DUMP] =
                new CommandLineArgument(
                        "-certpubdump",
                        1,
                        null,
                        "",
                        "-certpubdump <path>      "
                                + Constant.messages.getString("network.cmdline.certpubdump"));
        arguments[ARG_CERT_FULL_DUMP] =
                new CommandLineArgument(
                        "-certfulldump",
                        1,
                        null,
                        "",
                        "-certfulldump <path>     "
                                + Constant.messages.getString("network.cmdline.certfulldump"));

        arguments[ARG_HOST_IDX] =
                new CommandLineArgument(
                        "-host",
                        1,
                        null,
                        "",
                        "-host <host>             "
                                + Constant.messages.getString("network.cmdline.proxy.host"));
        arguments[ARG_PORT_IDX] =
                new CommandLineArgument(
                        "-port",
                        1,
                        null,
                        "",
                        "-port <port>             "
                                + Constant.messages.getString("network.cmdline.proxy.port"));
        return arguments;
    }

    @Override
    public void execute(CommandLineArgument[] arguments) {
        if (arguments[ARG_CERT_LOAD].isEnabled()) {
            Path file = Paths.get(arguments[ARG_CERT_LOAD].getArguments().firstElement());
            if (!Files.isReadable(file)) {
                CommandLine.error(
                        Constant.messages.getString(
                                "network.cmdline.error.noread", file.toAbsolutePath()));
            } else {
                String error = importRootCaCert(file);
                if (error == null) {
                    CommandLine.info(
                            Constant.messages.getString(
                                    "network.cmdline.certload.done", file.toAbsolutePath()));
                } else {
                    CommandLine.error(error);
                }
            }
        }
        if (arguments[ARG_CERT_PUB_DUMP].isEnabled()) {
            writeCert(
                    arguments[ARG_CERT_PUB_DUMP].getArguments().firstElement(),
                    this::writeRootCaCertAsPem);
        }
        if (arguments[ARG_CERT_FULL_DUMP].isEnabled()) {
            writeCert(
                    arguments[ARG_CERT_FULL_DUMP].getArguments().firstElement(),
                    this::writeRootCaCertAndPrivateKeyAsPem);
        }

        String mainProxyAddress = null;
        if (arguments[ARG_HOST_IDX].isEnabled()) {
            mainProxyAddress = arguments[ARG_HOST_IDX].getArguments().firstElement();
        }

        int mainProxyPort = NO_PORT_OVERRIDE;
        if (arguments[ARG_PORT_IDX].isEnabled()) {
            String argValue = arguments[ARG_PORT_IDX].getArguments().firstElement();
            try {
                mainProxyPort = Server.validatePort(Integer.parseInt(argValue));
            } catch (IllegalArgumentException e) {
                String message =
                        "The main proxy will not be started, invalid -port value: " + argValue;
                LOGGER.warn(message);
                boolean commandLineMode = ZAP.getProcessType() == ZAP.ProcessType.cmdline;
                if (commandLineMode) {
                    System.err.println(message);
                }

                if (ZAP.getProcessType() == ZAP.ProcessType.daemon || commandLineMode) {
                    shutdownZap("Terminating ZAP, unable to start the main proxy.");
                }

                mainProxyPort = INVALID_PORT;
                JOptionPane.showMessageDialog(
                        getView().getMainFrame(),
                        Constant.messages.getString(
                                "network.cmdline.proxy.port.invalid.message", argValue),
                        Constant.messages.getString("network.cmdline.proxy.port.invalid.title"),
                        JOptionPane.WARNING_MESSAGE);
            }
        }

        startLocalServers(mainProxyAddress, mainProxyPort, false);
    }

    private static void shutdownZap(String error) throws RuntimeException {
        CommandLine.error(error);
        RuntimeException exception;
        try {
            exception =
                    (RuntimeException)
                            Class.forName("org.zaproxy.zap.ShutdownRequestedException")
                                    .getDeclaredConstructor()
                                    .newInstance();
        } catch (Exception ignore) {
            if (ZAP.getProcessType() == ZAP.ProcessType.daemon) {
                Control.getSingleton().shutdown(false);
                throw new Error(error);
            }
            throw new IllegalStateException(error);
        }
        throw exception;
    }

    private static void writeCert(String path, CertWriter writer) {
        Path file = Paths.get(path);
        if (Files.exists(file) && !Files.isWritable(file)) {
            CommandLine.error(
                    Constant.messages.getString(
                            "network.cmdline.error.nowrite", file.toAbsolutePath()));
        } else {
            try {
                writer.write(file);
                CommandLine.info(
                        Constant.messages.getString(
                                "network.cmdline.certdump.done", file.toAbsolutePath()));
            } catch (Exception e) {
                CommandLine.error(
                        Constant.messages.getString(
                                "network.cmdline.error.write", file.toAbsolutePath()),
                        e);
            }
        }
    }

    private interface CertWriter {
        void write(Path path) throws Exception;
    }

    @Override
    public boolean handleFile(File file) {
        return false;
    }

    @Override
    public List<String> getHandledExtensions() {
        return Collections.emptyList();
    }

    ServerCertificateService getServerCertificateService() {
        return serverCertificateService;
    }

    ServerCertificatesOptions getServerCertificatesOptions() {
        return serverCertificatesOptions;
    }

    LocalServersOptions getLocalServersOptions() {
        return localServersOptions;
    }

    @Override
    public void start() {
        loadRootCaCert();
    }

    @Override
    public void stop() {
        localServers.values().removeIf(ExtensionNetwork::stopAdditionalLocalServer);
        stopLocalServer(mainProxyServer);
    }

    @Override
    public void destroy() {
        shutdownEventGroups();

        if (httpSenderNetwork != null) {
            httpSenderNetwork.close();
        }
    }

    class ServerCertificateServiceImpl implements ServerCertificateService {

        private ServerCertificateGenerator generator;

        public void setRootCaCert(KeyStore keyStore) {
            generator = new ServerCertificateGenerator(keyStore, serverCertificatesOptions);
        }

        @Override
        public KeyStore createCertificate(CertData certData) throws GenerationException {
            if (generator == null) {
                throw new GenerationException("The root CA certificate was not set.");
            }
            return generator.generate(certData);
        }
    }

    private boolean loadRootCaCert() {
        KeyStore rootCaKeyStore = getRootCaKeyStore();
        if (rootCaKeyStore == null) {
            return generateRootCaCert();
        }

        if (!applyRootCaCert()) {
            return false;
        }

        X509Certificate certificate = CertificateUtils.getCertificate(rootCaKeyStore);
        if (certificate == null || !certificate.getNotAfter().before(new Date())) {
            return true;
        }

        String warnMsg =
                Constant.messages.getString(
                        "network.warn.cert.expired",
                        certificate.getNotAfter().toString(),
                        new Date().toString());
        if (hasView()) {
            if (getView().showConfirmDialog(warnMsg) == JOptionPane.OK_OPTION) {
                if (!generateRootCaCert()) {
                    getView()
                            .showWarningDialog(
                                    Constant.messages.getString("network.warn.cert.failed"));
                } else {
                    Control.getSingleton()
                            .getMenuToolsControl()
                            .options(
                                    Constant.messages.getString(
                                            "network.ui.options.servercertificates.name"));
                }
                return true;
            }
        }
        LOGGER.warn(warnMsg);
        return true;
    }

    boolean applyRootCaCert() {
        try {
            serverCertificateService.setRootCaCert(getRootCaKeyStore());
            return true;
        } catch (Exception e) {
            LOGGER.error("An error occurred while initializing the certificate service:", e);
        }
        return false;
    }

    @Override
    public boolean canUnload() {
        // Do not allow, the HttpSender implementation is used everywhere.
        return false;
    }

    @Override
    @SuppressWarnings("deprecation")
    public void unload() {
        Control.getSingleton().getExtensionLoader().removeProxyServer(legacyProxyListenerHandler);
        legacyProxyListenerHandler = null;

        org.parosproxy.paros.network.ConnectionParam connectionParam =
                new org.parosproxy.paros.network.ConnectionParam();
        ApiImplementor coreApi = API.getInstance().getImplementors().get("core");
        if (coreApi != null) {
            updateOldCoreApiEndpoints(coreApi, connectionParam);
        }
        getModel().getOptionsParam().setConnectionParam(connectionParam);
        connectionParam.load(getModel().getOptionsParam().getConfig());

        if (httpSenderNetwork != null) {
            httpSenderNetwork.close();
        }

        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);

        if (hasView()) {
            OptionsDialog optionsDialog = View.getSingleton().getOptionsDialog("");
            optionsDialog.removeParamPanel(serverCertificatesOptionsPanel);

            localServerInfoLabel.unload();

            optionsDialog.removeParamPanel(localServersOptionsPanel);

            if (removeBreakListenerMethod != null) {
                try {
                    removeBreakListenerMethod.invoke(extensionBreak, serialiseForBreak);
                } catch (Exception e) {
                    LOGGER.error("An error occurred while removing the break listener:", e);
                }
            }
        }
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    /**
     * Writes the Root CA certificate to the specified file in PEM format, suitable for importing
     * into browsers.
     *
     * @param path the path the Root CA certificate will be written to.
     * @throws IOException if an error occurred while writing the certificate.
     */
    public void writeRootCaCertAsPem(Path path) throws IOException {
        try {
            CertificateUtils.keyStoreToCertificatePem(getRootCaKeyStore(), path);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    /**
     * Writes the Root CA certificate and the private key to the specified file in PEM format,
     * suitable for importing into ZAP.
     *
     * @param path the path the Root CA certificate and private key will be written to.
     */
    void writeRootCaCertAndPrivateKeyAsPem(Path path) {
        CertificateUtils.keyStoreToCertificateAndPrivateKeyPem(getRootCaKeyStore(), path);
    }

    KeyStore getRootCaKeyStore() {
        return serverCertificatesOptions.getRootCaKeyStore();
    }

    boolean generateRootCaCert() {
        try {
            LOGGER.info("Creating new root CA certificate.");
            KeyStore keyStore =
                    CertificateUtils.createRootCaKeyStore(
                            serverCertificatesOptions.getRootCaCertConfig());
            serverCertificatesOptions.setRootCaKeyStore(keyStore);
            LOGGER.info("New root CA certificate created.");
        } catch (Exception e) {
            LOGGER.error("Failed to create new root CA certificate:", e);
            return false;
        }

        return applyRootCaCert();
    }

    String importRootCaCert(Path pemFile) {
        String pem;
        try {
            pem = new String(Files.readAllBytes(pemFile), StandardCharsets.US_ASCII);
        } catch (IOException e) {
            return Constant.messages.getString(
                    "network.importpem.failedreadfile", e.getLocalizedMessage());
        }

        byte[] certificate;
        try {
            certificate = CertificateUtils.extractCertificate(pem);
            if (certificate.length == 0) {
                return Constant.messages.getString(
                        "network.importpem.nocertsection",
                        CertificateUtils.BEGIN_CERTIFICATE_TOKEN,
                        CertificateUtils.END_CERTIFICATE_TOKEN);
            }
        } catch (IllegalArgumentException e) {
            return Constant.messages.getString("network.importpem.certnobase64");
        }

        byte[] key;
        try {
            key = CertificateUtils.extractPrivateKey(pem);
            if (key.length == 0) {
                return Constant.messages.getString(
                        "network.importpem.noprivkeysection",
                        CertificateUtils.BEGIN_PRIVATE_KEY_TOKEN,
                        CertificateUtils.END_PRIVATE_KEY_TOKEN);
            }
        } catch (IllegalArgumentException e) {
            return Constant.messages.getString("network.importpem.privkeynobase64");
        }

        try {
            KeyStore keyStore = CertificateUtils.pemToKeyStore(certificate, key);
            serverCertificatesOptions.setRootCaKeyStore(keyStore);
            applyRootCaCert();
            return null;
        } catch (Exception e) {
            return Constant.messages.getString(
                    "network.importpem.failedkeystore", e.getLocalizedMessage());
        }
    }

    String getProxyPacContent(String hostname) {
        LocalServerConfig serverConfig = localServersOptions.getMainProxy();
        int port = serverConfig.getPort();
        String domain = null;
        if (serverConfig.isAnyLocalAddress()) {
            String localDomain = hostname;
            if (!API.API_DOMAIN.equals(localDomain)) {
                domain = localDomain;
            }
        }
        if (domain == null) {
            domain = serverConfig.getAddress();
        }

        StringBuilder sb = new StringBuilder(100);
        sb.append("function FindProxyForURL(url, host) {\n");
        sb.append("  return \"PROXY ").append(domain).append(':').append(port).append("\";\n");
        sb.append("} // End of function\n");
        return sb.toString();
    }

    private class SessionChangedListenerImpl implements SessionChangedListener {

        @Override
        @SuppressWarnings("deprecation")
        public void sessionChanged(Session session) {
            globalCookieStore = new BasicCookieStore();
            globalHttpState = new HttpState();
            getModel().getOptionsParam().getConnectionParam().setHttpState(globalHttpState);
        }

        @Override
        public void sessionAboutToChange(Session session) {}

        @Override
        public void sessionScopeChanged(Session session) {}

        @Override
        public void sessionModeChanged(Mode mode) {}
    }

    private class OptionsChangedListenerImpl implements OptionsChangedListener {

        @Override
        public void optionsChanged(OptionsParam optionsParam) {
            if (connectionOptions.isUseGlobalHttpState()) {
                if (globalCookieStore == null) {
                    globalCookieStore = new BasicCookieStore();
                }
                if (globalHttpState == null) {
                    globalHttpState = new HttpState();
                }
            } else {
                globalCookieStore = null;
                globalHttpState = null;
            }
        }
    }
}
