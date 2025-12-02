/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.spiderAjax;

import com.crawljax.browser.EmbeddedBrowser;
import com.crawljax.browser.WebDriverBackedEmbeddedBrowser;
import com.crawljax.core.CrawljaxRunner;
import com.crawljax.core.configuration.BrowserConfiguration;
import com.crawljax.core.configuration.CrawljaxConfiguration;
import com.crawljax.core.configuration.CrawljaxConfiguration.CrawljaxConfigurationBuilder;
import com.crawljax.core.plugin.OnBrowserCreatedPlugin;
import com.crawljax.core.plugin.Plugins;
import com.google.common.collect.ImmutableSortedSet;
import com.google.inject.ProvisionException;
import java.awt.EventQueue;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import javax.inject.Inject;
import javax.inject.Provider;
import lombok.Getter;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.addon.network.server.HttpServerConfig;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderParam.ScopeCheck;
import org.zaproxy.zap.extension.spiderAjax.SpiderListener.ResourceState;
import org.zaproxy.zap.extension.spiderAjax.internal.ExcludedElement;
import org.zaproxy.zap.model.ScanEventPublisher;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.Stats;

public class SpiderThread implements Runnable {

    private static final List<String> LOG_OUT_TEXT =
            List.of("logout", "logoff", "signout", "signoff");

    private static final List<String> LOG_OUT_ELEMENTS = List.of("a", "span", "button");

    private static final String XPATH_LOG_OUT_EXCLUDE =
            "//%s[contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ -', 'abcdefghijklmnopqrstuvwxyz'), '%s')]";

    private static final List<ExcludedElement> LOG_OUT_EXCLUDED_ELEMENTS =
            LOG_OUT_ELEMENTS.stream()
                    .flatMap(e -> LOG_OUT_TEXT.stream().map(t -> logoutExclude(e, t)))
                    .toList();

    private final String displayName;
    private final AjaxSpiderTarget target;
    private final List<AllowedResource> allowedResourcesEnabled;
    private final HttpPrefixUriValidator httpPrefixUriValidator;
    private CrawljaxRunner crawljax;
    private boolean running;
    private final Session session;
    private static final Logger LOGGER = LogManager.getLogger(SpiderThread.class);
    private long startTime;

    private HttpResponseHeader outOfScopeResponseHeader;
    private HttpResponseBody outOfScopeResponseBody;
    private List<SpiderListener> spiderListeners;
    private final List<String> exclusionList;
    private final String targetHost;
    private final ExtensionAjax extension;
    private AuthenticationHandler authHandler;

    private ExtensionNetwork extensionNetwork;
    private List<WebDriverProcess> webDriverProcesses;

    /**
     * Constructs a {@code SpiderThread} for the given target.
     *
     * @param displayName the name of the scan, must not be {@code null}.
     * @param target the target, must not be {@code null}.
     * @param extension the extension, must not be {@code null}.
     * @param spiderListener the listener, must not be {@code null}.
     */
    SpiderThread(
            String displayName,
            AjaxSpiderTarget target,
            ExtensionAjax extension,
            SpiderListener spiderListener,
            ExtensionNetwork extensionNetwork) {
        this.displayName = displayName;
        this.target = target;
        allowedResourcesEnabled =
                target.getOptions().getAllowedResources().stream()
                        .filter(AllowedResource::isEnabled)
                        .toList();
        HttpPrefixUriValidator validator = null;
        try {
            validator =
                    target.isSubtreeOnly()
                            ? new HttpPrefixUriValidator(
                                    new URI(target.getStartUri().toASCIIString(), true))
                            : null;
        } catch (URIException e) {
            LOGGER.error("Failed to create subtree validator:", e);
        }
        this.httpPrefixUriValidator = validator;
        this.running = false;
        spiderListeners = new ArrayList<>(2);
        spiderListeners.add(spiderListener);
        this.session = extension.getModel().getSession();
        this.exclusionList = new ArrayList<>();
        exclusionList.addAll(session.getExcludeFromSpiderRegexs());
        exclusionList.addAll(session.getGlobalExcludeURLRegexs());
        this.targetHost = target.getStartUri().getHost();
        this.extension = extension;

        this.extensionNetwork = extensionNetwork;
        webDriverProcesses = Collections.synchronizedList(new ArrayList<>());

        createOutOfScopeResponse(
                extension.getMessages().getString("spiderajax.outofscope.response"));
    }

    private void createOutOfScopeResponse(String response) {
        outOfScopeResponseBody = new HttpResponseBody();
        outOfScopeResponseBody.setBody(response.getBytes(StandardCharsets.UTF_8));

        final StringBuilder strBuilder = new StringBuilder(150);
        final String crlf = HttpHeader.CRLF;
        strBuilder.append("HTTP/1.1 403 Forbidden").append(crlf);
        strBuilder.append(HttpHeader.PRAGMA).append(": ").append("no-cache").append(crlf);
        strBuilder.append(HttpHeader.CACHE_CONTROL).append(": ").append("no-cache").append(crlf);
        strBuilder
                .append(HttpHeader.CONTENT_TYPE)
                .append(": ")
                .append("text/plain; charset=UTF-8")
                .append(crlf);
        strBuilder
                .append(HttpHeader.CONTENT_LENGTH)
                .append(": ")
                .append(outOfScopeResponseBody.length())
                .append(crlf);

        HttpResponseHeader responseHeader;
        try {
            responseHeader = new HttpResponseHeader(strBuilder.toString());
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error("Failed to create a valid! response header: ", e);
            responseHeader = new HttpResponseHeader();
        }
        outOfScopeResponseHeader = responseHeader;
    }

    private static ExcludedElement logoutExclude(String element, String text) {
        ExcludedElement excluded = new ExcludedElement();
        excluded.setElement(element);
        excluded.setXpath(XPATH_LOG_OUT_EXCLUDE.formatted(element, text));
        return excluded;
    }

    /**
     * @return the SpiderThread object
     */
    public SpiderThread getSpiderThread() {
        return this;
    }

    /**
     * @return the SpiderThread object
     */
    public boolean isRunning() {
        return this.running;
    }

    public CrawljaxConfiguration createCrawljaxConfiguration() {
        CrawljaxConfigurationBuilder configurationBuilder =
                CrawljaxConfiguration.builderFor(target.getStartUri().toString());

        configurationBuilder.setCrawlScope(
                url -> {
                    if (target.getOptions().getScopeCheck() == ScopeCheck.STRICT) {
                        return true;
                    }
                    return inScope(url);
                });

        configurationBuilder.setBrowserConfig(
                new BrowserConfiguration(
                        com.crawljax.browser.EmbeddedBrowser.BrowserType.FIREFOX,
                        target.getOptions().getNumberOfBrowsers(),
                        new AjaxSpiderBrowserBuilder(
                                extensionNetwork,
                                webDriverProcesses,
                                SpiderProxyListener::new,
                                target.getOptions().getBrowserId(),
                                target.getOptions().isEnableExtensions())));

        if (target.getOptions().isClickDefaultElems()) {
            configurationBuilder.crawlRules().clickDefaultElements();
        } else {
            for (String elem : target.getOptions().getElemsNames()) {
                configurationBuilder.crawlRules().click(elem);
            }
        }

        if (target.getOptions().isLogoutAvoidance()) {
            LOG_OUT_EXCLUDED_ELEMENTS.forEach(
                    e ->
                            configurationBuilder
                                    .crawlRules()
                                    .dontClick(e.getElement())
                                    .underXPath(e.getXpath()));
        }

        for (var excludedElement : target.getExcludedElements()) {
            var crawlElement =
                    configurationBuilder.crawlRules().dontClick(excludedElement.getElement());
            if (StringUtils.isNotBlank(excludedElement.getXpath())) {
                crawlElement.underXPath(excludedElement.getXpath());
            }
            if (StringUtils.isNotBlank(excludedElement.getText())) {
                crawlElement.withText(excludedElement.getText());
            }
            if (StringUtils.isNotBlank(excludedElement.getAttributeName())
                    && StringUtils.isNotBlank(excludedElement.getAttributeValue())) {
                crawlElement.withAttribute(
                        excludedElement.getAttributeName(), excludedElement.getAttributeValue());
            }
        }

        configurationBuilder.crawlRules().followExternalLinks(true);
        configurationBuilder
                .crawlRules()
                .insertRandomDataInInputForms(target.getOptions().isRandomInputs());
        configurationBuilder
                .crawlRules()
                .waitAfterEvent(target.getOptions().getEventWait(), TimeUnit.MILLISECONDS);
        configurationBuilder
                .crawlRules()
                .waitAfterReloadUrl(target.getOptions().getReloadWait(), TimeUnit.MILLISECONDS);

        if (target.getOptions().getMaxCrawlStates() == 0) {
            configurationBuilder.setUnlimitedStates();
        } else {
            configurationBuilder.setMaximumStates(target.getOptions().getMaxCrawlStates());
        }

        configurationBuilder.setMaximumDepth(target.getOptions().getMaxCrawlDepth());
        configurationBuilder.setMaximumRunTime(
                target.getOptions().getMaxDuration(), TimeUnit.MINUTES);
        configurationBuilder.crawlRules().clickOnce(target.getOptions().isClickElemsOnce());

        configurationBuilder.addPlugin(DummyPlugin.DUMMY_PLUGIN);

        return configurationBuilder.build();
    }

    private boolean inScope(String uri) {
        return checkState(uri) == ResourceState.PROCESSED;
    }

    private ResourceState checkState(String url) {
        ResourceState state = ResourceState.PROCESSED;
        URI uri = createUri(url);
        if (allowedResourcesEnabled.stream().anyMatch(e -> e.getPattern().matcher(url).matches())) {
            // Nothing to do, state already set to processed.
        } else if (httpPrefixUriValidator != null && !httpPrefixUriValidator.isValid(uri)) {
            LOGGER.debug("Excluding request [{}] not under subtree.", url);
            state = ResourceState.OUT_OF_SCOPE;
        } else if (target.getContext() != null) {
            if (!target.getContext().isInContext(url)) {
                LOGGER.debug("Excluding request [{}] not in specified context.", url);
                state = ResourceState.OUT_OF_CONTEXT;
            }
        } else if (target.isInScopeOnly()) {
            if (!session.isInScope(url)) {
                LOGGER.debug("Excluding request [{}] not in scope.", url);
                state = ResourceState.OUT_OF_SCOPE;
            }
        } else if (uri != null && !targetHost.equalsIgnoreCase(new String(uri.getRawHost()))) {
            LOGGER.debug("Excluding request [{}] not on target site [{}].", url, targetHost);
            state = ResourceState.OUT_OF_SCOPE;
        }
        if (state == ResourceState.PROCESSED) {
            for (String regex : exclusionList) {
                if (Pattern.matches(regex, url)) {
                    LOGGER.debug("Excluding request [{}] matched regex [{}].", url, regex);
                    state = ResourceState.EXCLUDED;
                }
            }
        }

        return state;
    }

    private static URI createUri(String uri) {
        try {
            return new URI(uri, true);
        } catch (Exception e) {
            LOGGER.warn("Failed to create URI from: {} Cause: {}", uri, e.getMessage());
        }
        return null;
    }

    /** Instantiates the crawljax classes. */
    @Override
    public void run() {
        LOGGER.info(
                "Running Crawljax (with {}): {}", target.getOptions().getBrowserId(), displayName);
        this.running = true;
        this.startTime = System.currentTimeMillis();
        notifyListenersSpiderStarted();
        SpiderEventPublisher.publishScanEvent(
                ScanEventPublisher.SCAN_STARTED_EVENT,
                0,
                this.target.toTarget(),
                target.getStartUri().toString(),
                this.target.getUser());
        Stats.incCounter("stats.spiderAjax.started");

        User user = target.getUser();
        if (user != null) {
            Stats.incCounter("stats.spiderAjax.started.user");
            for (AuthenticationHandler ah : extension.getAuthenticationHandlers()) {
                if (ah.enableAuthentication(user)) {
                    authHandler = ah;
                    break;
                }
            }
        }

        try {
            crawljax = new CrawljaxRunner(createCrawljaxConfiguration());
            crawljax.call();
        } catch (ProvisionException e) {
            LOGGER.warn("Failed to start browser {}", target.getOptions().getBrowserId(), e);
            if (View.isInitialised()) {
                ExtensionSelenium extSelenium =
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionSelenium.class);
                String providedBrowserId = target.getOptions().getBrowserId();
                View.getSingleton()
                        .showWarningDialog(
                                extSelenium.getWarnMessageFailedToStart(providedBrowserId, e));
            }
        } catch (Exception e) {
            LOGGER.error(e, e);
        } finally {
            this.running = false;
            Stats.incCounter("stats.spiderAjax.time", System.currentTimeMillis() - this.startTime);
            LOGGER.info("Stopping proxy...");
            stopProxy();
            LOGGER.info("Proxy stopped.");
            notifyListenersSpiderStoped();
            SpiderEventPublisher.publishScanEvent(ScanEventPublisher.SCAN_STOPPED_EVENT, 0);
            if (authHandler != null) {
                authHandler.disableAuthentication(user);
            }

            LOGGER.info("Finished Crawljax: {}", displayName);
        }
    }

    private void stopProxy() {
        webDriverProcesses.forEach(WebDriverProcess::shutdown);
        webDriverProcesses.clear();
    }

    /** called by the buttons of the panel to stop the spider */
    public void stopSpider() {
        crawljax.stop();
    }

    public void addSpiderListener(SpiderListener spiderListener) {
        spiderListeners.add(spiderListener);
    }

    public void removeSpiderListener(SpiderListener spiderListener) {
        spiderListeners.remove(spiderListener);
    }

    private void notifyListenersSpiderStarted() {
        for (SpiderListener listener : spiderListeners) {
            listener.spiderStarted();
        }
    }

    private void notifySpiderListenersFoundMessage(
            HistoryReference historyReference, HttpMessage httpMessage, ResourceState state) {
        for (SpiderListener listener : spiderListeners) {
            listener.foundMessage(historyReference, httpMessage, state);
        }
    }

    private void notifyListenersSpiderStoped() {
        for (SpiderListener listener : spiderListeners) {
            listener.spiderStopped();
        }
    }

    private class SpiderProxyListener implements HttpMessageHandler {

        private boolean allowAll = true;

        @Override
        public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage httpMessage) {
            if (allowAll) {
                return;
            }

            ResourceState state =
                    checkState(httpMessage.getRequestHeader().getURI().getEscapedURI());

            if (!ctx.isFromClient()) {
                Stats.incCounter("stats.spiderAjax.urls.added");
                notifyMessage(
                        httpMessage,
                        HistoryReference.TYPE_SPIDER_AJAX,
                        target.getOptions().getScopeCheck() == ScopeCheck.STRICT
                                ? getResourceState(httpMessage)
                                : getResourceStateFlexible(httpMessage, state));
                return;
            }

            if (state != ResourceState.PROCESSED) {
                if (target.getOptions().getScopeCheck() == ScopeCheck.STRICT) {
                    setOutOfScopeResponse(httpMessage);
                    notifyMessage(httpMessage, HistoryReference.TYPE_SPIDER_AJAX_TEMPORARY, state);
                    ctx.overridden();
                }
                return;
            }

            if (authHandler == null) {
                // Only set the user if there is not an authHandler - if there is that will take
                // responsibility for handling auth. If we do set the user then its likely to loop.
                httpMessage.setRequestingUser(target.getUser());
            }
        }

        private void setOutOfScopeResponse(HttpMessage httpMessage) {
            try {
                httpMessage.setTimeSentMillis(System.currentTimeMillis());
                httpMessage.setTimeElapsedMillis(0);
                httpMessage.setResponseHeader(outOfScopeResponseHeader.toString());
            } catch (HttpMalformedHeaderException ignore) {
                // Setting a valid response header.
            }
            httpMessage.setResponseBody(outOfScopeResponseBody.getBytes());
        }

        private ResourceState getResourceState(HttpMessage httpMessage) {
            if (!httpMessage.isResponseFromTargetHost()) {
                return ResourceState.IO_ERROR;
            }
            return ResourceState.PROCESSED;
        }

        private ResourceState getResourceStateFlexible(
                HttpMessage httpMessage, ResourceState state) {
            if (!httpMessage.isResponseFromTargetHost()) {
                return ResourceState.IO_ERROR;
            }
            if (state != ResourceState.PROCESSED) {
                return ResourceState.THIRD_PARTY;
            }
            return state;
        }

        public void setAllowAll(boolean allow) {
            this.allowAll = allow;
        }
    }

    private void notifyMessage(
            final HttpMessage httpMessage, final int historyType, final ResourceState state) {
        try {
            if (extension.getView() != null && !EventQueue.isDispatchThread()) {
                EventQueue.invokeLater(() -> notifyMessage(httpMessage, historyType, state));
                return;
            }

            HistoryReference historyRef = new HistoryReference(session, historyType, httpMessage);
            if (state == ResourceState.PROCESSED || state == ResourceState.THIRD_PARTY) {
                historyRef.setCustomIcon("/resource/icon/10/spiderAjax.png", true);
                session.getSiteTree().addPath(historyRef, httpMessage);
            }

            notifySpiderListenersFoundMessage(historyRef, httpMessage, state);
        } catch (Exception e) {
            LOGGER.error(e, e);
        }
    }

    // NOTE: The implementation of this class was copied from
    // com.crawljax.browser.WebDriverBrowserBuilder since it's not
    // possible to correctly extend it because of DI issues.
    // Changes:
    // - Changed to use Selenium add-on to leverage the creation of WebDrivers.
    private static class AjaxSpiderBrowserBuilder implements Provider<EmbeddedBrowser> {

        @Inject private CrawljaxConfiguration configuration;
        @Inject private Plugins plugins;

        private final ExtensionNetwork extensionNetwork;
        private final List<WebDriverProcess> webDriverProcesses;
        private final Supplier<SpiderProxyListener> listenerFactory;
        private final String providedBrowserId;
        private final boolean enableExtensions;

        public AjaxSpiderBrowserBuilder(
                ExtensionNetwork extensionNetwork,
                List<WebDriverProcess> webDriverProcesses,
                Supplier<SpiderProxyListener> listenerFactory,
                String providedBrowserId,
                boolean enableExtensions) {
            super();
            this.extensionNetwork = extensionNetwork;
            this.webDriverProcesses = webDriverProcesses;
            this.listenerFactory = listenerFactory;
            this.providedBrowserId =
                    StringUtils.isEmpty(providedBrowserId)
                            ? AjaxSpiderParam.DEFAULT_BROWSER_ID
                            : providedBrowserId;
            this.enableExtensions = enableExtensions;
        }

        /**
         * Build a new WebDriver based EmbeddedBrowser.
         *
         * @return the new build WebDriver based embeddedBrowser
         */
        @Override
        public EmbeddedBrowser get() {
            LOGGER.debug("Setting up a Browser");
            // Retrieve the config values used
            ImmutableSortedSet<String> filterAttributes =
                    configuration.getCrawlRules().getPreCrawlConfig().getFilterAttributeNames();
            long crawlWaitReload = configuration.getCrawlRules().getWaitAfterReloadUrl();
            long crawlWaitEvent = configuration.getCrawlRules().getWaitAfterEvent();

            SpiderProxyListener listener = listenerFactory.get();
            WebDriverProcess webDriverProcess;
            try {
                webDriverProcess =
                        new WebDriverProcess(
                                extensionNetwork, listener, providedBrowserId, enableExtensions);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
            webDriverProcesses.add(webDriverProcess);

            EmbeddedBrowser embeddedBrowser =
                    WebDriverBackedEmbeddedBrowser.withDriver(
                            webDriverProcess.getWebDriver(),
                            filterAttributes,
                            crawlWaitEvent,
                            crawlWaitReload);
            plugins.runOnBrowserCreatedPlugins(embeddedBrowser);
            return embeddedBrowser;
        }
    }

    /**
     * A {@link com.crawljax.core.plugin.Plugin} that does nothing, used only to suppress log
     * warning when the {@link CrawljaxRunner} is started.
     *
     * @see SpiderThread#createCrawljaxConfiguration()
     * @see SpiderThread#run()
     */
    private static class DummyPlugin implements OnBrowserCreatedPlugin {

        public static final DummyPlugin DUMMY_PLUGIN = new DummyPlugin();

        @Override
        public void onBrowserCreated(EmbeddedBrowser arg0) {
            // Nothing to do.
        }
    }

    @Getter
    static class WebDriverProcess {

        private static final String LOCAL_PROXY_IP = "127.0.0.1";
        private static final int INITIATOR = HttpSender.AJAX_SPIDER_INITIATOR;

        private final int port;

        private Server proxy;
        private WebDriver webDriver;

        private WebDriverProcess(
                ExtensionNetwork extensionNetwork,
                SpiderProxyListener listener,
                String browser,
                boolean enableExtensions)
                throws IOException {
            proxy =
                    extensionNetwork.createHttpServer(
                            HttpServerConfig.builder()
                                    .setHttpMessageHandler(listener)
                                    .setHttpSender(new HttpSender(INITIATOR))
                                    .setServeZapApi(true)
                                    .build());
            port = proxy.start(Server.ANY_PORT);
            LOGGER.debug("Started proxy for browser, listening at port [{}].", port);

            webDriver =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionSelenium.class)
                            .getWebDriver(
                                    INITIATOR, browser, LOCAL_PROXY_IP, port, enableExtensions);
            listener.setAllowAll(false);
        }

        private void shutdown() {
            if (webDriver != null) {
                try {
                    webDriver.quit();
                } catch (Exception e) {
                    LOGGER.debug("An error occurred while quitting the browser.", e);
                }
            }

            if (proxy != null) {
                try {
                    proxy.close();
                } catch (IOException e) {
                    LOGGER.debug("An error occurred while stopping the proxy.", e);
                }
            }
        }
    }
}
