/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.quality.Strictness;
import org.openqa.selenium.MutableCapabilities;
import org.openqa.selenium.Proxy;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.edge.EdgeOptions;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.remote.CapabilityType;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.network.HttpSenderListener;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/**
 * Verifies that browser related background requests are not notified to {@link HttpSenderListener}s
 * when the action is hide.
 */
@Tag("weekly")
class BrowserRequestsTest extends TestUtils {

    private static final String REQUESTED_URL = "https://www.example.org";

    private enum BrowserTestData {
        CHROME,
        EDGE,
        FIREFOX,
        ;

        BrowserTestData() {}

        List<WebDriver> create(int proxyPort) {
            List<WebDriver> webDrivers = new ArrayList<>();
            for (int i = 0; i < 3; i++) {
                webDrivers.add(createWebdriver(proxyPort));
            }
            return webDrivers;
        }

        private WebDriver createWebdriver(int proxyPort) {
            switch (this) {
                case CHROME:
                    {
                        ChromeOptions options = new ChromeOptions();
                        options.addArguments("--headless=new");
                        options.addArguments("--proxy-bypass-list=<-loopback>");

                        setCommonProperties(proxyPort, options);

                        return new ChromeDriver(options);
                    }

                case EDGE:
                    {
                        EdgeOptions options = new EdgeOptions();
                        options.addArguments("--headless");
                        options.addArguments("--proxy-bypass-list=<-loopback>");

                        setCommonProperties(proxyPort, options);

                        return new EdgeDriver(options);
                    }

                case FIREFOX:
                    {
                        FirefoxOptions options = new FirefoxOptions();
                        options.addArguments("-headless");
                        options.addPreference("network.proxy.allow_hijacking_localhost", true);

                        setCommonProperties(proxyPort, options);

                        return new FirefoxDriver(options);
                    }

                default:
                    throw new IllegalArgumentException("Unexpected value: " + this);
            }
        }

        private void setCommonProperties(int proxyPort, MutableCapabilities capabilities) {
            capabilities.setCapability(CapabilityType.ACCEPT_INSECURE_CERTS, true);

            Proxy proxyConfig = new Proxy();
            String httpProxy = "127.0.0.1:" + proxyPort;
            proxyConfig.setHttpProxy(httpProxy);
            proxyConfig.setSslProxy(httpProxy);

            capabilities.setCapability(CapabilityType.PROXY, proxyConfig);
        }
    }

    private static ExtensionNetwork extension;

    private Server httpProxy;
    private int httpProxyPort;
    private Server httpServer;
    private int httpServerPort;
    private HttpSenderListener listener;
    private SortedSet<String> receivedUris;
    private SortedSet<String> notifiedUris;

    @BeforeAll
    @SuppressWarnings("deprecation")
    static void setUpAll() {
        Security.addProvider(new BouncyCastleProvider());

        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(null, extensionLoader);

        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        Model.setSingletonForTesting(model);
        OptionsParam optionsParam =
                mock(OptionsParam.class, withSettings().strictness(Strictness.LENIENT));
        given(optionsParam.getConnectionParam())
                .willReturn(new org.parosproxy.paros.network.ConnectionParam());
        given(optionsParam.getProxyParam())
                .willReturn(mock(org.parosproxy.paros.core.proxy.ProxyParam.class));
        given(model.getOptionsParam()).willReturn(optionsParam);
        Session session = mock(Session.class);
        given(model.getSession()).willReturn(session);

        extension = new ExtensionNetwork();
        extension.init();
        extension.initModel(model);
        mockMessages(extension);

        extension.hook(mock(ExtensionHook.class));
        extension.getServerCertificatesOptions().load(new ZapXmlConfiguration());
        extension.getLocalServersOptions().load(new ZapXmlConfiguration());

        extension.start();
        extension.postInstall();
    }

    @BeforeEach
    void beforeEach() throws Exception {
        receivedUris = Collections.synchronizedSortedSet(new TreeSet<>());
        notifiedUris = Collections.synchronizedSortedSet(new TreeSet<>());

        listener =
                new HttpSenderListener() {
                    @Override
                    public int getListenerOrder() {
                        return 0;
                    }

                    @Override
                    public void onHttpRequestSend(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        notifiedUris.add(msg.getRequestHeader().getURI().toString());
                    }

                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {}
                };
        HttpSender.addListener(listener);

        httpProxy =
                extension.createHttpProxy(
                        new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR),
                        (ctx, msg) -> {
                            if (!ctx.isFromClient()) {
                                return;
                            }
                            receivedUris.add(msg.getRequestHeader().getURI().toString());
                        });
        httpProxyPort = httpProxy.start("127.0.0.1", 0);

        httpServer =
                extension.createHttpServer(
                        (ctx, msg) -> {
                            if (!ctx.isFromClient()) {
                                return;
                            }

                            receivedUris.add(msg.getRequestHeader().getURI().toString());
                            try {
                                msg.setResponseHeader("HTTP/1.1 200 OK\r\ncontent-length: 0");
                            } catch (HttpMalformedHeaderException ignore) {
                            }
                        });
        httpServerPort = httpServer.start("127.0.0.1", 0);
    }

    @AfterEach
    void afterEach() throws Exception {
        HttpSender.removeListener(listener);
        if (httpProxy != null) {
            httpProxy.close();
        }
        if (httpServer != null) {
            httpServer.close();
        }
    }

    @AfterAll
    static void tearDownAll() {
        if (extension != null) {
            extension.stop();
            extension.destroy();
        }
    }

    @ParameterizedTest
    @EnumSource(BrowserTestData.class)
    void shouldNotNotifyBrowserRequests(BrowserTestData data) throws Exception {
        List<WebDriver> webdrivers = new ArrayList<>();
        try {
            webdrivers.addAll(data.create(httpProxyPort));
            webdrivers.addAll(data.create(httpServerPort));
            webdrivers.forEach(wd -> wd.get(REQUESTED_URL));

            Thread.sleep(30_000);
        } finally {
            webdrivers.forEach(
                    wd -> {
                        try {
                            wd.quit();
                        } catch (Exception e) {
                            // Ignore.
                        }
                    });
        }

        assertUris(receivedUris);
        assertUris(notifiedUris);
    }

    private void assertUris(SortedSet<String> uris) {
        assertThat(uris.removeIf(e -> e.startsWith(REQUESTED_URL)), is(equalTo(true)));
        assertThat(uris, is(empty()));
    }
}
