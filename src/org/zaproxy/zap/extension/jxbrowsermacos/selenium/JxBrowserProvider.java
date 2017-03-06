/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.jxbrowsermacos.selenium;

import java.awt.EventQueue;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.remote.DesiredCapabilities;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.jxbrowser.BrowserFrame;
import org.zaproxy.zap.extension.jxbrowser.BrowserPanel;
import org.zaproxy.zap.extension.jxbrowser.ZapBrowserFrame;
import org.zaproxy.zap.extension.selenium.ProvidedBrowser;
import org.zaproxy.zap.extension.selenium.SingleWebDriverProvider;

import com.teamdev.jxbrowser.chromium.Browser;
import com.teamdev.jxbrowser.chromium.BrowserContext;
import com.teamdev.jxbrowser.chromium.BrowserContextParams;
import com.teamdev.jxbrowser.chromium.BrowserPreferences;
import com.teamdev.jxbrowser.chromium.CustomProxyConfig;

/**
 * A {@link SingleWebDriverProvider} for JxBrowser.
 */
public class JxBrowserProvider implements SingleWebDriverProvider {

    private static final String PROVIDER_ID = "jxbrowser";

    private final ProvidedBrowser providedBrowser;
    private BrowserFrame zbf;
    private Integer chromePort;

    public JxBrowserProvider() {
        this.providedBrowser = new ProvidedBrowserImpl();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public ProvidedBrowser getProvidedBrowser() {
        return providedBrowser;
    }

    @Override
    public String getWarnMessageFailedToStart(Throwable arg0) {
        // Do not return a custom message, for now.
        return null;
    }

    @Override
    public WebDriver getWebDriver(int requesterId) {
        return getRemoteWebDriver(null, 0);
    }

    private RemoteWebDriver getRemoteWebDriver(final String proxyAddress, final int proxyPort) {
        if (View.isInitialised()) {
            try {
                GetWebDriverRunnable wb = new GetWebDriverRunnable(proxyAddress, proxyPort);
                EventQueue.invokeAndWait(wb);
                return wb.getWebDriver();
            } catch (InvocationTargetException | InterruptedException e) {
                throw new WebDriverException(e);
            }
        }

        synchronized (this) {
            return getRemoteWebDriverImpl(proxyAddress, proxyPort);
        }
    }

    private RemoteWebDriver getRemoteWebDriverImpl(String proxyAddress, int proxyPort) {
        try {
            if (zbf == null) {
                zbf = new ZapBrowserFrame(false, true, false, false);
                // Reuse the same port, as the JxBrowser/Chrome process tends to live longer on macOS.
                if (chromePort == null) {
                    chromePort = getFreePort();
                }
            } else if (!zbf.isVisible()) {
                zbf.setVisible(true);
            }

            File dataDir = Files.createTempDirectory("zap-jxbrowser").toFile();
            dataDir.deleteOnExit();
            BrowserContextParams contextParams = new BrowserContextParams(dataDir.getAbsolutePath());

            if (proxyAddress != null && !proxyAddress.isEmpty()) {
                String hostPort = proxyAddress + ":" + proxyPort;
                String proxyRules = "http=" + hostPort + ";https=" + hostPort;
                contextParams.setProxyConfig(new CustomProxyConfig(proxyRules));
            }

            BrowserPreferences.setChromiumSwitches("--remote-debugging-port=" + chromePort);
            Browser browser = new Browser(new BrowserContext(contextParams));
            final BrowserPanel browserPanel = zbf.addNewBrowserPanel(false, browser);

            final ChromeDriverService service = new ChromeDriverService.Builder().usingAnyFreePort().build();
            service.start();

            DesiredCapabilities capabilities = new DesiredCapabilities();
            ChromeOptions options = new ChromeOptions();

            options.setExperimentalOption("debuggerAddress", "localhost:" + chromePort);
            capabilities.setCapability(ChromeOptions.CAPABILITY, options);

            return new RemoteWebDriver(service.getUrl(), capabilities) {

                @Override
                public void close() {
                    super.close();

                    cleanUpBrowser(browserPanel);
                    // XXX should stop here too?
                    // service.stop();
                }

                @Override
                public void quit() {
                    super.quit();

                    cleanUpBrowser(browserPanel);

                    boolean interrupted = Thread.interrupted();
                    service.stop();
                    if (interrupted) {
                        Thread.currentThread().interrupt();
                    }
                }
            };
        } catch (Exception e) {
            throw new WebDriverException(e);
        }
    }

    private void cleanUpBrowser(final BrowserPanel browserPanel) {
        if (View.isInitialised()) {
            EventQueue.invokeLater(new Runnable() {

                @Override
                public void run() {
                    if (zbf == null) {
                        return;
                    }

                    cleanUpBrowserImpl(browserPanel);
                }
            });
        } else {
            synchronized (this) {
                if (zbf == null) {
                    return;
                }
                cleanUpBrowserImpl(browserPanel);
            }
        }
    }

    private void cleanUpBrowserImpl(BrowserPanel browserPanel) {
        browserPanel.getBrowser().dispose();
        zbf.removeTab(browserPanel);

        if (!zbf.hasPanels()) {
            zbf.dispose();
            zbf = null;
        }
    }

    @Override
    public synchronized WebDriver getWebDriver(int requesterId, String proxyAddress, int proxyPort) {
        return getRemoteWebDriver(proxyAddress, proxyPort);
    }

    private int getFreePort() {
        try (ServerSocket socket = new ServerSocket(0, 400, InetAddress.getByName("localhost"))) {
            return socket.getLocalPort();
        } catch (Exception e) {
            throw new WebDriverException(e);
        }
    }

    private class ProvidedBrowserImpl implements ProvidedBrowser {

        @Override
        public String getProviderId() {
            return PROVIDER_ID;
        }

        @Override
        public String getId() {
            return PROVIDER_ID;
        }

        @Override
        public String getName() {
            return "JxBrowser";
        }
    }

    private class GetWebDriverRunnable implements Runnable {

        private final String proxyAddress;
        private final int proxyPort;

        private RemoteWebDriver webDriver;

        public GetWebDriverRunnable(String proxyAddress, int proxyPort) {
            this.proxyAddress = proxyAddress;
            this.proxyPort = proxyPort;
        }

        @Override
        public void run() {
            webDriver = getRemoteWebDriverImpl(proxyAddress, proxyPort);
        }

        public RemoteWebDriver getWebDriver() {
            return webDriver;
        }
    }
}
