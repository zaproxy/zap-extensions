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
package org.zaproxy.zap.extension.jxbrowserlinux64.selenium;

import com.teamdev.jxbrowser.chromium.Browser;
import com.teamdev.jxbrowser.chromium.BrowserContext;
import com.teamdev.jxbrowser.chromium.BrowserContextParams;
import com.teamdev.jxbrowser.chromium.BrowserPreferences;
import com.teamdev.jxbrowser.chromium.CustomProxyConfig;
import java.awt.EventQueue;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang3.SystemUtils;
import org.apache.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.remote.DesiredCapabilities;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.jxbrowser.BrowserPanel;
import org.zaproxy.zap.extension.jxbrowser.ZapBrowserFrame;
import org.zaproxy.zap.extension.selenium.ProvidedBrowser;
import org.zaproxy.zap.extension.selenium.SingleWebDriverProvider;

/**
 * A {@link SingleWebDriverProvider} for JxBrowser.
 *
 * <p>Note that this class is duplicated in: - org.zaproxy.zap.extension.jxbrowserlinux32.selenium -
 * org.zaproxy.zap.extension.jxbrowserlinux64.selenium -
 * org.zaproxy.zap.extension.jxbrowsermacos.selenium -
 * org.zaproxy.zap.extension.jxbrowserwindows.selenium
 *
 * <p>Ideally it should be defined just once in org.zaproxy.zap.extension.jxbrowser.selenium but
 * that currently doesnt work due to class loading issues. If you need to change this file them make
 * sure you update it in all 4 locations. If you need to make platform specific changes then make
 * them in a class that extends this one.
 */
public class JxBrowserProvider implements SingleWebDriverProvider {

    private static final String PROVIDER_ID = "jxbrowser";

    private static final Logger LOGGER = Logger.getLogger(JxBrowserProvider.class);

    private final ProvidedBrowser providedBrowser;
    private final Path webdriver;
    /* One ZapBrowserFrame per requesterId, so that tools like the Ajax Spider
     * don't interfere with other tools.
     */
    private Map<Integer, ZapBrowserFrame> requesterToZbf = new HashMap<Integer, ZapBrowserFrame>();
    private int chromePort;

    public JxBrowserProvider(Path webdriver) {
        this.providedBrowser = new ProvidedBrowserImpl();
        this.webdriver = webdriver;
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
        return Constant.messages.getString("jxbrowser.warn.message.failed.start.browser");
    }

    @Override
    public WebDriver getWebDriver(int requesterId) {
        return getRemoteWebDriver(requesterId, null, 0);
    }

    private RemoteWebDriver getRemoteWebDriver(
            final int requesterId, final String proxyAddress, final int proxyPort) {
        if (View.isInitialised()) {
            try {
                GetWebDriverRunnable wb =
                        new GetWebDriverRunnable(requesterId, proxyAddress, proxyPort);
                EventQueue.invokeAndWait(wb);
                return wb.getWebDriver();
            } catch (InvocationTargetException | InterruptedException e) {
                throw new WebDriverException(e);
            }
        }

        synchronized (this) {
            return getRemoteWebDriverImpl(requesterId, proxyAddress, proxyPort);
        }
    }

    private boolean isNotAutomated(int requesterId) {
        switch (requesterId) {
            case HttpSender.MANUAL_REQUEST_INITIATOR:
            case HttpSender.PROXY_INITIATOR:
                return true;
            default:
                return false;
        }
    }

    private ZapBrowserFrame getZapBrowserFrame(int requesterId) {
        ZapBrowserFrame zbf = this.requesterToZbf.get(requesterId);
        if (zbf == null || zbf.isClosed()) {
            zbf =
                    new ZapBrowserFrame(
                            isNotAutomated(requesterId), true, false, isNotAutomated(requesterId));
            this.requesterToZbf.put(requesterId, zbf);
            chromePort = getFreePort();
        } else if (!zbf.isVisible()) {
            zbf.setVisible(true);
        }
        if (isNotAutomated(requesterId)) {
            zbf.requestFocus();
        }
        return zbf;
    }

    private RemoteWebDriver getRemoteWebDriverImpl(
            final int requesterId, String proxyAddress, int proxyPort) {
        try {
            ZapBrowserFrame zbf = this.getZapBrowserFrame(requesterId);

            File dataDir = Files.createTempDirectory("zap-jxbrowser").toFile();
            dataDir.deleteOnExit();
            BrowserContextParams contextParams =
                    new BrowserContextParams(dataDir.getAbsolutePath());

            if (proxyAddress != null && !proxyAddress.isEmpty()) {
                String hostPort = proxyAddress + ":" + proxyPort;
                String proxyRules = "http=" + hostPort + ";https=" + hostPort;
                contextParams.setProxyConfig(new CustomProxyConfig(proxyRules));
            }

            BrowserPreferences.setChromiumSwitches("--remote-debugging-port=" + chromePort);
            Browser browser = new Browser(new BrowserContext(contextParams));
            final BrowserPanel browserPanel =
                    zbf.addNewBrowserPanel(isNotAutomated(requesterId), browser);

            if (!ensureExecutable(webdriver)) {
                throw new IllegalStateException("Failed to ensure WebDriver is executable.");
            }
            final ChromeDriverService service =
                    new ChromeDriverService.Builder()
                            .usingDriverExecutable(webdriver.toFile())
                            .usingAnyFreePort()
                            .build();
            service.start();

            DesiredCapabilities capabilities = new DesiredCapabilities();
            ChromeOptions options = new ChromeOptions();

            options.setExperimentalOption("debuggerAddress", "localhost:" + chromePort);
            capabilities.setCapability(ChromeOptions.CAPABILITY, options);

            return new RemoteWebDriver(service.getUrl(), capabilities) {

                @Override
                public void close() {
                    super.close();

                    cleanUpBrowser(requesterId, browserPanel);
                    // XXX should stop here too?
                    // service.stop();
                }

                @Override
                public void quit() {
                    super.quit();

                    cleanUpBrowser(requesterId, browserPanel);

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

    private static void setExecutable(Path file) throws IOException {
        if (!SystemUtils.IS_OS_MAC && !SystemUtils.IS_OS_UNIX) {
            return;
        }

        Set<PosixFilePermission> perms =
                Files.readAttributes(file, PosixFileAttributes.class).permissions();
        if (perms.contains(PosixFilePermission.OWNER_EXECUTE)) {
            return;
        }

        perms.add(PosixFilePermission.OWNER_EXECUTE);
        Files.setPosixFilePermissions(file, perms);
    }

    private static boolean ensureExecutable(Path driver) {
        try {
            setExecutable(driver);
            return true;
        } catch (IOException e) {
            LOGGER.warn("Failed to set the bundled WebDriver executable:", e);
        }
        return false;
    }

    private void cleanUpBrowser(final int requesterId, final BrowserPanel browserPanel) {
        if (View.isInitialised()) {
            EventQueue.invokeLater(
                    new Runnable() {

                        @Override
                        public void run() {
                            if (!requesterToZbf.containsKey(requesterId)) {
                                return;
                            }

                            cleanUpBrowserImpl(requesterId, browserPanel);
                        }
                    });
        } else {
            synchronized (this) {
                if (!requesterToZbf.containsKey(requesterId)) {
                    return;
                }
                cleanUpBrowserImpl(requesterId, browserPanel);
            }
        }
    }

    private void cleanUpBrowserImpl(int requesterId, BrowserPanel browserPanel) {
        browserPanel.getBrowser().dispose();
        ZapBrowserFrame zbf = this.getZapBrowserFrame(requesterId);
        zbf.removeTab(browserPanel);

        if (!zbf.hasPanels()) {
            zbf.dispose();
            zbf = null;
            this.requesterToZbf.remove(requesterId);
        }
    }

    @Override
    public synchronized WebDriver getWebDriver(
            int requesterId, String proxyAddress, int proxyPort) {
        return getRemoteWebDriver(requesterId, proxyAddress, proxyPort);
    }

    protected int getFreePort() {
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

        @Override
        public boolean isHeadless() {
            return false;
        }

        @Override
        public boolean isConfigured() {
            // It should always work;)
            return true;
        }
    }

    private class GetWebDriverRunnable implements Runnable {

        private final int requesterId;
        private final String proxyAddress;
        private final int proxyPort;

        private RemoteWebDriver webDriver;

        public GetWebDriverRunnable(int requesterId, String proxyAddress, int proxyPort) {
            this.requesterId = requesterId;
            this.proxyAddress = proxyAddress;
            this.proxyPort = proxyPort;
        }

        @Override
        public void run() {
            webDriver = getRemoteWebDriverImpl(requesterId, proxyAddress, proxyPort);
        }

        public RemoteWebDriver getWebDriver() {
            return webDriver;
        }
    }

    @Override
    public boolean isConfigured() {
        return true;
    }
}
