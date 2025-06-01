/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.browserView;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javafx.application.Platform;
import javafx.beans.value.ObservableValue;
import javafx.concurrent.Worker.State;
import javafx.embed.swing.JFXPanel;
import javafx.scene.Scene;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebView;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@SuppressWarnings("serial")
public class BrowserPanel extends JPanel {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LogManager.getLogger(BrowserPanel.class);

    private final JFXPanel jfxPanel = new JFXPanel();
    private WebEngine engine;
    private boolean enabled;
    private boolean resizeOnLoad;

    public BrowserPanel(boolean enabled) {
        super();
        this.enabled = enabled;
        initComponents();
    }

    private void initComponents() {
        createScene();
        this.setLayout(new BorderLayout());
        this.add(jfxPanel, BorderLayout.CENTER);
    }

    private void createScene() {
        Platform.runLater(
                () -> {
                    WebView view = new WebView();
                    view.setDisable(!enabled);
                    engine = view.getEngine();
                    listenToStateChangesForAdjustingPanelHeightToWebsite();
                    jfxPanel.setScene(new Scene(view));
                });
    }

    private void listenToStateChangesForAdjustingPanelHeightToWebsite() {
        engine.getLoadWorker()
                .stateProperty()
                .addListener(
                        (ObservableValue<?> observable, Object oldValue, Object newValue) -> {
                            if (State.SUCCEEDED == newValue && resizeOnLoad) {
                                resizeOnLoad = false;
                                final int height = getWebsiteHeight();
                                SwingUtilities.invokeLater(() -> setWebsiteHeight(height));
                            }
                        });
    }

    public void loadURL(final String url) {
        resizeOnLoad = true;
        Platform.runLater(
                () -> {
                    String tmp = toURL(url);
                    if (tmp == null) {
                        tmp = toURL("http://" + url);
                    }
                    engine.load(tmp);
                });
    }

    public void loadContent(final String content) {
        resizeOnLoad = true;
        Platform.runLater(() -> engine.loadContent(content));
    }

    private static String toURL(String str) {
        try {
            return new URL(str).toExternalForm();
        } catch (MalformedURLException exception) {
            return null;
        }
    }

    private int getWebsiteHeight() {
        String script =
                "var body = document.body, html = document.documentElement;"
                        + "Math.max(body.offsetHeight, html.offsetHeight);";
        return Integer.parseInt(engine.executeScript(script).toString());
    }

    public void adjustPanelHeightToWebsite() {
        final AtomicReference<Integer> webSiteHeight = new AtomicReference<>();
        final CountDownLatch latch = new CountDownLatch(1);

        Platform.runLater(
                () -> {
                    int height = getWebsiteHeight();
                    webSiteHeight.set(height);
                    latch.countDown();
                });

        try {
            if (!latch.await(3, TimeUnit.SECONDS)) {
                LOGGER.debug(
                        "Timeout while waiting for determining websiteHeight in JavaFX-Thread.");
                return;
            }
        } catch (Exception ex) {
            LOGGER.debug("Error while waiting for determining websiteHeight in JavaFX-Thread.", ex);
            return;
        }

        setWebsiteHeight(webSiteHeight.get());
    }

    private void setWebsiteHeight(int height) {
        Dimension preferredSize = jfxPanel.getPreferredSize();
        preferredSize.height = height;
        jfxPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, height));
        jfxPanel.setMinimumSize(new Dimension(Integer.MIN_VALUE, height));
        jfxPanel.setPreferredSize(preferredSize);
        jfxPanel.revalidate();
        jfxPanel.repaint();
    }
}
