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

import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.component.all.request.RequestAllComponent;
import org.zaproxy.zap.extension.httppanel.component.all.response.ResponseAllComponent;
import org.zaproxy.zap.extension.httppanel.component.split.response.ResponseSplitComponent;
import org.zaproxy.zap.extension.httppanel.view.DefaultHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.view.HttpPanelManager;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelViewFactory;

public class ExtensionHttpPanelBrowserView extends ExtensionAdaptor {

    public static final String NAME = "ExtensionHttpPanelBrowserView";

    private static final Logger LOGGER = Logger.getLogger(ExtensionHttpPanelBrowserView.class);

    /**
     * The name of the system property used to keep track of initialisation errors of JavaFX.
     *
     * <p>It's needed because attempting to create a 2nd {@code javafx.embed.swing.JFXPanel} leads
     * to a dead lock when JavaFX fails to initialise (instead of throwing an {@code Exception}).
     * It's possible to attempt to create a 2nd {@code JFXPanel} if the user uninstalled the add-on
     * and installed it again without exiting ZAP.
     *
     * @see #isJavaFxAvailable()
     */
    private static final String ZAP_JAVAFX_INIT_FAILED_SYSTEM_PROPERTY = "zap.javafx.init.failed";

    private BrowserViewParam browserViewParam;
    private boolean javaFxAvailable;

    public ExtensionHttpPanelBrowserView() {
        super(NAME);
    }

    @Override
    public void init() {
        super.init();

        browserViewParam = new BrowserViewParam();
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addOptionsParamSet(browserViewParam);

        if (getView() != null) {
            javaFxAvailable = isJavaFxAvailable();

            if (javaFxAvailable) {
                HttpPanelManager panelManager = HttpPanelManager.getInstance();
                panelManager.addResponseViewFactory(
                        ResponseSplitComponent.NAME, new ResponseBrowserViewFactory());
                panelManager.addResponseViewFactory(
                        ResponseAllComponent.NAME, new ResponseBrowserViewFactory2());
            }
        }
    }

    private static boolean isJavaFxAvailable() {
        if (System.getProperty(ZAP_JAVAFX_INIT_FAILED_SYSTEM_PROPERTY) != null) {
            return false;
        }

        try {
            // Attempt to create a JFXPanel which will lead to initialisation (or not) of JavaFX...
            @SuppressWarnings("unused")
            javafx.embed.swing.JFXPanel unused = new javafx.embed.swing.JFXPanel();
            return true;
        } catch (Throwable e) {
            LOGGER.warn("Unable to use JavaFX:", e);
            System.setProperty(ZAP_JAVAFX_INIT_FAILED_SYSTEM_PROPERTY, "true");
        }
        return false;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void start() {
        super.start();

        if (getView() != null && !javaFxAvailable && browserViewParam.isWarnOnJavaFXInitError()) {
            JCheckBox checkBoxDoNotShowErrorAgain =
                    new JCheckBox(
                            getMessages()
                                    .getString(
                                            "browserView.dialog.warn.javafx.init.error.doNotShowAgain"));

            Object[] messages = {
                getMessages().getString("browserView.dialog.warn.javafx.init.error.text"),
                " ",
                checkBoxDoNotShowErrorAgain
            };

            JOptionPane.showMessageDialog(
                    View.getSingleton().getMainFrame(),
                    messages,
                    getMessages().getString("browserView.dialog.warn.javafx.init.error.title"),
                    JOptionPane.WARNING_MESSAGE);

            browserViewParam.setWarnOnJavaFXInitError(!checkBoxDoNotShowErrorAgain.isSelected());
        }
    }

    @Override
    public void unload() {
        super.unload();

        if (getView() != null && javaFxAvailable) {
            HttpPanelManager panelManager = HttpPanelManager.getInstance();
            panelManager.removeResponseViewFactory(
                    ResponseSplitComponent.NAME, ResponseBrowserViewFactory.NAME);
            panelManager.removeResponseViews(
                    ResponseSplitComponent.NAME,
                    ResponseBrowserView.NAME,
                    ResponseSplitComponent.ViewComponent.BODY);
            panelManager.removeResponseViewFactory(
                    RequestAllComponent.NAME, ResponseBrowserViewFactory2.NAME);
            panelManager.removeResponseViews(
                    ResponseAllComponent.NAME, ResponseBrowserViewFactory2.NAME, null);
        }
    }

    private static final class ResponseBrowserViewFactory implements HttpPanelViewFactory {

        public static final String NAME = "ResponseBrowserViewFactory";

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public HttpPanelView getNewView() {
            return new ResponseBrowserView(new DefaultHttpPanelViewModel());
        }

        @Override
        public Object getOptions() {
            return ResponseSplitComponent.ViewComponent.BODY;
        }
    }

    private static final class ResponseBrowserViewFactory2 implements HttpPanelViewFactory {

        public static final String NAME = "ResponseBrowserViewFactory2";

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public HttpPanelView getNewView() {
            return new ResponseBrowserView(new DefaultHttpPanelViewModel());
        }

        @Override
        public Object getOptions() {
            return null;
        }
    }
}
