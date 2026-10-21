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
package org.zaproxy.addon.authhelper;

import java.awt.GridBagLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.selenium.BrowserUI;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.NodeSelectDialog;

/**
 * Builds the "Login URL" / "Browser" / "Login Wait" fields shared by the Browser Based and AI
 * Assisted authentication method options panels.
 */
public final class AuthMethodOptionsPanelUtils {

    private static final Logger LOGGER = LogManager.getLogger(AuthMethodOptionsPanelUtils.class);

    private AuthMethodOptionsPanelUtils() {}

    /**
     * Adds the Login URL (with a site-tree select button), Browser and Login Wait fields to {@code
     * panel}, occupying grid rows 0-3. Callers should add any further fields from row 4 onwards.
     *
     * @param panel the panel to add the fields to; must use a {@link GridBagLayout}
     * @param extSel the Selenium extension, used to populate the browser combo box
     * @param defaultPageWait the initial value of the login-wait spinner
     * @return the created fields
     */
    public static LoginUrlBrowserWaitFields addLoginUrlBrowserWaitFields(
            JPanel panel, ExtensionSelenium extSel, int defaultPageWait) {
        ZapTextField loginUrlField = new ZapTextField();

        JButton selectButton = new JButton(Constant.messages.getString("all.button.select"));
        selectButton.setIcon(new ImageIcon(View.class.getResource("/resource/icon/16/094.png")));
        selectButton.addActionListener(
                e -> {
                    NodeSelectDialog nsd = new NodeSelectDialog(View.getSingleton().getMainFrame());
                    SiteNode node = null;
                    if (!loginUrlField.getText().trim().isEmpty()) {
                        try {
                            node =
                                    Model.getSingleton()
                                            .getSession()
                                            .getSiteTree()
                                            .findNode(new URI(loginUrlField.getText(), false));
                        } catch (Exception e2) {
                            // Ignore. It means we could not properly get a node for the existing
                            // value and does not have any harmful effects.
                        }
                    }
                    node = nsd.showDialog(node);
                    if (node != null && node.getHistoryReference() != null) {
                        try {
                            loginUrlField.setText(node.getHistoryReference().getURI().toString());
                        } catch (Exception e1) {
                            LOGGER.error(e1.getMessage(), e1);
                        }
                    }
                });

        JLabel urlSelectLabel =
                new JLabel(
                        Constant.messages.getString(
                                "authhelper.auth.method.browser.label.loginUrl"));
        urlSelectLabel.setLabelFor(loginUrlField);
        panel.add(urlSelectLabel, LayoutHelper.getGBC(0, 0, 2, 1.0d, 0.0d));

        JPanel urlSelectPanel = new JPanel(new GridBagLayout());
        urlSelectPanel.add(loginUrlField, LayoutHelper.getGBC(0, 0, 1, 1.0D));
        urlSelectPanel.add(selectButton, LayoutHelper.getGBC(1, 0, 1, 0.0D));
        panel.add(urlSelectPanel, LayoutHelper.getGBC(0, 1, 2, 1.0d, 0.0d));

        JComboBox<BrowserUI> browserCombo = new JComboBox<>(extSel.createBrowsersComboBoxModel());
        JLabel browserSelectLabel =
                new JLabel(
                        Constant.messages.getString(
                                "authhelper.auth.method.browser.label.browser"));
        browserSelectLabel.setLabelFor(browserCombo);
        panel.add(browserSelectLabel, LayoutHelper.getGBC(0, 2, 1, 1.0d, 0.0d));
        panel.add(browserCombo, LayoutHelper.getGBC(1, 2, 1, 1.0d, 0.0d));

        ZapNumberSpinner loginUrlWait = new ZapNumberSpinner(0, defaultPageWait, Integer.MAX_VALUE);
        JLabel loginWaitLabel =
                new JLabel(
                        Constant.messages.getString(
                                "authhelper.auth.method.browser.label.loginWait"));
        loginWaitLabel.setLabelFor(loginUrlWait);
        panel.add(loginWaitLabel, LayoutHelper.getGBC(0, 3, 1, 1.0d, 0.0d));
        panel.add(loginUrlWait, LayoutHelper.getGBC(1, 3, 1, 1.0d, 0.0d));

        return new LoginUrlBrowserWaitFields(loginUrlField, browserCombo, loginUrlWait);
    }

    /** The fields created by {@link #addLoginUrlBrowserWaitFields}. */
    public record LoginUrlBrowserWaitFields(
            ZapTextField loginUrlField,
            JComboBox<BrowserUI> browserCombo,
            ZapNumberSpinner loginUrlWait) {}
}
