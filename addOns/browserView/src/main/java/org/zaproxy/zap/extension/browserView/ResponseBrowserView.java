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
import java.awt.event.ActionListener;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import org.apache.commons.configuration.FileConfiguration;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModelEvent;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModelListener;

public class ResponseBrowserView implements HttpPanelView, HttpPanelViewModelListener {

    public static final String NAME = "ResponseWebView";
    private static final String RESOURCE = "/org/zaproxy/zap/extension/browserView/resources";
    private static final ImageIcon ADJUST_HEIGHT_ICON =
            new ImageIcon(BrowserPanel.class.getResource(RESOURCE + "/adjustHeightIcon.png"));
    public static final String CAPTION_NAME = Constant.messages.getString("browserView.view.name");
    public static final String ADJUST_HEIGHT_BUTTON_TOOLTIP =
            Constant.messages.getString("browserView.panel.adjustheight");

    private JPanel mainPanel;
    private BrowserPanel ssb;

    private HttpPanelViewModel model;

    public ResponseBrowserView(HttpPanelViewModel model) {
        this.model = model;
        ssb = new BrowserPanel(false);
        mainPanel = new JPanel(new BorderLayout());

        JToolBar toolBar = createToolbar();
        mainPanel.add(toolBar, BorderLayout.PAGE_START);

        mainPanel.add(new JScrollPane(ssb), BorderLayout.CENTER);
        this.model.addHttpPanelViewModelListener(this);
    }

    private JToolBar createToolbar() {
        JToolBar toolBar = new JToolBar();
        toolBar.setFloatable(false);
        toolBar.setMinimumSize(new Dimension(50, 50));
        JButton button = createAdjustHeightButton();
        toolBar.add(button);
        return toolBar;
    }

    private JButton createAdjustHeightButton() {
        JButton button = new JButton();
        button.setToolTipText(ADJUST_HEIGHT_BUTTON_TOOLTIP);
        button.setIcon(ADJUST_HEIGHT_ICON);

        ActionListener actionListener = e -> ssb.adjustPanelHeightToWebsite();

        button.addActionListener(actionListener);
        return button;
    }

    @Override
    public void save() {}

    @Override
    public void setSelected(boolean selected) {
        if (selected) {
            ssb.requestFocusInWindow();
        }
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getCaptionName() {
        return CAPTION_NAME;
    }

    @Override
    public String getTargetViewName() {
        return "";
    }

    @Override
    public int getPosition() {
        return 1;
    }

    @Override
    public boolean isEnabled(Message aMessage) {
        return isHtml(aMessage);
    }

    @Override
    public boolean hasChanged() {
        return false;
    }

    @Override
    public JComponent getPane() {
        return mainPanel;
    }

    @Override
    public boolean isEditable() {
        return false;
    }

    @Override
    public void setEditable(boolean editable) {}

    @Override
    public void setParentConfigurationKey(String configurationKey) {}

    @Override
    public void loadConfiguration(FileConfiguration fileConfiguration) {}

    @Override
    public void saveConfiguration(FileConfiguration fileConfiguration) {}

    @Override
    public HttpPanelViewModel getModel() {
        return model;
    }

    @Override
    public void dataChanged(HttpPanelViewModelEvent e) {
        HttpMessage msg = (HttpMessage) model.getMessage();
        if (isHtml(msg)) {
            ssb.loadContent(msg.getResponseBody().toString());
        }
    }

    static boolean isHtml(final Message aMessage) {
        if (aMessage instanceof HttpMessage) {
            HttpMessage httpMessage = (HttpMessage) aMessage;
            if (httpMessage.getResponseBody().length() == 0) {
                return false;
            }
            return httpMessage.getResponseHeader().isHtml();
        }
        return false;
    }
}
