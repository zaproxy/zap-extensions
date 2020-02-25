/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.plugnhack.httppanel.component;

import java.awt.BorderLayout;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.regex.Pattern;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JToggleButton;
import org.apache.commons.configuration.FileConfiguration;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.component.HttpPanelComponentInterface;
import org.zaproxy.zap.extension.httppanel.component.HttpPanelComponentViewsManager;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelDefaultViewSelector;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.plugnhack.ClientMessage;
import org.zaproxy.zap.extension.plugnhack.ExtensionPlugNHack;
import org.zaproxy.zap.extension.plugnhack.httppanel.models.JsonClientPanelViewModel;
import org.zaproxy.zap.extension.plugnhack.httppanel.models.StringClientPanelViewModel;
import org.zaproxy.zap.extension.plugnhack.httppanel.views.ClientPanelJsonView;
import org.zaproxy.zap.extension.plugnhack.httppanel.views.ClientPanelTextView;
import org.zaproxy.zap.extension.search.SearchMatch;
import org.zaproxy.zap.extension.search.SearchableHttpPanelComponent;

public class ClientComponent implements HttpPanelComponentInterface, SearchableHttpPanelComponent {

    public static final String NAME = "PnhClientComponent";

    private static final String BUTTON_TOOL_TIP =
            Constant.messages.getString("plugnhack.panel.component.all.tooltip");
    private static final SimpleDateFormat SDF = new SimpleDateFormat("HH:mm:ss.SSS");

    protected JToggleButton buttonShowView;

    protected JPanel panelOptions;
    protected JPanel panelMoreOptions;
    protected JPanel panelMain;

    private JLabel informationLabel;

    protected ClientMessage message;

    protected HttpPanelComponentViewsManager views;

    public ClientComponent() {
        this.message = null;

        views = new HttpPanelComponentViewsManager("pnhClient");

        initUi();
    }

    protected void initUi() {
        // Common
        buttonShowView =
                new JToggleButton(
                        new ImageIcon(
                                HttpPanelComponentInterface.class.getResource(
                                        ExtensionPlugNHack.CLIENT_ACTIVE_ICON_RESOURCE)));

        buttonShowView.setToolTipText(BUTTON_TOOL_TIP);

        panelOptions = new JPanel();
        panelOptions.add(views.getSelectableViewsComponent());

        informationLabel = new JLabel();
        panelMoreOptions = new JPanel();
        panelMoreOptions.add(informationLabel);

        initViews();

        // All
        panelMain = new JPanel(new BorderLayout());
        panelMain.add(views.getViewsPanel());

        setSelected(false);
    }

    @Override
    public void setParentConfigurationKey(String configurationKey) {
        views.setConfigurationKey(configurationKey);
    }

    @Override
    public JToggleButton getButton() {
        return buttonShowView;
    }

    @Override
    public JPanel getOptionsPanel() {
        return panelOptions;
    }

    @Override
    public JPanel getMoreOptionsPanel() {
        return panelMoreOptions;
    }

    @Override
    public JPanel getMainPanel() {
        return panelMain;
    }

    @Override
    public void setSelected(boolean selected) {
        buttonShowView.setSelected(selected);

        views.setSelected(selected);
    }

    @Override
    public boolean isEnabled(Message aMessage) {
        return (aMessage instanceof ClientMessage);
    }

    protected void initViews() {
        views.addView(new ClientPanelTextView(new StringClientPanelViewModel()));
        views.addView(new ClientPanelJsonView(new JsonClientPanelViewModel()));
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public int getPosition() {
        return 2;
    }

    @Override
    public void setMessage(Message aMessage) {
        this.message = (ClientMessage) aMessage;

        informationLabel.setText(
                Constant.messages.getString(
                        "plugnhack.clientmsg",
                        SDF.format(message.getReceived()),
                        message.getClientId(),
                        message.getType()));

        views.setMessage(message);
    }

    @Override
    public void save() {
        if (message == null) {
            return;
        }

        views.save();
    }

    @Override
    public void addView(HttpPanelView view, Object options, FileConfiguration fileConfiguration) {
        views.addView(view, fileConfiguration);
    }

    @Override
    public void removeView(String viewName, Object options) {
        views.removeView(viewName);
    }

    @Override
    public void clearView() {
        views.clearView();

        informationLabel.setText("");
    }

    @Override
    public void clearView(boolean enableViewSelect) {
        clearView();

        setEnableViewSelect(enableViewSelect);
    }

    @Override
    public void setEnableViewSelect(boolean enableViewSelect) {
        views.setEnableViewSelect(enableViewSelect);
    }

    @Override
    public void addDefaultViewSelector(
            HttpPanelDefaultViewSelector defaultViewSelector, Object options) {
        views.addDefaultViewSelector(defaultViewSelector);
    }

    @Override
    public void removeDefaultViewSelector(String defaultViewSelectorName, Object options) {
        views.removeDefaultViewSelector(defaultViewSelectorName);
    }

    @Override
    public void loadConfig(FileConfiguration fileConfiguration) {
        views.loadConfig(fileConfiguration);
    }

    @Override
    public void saveConfig(FileConfiguration fileConfiguration) {
        views.saveConfig(fileConfiguration);
    }

    @Override
    public void setEditable(boolean editable) {
        views.setEditable(editable);
    }

    @Override
    public void highlightHeader(SearchMatch sm) {
        views.highlight(sm);
    }

    @Override
    public void highlightBody(SearchMatch sm) {
        views.highlight(sm);
    }

    @Override
    public void searchHeader(Pattern p, List<SearchMatch> matches) {
        views.search(p, matches);
    }

    @Override
    public void searchBody(Pattern p, List<SearchMatch> matches) {
        views.search(p, matches);
    }

    @Override
    public HttpPanelView setSelectedView(String arg0) {
        return null;
    }
}
