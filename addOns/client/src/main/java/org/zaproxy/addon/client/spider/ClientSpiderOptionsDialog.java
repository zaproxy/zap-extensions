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
package org.zaproxy.addon.client.spider;

import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.client.internal.ScopeCheckComponent;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProvidedBrowserUI;
import org.zaproxy.zap.extension.selenium.ProvidedBrowsersComboBoxModel;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class ClientSpiderOptionsDialog extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private final JComboBox<ProvidedBrowserUI> browserCombo;
    private final ZapNumberSpinner numBrowsersSpinner;
    private final ZapNumberSpinner maxDepthSpinner;
    private final ZapNumberSpinner maxChildrenSpinner;
    private final ZapNumberSpinner initialLoadTimeSpinner;
    private final ZapNumberSpinner pageLoadTimeSpinner;
    private final ZapNumberSpinner actionWaitTimeSpinner;
    private final ZapNumberSpinner shutdownTimeSpinner;
    private final ZapNumberSpinner maxDurationSpinner;
    private final JCheckBox logoutAvoidanceCheckbox;
    private final JCheckBox cacheStaticResourcesCheckbox;
    private final ScopeCheckComponent scopeCheckComponent;

    public ClientSpiderOptionsDialog() {
        setName(Constant.messages.getString("client.spider.options.panel.name"));

        ExtensionSelenium extSelenium =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
        browserCombo = new JComboBox<>(extSelenium.createProvidedBrowsersComboBoxModel());
        numBrowsersSpinner = new ZapNumberSpinner(1, 1, 64);
        maxDepthSpinner =
                new ZapNumberSpinner(0, ClientSpiderOptions.DEFAULT_MAX_DEPTH, Integer.MAX_VALUE);
        maxChildrenSpinner = new ZapNumberSpinner(0, 0, Integer.MAX_VALUE);
        initialLoadTimeSpinner =
                new ZapNumberSpinner(
                        0, ClientSpiderOptions.DEFAULT_INITIAL_LOAD_TIME, Integer.MAX_VALUE);
        pageLoadTimeSpinner =
                new ZapNumberSpinner(
                        0, ClientSpiderOptions.DEFAULT_PAGE_LOAD_TIME, Integer.MAX_VALUE);
        actionWaitTimeSpinner =
                new ZapNumberSpinner(
                        0, ClientSpiderOptions.DEFAULT_ACTION_WAIT_TIME, Integer.MAX_VALUE);
        shutdownTimeSpinner =
                new ZapNumberSpinner(
                        0, ClientSpiderOptions.DEFAULT_SHUTDOWN_TIME, Integer.MAX_VALUE);
        maxDurationSpinner = new ZapNumberSpinner(0, 0, Integer.MAX_VALUE);
        logoutAvoidanceCheckbox =
                new JCheckBox(Constant.messages.getString("client.options.label.logoutAvoidance"));
        cacheStaticResourcesCheckbox =
                new JCheckBox(
                        Constant.messages.getString("client.options.label.cacheStaticResources"));
        scopeCheckComponent = new ScopeCheckComponent();

        setLayout(new GridBagLayout());
        int row = 0;

        JLabel browserLabel =
                new JLabel(Constant.messages.getString("client.scandialog.label.browser"));
        browserLabel.setLabelFor(browserCombo);
        add(browserLabel, LayoutHelper.getGBC(0, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        add(browserCombo, LayoutHelper.getGBC(1, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        row++;

        JLabel numBrowsersLabel =
                new JLabel(Constant.messages.getString("client.options.label.browsers"));
        numBrowsersLabel.setLabelFor(numBrowsersSpinner);
        add(numBrowsersLabel, LayoutHelper.getGBC(0, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        add(numBrowsersSpinner, LayoutHelper.getGBC(1, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        row++;

        JLabel maxDepthLabel =
                new JLabel(Constant.messages.getString("client.options.label.depth"));
        maxDepthLabel.setLabelFor(maxDepthSpinner);
        add(maxDepthLabel, LayoutHelper.getGBC(0, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        add(maxDepthSpinner, LayoutHelper.getGBC(1, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        row++;

        JLabel maxChildrenLabel =
                new JLabel(Constant.messages.getString("client.options.label.children"));
        maxChildrenLabel.setLabelFor(maxChildrenSpinner);
        add(maxChildrenLabel, LayoutHelper.getGBC(0, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        add(maxChildrenSpinner, LayoutHelper.getGBC(1, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        row++;

        JLabel initialLoadTimeLabel =
                new JLabel(Constant.messages.getString("client.options.label.initialloadtime"));
        initialLoadTimeLabel.setLabelFor(initialLoadTimeSpinner);
        add(initialLoadTimeLabel, LayoutHelper.getGBC(0, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        add(initialLoadTimeSpinner, LayoutHelper.getGBC(1, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        row++;

        JLabel pageLoadTimeLabel =
                new JLabel(Constant.messages.getString("client.options.label.pageloadtime"));
        pageLoadTimeLabel.setLabelFor(pageLoadTimeSpinner);
        add(pageLoadTimeLabel, LayoutHelper.getGBC(0, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        add(pageLoadTimeSpinner, LayoutHelper.getGBC(1, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        row++;

        JLabel actionWaitTimeLabel =
                new JLabel(Constant.messages.getString("client.options.label.actionwaittime"));
        actionWaitTimeLabel.setLabelFor(actionWaitTimeSpinner);
        add(actionWaitTimeLabel, LayoutHelper.getGBC(0, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        add(actionWaitTimeSpinner, LayoutHelper.getGBC(1, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        row++;

        JLabel shutdownTimeLabel =
                new JLabel(Constant.messages.getString("client.options.label.shutdowntime"));
        shutdownTimeLabel.setLabelFor(shutdownTimeSpinner);
        add(shutdownTimeLabel, LayoutHelper.getGBC(0, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        add(shutdownTimeSpinner, LayoutHelper.getGBC(1, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        row++;

        JLabel maxDurationLabel =
                new JLabel(Constant.messages.getString("client.options.label.maxduration"));
        maxDurationLabel.setLabelFor(maxDurationSpinner);
        add(maxDurationLabel, LayoutHelper.getGBC(0, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        add(maxDurationSpinner, LayoutHelper.getGBC(1, row, 1, 0.5, new Insets(2, 2, 2, 2)));
        row++;

        add(
                scopeCheckComponent.getComponent(),
                LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(2, 2, 2, 2)));
        row++;

        add(logoutAvoidanceCheckbox, LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(2, 2, 2, 2)));
        row++;

        add(
                cacheStaticResourcesCheckbox,
                LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(2, 2, 2, 2)));
        row++;

        add(new JLabel(), LayoutHelper.getGBC(0, row, 2, 1.0, 1.0));
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        ClientSpiderOptions clientOptions = optionsParam.getParamSet(ClientSpiderOptions.class);

        ((ProvidedBrowsersComboBoxModel) browserCombo.getModel())
                .setSelectedBrowser(clientOptions.getBrowserId());

        numBrowsersSpinner.setValue(clientOptions.getThreadCount());
        maxDepthSpinner.setValue(clientOptions.getMaxDepth());
        maxChildrenSpinner.setValue(clientOptions.getMaxChildren());
        initialLoadTimeSpinner.setValue(clientOptions.getInitialLoadTimeInSecs());
        pageLoadTimeSpinner.setValue(clientOptions.getPageLoadTimeInSecs());
        actionWaitTimeSpinner.setValue(clientOptions.getActionWaitTimeInSecs());
        shutdownTimeSpinner.setValue(clientOptions.getShutdownTimeInSecs());
        maxDurationSpinner.setValue(clientOptions.getMaxDuration());
        logoutAvoidanceCheckbox.setSelected(clientOptions.isLogoutAvoidance());
        cacheStaticResourcesCheckbox.setSelected(clientOptions.isCacheStaticResources());
        scopeCheckComponent.setScopeCheck(clientOptions.getScopeCheck());
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam optionsParam = (OptionsParam) obj;
        ClientSpiderOptions clientOptions = optionsParam.getParamSet(ClientSpiderOptions.class);

        ProvidedBrowserUI selectedBrowser = (ProvidedBrowserUI) browserCombo.getSelectedItem();
        if (selectedBrowser != null) {
            clientOptions.setBrowserId(selectedBrowser.getBrowser().getId());
        }

        clientOptions.setThreadCount(numBrowsersSpinner.getValue());
        clientOptions.setMaxDepth(maxDepthSpinner.getValue());
        clientOptions.setMaxChildren(maxChildrenSpinner.getValue());
        clientOptions.setInitialLoadTimeInSecs(initialLoadTimeSpinner.getValue());
        clientOptions.setPageLoadTimeInSecs(pageLoadTimeSpinner.getValue());
        clientOptions.setActionWaitTimeInSecs(actionWaitTimeSpinner.getValue());
        clientOptions.setShutdownTimeInSecs(shutdownTimeSpinner.getValue());
        clientOptions.setMaxDuration(maxDurationSpinner.getValue());
        clientOptions.setLogoutAvoidance(logoutAvoidanceCheckbox.isSelected());
        clientOptions.setCacheStaticResources(cacheStaticResourcesCheckbox.isSelected());
        clientOptions.setScopeCheck(scopeCheckComponent.getScopeCheck());
    }

    @Override
    public String getHelpIndex() {
        return "addon.client.spider.options";
    }
}
