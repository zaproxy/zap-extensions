/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters;

import java.awt.CardLayout;
import java.awt.GridBagLayout;
import java.awt.Window;
import javax.swing.JLabel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.view.AbstractContextPropertiesPanel;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class ContextAlertFilterPanel extends AbstractContextPropertiesPanel {

    private AlertFiltersMultipleOptionsPanel alertFilterOptionsPanel;
    private ContextAlertFilterManager contextManager;
    private AlertFilterTableModel alertFilterTableModel;
    private ExtensionAlertFilters extension;
    private Window owner;

    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = -3920598166129639573L;

    private static final String PANEL_NAME =
            Constant.messages.getString("alertFilters.panel.title");

    public ContextAlertFilterPanel(ExtensionAlertFilters extension, Window owner, int contextId) {
        super(contextId);
        this.extension = extension;
        this.owner = owner;
        this.contextManager = extension.getContextAlertFilterManager(contextId);
        initialize();
    }

    public static String getPanelName(int contextId) {
        // Panel names have to be unique, so prefix with the context id
        return contextId + ": " + PANEL_NAME;
    }

    private void initialize() {
        this.setLayout(new CardLayout());
        this.setName(getPanelName(getContextId()));
        this.setLayout(new GridBagLayout());

        this.add(
                new JLabel(Constant.messages.getString("alertFilters.panel.description")),
                LayoutHelper.getGBC(0, 0, 1, 1.0d, 0.0d));

        alertFilterTableModel = new AlertFilterTableModel();
        alertFilterOptionsPanel =
                new AlertFiltersMultipleOptionsPanel(extension, this.owner, alertFilterTableModel);
        this.add(alertFilterOptionsPanel, LayoutHelper.getGBC(0, 1, 1, 1.0d, 1.0d));
    }

    @Override
    public String getHelpIndex() {
        return "addon.contextAlertFilter";
    }

    @Override
    public void initContextData(Session session, Context uiCommonContext) {
        this.alertFilterOptionsPanel.setWorkingContext(uiCommonContext);
        this.alertFilterTableModel.setAlertFilters(this.contextManager.getAlertFilters());
    }

    @Override
    public void validateContextData(Session session) throws Exception {
        // Nothing to validate
    }

    @Override
    public void saveContextData(Session session) throws Exception {
        this.contextManager.setAlertFilters(alertFilterTableModel.getAlertFilters());
    }

    @Override
    public void saveTemporaryContextData(Context uiSharedContext) {
        // Data is already saved in the uiSharedContext
    }

    protected AlertFilterTableModel getAlertFiltersTableModel() {
        return alertFilterTableModel;
    }
}
