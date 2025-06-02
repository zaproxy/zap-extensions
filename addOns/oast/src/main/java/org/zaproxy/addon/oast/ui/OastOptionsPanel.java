/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.oast.ui;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JTabbedPane;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class OastOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private final JTabbedPane serviceTabsPane;
    private final List<OastOptionsPanelTab> serviceTabsList = new ArrayList<>();

    public OastOptionsPanel() {
        setName(Constant.messages.getString("oast.options.title"));
        setLayout(new GridBagLayout());
        int rowIndex = -1;
        serviceTabsPane = new JTabbedPane();
        add(
                serviceTabsPane,
                LayoutHelper.getGBC(
                        0,
                        ++rowIndex,
                        GridBagConstraints.REMAINDER,
                        1.0,
                        1.0,
                        GridBagConstraints.BOTH,
                        new Insets(0, 0, 0, 3)));
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam options = (OptionsParam) obj;
        serviceTabsList.forEach(s -> s.initParam(options));
    }

    @Override
    public void saveParam(Object obj) {
        OptionsParam options = (OptionsParam) obj;
        serviceTabsList.forEach(s -> s.saveParam(options));
    }

    public void addServicePanel(OastOptionsPanelTab tab) {
        serviceTabsPane.addTab(tab.getName(), tab);
        serviceTabsList.add(tab);
    }

    @Override
    public String getHelpIndex() {
        return "oast.options";
    }
}
