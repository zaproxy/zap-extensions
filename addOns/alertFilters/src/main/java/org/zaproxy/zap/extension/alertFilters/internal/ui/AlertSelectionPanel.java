/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters.internal.ui;

import java.awt.event.ItemEvent;
import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import org.zaproxy.zap.extension.alertFilters.ExtensionAlertFilters;
import org.zaproxy.zap.extension.alertFilters.internal.ScanRulesInfo;

public class AlertSelectionPanel {

    private final JPanel panel;
    private final JComboBox<ScanRulesInfo.Entry> names;
    private final JComboBox<String> ids;

    public AlertSelectionPanel() {
        names =
                new JComboBox<>(
                        new ScanRulesInfoComboBoxModel(ExtensionAlertFilters.getScanRulesInfo()));
        ids = new JComboBox<>();
        ids.setEditable(true);

        panel = new JPanel();
        GroupLayout layout = new GroupLayout(panel);
        panel.setLayout(layout);
        layout.setAutoCreateGaps(true);

        layout.setHorizontalGroup(
                layout.createSequentialGroup().addComponent(names).addComponent(ids));

        layout.setVerticalGroup(layout.createParallelGroup().addComponent(names).addComponent(ids));

        names.addItemListener(
                e -> {
                    if (e.getStateChange() == ItemEvent.DESELECTED) {
                        return;
                    }

                    ids.setSelectedItem(((ScanRulesInfo.Entry) e.getItem()).getId());
                });
        ids.addItemListener(
                e -> {
                    if (e.getStateChange() == ItemEvent.DESELECTED) {
                        return;
                    }

                    if (e.getItem() == null) {
                        return;
                    }

                    names.setSelectedItem(
                            ExtensionAlertFilters.getScanRulesInfo()
                                    .getById(e.getItem().toString()));
                });

        reset();
    }

    public JPanel getPanel() {
        return panel;
    }

    public void reset() {
        ids.removeAllItems();
        ExtensionAlertFilters.getScanRulesInfo().getIds().stream().sorted().forEach(ids::addItem);
    }

    public String getSelectedId() {
        String selected = (String) ids.getSelectedItem();
        return selected == null || selected.isBlank() ? null : selected;
    }

    public void setSelectedId(String id) {
        ids.setSelectedItem(id);
    }

    public String getSelectedName() {
        return ExtensionAlertFilters.getScanRulesInfo().getNameById(getSelectedId());
    }
}
