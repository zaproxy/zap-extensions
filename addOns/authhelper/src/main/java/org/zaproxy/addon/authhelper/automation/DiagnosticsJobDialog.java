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
package org.zaproxy.addon.authhelper.automation;

import java.awt.Component;
import java.awt.Container;
import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JList;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.authhelper.AuthDiagnosticsPolicy.Mode;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class DiagnosticsJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "authhelper.automation.diagnostics.dialog.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";
    private static final String ENABLED_PARAM = "authhelper.automation.diagnostics.dialog.enabled";
    private static final String TYPE_PARAM = "authhelper.automation.diagnostics.dialog.type";
    private static final String COUNT_PARAM = "authhelper.automation.diagnostics.dialog.count";

    private final DiagnosticsJob job;
    private final DefaultComboBoxModel<Mode> typeModel;
    private final Component countField;
    private final JLabel countLabel;

    public DiagnosticsJobDialog(DiagnosticsJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(400, 260));
        this.job = job;

        this.addTextField(NAME_PARAM, this.job.getData().getName());
        this.addCheckBoxField(ENABLED_PARAM, this.job.getParameters().isEnabled());

        typeModel = new DefaultComboBoxModel<>(Mode.values());
        typeModel.insertElementAt(null, 0);
        typeModel.setSelectedItem(this.job.getParameters().getType());

        DefaultListCellRenderer renderer =
                new DefaultListCellRenderer() {
                    private static final long serialVersionUID = 1L;

                    @Override
                    public Component getListCellRendererComponent(
                            JList<?> list,
                            Object value,
                            int index,
                            boolean isSelected,
                            boolean cellHasFocus) {
                        JLabel label =
                                (JLabel)
                                        super.getListCellRendererComponent(
                                                list, value, index, isSelected, cellHasFocus);
                        // A non-breaking space keeps the row's height when blank, so it stays
                        // clickable in the drop-down list.
                        label.setText(value instanceof Mode ? ((Mode) value).getName() : " ");
                        return label;
                    }
                };

        this.addComboField(TYPE_PARAM, typeModel);
        Component typeField = this.getField(TYPE_PARAM);
        if (typeField instanceof JComboBox) {
            ((JComboBox<?>) typeField).setRenderer(renderer);
        }

        this.addNumberField(COUNT_PARAM, 1, Integer.MAX_VALUE, this.job.getParameters().getCount());
        countField = this.getField(COUNT_PARAM);
        countLabel = labelFor(countField);

        this.addFieldListener(TYPE_PARAM, e -> updateCountEnabled());
        updateCountEnabled();

        this.addPadding();
    }

    private void updateCountEnabled() {
        boolean rolling = typeModel.getSelectedItem() == Mode.AUTH_FAILURE_ROLLING;
        countField.setEnabled(rolling);
        if (countLabel != null) {
            countLabel.setEnabled(rolling);
        }
    }

    private static JLabel labelFor(Component field) {
        Container parent = field.getParent();
        if (parent == null) {
            return null;
        }
        for (Component sibling : parent.getComponents()) {
            if (sibling instanceof JLabel && ((JLabel) sibling).getLabelFor() == field) {
                return (JLabel) sibling;
            }
        }
        return null;
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getParameters().setEnabled(this.getBoolValue(ENABLED_PARAM));
        this.job.getParameters().setType((Mode) typeModel.getSelectedItem());
        this.job.getParameters().setCount(this.getIntValue(COUNT_PARAM));
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        return null;
    }
}
