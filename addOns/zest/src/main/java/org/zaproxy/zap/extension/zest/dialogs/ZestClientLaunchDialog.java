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
package org.zaproxy.zap.extension.zest.dialogs;

import java.awt.Dimension;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ZestClientLaunchDialog extends StandardFieldsDialog implements ZestDialog {

    private static final String FIELD_WINDOW_HANDLE = "zest.dialog.client.label.windowHandle";
    private static final String FIELD_BROWSER_TYPE = "zest.dialog.client.label.browserType";
    private static final String FIELD_HEADLESS = "zest.dialog.client.label.headless";
    private static final String FIELD_URL = "zest.dialog.client.label.url";

    private static String BROWSER_TYPE_PREFIX = "zest.dialog.client.browserType.label.";
    private static String[] BROWSER_TYPES = {
        "firefox", "chrome", "htmlunit", "internetexplorer", "opera", "phantomjs", "safari"
    };
    private static String DEFAULT_BROWSER_TYPE = "firefox";

    private static final long serialVersionUID = 1L;

    private ExtensionZest extension = null;
    private ScriptNode parent = null;
    private ScriptNode child = null;
    private ZestScriptWrapper script = null;
    private ZestStatement request = null;
    private ZestClientLaunch client = null;
    private boolean add = false;

    private JButton addButton = null;
    private JButton modifyButton = null;
    private JButton removeButton = null;

    private JTable paramsTable = null;
    private ScriptTokensTableModel paramsModel = null;
    private ZestParameterDialog parmaDialog = null;

    public ZestClientLaunchDialog(ExtensionZest ext, Frame owner, Dimension dim) {
        super(
                owner,
                "zest.dialog.clientLaunch.add.title",
                dim,
                new String[] {
                    "zest.dialog.clientLaunch.tab.client",
                    "zest.dialog.clientLaunch.tab.capabilities"
                });
        this.extension = ext;
    }

    public void init(
            ZestScriptWrapper script,
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestClientLaunch client,
            boolean add) {
        this.script = script;
        this.add = add;
        this.parent = parent;
        this.child = child;
        this.request = req;
        this.client = client;

        this.removeAllFields();

        if (add) {
            this.setTitle(Constant.messages.getString("zest.dialog.clientLaunch.add.title"));
        } else {
            this.setTitle(Constant.messages.getString("zest.dialog.clientLaunch.edit.title"));
        }

        this.addTextField(0, FIELD_WINDOW_HANDLE, client.getWindowHandle());
        String browserType = client.getBrowserType();
        if (browserType == null || browserType.length() == 0) {
            browserType = DEFAULT_BROWSER_TYPE;
        }
        this.addComboField(
                0,
                FIELD_BROWSER_TYPE,
                getBrowserTypes(),
                Constant.messages.getString(BROWSER_TYPE_PREFIX + browserType));
        this.addCheckBoxField(0, FIELD_HEADLESS, client.isHeadless());
        this.addTextField(0, FIELD_URL, client.getUrl());
        this.addPadding(0);

        this.getParamsModel().setValues(getCapabilities(client));

        List<JButton> buttons = new ArrayList<JButton>();
        buttons.add(getAddButton());
        buttons.add(getModifyButton());
        buttons.add(getRemoveButton());

        this.addTableField(1, this.getParamsTable(), buttons);

        setFieldMainPopupMenu(FIELD_URL);
    }

    private List<String[]> getCapabilities(ZestClientLaunch client) {
        // TODO
        List<String[]> list = new ArrayList<String[]>();
        if (client.getCapabilities() != null) {
            for (String capability : client.getCapabilities().split("\n")) {
                if (capability != null && capability.trim().length() > 0) {
                    String[] typeValue = capability.split("=");
                    if (typeValue.length == 2) {
                        list.add(typeValue);
                    }
                }
            }
        }
        return list;
    }

    private String getCapabilityString() {
        StringBuilder sb = new StringBuilder();
        for (String[] kv : this.getParamsModel().getValues()) {
            sb.append(kv[0]);
            sb.append("=");
            sb.append(kv[1]);
            sb.append("\n");
        }
        return sb.toString();
    }

    private String[] getBrowserTypes() {
        String[] list = new String[BROWSER_TYPES.length];
        for (int i = 0; i < BROWSER_TYPES.length; i++) {
            list[i] = Constant.messages.getString(BROWSER_TYPE_PREFIX + BROWSER_TYPES[i]);
        }
        return list;
    }

    private String getSelectedBrowserType() {
        String selectedType = this.getStringValue(FIELD_BROWSER_TYPE);
        for (String type : BROWSER_TYPES) {
            if (Constant.messages.getString(BROWSER_TYPE_PREFIX + type).equals(selectedType)) {
                return type;
            }
        }
        return null;
    }

    private JButton getAddButton() {
        if (this.addButton == null) {
            this.addButton =
                    new JButton(Constant.messages.getString("zest.dialog.script.button.add"));
            this.addButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            ZestParameterDialog dialog = getParamDialog();
                            if (!dialog.isVisible()) {
                                dialog.init(script, "", "", true, -1, true);
                                dialog.setVisible(true);
                            }
                        }
                    });
        }
        return this.addButton;
    }

    private JButton getModifyButton() {
        if (this.modifyButton == null) {
            this.modifyButton =
                    new JButton(Constant.messages.getString("zest.dialog.script.button.modify"));
            this.modifyButton.setEnabled(false);
            this.modifyButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            showParamDialog();
                        }
                    });
        }
        return this.modifyButton;
    }

    private void showParamDialog() {
        ZestParameterDialog dialog = getParamDialog();
        if (!dialog.isVisible()) {
            int row = getParamsTable().getSelectedRow();
            dialog.init(
                    script,
                    (String) getParamsModel().getValueAt(row, 0),
                    (String) getParamsModel().getValueAt(row, 1),
                    false,
                    row,
                    true);
            dialog.setVisible(true);
        }
    }

    private JButton getRemoveButton() {
        if (this.removeButton == null) {
            this.removeButton =
                    new JButton(Constant.messages.getString("zest.dialog.script.button.remove"));
            this.removeButton.setEnabled(false);
            final ZestClientLaunchDialog parent = this;
            this.removeButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            if (JOptionPane.OK_OPTION
                                    == View.getSingleton()
                                            .showConfirmDialog(
                                                    parent,
                                                    Constant.messages.getString(
                                                            "zest.dialog.script.remove.confirm"))) {
                                getParamsModel().remove(getParamsTable().getSelectedRow());
                            }
                        }
                    });
        }
        return this.removeButton;
    }

    private ZestParameterDialog getParamDialog() {
        if (this.parmaDialog == null) {
            this.parmaDialog =
                    new ZestParameterDialog(this.getParamsModel(), this, new Dimension(300, 200));
        }
        return this.parmaDialog;
    }

    private JTable getParamsTable() {
        if (paramsTable == null) {
            paramsTable = new JTable();
            paramsTable.setModel(getParamsModel());
            paramsTable
                    .getSelectionModel()
                    .addListSelectionListener(
                            new ListSelectionListener() {
                                @Override
                                public void valueChanged(ListSelectionEvent e) {
                                    if (getParamsTable().getSelectedRowCount() == 0) {
                                        modifyButton.setEnabled(false);
                                        removeButton.setEnabled(false);
                                    } else if (getParamsTable().getSelectedRowCount() == 1) {
                                        modifyButton.setEnabled(true);
                                        removeButton.setEnabled(true);
                                    } else {
                                        modifyButton.setEnabled(false);
                                        // TODO allow multiple deletions?
                                        removeButton.setEnabled(false);
                                    }
                                }
                            });
            paramsTable.addMouseListener(
                    new MouseListener() {
                        @Override
                        public void mouseClicked(MouseEvent e) {
                            // Show param dialog on double click
                            if (e.getClickCount() > 1) {
                                showParamDialog();
                            }
                        }

                        @Override
                        public void mousePressed(MouseEvent e) {}

                        @Override
                        public void mouseReleased(MouseEvent e) {}

                        @Override
                        public void mouseEntered(MouseEvent e) {}

                        @Override
                        public void mouseExited(MouseEvent e) {}
                    });
        }
        return paramsTable;
    }

    private ScriptTokensTableModel getParamsModel() {
        if (paramsModel == null) {
            paramsModel = new ScriptTokensTableModel();
        }
        return paramsModel;
    }

    @Override
    public void save() {
        client.setWindowHandle(this.getStringValue(FIELD_WINDOW_HANDLE));
        client.setBrowserType(this.getSelectedBrowserType());
        client.setHeadless(this.getBoolValue(FIELD_HEADLESS));
        client.setUrl(this.getStringValue(FIELD_URL));
        client.setCapabilities(this.getCapabilityString());

        if (add) {
            if (request == null) {
                extension.addToParent(parent, client);
            } else {
                extension.addAfterRequest(parent, child, request, client);
            }
        } else {
            extension.updated(child);
            extension.display(child, false);
        }
    }

    @Override
    public String validateFields() {
        // Cant validate the url as it may contain tokens

        if (!ZestZapUtils.isValidVariableName(this.getStringValue(FIELD_WINDOW_HANDLE))) {
            return Constant.messages.getString("zest.dialog.client.error.windowHandle");
        }

        // TODO validate capabilities?

        return null;
    }

    @Override
    public ZestScriptWrapper getScript() {
        return this.script;
    }
}
