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
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.view.StandardFieldsDialog;
import org.zaproxy.zest.core.v1.ZestAction;
import org.zaproxy.zest.core.v1.ZestActionFail;
import org.zaproxy.zest.core.v1.ZestActionGlobalVariableRemove;
import org.zaproxy.zest.core.v1.ZestActionGlobalVariableSet;
import org.zaproxy.zest.core.v1.ZestActionInvoke;
import org.zaproxy.zest.core.v1.ZestActionPrint;
import org.zaproxy.zest.core.v1.ZestActionScan;
import org.zaproxy.zest.core.v1.ZestActionSleep;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ZestActionDialog extends StandardFieldsDialog implements ZestDialog {

    private static final String FIELD_MESSAGE = "zest.dialog.action.label.message";
    private static final String FIELD_PARAM = "zest.dialog.action.label.targetparam";
    private static final String FIELD_PRIORITY = "zest.dialog.action.label.priority";
    private static final String FIELD_MILLISECS = "zest.dialog.action.label.millisecs";
    private static final String FIELD_SCRIPT = "zest.dialog.action.label.script";
    private static final String FIELD_VARIABLE = "zest.dialog.action.label.variable";
    private static final String FIELD_PARAMS = "zest.dialog.action.label.params";
    private static final String FIELD_GLOBAL_VAR = "zest.dialog.action.label.globalvar";
    private static final String FIELD_GLOBAL_VAR_VALUE = "zest.dialog.action.label.globalvar.value";

    private static final String PRIORITY_PREFIX = "zest.dialog.action.priority.";

    private static final long serialVersionUID = 1L;

    private ExtensionZest extension = null;
    private ScriptNode parent = null;
    private ScriptNode child = null;
    private ZestScriptWrapper script = null;
    private ZestStatement stmt = null;
    private ZestAction action = null;
    private boolean add = false;

    private JButton addButton = null;
    private JButton modifyButton = null;
    private JButton removeButton = null;

    private JTable paramsTable = null;
    private ScriptTokensTableModel paramsModel = null;
    private ZestParameterDialog parmaDialog = null;

    public ZestActionDialog(ExtensionZest ext, Frame owner, Dimension dim) {
        super(owner, "zest.dialog.action.add.title", dim);
        this.extension = ext;
    }

    public void init(
            ZestScriptWrapper script,
            ScriptNode parent,
            ScriptNode child,
            ZestStatement stmt,
            ZestAction action,
            boolean add) {
        this.script = script;
        this.add = add;
        this.parent = parent;
        this.child = child;
        this.stmt = stmt;
        this.action = action;

        this.removeAllFields();

        if (add) {
            this.setTitle(Constant.messages.getString("zest.dialog.action.add.title"));
        } else {
            this.setTitle(Constant.messages.getString("zest.dialog.action.edit.title"));
        }

        if (action instanceof ZestActionScan) {
            ZestActionScan za = (ZestActionScan) action;
            List<String> namesList = new ArrayList<String>();
            if (stmt != null && stmt instanceof ZestRequest) {
                ZestRequest req = (ZestRequest) stmt;
                namesList = this.getParamNames(req.getUrl().getQuery());
                if (req.getData() != null) {
                    namesList.addAll(this.getParamNames(req.getData()));
                }
            }
            namesList.add(0, ""); // Allow blank
            this.addComboField(FIELD_PARAM, namesList, za.getTargetParameter());

        } else if (action instanceof ZestActionFail) {
            ZestActionFail za = (ZestActionFail) action;
            this.addTextField(FIELD_MESSAGE, za.getMessage());
            String[] priorities = {
                priorityToStr(ZestActionFail.Priority.INFO),
                priorityToStr(ZestActionFail.Priority.LOW),
                priorityToStr(ZestActionFail.Priority.MEDIUM),
                priorityToStr(ZestActionFail.Priority.HIGH)
            };
            if (za.getPriority() == null) {
                this.addComboField(
                        FIELD_PRIORITY, priorities, priorityToStr(ZestActionFail.Priority.HIGH));
            } else {
                this.addComboField(
                        FIELD_PRIORITY,
                        priorities,
                        priorityToStr(ZestActionFail.Priority.valueOf(za.getPriority())));
            }
            setFieldMainPopupMenu(FIELD_MESSAGE);

        } else if (action instanceof ZestActionPrint) {
            ZestActionPrint za = (ZestActionPrint) action;
            this.addMultilineField(FIELD_MESSAGE, za.getMessage());
            setFieldMainPopupMenu(FIELD_MESSAGE);

        } else if (action instanceof ZestActionSleep) {
            ZestActionSleep za = (ZestActionSleep) action;
            // TODO support longs?
            this.addNumberField(FIELD_MILLISECS, 0, Integer.MAX_VALUE, (int) za.getMilliseconds());

        } else if (action instanceof ZestActionInvoke) {
            ZestActionInvoke za = (ZestActionInvoke) action;

            this.addComboField(FIELD_SCRIPT, this.getScriptNames(), getScriptName(za.getScript()));
            this.addTextField(FIELD_VARIABLE, za.getVariableName());

            this.getParamsModel().setValues(za.getParameters());

            List<JButton> buttons = new ArrayList<JButton>();
            buttons.add(getAddButton());
            buttons.add(getModifyButton());
            buttons.add(getRemoveButton());

            this.addTableField(FIELD_PARAMS, this.getParamsTable(), buttons);
        } else if (action instanceof ZestActionGlobalVariableSet) {
            ZestActionGlobalVariableSet za = (ZestActionGlobalVariableSet) action;
            addTextField(FIELD_GLOBAL_VAR, za.getGlobalVariableName());
            addMultilineField(FIELD_GLOBAL_VAR_VALUE, za.getValue());
            setFieldMainPopupMenu(FIELD_GLOBAL_VAR_VALUE);
        } else if (action instanceof ZestActionGlobalVariableRemove) {
            ZestActionGlobalVariableRemove za = (ZestActionGlobalVariableRemove) action;
            addTextField(FIELD_GLOBAL_VAR, za.getGlobalVariableName());
        }
        this.addPadding();
    }

    private String getScriptName(String filePath) {
        if (filePath == null) {
            return "";
        }

        for (ScriptWrapper script :
                this.extension.getExtScript().getScripts(ExtensionScript.TYPE_STANDALONE)) {
            if (script.getFile() != null && filePath.equals(script.getFile().getAbsolutePath())) {
                return script.getName();
            }
        }
        return "";
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
            final ZestActionDialog parent = this;
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
            // TODO this
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

    private String priorityToStr(ZestActionFail.Priority priority) {
        return Constant.messages.getString(PRIORITY_PREFIX + priority.name().toLowerCase());
    }

    private ZestActionFail.Priority strToPriority(String str) {
        for (ZestActionFail.Priority p : ZestActionFail.Priority.values()) {
            if (this.priorityToStr(p).equals(str)) {
                return p;
            }
        }
        return null;
    }

    private List<String> getScriptNames() {
        List<String> vals = new ArrayList<String>();
        for (ScriptWrapper script :
                this.extension.getExtScript().getScripts(ExtensionScript.TYPE_STANDALONE)) {
            if (script.getFile() != null) {
                // Only show scripts we can refer to
                vals.add(script.getName());
            }
        }
        return vals;
    }

    private List<String> getParamNames(String data) {
        List<String> vals = new ArrayList<String>();
        if (data != null && data.length() > 0) {
            String[] nameValues = data.split("&");
            for (String nameValue : nameValues) {
                String[] nvs = nameValue.split("=");
                if (nvs.length == 2) {
                    vals.add(nvs[0]);
                }
            }
        }
        return vals;
    }

    @Override
    public void save() {
        if (action instanceof ZestActionScan) {
            ZestActionScan za = (ZestActionScan) action;
            za.setTargetParameter(this.getStringValue(FIELD_PARAM));

        } else if (action instanceof ZestActionFail) {
            ZestActionFail za = (ZestActionFail) action;
            za.setMessage(this.getStringValue(FIELD_MESSAGE));
            za.setPriority(this.strToPriority(this.getStringValue(FIELD_PRIORITY)));

        } else if (action instanceof ZestActionPrint) {
            ZestActionPrint za = (ZestActionPrint) action;
            za.setMessage(this.getStringValue(FIELD_MESSAGE));

        } else if (action instanceof ZestActionSleep) {
            ZestActionSleep za = (ZestActionSleep) action;
            za.setMilliseconds(this.getIntValue(FIELD_MILLISECS));

        } else if (action instanceof ZestActionInvoke) {
            ZestActionInvoke za = (ZestActionInvoke) action;
            za.setVariableName(this.getStringValue(FIELD_VARIABLE));
            za.setParameters(this.getParamsModel().getValues());

            ScriptWrapper sc =
                    this.extension.getExtScript().getScript(this.getStringValue(FIELD_SCRIPT));

            za.setScript(sc.getFile().getAbsolutePath());
        } else if (action instanceof ZestActionGlobalVariableSet) {
            ZestActionGlobalVariableSet za = (ZestActionGlobalVariableSet) action;
            za.setGlobalVariableName(getStringValue(FIELD_GLOBAL_VAR));
            za.setValue(getStringValue(FIELD_GLOBAL_VAR_VALUE));
        } else if (action instanceof ZestActionGlobalVariableRemove) {
            ZestActionGlobalVariableRemove za = (ZestActionGlobalVariableRemove) action;
            za.setGlobalVariableName(getStringValue(FIELD_GLOBAL_VAR));
        }

        if (add) {
            if (stmt == null) {
                extension.addToParent(parent, action);
            } else {
                extension.addAfterRequest(parent, child, stmt, action);
            }
        } else {
            extension.updated(child);
            extension.display(child, false);
        }
    }

    @Override
    public String validateFields() {
        if (action instanceof ZestActionGlobalVariableSet
                || action instanceof ZestActionGlobalVariableRemove) {
            if (isEmptyField(FIELD_GLOBAL_VAR)) {
                return Constant.messages.getString("zest.dialog.action.error.globalvar");
            }
        }

        // TODO check script chosen + variable name exists
        return null;
    }

    @Override
    public ZestScriptWrapper getScript() {
        return this.script;
    }
}
