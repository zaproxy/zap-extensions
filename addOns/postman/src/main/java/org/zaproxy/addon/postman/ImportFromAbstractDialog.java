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
package org.zaproxy.addon.postman;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.IOException;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JTextField;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.view.View;

@SuppressWarnings("serial")
abstract class ImportFromAbstractDialog extends AbstractDialog {

    private static final long serialVersionUID = 1L;
    private static final String MESSAGE_PREFIX = "postman.importfromdialog.";

    private final JTextField fieldFrom = new JTextField(35);
    private final JTextField fieldEndpoint = new JTextField(35);

    public ImportFromAbstractDialog(JFrame parent, String title, String schemaFieldLabel) {
        super(parent, true);
        this.setTitle(title);
        centreDialog();

        setLayout(new GridBagLayout());
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.anchor = GridBagConstraints.WEST;
        constraints.insets = new Insets(5, 5, 5, 5);

        JButton buttonImport =
                new JButton(Constant.messages.getString(MESSAGE_PREFIX + "importbutton"));
        buttonImport.addActionListener(
                e -> {
                    try {
                        if (validateEndpointUrl() && importDefinition()) {
                            setVisible(false);
                            dispose();
                        }
                    } catch (IOException ex) {
                        if (ex instanceof JsonProcessingException) {
                            String baseMsg = Constant.messages.getString("postman.parse.error");

                            View.getSingleton().getOutputPanel().append(baseMsg + "\n");
                            View.getSingleton().getOutputPanel().append(ex.getMessage());

                            showWarningDialog(
                                    baseMsg
                                            + "\n\n"
                                            + Constant.messages.getString("postman.parse.trailer"));
                        } else {
                            showWarningDialog(ex.getMessage());
                        }
                    }
                });
        JButton buttonCancel = new JButton(Constant.messages.getString("all.button.cancel"));
        buttonCancel.addActionListener(
                e -> {
                    setVisible(false);
                    dispose();
                });

        constraints.gridx = 0;
        constraints.gridy = 0;
        add(new JLabel(schemaFieldLabel), constraints);

        constraints.gridx = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1.0;
        constraints.gridwidth = 3;
        setContextMenu(fieldFrom);
        addFormFields(constraints);

        constraints.weightx = 0;
        constraints.gridwidth = 1;
        constraints.gridx = 0;
        constraints.gridy = 1;
        add(new JLabel(Constant.messages.getString(MESSAGE_PREFIX + "labelendpoint")), constraints);

        constraints.gridx = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1.0;
        constraints.gridwidth = 3;
        setContextMenu(fieldEndpoint);
        add(fieldEndpoint, constraints);

        constraints.gridwidth = 1;
        constraints.gridx = 2;
        constraints.gridy = 2;
        constraints.anchor = GridBagConstraints.CENTER;
        add(buttonCancel, constraints);
        constraints.gridx = 3;
        constraints.anchor = GridBagConstraints.CENTER;
        add(buttonImport, constraints);

        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        pack();
        setVisible(true);
    }

    protected void addFormFields(GridBagConstraints constraints) {
        add(fieldFrom, constraints);
    }

    protected JTextField getFromField() {
        return fieldFrom;
    }

    protected JTextField getEndpointField() {
        return fieldEndpoint;
    }

    protected boolean validateEndpointUrl() {
        // TODO: Implement validation
        return true;
    }

    protected void clear() {
        getFromField().setText("");
        getEndpointField().setText("");
    }

    protected abstract boolean importDefinition() throws IOException;

    protected void showMessageDialog(String message) {
        View.getSingleton().showMessageDialog(this, message);
    }

    protected void showWarningDialog(String message) {
        View.getSingleton().showWarningDialog(this, message);
    }

    private static void setContextMenu(JTextField field) {
        JMenuItem paste =
                new JMenuItem(Constant.messages.getString(MESSAGE_PREFIX + "pasteaction"));
        paste.addActionListener(e -> field.paste());

        JPopupMenu jPopupMenu = new JPopupMenu();
        jPopupMenu.add(paste);
        field.setComponentPopupMenu(jPopupMenu);
    }
}
