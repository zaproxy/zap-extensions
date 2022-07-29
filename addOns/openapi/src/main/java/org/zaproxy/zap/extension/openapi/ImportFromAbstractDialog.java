/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JTextField;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.openapi.converter.swagger.UriBuilder;

@SuppressWarnings("serial")
abstract class ImportFromAbstractDialog extends AbstractDialog {

    private static final long serialVersionUID = 1L;
    private static final String MESSAGE_PREFIX = "openapi.importfromdialog.";

    private final JTextField fieldFrom = new JTextField(35);
    private final JTextField fieldTarget = new JTextField(35);

    protected final ExtensionOpenApi caller;

    public ImportFromAbstractDialog(
            JFrame parent, ExtensionOpenApi caller, String title, String fromFieldLabel) {
        super(parent, true);
        this.setTitle(title);
        this.caller = caller;
        centreDialog();

        setLayout(new GridBagLayout());
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.anchor = GridBagConstraints.WEST;
        constraints.insets = new Insets(5, 5, 5, 5);

        JButton buttonImport =
                new JButton(Constant.messages.getString(MESSAGE_PREFIX + "importbutton"));
        buttonImport.addActionListener(
                e -> {
                    if (validateTargetUrl() && importDefinition()) {
                        setVisible(false);
                        dispose();
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
        add(new JLabel(fromFieldLabel), constraints);

        constraints.gridx = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1.0;
        constraints.gridwidth = 3;
        setContextMenu(fieldFrom);
        addFromFields(constraints);

        constraints.weightx = 0;
        constraints.gridwidth = 1;
        constraints.gridx = 0;
        constraints.gridy = 1;
        add(new JLabel(Constant.messages.getString(MESSAGE_PREFIX + "labeltarget")), constraints);

        constraints.gridx = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1.0;
        constraints.gridwidth = 3;
        add(fieldTarget, constraints);

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

    private boolean validateTargetUrl() {
        try {
            UriBuilder.parseLenient(fieldTarget.getText());
        } catch (IllegalArgumentException e) {
            showWarningDialog(
                    Constant.messages.getString(
                            "openapi.swaggerconverter.targeturl.errorsyntax",
                            fieldTarget.getText()));
            fieldTarget.requestFocusInWindow();
            return false;
        }
        return true;
    }

    protected JTextField getFromField() {
        return fieldFrom;
    }

    protected JTextField getTargetField() {
        return fieldTarget;
    }

    protected void addFromFields(GridBagConstraints constraints) {
        add(fieldFrom, constraints);
    }

    protected abstract boolean importDefinition();

    protected void showWarningDialog(String message) {
        View.getSingleton().showWarningDialog(this, message);
    }

    protected void showWarningInvalidUrl(String url) {
        showWarningDialog(Constant.messages.getString(MESSAGE_PREFIX + "invalidurl", url));
    }

    protected void clear() {
        getFromField().setText("");
        getTargetField().setText("");
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
