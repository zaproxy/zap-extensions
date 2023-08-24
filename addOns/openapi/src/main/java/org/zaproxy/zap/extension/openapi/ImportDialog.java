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
package org.zaproxy.zap.extension.openapi;

import java.awt.Font;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JProgressBar;
import javax.swing.JTextField;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.openapi.OpenApiExceptions.EmptyDefinitionException;
import org.zaproxy.zap.extension.openapi.OpenApiExceptions.InvalidDefinitionException;
import org.zaproxy.zap.extension.openapi.OpenApiExceptions.InvalidUrlException;
import org.zaproxy.zap.extension.openapi.converter.swagger.UriBuilder;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.utils.ZapHtmlLabel;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class ImportDialog extends AbstractDialog {

    private static final long serialVersionUID = 1L;
    private static final String MESSAGE_PREFIX = "openapi.importDialog.";

    private JTextField fieldDefinition;
    private JTextField fieldTarget;
    private JComboBox<String> contextsComboBox;
    private ContextsChangedListenerImpl contextsChangedListener;
    private final ExtensionOpenApi extOpenApi;
    private JButton buttonChooseFile;
    private JButton buttonCancel;
    private JButton buttonImport;
    private JProgressBar progressBar;

    public ImportDialog(JFrame parent, ExtensionOpenApi extOpenApi) {
        super(parent, true);
        setTitle(Constant.messages.getString(MESSAGE_PREFIX + "title"));
        this.extOpenApi = extOpenApi;
        centreDialog();
        setLayout(new GridBagLayout());

        var fieldsPanel = new JPanel(new GridBagLayout());
        int fieldsRow = 0;
        var definitionLabel =
                new ZapHtmlLabel(
                        "<html>"
                                + Constant.messages.getString(MESSAGE_PREFIX + "labelDefinition")
                                + "<font color=red>*</font></html>");
        fieldsPanel.add(
                definitionLabel, LayoutHelper.getGBC(0, fieldsRow, 1, 0.5, new Insets(0, 0, 4, 4)));
        fieldsPanel.add(
                getDefinitionField(),
                LayoutHelper.getGBC(1, fieldsRow, 1, 0.5, new Insets(0, 4, 4, 4)));
        fieldsPanel.add(
                getChooseFileButton(),
                LayoutHelper.getGBC(2, fieldsRow, 1, 0.5, new Insets(0, 4, 4, 0)));
        fieldsRow++;
        fieldsPanel.add(
                new JLabel(Constant.messages.getString(MESSAGE_PREFIX + "labelTarget")),
                LayoutHelper.getGBC(0, fieldsRow, 1, 0.5, new Insets(4, 0, 4, 4)));
        fieldsPanel.add(
                getTargetField(),
                LayoutHelper.getGBC(1, fieldsRow, 2, 0.5, new Insets(4, 4, 4, 0)));
        fieldsRow++;
        fieldsPanel.add(
                new JLabel(Constant.messages.getString(MESSAGE_PREFIX + "labelContext")),
                LayoutHelper.getGBC(0, fieldsRow, 1, 0.5, new Insets(4, 0, 0, 4)));
        fieldsPanel.add(
                getContextsComboBox(),
                LayoutHelper.getGBC(1, fieldsRow, 2, 0.5, new Insets(4, 4, 0, 0)));

        int row = 0;
        add(fieldsPanel, LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(8, 8, 4, 8)));
        row++;
        var requiredFieldsLabel =
                new ZapHtmlLabel(
                        "<html><font color=red>*</font> "
                                + Constant.messages.getString(MESSAGE_PREFIX + "requiredFields")
                                + "</html>");
        Font font = requiredFieldsLabel.getFont();
        requiredFieldsLabel.setFont(FontUtils.getFont(font, FontUtils.Size.much_smaller));
        requiredFieldsLabel.setHorizontalAlignment(JLabel.RIGHT);
        add(requiredFieldsLabel, LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(4, 8, 4, 8)));
        row++;
        add(getCancelButton(), LayoutHelper.getGBC(0, row, 1, 0.5, new Insets(4, 8, 8, 4)));
        add(getImportButton(), LayoutHelper.getGBC(1, row, 1, 0.5, new Insets(4, 4, 8, 8)));
        row++;
        add(getProgressBar(), LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(0, 8, 8, 8)));
        pack();
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }

    private boolean validateTargetUrl() {
        try {
            UriBuilder.parseLenient(fieldTarget.getText());
        } catch (IllegalArgumentException e) {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningDialog(
                                Constant.messages.getString(
                                        "openapi.swaggerconverter.targeturl.errorsyntax",
                                        fieldTarget.getText()));
                        fieldTarget.requestFocusInWindow();
                    });
            return false;
        }
        return true;
    }

    private JTextField getDefinitionField() {
        if (fieldDefinition == null) {
            fieldDefinition = new JTextField(25);
            setContextMenu(fieldDefinition);
        }
        return fieldDefinition;
    }

    private JTextField getTargetField() {
        if (fieldTarget == null) {
            fieldTarget = new JTextField(25);
            setContextMenu(fieldTarget);
        }
        return fieldTarget;
    }

    private int getSelectedContextId() {
        if (contextsComboBox.getSelectedItem() == null) {
            return -1;
        }
        String selectedContextName = contextsComboBox.getSelectedItem().toString();
        if ("".equals(selectedContextName)) {
            return -1;
        }
        Context selectedContext =
                extOpenApi.getModel().getSession().getContext(selectedContextName);
        if (selectedContext == null) {
            return -1;
        }
        return selectedContext.getId();
    }

    void showWarningDialog(String message) {
        showProgressBar(false);
        View.getSingleton().showWarningDialog(this, message);
    }

    private void showWarningInvalidUrl(String url) {
        showWarningDialog(Constant.messages.getString(MESSAGE_PREFIX + "invalidUrl", url));
    }

    private void showWarningFileNotFound(String fileLocation) {
        showWarningDialog(
                Constant.messages.getString("openapi.import.error.fileNotFound", fileLocation));
    }

    void clearFields() {
        getDefinitionField().setText("");
        getTargetField().setText("");
    }

    public void unload() {
        extOpenApi.getModel().getSession().removeOnContextsChangedListener(contextsChangedListener);
    }

    private JButton getChooseFileButton() {
        if (buttonChooseFile == null) {
            buttonChooseFile =
                    new JButton(Constant.messages.getString(MESSAGE_PREFIX + "chooseFileButton"));
            buttonChooseFile.addActionListener(
                    e -> {
                        JFileChooser filechooser =
                                new JFileChooser(
                                        Model.getSingleton().getOptionsParam().getUserDirectory());
                        int state = filechooser.showOpenDialog(this);
                        if (state == JFileChooser.APPROVE_OPTION) {
                            String filename = filechooser.getSelectedFile().getAbsolutePath();
                            try {
                                getDefinitionField().setText(filename);
                                Model.getSingleton()
                                        .getOptionsParam()
                                        .setUserDirectory(filechooser.getCurrentDirectory());
                            } catch (Exception e1) {
                                showWarningFileNotFound(filename);
                            }
                        }
                    });
        }
        return buttonChooseFile;
    }

    private JButton getCancelButton() {
        if (buttonCancel == null) {
            buttonCancel = new JButton(Constant.messages.getString("all.button.cancel"));
            buttonCancel.addActionListener(
                    e -> {
                        dispose();
                        showProgressBar(false);
                    });
        }
        return buttonCancel;
    }

    private JButton getImportButton() {
        if (buttonImport == null) {
            buttonImport =
                    new JButton(Constant.messages.getString(MESSAGE_PREFIX + "importButton"));
            buttonImport.addActionListener(
                    e -> {
                        showProgressBar(true);
                        new Thread(
                                        () -> {
                                            if (validateTargetUrl() && importDefinition()) {
                                                ThreadUtils.invokeAndWaitHandled(
                                                        () -> {
                                                            dispose();
                                                            showProgressBar(false);
                                                        });
                                            }
                                        },
                                        "ZAP-OpenAPI-UI-Import")
                                .start();
                    });
        }
        return buttonImport;
    }

    private JProgressBar getProgressBar() {
        if (progressBar == null) {
            progressBar = new JProgressBar();
            progressBar.setIndeterminate(true);
            progressBar.setVisible(false);
        }
        return progressBar;
    }

    private void showProgressBar(boolean show) {
        if (getProgressBar().isVisible() == show) {
            return;
        }

        setSize(getWidth(), getHeight() + (show ? 10 : -10));
        getProgressBar().setVisible(show);

        getImportButton().setEnabled(!show);
        getDefinitionField().setEnabled(!show);
        getTargetField().setEnabled(!show);
        getChooseFileButton().setEnabled(!show);
        getContextsComboBox().setEnabled(!show);
    }

    private boolean importDefinition() {
        String definitionLocation = getDefinitionField().getText();
        if (definitionLocation == null || definitionLocation.isEmpty()) {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningDialog(
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "error.missingDefinition"));
                        getDefinitionField().requestFocusInWindow();
                    });
            return false;
        }

        try {
            new URL(definitionLocation).toURI();
            var uri = new URI(definitionLocation, true);
            return extOpenApi.importOpenApiDefinition(
                            uri, getTargetField().getText(), true, getSelectedContextId())
                    == null;
        } catch (URIException | MalformedURLException | URISyntaxException ignored) {
            // Not a valid URI, try to import as a file
        } catch (InvalidUrlException e) {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningInvalidUrl(e.getUrl());
                        getDefinitionField().requestFocusInWindow();
                    });
            return false;
        } catch (EmptyDefinitionException | InvalidDefinitionException e) {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningDialog(e.getLocalizedMessage());
                        getDefinitionField().requestFocusInWindow();
                    });
            return false;
        }

        var file = new File(definitionLocation);
        if (!file.canRead()) {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningFileNotFound(definitionLocation);
                        getDefinitionField().requestFocusInWindow();
                    });
            return false;
        }
        try {
            return extOpenApi.importOpenApiDefinition(
                            file, getTargetField().getText(), true, getSelectedContextId())
                    == null;
        } catch (InvalidUrlException e) {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningInvalidUrl(e.getUrl());
                        getDefinitionField().requestFocusInWindow();
                    });
            return false;
        } catch (EmptyDefinitionException | InvalidDefinitionException e) {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningDialog(e.getLocalizedMessage());
                        getDefinitionField().requestFocusInWindow();
                    });
            return false;
        }
    }

    private static void setContextMenu(JTextField field) {
        JMenuItem paste =
                new JMenuItem(Constant.messages.getString(MESSAGE_PREFIX + "pasteAction"));
        paste.addActionListener(e -> field.paste());

        JPopupMenu jPopupMenu = new JPopupMenu();
        jPopupMenu.add(paste);
        field.setComponentPopupMenu(jPopupMenu);
    }

    private JComboBox<String> getContextsComboBox() {
        if (contextsComboBox == null) {
            contextsComboBox = new JComboBox<>();
            refreshContextsComboBox();
            contextsChangedListener = new ContextsChangedListenerImpl();
            extOpenApi
                    .getModel()
                    .getSession()
                    .addOnContextsChangedListener(contextsChangedListener);
        }
        return contextsComboBox;
    }

    void refreshContextsComboBox() {
        contextsComboBox.removeAllItems();
        contextsComboBox.addItem("");
        extOpenApi.getModel().getSession().getContexts().stream()
                .map(Context::getName)
                .forEach(contextsComboBox::addItem);
        if (contextsComboBox.getItemCount() > 1) {
            contextsComboBox.setSelectedIndex(1);
        }
    }

    private class ContextsChangedListenerImpl implements Session.OnContextsChangedListener {
        @Override
        public void contextAdded(Context context) {
            contextsComboBox.addItem(context.getName());
        }

        @Override
        public void contextDeleted(Context context) {
            contextsComboBox.removeItem(context.getName());
        }

        @Override
        public void contextsChanged() {
            refreshContextsComboBox();
        }
    }
}
