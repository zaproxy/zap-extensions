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
import java.awt.Font;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import javax.swing.JButton;
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
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.utils.ZapHtmlLabel;
import org.zaproxy.zap.view.LayoutHelper;

public class ImportDialog extends AbstractDialog {

    private static final long serialVersionUID = 1L;

    private JTextField fieldCollection;
    private JTextField fieldTarget;
    private JTextField fieldVariables;
    private JButton buttonChooseFile;
    private JButton buttonCancel;
    private JButton buttonImport;
    private JProgressBar progressBar;

    public ImportDialog(JFrame parent) {
        super(parent, true);
        setTitle(Constant.messages.getString("postman.importDialog.title"));
        centreDialog();
        setLayout(new GridBagLayout());

        var fieldsPanel = new JPanel(new GridBagLayout());
        int fieldsRow = 0;
        var collectionLabel =
                new ZapHtmlLabel(
                        "<html>"
                                + Constant.messages.getString(
                                        "postman.importDialog.labelCollection")
                                + "<font color=red>*</font></html>");
        fieldsPanel.add(
                collectionLabel, LayoutHelper.getGBC(0, fieldsRow, 1, 0.5, new Insets(0, 0, 4, 4)));
        fieldsPanel.add(
                getCollectionField(),
                LayoutHelper.getGBC(1, fieldsRow, 1, 0.5, new Insets(0, 4, 4, 4)));
        fieldsPanel.add(
                getChooseFileButton(),
                LayoutHelper.getGBC(2, fieldsRow, 1, 0.5, new Insets(0, 4, 4, 0)));
        fieldsRow++;

        JLabel labelTaget =
                new JLabel(Constant.messages.getString("postman.importDialog.labelTarget"));
        fieldsPanel.add(
                labelTaget, LayoutHelper.getGBC(0, fieldsRow, 1, 0.5, new Insets(4, 0, 4, 4)));
        labelTaget.setVisible(false);
        fieldsPanel.add(
                getTargetField(),
                LayoutHelper.getGBC(1, fieldsRow, 2, 0.5, new Insets(4, 4, 4, 0)));
        getTargetField().setVisible(false);
        fieldsRow++;

        fieldsPanel.add(
                new JLabel(Constant.messages.getString("postman.importDialog.labelVariables")),
                LayoutHelper.getGBC(0, fieldsRow, 1, 0.5, new Insets(4, 0, 4, 4)));
        fieldsPanel.add(
                getVariablesField(),
                LayoutHelper.getGBC(1, fieldsRow, 2, 0.5, new Insets(4, 4, 4, 0)));

        int row = 0;
        add(fieldsPanel, LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(8, 8, 4, 8)));
        row++;
        var requiredFieldsLabel =
                new ZapHtmlLabel(
                        "<html><font color=red>*</font> "
                                + Constant.messages.getString("postman.importDialog.requiredFields")
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

    private JTextField getCollectionField() {
        if (fieldCollection == null) {
            fieldCollection = new JTextField(25);
            setContextMenu(fieldCollection);
        }
        return fieldCollection;
    }

    private JTextField getTargetField() {
        if (fieldTarget == null) {
            fieldTarget = new JTextField(25);
            setContextMenu(fieldTarget);
        }
        return fieldTarget;
    }

    private JTextField getVariablesField() {
        if (fieldVariables == null) {
            fieldVariables = new JTextField(25);
            setContextMenu(fieldVariables);
        }
        return fieldVariables;
    }

    private static void setContextMenu(JTextField field) {
        JMenuItem paste =
                new JMenuItem(Constant.messages.getString("postman.importDialog.pasteAction"));
        paste.addActionListener(e -> field.paste());

        JPopupMenu jPopupMenu = new JPopupMenu();
        jPopupMenu.add(paste);
        field.setComponentPopupMenu(jPopupMenu);
    }

    private JButton getChooseFileButton() {
        if (buttonChooseFile == null) {
            buttonChooseFile =
                    new JButton(
                            Constant.messages.getString("postman.importDialog.chooseFileButton"));
            buttonChooseFile.addActionListener(
                    e -> {
                        JFileChooser filechooser =
                                new JFileChooser(
                                        Model.getSingleton().getOptionsParam().getUserDirectory());
                        int state = filechooser.showOpenDialog(this);
                        if (state == JFileChooser.APPROVE_OPTION) {
                            String filename = filechooser.getSelectedFile().getAbsolutePath();
                            try {
                                getCollectionField().setText(filename);
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
            buttonCancel.addActionListener(e -> hideImportDialog());
        }
        return buttonCancel;
    }

    private JButton getImportButton() {
        if (buttonImport == null) {
            buttonImport =
                    new JButton(Constant.messages.getString("postman.importDialog.importButton"));
            buttonImport.addActionListener(
                    e -> {
                        showProgressBar(true);
                        new Thread(
                                        () -> {
                                            if (importCollection()) {
                                                ThreadUtils.invokeAndWaitHandled(
                                                        this::hideImportDialog);
                                            }
                                        },
                                        "ZAP-Postman-UI-Import")
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

    private boolean importCollection() {
        String collectionLocation = getCollectionField().getText();
        if (collectionLocation == null || collectionLocation.isEmpty()) {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningDialog(
                                Constant.messages.getString(
                                        "postman.importDialog.error.missingCollection"));
                        getCollectionField().requestFocusInWindow();
                    });
            return false;
        }

        PostmanParser parser = new PostmanParser();
        boolean importedWithoutErrors = false;

        try {
            new URL(collectionLocation).toURI();
            new URI(collectionLocation, true);
            importedWithoutErrors =
                    parser.importFromUrl(
                            getCollectionField().getText(), getVariablesField().getText(), true);
        } catch (URIException | MalformedURLException | URISyntaxException e1) {
            // Not a valid URI, try to import as a file
            var file = new File(collectionLocation);
            if (!file.canRead()) {
                ThreadUtils.invokeAndWaitHandled(
                        () -> {
                            showWarningFileNotFound(collectionLocation);
                            getCollectionField().requestFocusInWindow();
                        });
                return false;
            }
            try {
                importedWithoutErrors =
                        parser.importFromFile(
                                getCollectionField().getText(),
                                getVariablesField().getText(),
                                true);
            } catch (IOException e2) {
                handleParseException(e2);
                return false;
            }
        } catch (IOException e) {
            handleParseException(e);
            return false;
        }

        if (importedWithoutErrors) {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        hideImportDialog();
                        View.getSingleton()
                                .showMessageDialog(
                                        Constant.messages.getString("postman.import.ok"));
                    });
        } else {
            String baseMsg = Constant.messages.getString("postman.import.okWithError");
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningDialog(
                                baseMsg
                                        + "\n\n"
                                        + Constant.messages.getString("postman.import.trailer"));
                        getCollectionField().requestFocusInWindow();
                    });
        }

        return true;
    }

    private void showProgressBar(boolean show) {
        if (getProgressBar().isVisible() == show) {
            return;
        }

        setSize(getWidth(), getHeight() + (show ? 10 : -10));
        getProgressBar().setVisible(show);

        getImportButton().setEnabled(!show);
        getCollectionField().setEnabled(!show);
        getTargetField().setEnabled(!show);
        getVariablesField().setEditable(!show);
        getChooseFileButton().setEnabled(!show);
    }

    void showWarningDialog(String message) {
        showProgressBar(false);
        View.getSingleton().showWarningDialog(this, message);
    }

    private void showWarningFileNotFound(String fileLocation) {
        showWarningDialog(
                Constant.messages.getString("postman.importfromfile.filenotfound", fileLocation));
    }

    private void showParseErrors(Exception ex) {
        String baseMsg = Constant.messages.getString("postman.import.error");

        View.getSingleton().getOutputPanel().append(baseMsg + "\n");
        View.getSingleton().getOutputPanel().append(ex.getMessage());

        showWarningDialog(baseMsg + "\n\n" + Constant.messages.getString("postman.import.trailer"));
    }

    private void handleParseException(Exception e) {
        if (e instanceof JsonProcessingException) {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showParseErrors(e);
                        getCollectionField().requestFocusInWindow();
                    });
        } else {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningDialog(e.getLocalizedMessage());
                        getCollectionField().requestFocusInWindow();
                    });
        }
    }

    private void hideImportDialog() {
        dispose();
        showProgressBar(false);
    }

    void clearFields() {
        getCollectionField().setText("");
        getTargetField().setText("");
        getVariablesField().setText("");
    }
}
