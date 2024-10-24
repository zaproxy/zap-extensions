package org.zaproxy.addon.llm;

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
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.utils.ZapHtmlLabel;
import org.zaproxy.zap.view.LayoutHelper;

import java.awt.Font;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
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
import javax.swing.filechooser.FileNameExtensionFilter;
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

@SuppressWarnings("serial")
public class ImportDialog extends AbstractDialog {

    private static final long serialVersionUID = -7074394202143400215L;

    private final ExtensionLlm extLlm;
    private JTextField fieldSwagger;
    private JButton buttonChooseFile;
    private JButton buttonCancel;
    private JButton buttonImport;
    private JProgressBar progressBar;
    private static AnswerService answerService;

    public ImportDialog(JFrame parent, final ExtensionLlm extLlm) {
        super(parent, true);
        super.setTitle(Constant.messages.getString("llm.importDialog.title"));
        this.extLlm = extLlm;
        centreDialog();
        setLayout(new GridBagLayout());

        var fieldsPanel = new JPanel(new GridBagLayout());
        int fieldsRow = 0;

        var labelWsdl =
                new ZapHtmlLabel(
                        "<html>"
                                + Constant.messages.getString("llm.importDialog.labelSwagger")
                                + "<font color=red>*</font></html>");
        fieldsPanel.add(
                labelWsdl, LayoutHelper.getGBC(0, fieldsRow, 1, 0.5, new Insets(0, 0, 4, 4)));
        fieldsPanel.add(
                getSwaggerField(), LayoutHelper.getGBC(1, fieldsRow, 1, 0.5, new Insets(0, 4, 4, 4)));
        fieldsPanel.add(
                getChooseFileButton(),
                LayoutHelper.getGBC(2, fieldsRow, 1, 0.5, new Insets(0, 4, 4, 0)));

        int row = 0;
        add(fieldsPanel, LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(8, 8, 4, 8)));
        row++;
        var requiredFieldsLabel =
                new ZapHtmlLabel(
                        "<html><font color=red>*</font> "
                                + Constant.messages.getString("llm.importDialog.requiredFields")
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

    private boolean importSwagger() throws IOException, URISyntaxException, ApiException, DatabaseException {

        String swaggerLocation = getSwaggerField().getText();
        answerService = new AnswerService();
        if (swaggerLocation == null || swaggerLocation.isEmpty()) {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningDialog(
                                Constant.messages.getString("llm.importDialog.error.missingSwagger"));
                        getSwaggerField().requestFocusInWindow();
                    });
            return false;
        }
        answerService.init();

        try {
            new URL(swaggerLocation).toURI();
            new URI(swaggerLocation, true);
            // implement logic here
            answerService.importSwaggerFromUrl(swaggerLocation);

            return true;
        } catch (URIException | MalformedURLException | URISyntaxException e) {
            // Not a valid URI, try to import as a file
            answerService.importSwaggerFromFile(swaggerLocation);
        }

        var file = new File(swaggerLocation);
        if (!file.canRead()) {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        showWarningFileNotFound(swaggerLocation);
                        getSwaggerField().requestFocusInWindow();
                    });
            return false;
        }

        answerService.importSwaggerFromFile(swaggerLocation);

        return true;
    }

    private static void setContextMenu(JTextField field) {
        JMenuItem paste =
                new JMenuItem(Constant.messages.getString("llm.importDialog.pasteAction"));
        paste.addActionListener(e -> field.paste());

        JPopupMenu jPopupMenu = new JPopupMenu();
        jPopupMenu.add(paste);
        field.setComponentPopupMenu(jPopupMenu);
    }

    private JTextField getSwaggerField() {
        if (fieldSwagger == null) {
            fieldSwagger = new JTextField(25);
            setContextMenu(fieldSwagger);
        }
        return fieldSwagger;
    }

    private JButton getChooseFileButton() {
        if (buttonChooseFile == null) {
            buttonChooseFile =
                    new JButton(Constant.messages.getString("llm.importDialog.chooseFileButton"));
            buttonChooseFile.addActionListener(
                    e -> {
                        JFileChooser fileChooser =
                                new JFileChooser(
                                        Model.getSingleton().getOptionsParam().getUserDirectory());
                        FileNameExtensionFilter filter =
                                new FileNameExtensionFilter(
                                        Constant.messages.getString(
                                                "llm.importDialog.fileFilterDescription"),
                                        "json");
                        fileChooser.setFileFilter(filter);
                        int state = fileChooser.showOpenDialog(this);
                        if (state == JFileChooser.APPROVE_OPTION) {
                            String filename = fileChooser.getSelectedFile().getAbsolutePath();
                            try {
                                getSwaggerField().setText(filename);
                                Model.getSingleton()
                                        .getOptionsParam()
                                        .setUserDirectory(fileChooser.getCurrentDirectory());
                            } catch (Exception e1) {
                                showWarningFileNotFound(filename);
                            }
                        }
                    });
        }
        return buttonChooseFile;
    }

    void showWarningDialog(String message) {
        showProgressBar(false);
        View.getSingleton().showWarningDialog(this, message);
    }

    private void showWarningFileNotFound(String fileLocation) {
        showWarningDialog(
                Constant.messages.getString("llm.importDialog.error.fileNotFound", fileLocation));
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
                    new JButton(Constant.messages.getString("llm.importDialog.importButton"));
            buttonImport.addActionListener(
                    e -> {
                        showProgressBar(true);
                        new Thread(
                                () -> {
                                    try {
                                        if (importSwagger()) {
                                            ThreadUtils.invokeAndWaitHandled(
                                                    () -> {
                                                        dispose();
                                                        showProgressBar(false);
                                                    });
                                        }
                                    } catch (IOException ex) {
                                        throw new RuntimeException(ex);
                                    } catch (URISyntaxException ex) {
                                        throw new RuntimeException(ex);
                                    } catch (ApiException ex) {
                                        throw new RuntimeException(ex);
                                    } catch (DatabaseException ex) {
                                        throw new RuntimeException(ex);
                                    }
                                },
                                "ZAP-LLM-UI-SWAGGER-Import")
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
        getSwaggerField().setEnabled(!show);
        getChooseFileButton().setEnabled(!show);
    }

    void clearFields() {
        getSwaggerField().setText("");
    }
}
