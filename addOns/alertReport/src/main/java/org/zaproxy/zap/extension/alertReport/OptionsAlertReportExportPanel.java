/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertReport;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.util.ResourceBundle;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.filechooser.FileFilter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ZapTextArea;
import org.zaproxy.zap.utils.ZapTextField;

public class OptionsAlertReportExportPanel extends AbstractParamPanel {
    // ZAP: i18n
    private static final long serialVersionUID = 1L;
    private JPanel editPane = null;
    private ZapTextField editTitleReport = null;
    private ZapTextField editLogoFileName = null;
    private ZapTextField editWorkingDir = null;
    private ZapTextField editAttachDoc = null;
    private ZapTextField editCustomerName = null;
    private ZapTextArea editConfidentialText = null;
    private ZapTextField editCompanyName = null;
    private ZapTextField editPDFKeywords = null;
    private ZapTextField editAuthorName = null;
    private JScrollPane scrollPaneConfidentialText = null;
    private JButton chooseApp = null;
    private JButton chooseDir = null;
    private JButton chooseDoc = null;
    private ResourceBundle messages = null;
    private JComboBox<String> comboLevel = null;

    public OptionsAlertReportExportPanel() {
        super();
        initialize();
    }

    private JScrollPane getScrollPaneConfidentialText() {
        if (scrollPaneConfidentialText == null) {
            scrollPaneConfidentialText = new JScrollPane();
            scrollPaneConfidentialText.setViewportView(getEditConfidentialText());
        }
        return scrollPaneConfidentialText;
    }

    private JComboBox<String> getComboLevel() {
        if (comboLevel == null) {
            comboLevel = new JComboBox<>();
            comboLevel.addItem("PDF");
            comboLevel.addItem("ODT");
            /*comboLevel.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
            	// Set the explanation
                if (comboLevel.getSelectedItem().equals("PDF")){
                	//View.getSingleton().showMessageDialog("Coming Soon!!");
                	chooseDoc.setEnabled(false);
                } else
                	chooseDoc.setEnabled(true);
            }});*/
        }
        return comboLevel;
    }

    public ZapTextField getEditAttachDoc() {
        return editAttachDoc;
    }

    public void setEditAttachDoc(ZapTextField editAttachDoc) {
        this.editAttachDoc = editAttachDoc;
    }

    public String getMessageString(String key) {
        return messages.getString(key);
    }

    public ZapTextField getEditTitleReport() {
        return editTitleReport;
    }

    public void setEditTitleReport(ZapTextField editTitleReport) {
        this.editTitleReport = editTitleReport;
    }

    public ZapTextField getEditLogoFileName() {
        return editLogoFileName;
    }

    public void setEditLogoFileName(ZapTextField editLogoFileName) {
        this.editLogoFileName = editLogoFileName;
    }

    public ZapTextField getEditWorkingDir() {
        return editWorkingDir;
    }

    public void setEditWorkingDir(ZapTextField editWorkingDir) {
        this.editWorkingDir = editWorkingDir;
    }

    public ZapTextField getEditCustomerName() {
        return editCustomerName;
    }

    public void setEditCustomerName(ZapTextField editCustomerName) {
        this.editCustomerName = editCustomerName;
    }

    public ZapTextArea getEditConfidentialText() {
        if (editConfidentialText == null) {
            editConfidentialText = new ZapTextArea();
            editConfidentialText.setLineWrap(true);
            editConfidentialText.setRows(4);
            editConfidentialText.setFont(FontUtils.getFont("Dialog"));
        }
        return editConfidentialText;
    }

    public void setEditConfidentialText(ZapTextArea editConfidentialText) {
        this.editConfidentialText = editConfidentialText;
    }

    public ZapTextField getEditCompanyName() {
        return editCompanyName;
    }

    public void setEditCompanyName(ZapTextField editCompanyName) {
        this.editCompanyName = editCompanyName;
    }

    public ZapTextField getEditPDFKeywords() {
        return editPDFKeywords;
    }

    public void setEditPDFKeywords(ZapTextField editPDFKeywords) {
        this.editPDFKeywords = editPDFKeywords;
    }

    public ZapTextField getEditAuthorName() {
        return editAuthorName;
    }

    public void setEditAuthorName(ZapTextField editAuthorName) {
        this.editAuthorName = editAuthorName;
    }

    /** This method initializes this */
    private void initialize() {

        // Load extension specific language files - these are held in the extension jar
        messages =
                ResourceBundle.getBundle(
                        this.getClass().getPackage().getName() + ".resources.Messages",
                        Constant.getLocale());

        getComboLevel();

        GridBagConstraints gbc1 = new GridBagConstraints();
        GridBagConstraints gbc2 = new GridBagConstraints();
        GridBagConstraints gbc3 = new GridBagConstraints();
        GridBagConstraints gbc4 = new GridBagConstraints();

        JLabel jLabel1 = new JLabel();
        //  JLabel jLabel2 = new JLabel();

        this.setLayout(new GridBagLayout());
        this.setSize(409, 268);

        this.setName(getMessageString("alertreport.export.message.export.option.title"));

        jLabel1.setText(getMessageString("alertreport.export.message.export.option.desc"));
        jLabel1.setPreferredSize(new java.awt.Dimension(494, 30));
        jLabel1.setMinimumSize(new java.awt.Dimension(494, 30));

        gbc1.gridx = 0;
        gbc1.gridy = 0;
        gbc1.gridheight = 1;
        gbc1.ipady = 5;
        gbc1.insets = new java.awt.Insets(10, 0, 5, 0);
        gbc1.anchor = GridBagConstraints.NORTHWEST;
        gbc1.fill = GridBagConstraints.HORIZONTAL;

        gbc2.gridx = 0;
        gbc2.gridy = 1;
        gbc2.weightx = 1.0;
        gbc2.weighty = 1.0;
        gbc2.fill = GridBagConstraints.BOTH;
        gbc2.ipadx = 0;
        gbc2.insets = new java.awt.Insets(0, 0, 0, 0);
        gbc2.anchor = GridBagConstraints.NORTHWEST;

        gbc3.gridx = 0;
        gbc3.gridy = 2;
        gbc3.weightx = 1.0;
        // gbc3.weighty = 1.0;
        gbc3.fill = GridBagConstraints.BOTH;
        gbc3.ipadx = 0;
        gbc3.insets = new java.awt.Insets(0, 0, 0, 0);
        gbc3.anchor = GridBagConstraints.NORTHWEST;
        gbc3.gridwidth = 2;
        gbc3.gridheight = 4;

        gbc4.gridx = 0;
        gbc4.gridy = 3;
        gbc4.weightx = 1.0;
        gbc4.weighty = 0.2;
        gbc4.fill = GridBagConstraints.BOTH;
        gbc4.ipadx = 0;
        gbc4.insets = new java.awt.Insets(0, 0, 0, 0);
        gbc4.anchor = GridBagConstraints.NORTHWEST;

        this.add(jLabel1, gbc1);
        this.add(getEditPane(), gbc2);
    }

    private GridBagConstraints getGridBackConstrants(
            int y, int x, double weight, boolean fullWidth) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridy = y;
        gbc.gridx = x;
        gbc.insets = new java.awt.Insets(0, 0, 0, 0);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = weight;
        if (fullWidth) {
            gbc.gridwidth = 2;
        }
        return gbc;
    }

    private GridBagConstraints getGridBackContrantsScrollPane(int y) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = y;
        gbc.weightx = 1.0;
        gbc.weighty = 0.3;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 0);
        gbc.gridwidth = 2;
        gbc.gridheight = 4;
        return gbc;
    }

    private JPanel getEditPane() {
        if (editPane == null) {
            editPane = new JPanel();
            /*	editPane.setBorder(
            javax.swing.BorderFactory.createTitledBorder(
            		null, "",
            		javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
            		javax.swing.border.TitledBorder.DEFAULT_POSITION,
            		new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11),
            		java.awt.Color.black));*/
            editPane.setFont(FontUtils.getFont("Dialog"));
            editPane.setLayout(new GridBagLayout());
            editPane.setAutoscrolls(true);

            editTitleReport = new ZapTextField();
            editLogoFileName = new ZapTextField();
            editLogoFileName.setEditable(false);
            editWorkingDir = new ZapTextField();
            editWorkingDir.setEditable(false);
            editAttachDoc = new ZapTextField();

            chooseApp =
                    new JButton(
                            getMessageString(
                                    "alertreport.export.message.export.option.label.file"));
            chooseApp.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            JFileChooser fcCommand = new JFileChooser();
                            fcCommand.setFileFilter(
                                    new FileFilter() {
                                        @Override
                                        public String getDescription() {
                                            return "*.png";
                                        }

                                        @Override
                                        public boolean accept(File f) {
                                            return f.isDirectory() || f.canExecute();
                                        }
                                    });
                            if (editLogoFileName.getText() != null
                                    && editLogoFileName.getText().length() > 0) {
                                // If theres and existing file select containing directory
                                File f = new File(editLogoFileName.getText());
                                fcCommand.setCurrentDirectory(f.getParentFile());
                            }

                            int state = fcCommand.showOpenDialog(null);

                            if (state == JFileChooser.APPROVE_OPTION) {
                                editLogoFileName.setText(fcCommand.getSelectedFile().toString());
                            }
                        }
                    });

            chooseDir =
                    new JButton(
                            getMessageString("alertreport.export.message.export.option.label.dir"));
            chooseDir.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            JFileChooser fcDirectory = new JFileChooser();
                            fcDirectory.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                            // disable the "All files" option.
                            fcDirectory.setAcceptAllFileFilterUsed(false);

                            if (editWorkingDir.getText() != null
                                    && editWorkingDir.getText().length() > 0) {
                                // If theres and existing directory then select it
                                File f = new File(editWorkingDir.getText());
                                fcDirectory.setCurrentDirectory(f);
                            }

                            int state = fcDirectory.showOpenDialog(null);

                            if (state == JFileChooser.APPROVE_OPTION) {
                                editWorkingDir.setText(fcDirectory.getSelectedFile().toString());
                            }
                        }
                    });

            chooseDoc =
                    new JButton(
                            getMessageString(
                                    "alertreport.export.message.export.option.label.file"));
            chooseDoc.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            JFileChooser fcCommand = new JFileChooser();
                            /*	fcCommand.setFileFilter( new FileFilter()
                            {
                            	@Override
                            	public String getDescription() {
                            		return getMessageString("alertreport.export.message.export.option.title.extension");
                            	}
                            	@Override
                            	public boolean accept(File f) {
                            		return f.isDirectory() || f.canExecute() ;
                            	}
                            } );*/
                            if (editAttachDoc.getText() != null
                                    && editAttachDoc.getText().length() > 0) {
                                // If theres and existing file select containing directory
                                File f = new File(editAttachDoc.getText());
                                fcCommand.setCurrentDirectory(f.getParentFile());
                            }

                            int state = fcCommand.showOpenDialog(null);

                            if (state == JFileChooser.APPROVE_OPTION) {
                                editAttachDoc.setText(fcCommand.getSelectedFile().toString());
                            }
                        }
                    });

            editCustomerName = new ZapTextField();

            editCompanyName = new ZapTextField();
            editPDFKeywords = new ZapTextField();
            editAuthorName = new ZapTextField();
            // editConfidentialText = getEditConfidentialText();

            int rowId = 0;

            editPane.add(
                    new JLabel(getMessageString("alertreport.export.message.export.option.format")),
                    getGridBackConstrants(rowId, 0, 0, false));
            editPane.add(getComboLevel(), getGridBackConstrants(rowId++, 1, 1, true));

            editPane.add(
                    new JLabel(getMessageString("alertreport.export.message.export.pdf.title")),
                    getGridBackConstrants(rowId, 0, 0, false));
            editPane.add(editTitleReport, getGridBackConstrants(rowId++, 1, 1, true));

            editPane.add(
                    new JLabel(
                            getMessageString(
                                    "alertreport.export.message.export.option.companyname")),
                    getGridBackConstrants(rowId, 0, 0, false));
            editPane.add(editCompanyName, getGridBackConstrants(rowId++, 1, 1, true));

            editPane.add(
                    new JLabel(
                            getMessageString(
                                    "alertreport.export.message.export.option.documentattach")),
                    getGridBackConstrants(rowId, 0, 0, false));
            editPane.add(editAttachDoc, getGridBackConstrants(rowId++, 1, 1, false));
            editPane.add(chooseDoc, getGridBackConstrants(rowId - 1, 2, 0, false));

            editPane.add(
                    new JLabel(
                            getMessageString(
                                    "alertreport.export.message.export.option.logofilename")),
                    getGridBackConstrants(rowId, 0, 0, false));
            editPane.add(editLogoFileName, getGridBackConstrants(rowId++, 1, 1, false));
            editPane.add(chooseApp, getGridBackConstrants(rowId - 1, 2, 0, false));

            editPane.add(
                    new JLabel(
                            getMessageString("alertreport.export.message.export.option.imagesdir")),
                    getGridBackConstrants(rowId, 0, 0, false));
            editPane.add(editWorkingDir, getGridBackConstrants(rowId++, 1, 1, false));
            editPane.add(chooseDir, getGridBackConstrants(rowId - 1, 2, 0, false));

            editPane.add(
                    new JLabel(
                            getMessageString("alertreport.export.message.export.pdf.customername")),
                    getGridBackConstrants(rowId, 0, 0, false));
            editPane.add(editCustomerName, getGridBackConstrants(rowId++, 1, 1, false));

            editPane.add(
                    new JLabel(
                            getMessageString(
                                    "alertreport.export.message.export.option.authorname")),
                    getGridBackConstrants(rowId, 0, 0, false));
            editPane.add(editAuthorName, getGridBackConstrants(rowId++, 1, 1, true));

            editPane.add(
                    new JLabel(
                            getMessageString(
                                    "alertreport.export.message.export.option.pdfkeywords")),
                    getGridBackConstrants(rowId, 0, 0, false));
            editPane.add(editPDFKeywords, getGridBackConstrants(rowId++, 1, 1, true));

            editPane.add(
                    new JLabel(
                            getMessageString("alertreport.export.message.export.pdf.confidential")),
                    getGridBackConstrants(rowId, 0, 0, false));
            editPane.add(getScrollPaneConfidentialText(), getGridBackContrantsScrollPane(rowId++));
        }
        return editPane;
    }

    @Override
    public void validateParam(Object obj) throws Exception {

        OptionsParam options = (OptionsParam) obj;

        AlertReportExportParam param = options.getParamSet(AlertReportExportParam.class);
        if (param != null) {
            if (getComboLevel().getSelectedItem().toString().equals("PDF")
                    && (!getEditAttachDoc().getText().isEmpty())
                    && (!getEditAttachDoc().getText().contains(".pdf"))) {
                throw new Exception(
                        getMessageString("alertreport.export.message.export.option.distintformat"));
            } else if (getComboLevel().getSelectedItem().toString().equals("ODT")
                    && (!getEditAttachDoc().getText().isEmpty())
                    && (!getEditAttachDoc().getText().contains(".odt"))) {
                throw new Exception(
                        getMessageString("alertreport.export.message.export.option.distintformat"));
            }
        }
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam options = (OptionsParam) obj;

        AlertReportExportParam param = options.getParamSet(AlertReportExportParam.class);
        if (param != null) {
            param.setTitleReport(getEditTitleReport().getText());
            param.setLogoFileName(getEditLogoFileName().getText());
            param.setWorkingDirImages(getEditWorkingDir().getText());
            param.setCustomerName(getEditCustomerName().getText());
            param.setConfidentialText(getEditConfidentialText().getText());
            param.setPdfKeywords(getEditPDFKeywords().getText());
            param.setAuthorName(getEditAuthorName().getText());
            param.setCompanyName(getEditCompanyName().getText());
            param.setFormatReport(getComboLevel().getSelectedItem().toString());
            param.setDocumentAttach(getEditAttachDoc().getText());
        }
    }

    @Override
    public String getHelpIndex() {
        return null;
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam options = (OptionsParam) obj;

        AlertReportExportParam param = options.getParamSet(AlertReportExportParam.class);
        if (param != null) {
            getEditTitleReport().setText(param.getTitleReport());
            getEditLogoFileName().setText(param.getLogoFileName());
            getEditAttachDoc().setText(param.getDocumentAttach());
            getEditWorkingDir().setText(param.getWorkingDirImages());
            getEditCustomerName().setText(param.getCustomerName());
            getEditConfidentialText().setText(param.getConfidentialText());
            getEditPDFKeywords().setText(param.getPdfKeywords());
            getEditAuthorName().setText(param.getAuthorName());
            getEditCompanyName().setText(param.getCompanyName());
            if (param.getFormatReport().equals("PDF")) getComboLevel().setSelectedIndex(0);
            else getComboLevel().setSelectedIndex(1);
        }
    }
}
