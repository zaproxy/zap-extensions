/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2010 The ZAP Development Team
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
package org.zaproxy.zap.extension.bruteforce;

import java.awt.CardLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.io.IOException;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSlider;
import javax.swing.filechooser.FileFilter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.FileCopier;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.PositiveValuesSlider;

@SuppressWarnings("serial")
public class OptionsBruteForcePanel extends AbstractParamPanel {

    private static final String MESSAGE_PREFIX = "bruteforce.options.";
    private ExtensionBruteForce extension = null;
    private static final long serialVersionUID = 1L;
    private JPanel panelPortScan = null;
    private JCheckBox checkBoxRecursive = null;
    private JComboBox<ForcedBrowseFile> defaultFileList = null;
    private JButton addFileButton = null;
    private JCheckBox checkBoxBrowseFilesWithoutExtension = null;
    private JCheckBox checkBoxBrowseFiles = null;
    private ZapTextField txtFileExtensions = null;
    private JLabel threadsLabel;
    private ZapTextField txtFileExtensionsToMiss = null;
    private ZapTextField txtFailCaseString = null;

    public OptionsBruteForcePanel(ExtensionBruteForce extension) {
        super();
        this.extension = extension;
        initialize();
    }

    private JSlider sliderThreadsPerScan = null;
    /** This method initializes this */
    private void initialize() {
        this.setLayout(new CardLayout());
        this.setName(Constant.messages.getString(MESSAGE_PREFIX + "title"));
        this.setSize(314, 345);
        this.add(getPanelPortScan(), getPanelPortScan().getName());
    }

    /**
     * This method initializes panelSpider
     *
     * @return javax.swing.JPanel
     */
    private JPanel getPanelPortScan() {
        if (panelPortScan == null) {

            panelPortScan = new JPanel();
            JLabel jLabelDefaultFile = new JLabel();
            JLabel jLabelAddFile = new JLabel();
            JLabel jLabelx = new JLabel();
            JLabel jLabelExtensions = new JLabel();
            JLabel jLabelExtensionsToMiss = new JLabel();
            JLabel jLabelFailCaseString = new JLabel();

            GridBagConstraints gridBagConstraintsThreadsLable = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsThreadsSlider = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsDefaultFileLable = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsDefaultFlieList = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsAddFileLable = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsAddFileButton = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsX = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsBrowseFilesWithoutExtensionCheckBox =
                    new GridBagConstraints();
            GridBagConstraints gridBagConstraintsBrowseFilesCheckBox = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsFileExtensionsLabel = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsFileExtensionsList = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsExtensionsToMissLabel = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsExtensionsToMissList = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsFailCaseStringLabel = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsFailCaseString = new GridBagConstraints();
            GridBagConstraints gridBagConstraintsRecursiveCheckBox = new GridBagConstraints();

            panelPortScan.setLayout(new GridBagLayout());
            panelPortScan.setSize(114, 132);
            panelPortScan.setName(BruteForceParam.EMPTY_STRING);
            jLabelDefaultFile.setText(
                    Constant.messages.getString(MESSAGE_PREFIX + "label.defaultfile"));
            jLabelAddFile.setText(Constant.messages.getString(MESSAGE_PREFIX + "label.addfile"));
            jLabelExtensions.setText(
                    Constant.messages.getString(MESSAGE_PREFIX + "label.fileextensions"));
            jLabelExtensionsToMiss.setText(
                    Constant.messages.getString(MESSAGE_PREFIX + "label.extensionsToMiss"));
            jLabelFailCaseString.setText(
                    Constant.messages.getString(MESSAGE_PREFIX + "label.failCaseString"));

            int rowNumber = 2;

            gridBagConstraintsThreadsLable.gridx = 0;
            gridBagConstraintsThreadsLable.gridy = rowNumber;
            gridBagConstraintsThreadsLable.ipadx = 0;
            gridBagConstraintsThreadsLable.ipady = 0;
            gridBagConstraintsThreadsLable.anchor = GridBagConstraints.NORTHWEST;
            gridBagConstraintsThreadsLable.fill = GridBagConstraints.HORIZONTAL;
            gridBagConstraintsThreadsLable.insets = new Insets(2, 2, 2, 2);
            gridBagConstraintsThreadsLable.weightx = 1.0D;
            gridBagConstraintsThreadsLable.gridwidth = 2;

            gridBagConstraintsThreadsSlider.gridx = 0;
            gridBagConstraintsThreadsSlider.gridy = ++rowNumber;
            gridBagConstraintsThreadsSlider.weightx = 1.0;
            gridBagConstraintsThreadsSlider.fill = GridBagConstraints.HORIZONTAL;
            gridBagConstraintsThreadsSlider.ipadx = 0;
            gridBagConstraintsThreadsSlider.ipady = 0;
            gridBagConstraintsThreadsSlider.anchor = GridBagConstraints.NORTHWEST;
            gridBagConstraintsThreadsSlider.insets = new Insets(2, 2, 2, 2);
            gridBagConstraintsThreadsSlider.gridwidth = 2;

            gridBagConstraintsRecursiveCheckBox.gridx = 0;
            gridBagConstraintsRecursiveCheckBox.gridy = ++rowNumber;
            gridBagConstraintsRecursiveCheckBox.weightx = 1.0;
            gridBagConstraintsRecursiveCheckBox.fill = GridBagConstraints.HORIZONTAL;
            gridBagConstraintsRecursiveCheckBox.ipadx = 0;
            gridBagConstraintsRecursiveCheckBox.ipady = 0;
            gridBagConstraintsRecursiveCheckBox.anchor = GridBagConstraints.NORTHWEST;
            gridBagConstraintsRecursiveCheckBox.insets = new Insets(2, 2, 2, 2);
            gridBagConstraintsRecursiveCheckBox.gridwidth = 2;

            gridBagConstraintsDefaultFileLable.gridx = 0;
            gridBagConstraintsDefaultFileLable.gridy = ++rowNumber;
            gridBagConstraintsDefaultFileLable.weightx = 1.0;
            gridBagConstraintsDefaultFileLable.fill = GridBagConstraints.HORIZONTAL;
            gridBagConstraintsDefaultFileLable.ipadx = 0;
            gridBagConstraintsDefaultFileLable.ipady = 0;
            gridBagConstraintsDefaultFileLable.anchor = GridBagConstraints.NORTHWEST;
            gridBagConstraintsDefaultFileLable.insets = new Insets(2, 2, 2, 2);
            gridBagConstraintsDefaultFileLable.gridwidth = 1;

            gridBagConstraintsDefaultFlieList.gridx = 1;
            gridBagConstraintsDefaultFlieList.gridy = rowNumber;
            gridBagConstraintsDefaultFlieList.weightx = 1.0;
            gridBagConstraintsDefaultFlieList.fill = GridBagConstraints.HORIZONTAL;
            gridBagConstraintsDefaultFlieList.ipadx = 0;
            gridBagConstraintsDefaultFlieList.ipady = 0;
            gridBagConstraintsDefaultFlieList.anchor = GridBagConstraints.NORTHWEST;
            gridBagConstraintsDefaultFlieList.insets = new Insets(2, 2, 2, 2);
            gridBagConstraintsDefaultFlieList.gridwidth = 1;

            gridBagConstraintsAddFileLable.gridx = 0;
            gridBagConstraintsAddFileLable.gridy = ++rowNumber;
            gridBagConstraintsAddFileLable.weightx = 1.0;
            gridBagConstraintsAddFileLable.fill = GridBagConstraints.HORIZONTAL;
            gridBagConstraintsAddFileLable.ipadx = 0;
            gridBagConstraintsAddFileLable.ipady = 0;
            gridBagConstraintsAddFileLable.anchor = GridBagConstraints.NORTHWEST;
            gridBagConstraintsAddFileLable.insets = new Insets(2, 2, 2, 2);
            gridBagConstraintsAddFileLable.gridwidth = 1;

            gridBagConstraintsAddFileButton.gridx = 1;
            gridBagConstraintsAddFileButton.gridy = rowNumber;
            gridBagConstraintsAddFileButton.weightx = 1.0;
            gridBagConstraintsAddFileButton.fill = GridBagConstraints.HORIZONTAL;
            gridBagConstraintsAddFileButton.ipadx = 0;
            gridBagConstraintsAddFileButton.ipady = 0;
            gridBagConstraintsAddFileButton.anchor = GridBagConstraints.NORTHWEST;
            gridBagConstraintsAddFileButton.insets = new Insets(2, 2, 2, 2);
            gridBagConstraintsAddFileButton.gridwidth = 1;

            gridBagConstraintsBrowseFilesWithoutExtensionCheckBox.gridx = 0;
            gridBagConstraintsBrowseFilesWithoutExtensionCheckBox.gridy = ++rowNumber;
            gridBagConstraintsBrowseFilesWithoutExtensionCheckBox.weightx = 1.0;
            gridBagConstraintsBrowseFilesWithoutExtensionCheckBox.fill =
                    GridBagConstraints.HORIZONTAL;
            gridBagConstraintsBrowseFilesWithoutExtensionCheckBox.ipadx = 0;
            gridBagConstraintsBrowseFilesWithoutExtensionCheckBox.ipady = 0;
            gridBagConstraintsBrowseFilesWithoutExtensionCheckBox.anchor =
                    GridBagConstraints.NORTHWEST;
            gridBagConstraintsBrowseFilesWithoutExtensionCheckBox.insets = new Insets(2, 2, 2, 2);
            gridBagConstraintsBrowseFilesWithoutExtensionCheckBox.gridwidth = 2;

            gridBagConstraintsBrowseFilesCheckBox.gridx = 0;
            gridBagConstraintsBrowseFilesCheckBox.gridy = ++rowNumber;
            gridBagConstraintsBrowseFilesCheckBox.weightx = 1.0;
            gridBagConstraintsBrowseFilesCheckBox.fill = GridBagConstraints.HORIZONTAL;
            gridBagConstraintsBrowseFilesCheckBox.ipadx = 0;
            gridBagConstraintsBrowseFilesCheckBox.ipady = 0;
            gridBagConstraintsBrowseFilesCheckBox.anchor = GridBagConstraints.NORTHWEST;
            gridBagConstraintsBrowseFilesCheckBox.insets = new Insets(2, 2, 2, 2);
            gridBagConstraintsBrowseFilesCheckBox.gridwidth = 2;

            gridBagConstraintsFileExtensionsLabel.gridx = 0;
            gridBagConstraintsFileExtensionsLabel.gridy = ++rowNumber;
            gridBagConstraintsFileExtensionsLabel.weightx = 1.0;
            gridBagConstraintsFileExtensionsLabel.fill = GridBagConstraints.HORIZONTAL;
            gridBagConstraintsFileExtensionsLabel.ipadx = 0;
            gridBagConstraintsFileExtensionsLabel.ipady = 0;
            gridBagConstraintsFileExtensionsLabel.anchor = GridBagConstraints.NORTHWEST;
            gridBagConstraintsFileExtensionsLabel.insets = new Insets(2, 2, 2, 2);
            gridBagConstraintsFileExtensionsLabel.gridwidth = 1;

            gridBagConstraintsFileExtensionsList.gridx = 1;
            gridBagConstraintsFileExtensionsList.gridy = rowNumber;
            gridBagConstraintsFileExtensionsList.weightx = 1.0;
            gridBagConstraintsFileExtensionsList.fill = GridBagConstraints.HORIZONTAL;
            gridBagConstraintsFileExtensionsList.ipadx = 0;
            gridBagConstraintsFileExtensionsList.ipady = 0;
            gridBagConstraintsFileExtensionsList.anchor = GridBagConstraints.NORTHWEST;
            gridBagConstraintsFileExtensionsList.insets = new Insets(2, 2, 2, 2);
            gridBagConstraintsFileExtensionsList.gridwidth = 1;

            gridBagConstraintsExtensionsToMissLabel.gridx = 0;
            gridBagConstraintsExtensionsToMissLabel.gridy = ++rowNumber;
            gridBagConstraintsExtensionsToMissLabel.weightx = 1.0;
            gridBagConstraintsExtensionsToMissLabel.fill = GridBagConstraints.HORIZONTAL;
            gridBagConstraintsExtensionsToMissLabel.ipadx = 0;
            gridBagConstraintsExtensionsToMissLabel.ipady = 0;
            gridBagConstraintsExtensionsToMissLabel.anchor = GridBagConstraints.NORTHWEST;
            gridBagConstraintsExtensionsToMissLabel.insets = new Insets(2, 2, 2, 2);
            gridBagConstraintsExtensionsToMissLabel.gridwidth = 1;

            gridBagConstraintsExtensionsToMissList.gridx = 1;
            gridBagConstraintsExtensionsToMissList.gridy = rowNumber;
            gridBagConstraintsExtensionsToMissList.weightx = 1.0;
            gridBagConstraintsExtensionsToMissList.fill = GridBagConstraints.HORIZONTAL;
            gridBagConstraintsExtensionsToMissList.ipadx = 0;
            gridBagConstraintsExtensionsToMissList.ipady = 0;
            gridBagConstraintsExtensionsToMissList.anchor = GridBagConstraints.NORTHWEST;
            gridBagConstraintsExtensionsToMissList.insets = new Insets(2, 2, 2, 2);
            gridBagConstraintsExtensionsToMissList.gridwidth = 1;

            gridBagConstraintsFailCaseStringLabel.gridx = 0;
            gridBagConstraintsFailCaseStringLabel.gridy = ++rowNumber;
            gridBagConstraintsFailCaseStringLabel.weightx = 1.0;
            gridBagConstraintsFailCaseStringLabel.fill = GridBagConstraints.HORIZONTAL;
            gridBagConstraintsFailCaseStringLabel.ipadx = 0;
            gridBagConstraintsFailCaseStringLabel.ipady = 0;
            gridBagConstraintsFailCaseStringLabel.anchor = GridBagConstraints.NORTHWEST;
            gridBagConstraintsFailCaseStringLabel.insets = new Insets(2, 2, 2, 2);
            gridBagConstraintsFailCaseStringLabel.gridwidth = 1;

            gridBagConstraintsFailCaseString.gridx = 1;
            gridBagConstraintsFailCaseString.gridy = rowNumber;
            gridBagConstraintsFailCaseString.weightx = 1.0;
            gridBagConstraintsFailCaseString.fill = GridBagConstraints.HORIZONTAL;
            gridBagConstraintsFailCaseString.ipadx = 0;
            gridBagConstraintsFailCaseString.ipady = 0;
            gridBagConstraintsFailCaseString.anchor = GridBagConstraints.NORTHWEST;
            gridBagConstraintsFailCaseString.insets = new Insets(2, 2, 2, 2);
            gridBagConstraintsFailCaseString.gridwidth = 1;

            gridBagConstraintsX.gridx = 0;
            gridBagConstraintsX.gridy = ++rowNumber;
            gridBagConstraintsX.anchor = GridBagConstraints.NORTHWEST;
            gridBagConstraintsX.fill = GridBagConstraints.BOTH;
            gridBagConstraintsX.insets = new Insets(2, 2, 2, 2);
            gridBagConstraintsX.weightx = 1.0D;
            gridBagConstraintsX.weighty = 1.0D;
            gridBagConstraintsX.gridwidth = 2;

            jLabelx.setText(BruteForceParam.EMPTY_STRING);
            panelPortScan.add(getThreadsLabel(), gridBagConstraintsThreadsLable);
            panelPortScan.add(getSliderThreadsPerScan(), gridBagConstraintsThreadsSlider);
            panelPortScan.add(getCheckBoxRecursive(), gridBagConstraintsRecursiveCheckBox);
            panelPortScan.add(jLabelDefaultFile, gridBagConstraintsDefaultFileLable);
            panelPortScan.add(getDefaultFileList(), gridBagConstraintsDefaultFlieList);
            panelPortScan.add(jLabelAddFile, gridBagConstraintsAddFileLable);
            panelPortScan.add(getAddFileButton(), gridBagConstraintsAddFileButton);
            panelPortScan.add(getCheckBoxBrowseFiles(), gridBagConstraintsBrowseFilesCheckBox);
            panelPortScan.add(
                    getcheckBoxBrowseFilesWithoutExtension(),
                    gridBagConstraintsBrowseFilesWithoutExtensionCheckBox);
            panelPortScan.add(jLabelExtensions, gridBagConstraintsFileExtensionsLabel);
            panelPortScan.add(getTxtFileExtensions(), gridBagConstraintsFileExtensionsList);
            panelPortScan.add(jLabelExtensionsToMiss, gridBagConstraintsExtensionsToMissLabel);
            panelPortScan.add(getTxtExtensionsToMiss(), gridBagConstraintsExtensionsToMissList);
            panelPortScan.add(jLabelFailCaseString, gridBagConstraintsFailCaseStringLabel);
            panelPortScan.add(getTxtFailCaseString(), gridBagConstraintsFailCaseString);
            panelPortScan.add(jLabelx, gridBagConstraintsX);
        }
        return panelPortScan;
    }

    private JLabel getThreadsLabel() {
        if (threadsLabel == null) {
            threadsLabel = new JLabel();
        }
        return threadsLabel;
    }

    private void setThreadsLabelValue(int value) {
        getThreadsLabel()
                .setText(Constant.messages.getString(MESSAGE_PREFIX + "label.threads", value));
    }

    private JComboBox<ForcedBrowseFile> getDefaultFileList() {
        if (defaultFileList == null) {
            defaultFileList = new JComboBox<>();
            refreshFileList();
        }
        return defaultFileList;
    }

    private void refreshFileList() {
        ForcedBrowseFile selectedDefaultFile = (ForcedBrowseFile) defaultFileList.getSelectedItem();
        defaultFileList.removeAllItems();
        List<ForcedBrowseFile> files = extension.getFileList();
        for (ForcedBrowseFile file : files) {
            defaultFileList.addItem(file);
        }
        if (selectedDefaultFile != null) {
            // Keep the same selection
            defaultFileList.setSelectedItem(selectedDefaultFile);
        }
    }

    private JCheckBox getCheckBoxRecursive() {
        if (checkBoxRecursive == null) {
            checkBoxRecursive = new JCheckBox();
            checkBoxRecursive.setText(
                    Constant.messages.getString(MESSAGE_PREFIX + "label.recursive"));
            checkBoxRecursive.setSelected(BruteForceParam.DEFAULT_RECURSIVE);
        }
        return checkBoxRecursive;
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam options = (OptionsParam) obj;
        BruteForceParam param = options.getParamSet(BruteForceParam.class);
        if (param == null) {
            getSliderThreadsPerScan().setValue(BruteForceParam.DEFAULT_THREAD_PER_SCAN);
            getCheckBoxRecursive().setSelected(BruteForceParam.DEFAULT_RECURSIVE);
            getCheckBoxBrowseFiles().setSelected(BruteForceParam.DEFAULT_BROWSE_FILES);
            getcheckBoxBrowseFilesWithoutExtension()
                    .setSelected(BruteForceParam.DEFAULT_BROWSE_FILES_WITHOUT_EXTENSION);
            getTxtFileExtensions().setEnabled(BruteForceParam.DEFAULT_BROWSE_FILES);
            getTxtExtensionsToMiss().setText(BruteForceParam.DEFAULT_EXTENSIONS_TO_MISS);
            getTxtFailCaseString().setText(BruteForceParam.DEFAULT_FAIL_CASE_STRING);
        } else {
            getSliderThreadsPerScan().setValue(param.getThreadPerScan());
            getCheckBoxRecursive().setSelected(param.getRecursive());
            getDefaultFileList().setSelectedItem(param.getDefaultFile());
            getCheckBoxBrowseFiles().setSelected(param.isBrowseFiles());
            getcheckBoxBrowseFilesWithoutExtension()
                    .setSelected(param.isBrowseFilesWithoutExtension());
            getTxtFileExtensions().setEnabled(param.isBrowseFiles());
            getTxtFileExtensions().setText(param.getFileExtensions());
            getTxtExtensionsToMiss().setText(param.getExtensionsToMiss());
            getTxtFailCaseString().setText(param.getFailCaseString());
        }

        getTxtFileExtensions().discardAllEdits();
        getTxtExtensionsToMiss().discardAllEdits();
        getTxtFailCaseString().discardAllEdits();
    }

    @Override
    public void validateParam(Object obj) {
        String failCaseString = getTxtFailCaseString().getText();
        if (failCaseString.isEmpty()) {
            throw new IllegalArgumentException(
                    Constant.messages.getString("bruteforce.options.error.failCaseString.invalid"));
        }
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam options = (OptionsParam) obj;
        BruteForceParam param = options.getParamSet(BruteForceParam.class);
        if (param == null) {
            param = new BruteForceParam();
            options.addParamSet(param);
        }
        param.setThreadPerScan(getSliderThreadsPerScan().getValue());
        param.setRecursive(getCheckBoxRecursive().isSelected());

        ForcedBrowseFile selectedDefaultFile =
                (ForcedBrowseFile) getDefaultFileList().getSelectedItem();
        param.setDefaultFile(selectedDefaultFile);
        extension.setDefaultFile(selectedDefaultFile);

        param.setBrowseFilesWithoutExtension(getcheckBoxBrowseFilesWithoutExtension().isSelected());

        param.setBrowseFiles(getCheckBoxBrowseFiles().isSelected());
        if (getTxtFileExtensions().getText() != null) {
            param.setFileExtensions(getTxtFileExtensions().getText());
        } else {
            param.setFileExtensions(BruteForceParam.EMPTY_STRING);
        }

        if (getTxtExtensionsToMiss().getText() != null) {
            param.setExtensionsToMiss(getTxtExtensionsToMiss().getText());
        } else {
            param.setExtensionsToMiss(BruteForceParam.DEFAULT_EXTENSIONS_TO_MISS);
        }

        if (getTxtFailCaseString().getText() != null) {
            param.setFailCaseString(getTxtFailCaseString().getText());
        } else {
            param.setFailCaseString(BruteForceParam.DEFAULT_FAIL_CASE_STRING);
        }
    }

    /**
     * This method initializes sliderThreadsPerHost
     *
     * @return JSlider
     */
    private JSlider getSliderThreadsPerScan() {
        if (sliderThreadsPerScan == null) {
            sliderThreadsPerScan =
                    new PositiveValuesSlider(
                            BruteForceParam.DEFAULT_THREAD_PER_SCAN,
                            BruteForceParam.MAXIMUM_THREADS_PER_SCAN);
            sliderThreadsPerScan.setSnapToTicks(false);
            sliderThreadsPerScan.setMinorTickSpacing(2);
            sliderThreadsPerScan.setMajorTickSpacing(20);

            sliderThreadsPerScan.addChangeListener(
                    e -> setThreadsLabelValue(getSliderThreadsPerScan().getValue()));
            setThreadsLabelValue(sliderThreadsPerScan.getValue());
        }
        return sliderThreadsPerScan;
    }

    private JButton getAddFileButton() {
        if (addFileButton == null) {
            addFileButton =
                    new JButton(Constant.messages.getString(MESSAGE_PREFIX + "button.addfile"));
            addFileButton.addActionListener(
                    e -> {
                        JFileChooser fcCommand = new JFileChooser();
                        fcCommand.setFileFilter(
                                new FileFilter() {
                                    @Override
                                    public String getDescription() {
                                        return Constant.messages.getString(
                                                MESSAGE_PREFIX + "title");
                                    }

                                    @Override
                                    public boolean accept(File f) {
                                        return true;
                                    }
                                });

                        // Copy the file into the 'home' dirbuster directory
                        int state = fcCommand.showOpenDialog(null);

                        if (state == JFileChooser.APPROVE_OPTION) {
                            FileCopier copier = new FileCopier();
                            File newFile =
                                    new File(
                                            Constant.getInstance().DIRBUSTER_CUSTOM_DIR
                                                    + File.separator
                                                    + fcCommand.getSelectedFile().getName());
                            if (newFile.exists()
                                    || extension.getFileNamesList().contains(newFile.getName())) {
                                View.getSingleton()
                                        .showWarningDialog(
                                                Constant.messages.getString(
                                                        "bruteforce.add.duplicate.error"));

                            } else if (!newFile.getParentFile().canWrite()) {
                                View.getSingleton()
                                        .showWarningDialog(
                                                Constant.messages.getString(
                                                                "bruteforce.add.dirperms.error")
                                                        + newFile.getParentFile()
                                                                .getAbsolutePath());

                            } else {
                                try {
                                    copier.copy(fcCommand.getSelectedFile(), newFile);
                                    // Refresh list in panel
                                    extension.refreshFileList();
                                    // Refresh the list in this popup
                                    refreshFileList();
                                    View.getSingleton()
                                            .showMessageDialog(
                                                    Constant.messages.getString(
                                                            "bruteforce.add.ok"));
                                } catch (IOException e1) {
                                    View.getSingleton()
                                            .showWarningDialog(
                                                    Constant.messages.getString(
                                                                    "bruteforce.add.fail.error")
                                                            + e1.getMessage());
                                }
                            }
                        }
                    });
        }
        return addFileButton;
    }

    private JCheckBox getcheckBoxBrowseFilesWithoutExtension() {
        if (checkBoxBrowseFilesWithoutExtension == null) {
            checkBoxBrowseFilesWithoutExtension = new JCheckBox();
            checkBoxBrowseFilesWithoutExtension.setText(
                    Constant.messages.getString(
                            MESSAGE_PREFIX + "label.browsefileswithoutextension"));
            checkBoxBrowseFilesWithoutExtension.setSelected(
                    BruteForceParam.DEFAULT_BROWSE_FILES_WITHOUT_EXTENSION);
        }
        return checkBoxBrowseFilesWithoutExtension;
    }

    private JCheckBox getCheckBoxBrowseFiles() {
        if (checkBoxBrowseFiles == null) {
            checkBoxBrowseFiles = new JCheckBox();
            checkBoxBrowseFiles.setText(
                    Constant.messages.getString(MESSAGE_PREFIX + "label.browsefiles"));
            checkBoxBrowseFiles.setSelected(BruteForceParam.DEFAULT_BROWSE_FILES);
            checkBoxBrowseFiles.addActionListener(
                    e -> txtFileExtensions.setEnabled(checkBoxBrowseFiles.isSelected()));
        }
        return checkBoxBrowseFiles;
    }

    private ZapTextField getTxtFileExtensions() {
        if (txtFileExtensions == null) {
            txtFileExtensions = new ZapTextField();
        }
        return txtFileExtensions;
    }

    private ZapTextField getTxtExtensionsToMiss() {
        if (txtFileExtensionsToMiss == null) {
            txtFileExtensionsToMiss = new ZapTextField();
        }
        return txtFileExtensionsToMiss;
    }

    private ZapTextField getTxtFailCaseString() {
        if (txtFailCaseString == null) {
            txtFailCaseString = new ZapTextField();
        }
        return txtFailCaseString;
    }

    public int getThreadPerScan() {
        return this.sliderThreadsPerScan.getValue();
    }

    public boolean getRecursive() {
        return this.checkBoxRecursive.isSelected();
    }

    @Override
    public String getHelpIndex() {
        return "addon.bruteforce.options";
    }
}
