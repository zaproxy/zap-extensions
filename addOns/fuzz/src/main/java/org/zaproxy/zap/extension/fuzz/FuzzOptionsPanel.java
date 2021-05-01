/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.MessageFormat;
import java.util.ResourceBundle;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.DefaultComboBoxModel;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSlider;
import javax.swing.LayoutStyle;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.filechooser.FileFilter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationsReplacementStrategy;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.view.PositiveValuesSlider;

public class FuzzOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 4273217959656622745L;

    private static final int MAX_DELAY_IN_MS = 1000;

    private final CustomFileFuzzerAddedListener customFileFuzzerAddedListener;

    private final String customCategoryName;

    private final JComboBox<String> defaultCategoryComboBox;
    private final JButton addCustomFuzzerFileButton;
    private final ZapNumberSpinner maxFinishedFuzzersInUINumberSpinner;
    private final ZapNumberSpinner retriesOnIOErrorNumberSpinner;
    private final ZapNumberSpinner maxErrorsAllowedNumberSpinner;
    private final JRadioButton depthFirstPayloadReplacementStrategyRadioButton;
    private final JRadioButton breadthFirstPayloadReplacementStrategyRadioButton;
    private final JSlider defaultThreadsPerFuzzerSlider;
    private final JSlider defaultFuzzDelayInMsSlider;

    private Path customFuzzerLastSelectedDirectory;

    public FuzzOptionsPanel(
            ResourceBundle resourceBundle, CustomFileFuzzerAddedListener fileAddedListener) {
        super();

        this.customFileFuzzerAddedListener = fileAddedListener;

        this.setLayout(new BorderLayout());
        this.setName(resourceBundle.getString("fuzz.options.title"));

        customCategoryName = resourceBundle.getString("fuzz.category.custom");

        defaultCategoryComboBox = new JComboBox<>();
        JLabel defaultCategoryLabel =
                new JLabel(resourceBundle.getString("fuzz.options.label.category"));
        defaultCategoryLabel.setLabelFor(defaultCategoryComboBox);

        addCustomFuzzerFileButton = createCustomFuzzerFileButton(resourceBundle);
        JLabel addCustomFuzzerFileLabel =
                new JLabel(resourceBundle.getString("fuzz.options.label.addfile"));
        addCustomFuzzerFileLabel.setLabelFor(addCustomFuzzerFileButton);

        maxFinishedFuzzersInUINumberSpinner =
                new ZapNumberSpinner(1, FuzzOptions.DEFAULT_MAX_FUZZERS_IN_UI, Integer.MAX_VALUE);
        JLabel maxFinishedFuzzersInUILabel =
                new JLabel(resourceBundle.getString("fuzz.options.label.maxFinishedFuzzersInUI"));
        maxFinishedFuzzersInUILabel.setLabelFor(maxFinishedFuzzersInUINumberSpinner);

        retriesOnIOErrorNumberSpinner =
                new ZapNumberSpinner(0, FuzzOptions.DEFAULT_RETRIES_ON_IO_ERROR, Integer.MAX_VALUE);
        JLabel retriesOnIOErrorLabel =
                new JLabel(resourceBundle.getString("fuzz.options.label.retriesOnIOError"));
        retriesOnIOErrorLabel.setLabelFor(retriesOnIOErrorNumberSpinner);

        maxErrorsAllowedNumberSpinner =
                new ZapNumberSpinner(0, FuzzOptions.DEFAULT_MAX_ERRORS_ALLOWED, Integer.MAX_VALUE);
        JLabel maxErrorsAllowedLabel =
                new JLabel(resourceBundle.getString("fuzz.options.label.maxErrorsAllowed"));
        maxErrorsAllowedLabel.setLabelFor(maxErrorsAllowedNumberSpinner);

        JLabel currentDefaultThreadsPerFuzzerLabel = new JLabel();
        defaultThreadsPerFuzzerSlider =
                createDefaultThreadsPerFuzzerSlider(
                        FuzzOptions.DEFAULT_THREADS_PER_FUZZER,
                        FuzzOptions.MAX_THREADS_PER_FUZZER,
                        currentDefaultThreadsPerFuzzerLabel);
        JLabel defaultFuzzThreadsPerFuzzerLabel =
                new JLabel(resourceBundle.getString("fuzz.options.label.threads"));
        defaultFuzzThreadsPerFuzzerLabel.setLabelFor(defaultThreadsPerFuzzerSlider);
        currentDefaultThreadsPerFuzzerLabel.setText(
                Integer.toString(FuzzOptions.DEFAULT_THREADS_PER_FUZZER));

        JLabel currentDefaultFuzzDelayLabel = new JLabel();
        defaultFuzzDelayInMsSlider =
                createDefaultFuzzDelayInMsSlider(
                        FuzzOptions.DEFAULT_FUZZ_DELAY_IN_MS,
                        MAX_DELAY_IN_MS,
                        currentDefaultFuzzDelayLabel);
        JLabel defaultFuzzDelayLabel =
                new JLabel(resourceBundle.getString("fuzz.options.label.delayInMs"));
        defaultFuzzDelayLabel.setLabelFor(defaultFuzzDelayInMsSlider);
        currentDefaultFuzzDelayLabel.setText(
                Integer.toString(FuzzOptions.DEFAULT_FUZZ_DELAY_IN_MS));

        ButtonGroup replacementStrategyButtonGroup = new ButtonGroup();
        depthFirstPayloadReplacementStrategyRadioButton =
                new JRadioButton(
                        resourceBundle.getString(
                                "fuzz.options.label.payloadReplacementStrategy.depthFirst"));
        replacementStrategyButtonGroup.add(depthFirstPayloadReplacementStrategyRadioButton);
        breadthFirstPayloadReplacementStrategyRadioButton =
                new JRadioButton(
                        resourceBundle.getString(
                                "fuzz.options.label.payloadReplacementStrategy.breadthFirst"));
        replacementStrategyButtonGroup.add(breadthFirstPayloadReplacementStrategyRadioButton);
        JLabel payloadReplacementStrategyLabel =
                new JLabel(
                        resourceBundle.getString("fuzz.options.label.payloadReplacementStrategy"));
        payloadReplacementStrategyLabel.setLabelFor(
                depthFirstPayloadReplacementStrategyRadioButton);

        JPanel innerPanel = new JPanel();
        GroupLayout layout = new GroupLayout(innerPanel);
        innerPanel.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
                layout.createParallelGroup()
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addGroup(
                                                layout.createParallelGroup()
                                                        .addComponent(defaultCategoryLabel)
                                                        .addComponent(addCustomFuzzerFileLabel)
                                                        .addComponent(maxFinishedFuzzersInUILabel)
                                                        .addComponent(retriesOnIOErrorLabel)
                                                        .addComponent(maxErrorsAllowedLabel))
                                        .addGroup(
                                                layout.createParallelGroup()
                                                        .addComponent(defaultCategoryComboBox)
                                                        .addComponent(addCustomFuzzerFileButton)
                                                        .addComponent(
                                                                maxFinishedFuzzersInUINumberSpinner)
                                                        .addComponent(retriesOnIOErrorNumberSpinner)
                                                        .addComponent(
                                                                maxErrorsAllowedNumberSpinner)))
                        .addGroup(
                                layout.createParallelGroup()
                                        .addComponent(payloadReplacementStrategyLabel)
                                        .addGroup(
                                                layout.createSequentialGroup()
                                                        .addPreferredGap(
                                                                payloadReplacementStrategyLabel,
                                                                depthFirstPayloadReplacementStrategyRadioButton,
                                                                LayoutStyle.ComponentPlacement
                                                                        .INDENT)
                                                        .addComponent(
                                                                depthFirstPayloadReplacementStrategyRadioButton))
                                        .addGroup(
                                                layout.createSequentialGroup()
                                                        .addPreferredGap(
                                                                payloadReplacementStrategyLabel,
                                                                breadthFirstPayloadReplacementStrategyRadioButton,
                                                                LayoutStyle.ComponentPlacement
                                                                        .INDENT)
                                                        .addComponent(
                                                                breadthFirstPayloadReplacementStrategyRadioButton)))
                        .addGroup(
                                layout.createParallelGroup()
                                        .addGroup(
                                                layout.createSequentialGroup()
                                                        .addComponent(
                                                                defaultFuzzThreadsPerFuzzerLabel)
                                                        .addComponent(
                                                                currentDefaultThreadsPerFuzzerLabel))
                                        .addComponent(defaultThreadsPerFuzzerSlider))
                        .addGroup(
                                layout.createParallelGroup()
                                        .addGroup(
                                                layout.createSequentialGroup()
                                                        .addComponent(defaultFuzzDelayLabel)
                                                        .addComponent(currentDefaultFuzzDelayLabel))
                                        .addComponent(defaultFuzzDelayInMsSlider)));

        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(defaultCategoryLabel)
                                        .addComponent(defaultCategoryComboBox))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(addCustomFuzzerFileLabel)
                                        .addComponent(addCustomFuzzerFileButton))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(maxFinishedFuzzersInUILabel)
                                        .addComponent(maxFinishedFuzzersInUINumberSpinner))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(retriesOnIOErrorLabel)
                                        .addComponent(retriesOnIOErrorNumberSpinner))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(maxErrorsAllowedLabel)
                                        .addComponent(maxErrorsAllowedNumberSpinner))
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addComponent(payloadReplacementStrategyLabel)
                                        .addComponent(
                                                depthFirstPayloadReplacementStrategyRadioButton)
                                        .addComponent(
                                                breadthFirstPayloadReplacementStrategyRadioButton))
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addGroup(
                                                layout.createParallelGroup()
                                                        .addComponent(
                                                                defaultFuzzThreadsPerFuzzerLabel)
                                                        .addComponent(
                                                                currentDefaultThreadsPerFuzzerLabel))
                                        .addComponent(defaultThreadsPerFuzzerSlider))
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addGroup(
                                                layout.createParallelGroup()
                                                        .addComponent(defaultFuzzDelayLabel)
                                                        .addComponent(currentDefaultFuzzDelayLabel))
                                        .addComponent(defaultFuzzDelayInMsSlider)));

        JScrollPane scrollPane = new JScrollPane(innerPanel);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());

        add(scrollPane);
    }

    private JSlider createDefaultThreadsPerFuzzerSlider(
            int defaultMaxThreadsPerFuzzer,
            int maxThreadsPerFuzzer,
            final JLabel currentValueFeedbackLabel) {
        final JSlider threadsSlider =
                new PositiveValuesSlider(defaultMaxThreadsPerFuzzer, maxThreadsPerFuzzer);
        threadsSlider.addChangeListener(
                new ChangeListener() {

                    @Override
                    public void stateChanged(ChangeEvent e) {
                        currentValueFeedbackLabel.setText(
                                Integer.toString(threadsSlider.getValue()));
                    }
                });
        return threadsSlider;
    }

    private static JSlider createDefaultFuzzDelayInMsSlider(
            int defaultDelayInMs, int maxDelayInMs, final JLabel currentValueFeedbackLabel) {
        final JSlider delaySlider = new JSlider();
        delaySlider.setMinimum(0);
        delaySlider.setValue(defaultDelayInMs);
        delaySlider.setMaximum(maxDelayInMs);
        delaySlider.setMinorTickSpacing(25);
        delaySlider.setMajorTickSpacing(100);
        delaySlider.setPaintTicks(true);
        delaySlider.setPaintLabels(true);
        delaySlider.addChangeListener(
                new ChangeListener() {

                    @Override
                    public void stateChanged(ChangeEvent e) {
                        currentValueFeedbackLabel.setText(Integer.toString(delaySlider.getValue()));
                    }
                });
        return delaySlider;
    }

    void setFuzzersDir(FuzzersDir fuzzersDir) {
        DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>();
        for (FuzzerPayloadCategory category : fuzzersDir.getCategories()) {
            addFuzzerCategories(category, model);
        }
        defaultCategoryComboBox.setModel(model);
    }

    private static void addFuzzerCategories(
            FuzzerPayloadCategory category, DefaultComboBoxModel<String> model) {
        if (!category.getFuzzerPayloadSources().isEmpty()) {
            model.addElement(category.getFullName());
        }

        for (FuzzerPayloadCategory subCategory : category.getSubCategories()) {
            addFuzzerCategories(subCategory, model);
        }
    }

    private JButton createCustomFuzzerFileButton(final ResourceBundle resourceBundle) {
        JButton button = new JButton(resourceBundle.getString("fuzz.options.button.addfile"));
        button.addActionListener(
                new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        JFileChooser fcCommand = new JFileChooser();
                        fcCommand.setFileFilter(
                                new FileFilter() {

                                    @Override
                                    public String getDescription() {
                                        return resourceBundle.getString("fuzz.options.title");
                                    }

                                    @Override
                                    public boolean accept(File f) {
                                        return true;
                                    }
                                });

                        if (customFuzzerLastSelectedDirectory != null) {
                            fcCommand.setCurrentDirectory(
                                    customFuzzerLastSelectedDirectory.toFile());
                        }

                        int state = fcCommand.showOpenDialog(null);

                        if (state == JFileChooser.APPROVE_OPTION) {
                            Path selectedFile = fcCommand.getSelectedFile().toPath();
                            Path newFile =
                                    Paths.get(Constant.getInstance().FUZZER_DIR)
                                            .resolve(selectedFile.getFileName());

                            boolean copyFile = false;
                            if (Files.exists(newFile)) {
                                copyFile = confirmOverwrite();
                            } else if (!Files.exists(newFile.getParent())) {
                                try {
                                    Files.createDirectories(newFile.getParent());
                                    copyFile = true;
                                } catch (IOException ex) {
                                    View.getSingleton()
                                            .showWarningDialog(
                                                    MessageFormat.format(
                                                            resourceBundle.getString(
                                                                    "fuzz.options.add.file.fail.error.create.dirs"),
                                                            newFile.getParent()));
                                }
                            } else if (!Files.isWritable(newFile.getParent())) {
                                View.getSingleton()
                                        .showWarningDialog(
                                                resourceBundle.getString(
                                                                "fuzz.options.add.file.dirperms.error")
                                                        + newFile.getParent().toAbsolutePath());
                            } else {
                                copyFile = true;
                            }

                            if (copyFile) {
                                copyFile(selectedFile, newFile);
                            }

                            customFuzzerLastSelectedDirectory =
                                    fcCommand.getCurrentDirectory().toPath();
                        }
                    }

                    private boolean confirmOverwrite() {
                        int option =
                                JOptionPane.showOptionDialog(
                                        View.getSingleton().getMainFrame(),
                                        resourceBundle.getString(
                                                "fuzz.options.add.file.duplicate.error"),
                                        resourceBundle.getString(
                                                "fuzz.options.add.file.duplicate.error.title"),
                                        JOptionPane.OK_CANCEL_OPTION,
                                        JOptionPane.QUESTION_MESSAGE,
                                        null,
                                        new String[] {
                                            resourceBundle.getString(
                                                    "fuzz.options.add.file.duplicate.error.button.confirm"),
                                            resourceBundle.getString("all.button.cancel")
                                        },
                                        null);

                        return option == JOptionPane.OK_OPTION;
                    }

                    private void copyFile(Path source, Path dest) {
                        try {
                            Files.copy(source, dest);
                            View.getSingleton()
                                    .showMessageDialog(
                                            resourceBundle.getString("fuzz.options.add.file.ok"));
                            customFileFuzzerAddedListener.added(dest);
                        } catch (IOException e) {
                            View.getSingleton()
                                    .showWarningDialog(
                                            resourceBundle.getString(
                                                            "fuzz.options.add.file.fail.error")
                                                    + e.getMessage());
                        }
                    }
                });
        return button;
    }

    @Override
    public void initParam(Object optionParams) {
        FuzzOptions options = ((OptionsParam) optionParams).getParamSet(FuzzOptions.class);

        String category;
        if (options.isCustomDefaultCategory()) {
            category = customCategoryName;
        } else {
            category = options.getDefaultCategoryName();
        }

        defaultCategoryComboBox.setSelectedItem(category);
        if (category != null && !category.equals(defaultCategoryComboBox.getSelectedItem())) {
            defaultCategoryComboBox.setSelectedIndex(-1);
        }

        maxFinishedFuzzersInUINumberSpinner.setValue(options.getMaxFinishedFuzzersInUI());

        retriesOnIOErrorNumberSpinner.setValue(options.getDefaultRetriesOnIOError());
        maxErrorsAllowedNumberSpinner.setValue(options.getDefaultMaxErrorsAllowed());
        defaultThreadsPerFuzzerSlider.setValue(options.getDefaultThreadsPerFuzzer());
        defaultFuzzDelayInMsSlider.setValue(options.getDefaultFuzzDelayInMs());
        if (options.getDefaultPayloadReplacementStrategy()
                == MessageLocationsReplacementStrategy.DEPTH_FIRST) {
            depthFirstPayloadReplacementStrategyRadioButton.setSelected(true);
        } else {
            breadthFirstPayloadReplacementStrategyRadioButton.setSelected(true);
        }

        customFuzzerLastSelectedDirectory = options.getCustomFuzzerLastSelectedDirectory();
    }

    @Override
    public void validateParam(Object optionParams) throws Exception {}

    @Override
    public void saveParam(Object optionParams) throws Exception {
        FuzzOptions options = ((OptionsParam) optionParams).getParamSet(FuzzOptions.class);

        String selectedCategory = (String) defaultCategoryComboBox.getSelectedItem();
        if (customCategoryName.equals(selectedCategory)) {
            selectedCategory = null;
        }
        options.setCustomDefaultCategory(selectedCategory == null);
        options.setDefaultCategoryName(selectedCategory);
        options.setMaxFinishedFuzzersInUI(
                maxFinishedFuzzersInUINumberSpinner.getValue().intValue());

        options.setDefaultRetriesOnIOError(retriesOnIOErrorNumberSpinner.getValue().intValue());
        options.setDefaultMaxErrorsAllowed(maxErrorsAllowedNumberSpinner.getValue().intValue());
        options.setDefaultThreadsPerFuzzer(defaultThreadsPerFuzzerSlider.getValue());
        options.setDefaultFuzzDelayInMs(defaultFuzzDelayInMsSlider.getValue());
        if (depthFirstPayloadReplacementStrategyRadioButton.isSelected()) {
            options.setDefaultPayloadReplacementStrategy(
                    MessageLocationsReplacementStrategy.DEPTH_FIRST);
        } else {
            options.setDefaultPayloadReplacementStrategy(
                    MessageLocationsReplacementStrategy.BREADTH_FIRST);
        }

        options.setCustomFuzzerLastSelectedDirectory(customFuzzerLastSelectedDirectory);
    }

    @Override
    public String getHelpIndex() {
        return "addon.fuzzer.options";
    }

    public static interface CustomFileFuzzerAddedListener {

        void added(Path file);
    }
}
