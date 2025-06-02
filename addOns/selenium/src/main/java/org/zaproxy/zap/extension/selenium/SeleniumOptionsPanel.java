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
package org.zaproxy.zap.extension.selenium;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.ResourceBundle;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.SequentialGroup;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.TitledBorder;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.extension.selenium.internal.BrowserArgumentsDialog;
import org.zaproxy.zap.extension.selenium.internal.BrowserArgumentsTableModel;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.AbstractMultipleOptionsTableModel;

/**
 * The GUI Selenium options panel.
 *
 * <p>It allows to change the following options:
 *
 * <ul>
 *   <li>The path to ChromeDriver;
 *   <li>The path to Firefox binary.
 *   <li>The path to Firefox driver (geckodriver).
 *   <li>The path to PhantomJS binary.
 * </ul>
 *
 * @see SeleniumOptions
 */
@SuppressWarnings("serial")
class SeleniumOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = -4918932139321106800L;

    private final JTextField chromeDriverTextField;
    private final JLabel infoBundledChromeDriverLabel;
    private final JButton useBundledChromeDriverButton;
    private final JTextField firefoxDriverTextField;
    private final JLabel infoBundledFirefoxDriverLabel;
    private final JButton useBundledFirefoxDriverButton;

    private final JTextField chromeBinaryTextField;
    private final JTextField chromeArgumentsTextField;
    private final BrowserArgumentsTableModel chromeArgumentsTableModel;
    private final JTextField firefoxBinaryTextField;
    private final JTextField firefoxArgumentsTextField;
    private final JComboBox<String> firefoxProfileCombo;
    private final BrowserArgumentsTableModel firefoxArgumentsTableModel;
    private final OptionsBrowserExtensionsTableModel browserExtModel;
    private final AtomicBoolean confirmRemoveBrowserArgument;
    private final String temporaryBrowserProfile;
    private static String directory;

    private ExtensionSelenium extSelenium;

    public SeleniumOptionsPanel(
            ExtensionSelenium extSelenium, Dialog parent, ResourceBundle resourceBundle) {
        this.extSelenium = extSelenium;
        setName(resourceBundle.getString("selenium.options.title"));

        String selectFileButtonLabel =
                resourceBundle.getString("selenium.options.label.button.select.file");
        String bundledWebDriverButtonLabel =
                resourceBundle.getString("selenium.options.label.button.bundleddriver");
        String bundledWebDriverButtonToolTip =
                resourceBundle.getString("selenium.options.tooltip.button.bundleddriver");

        String infoBundledWebDriverlabel =
                resourceBundle.getString("selenium.options.label.nobundleddriver");
        String infoBundledWebDriverToolTip =
                resourceBundle.getString("selenium.options.tooltip.nobundleddriver");
        ImageIcon infoIcon =
                new ImageIcon(
                        SeleniumOptionsPanel.class.getResource(
                                "/resource/icon/fugue/information-white.png"));

        chromeDriverTextField = createTextField();
        JButton chromeDriverButton =
                createButtonFileChooser(selectFileButtonLabel, chromeDriverTextField);
        JLabel chromeDriverLabel =
                new JLabel(resourceBundle.getString("selenium.options.label.driver.chrome"));
        chromeDriverLabel.setLabelFor(chromeDriverButton);

        infoBundledChromeDriverLabel =
                createBundledWebDriverLabel(
                        infoBundledWebDriverlabel, infoBundledWebDriverToolTip, infoIcon);
        useBundledChromeDriverButton =
                createBundledWebDriverButton(
                        bundledWebDriverButtonLabel,
                        bundledWebDriverButtonToolTip,
                        infoBundledWebDriverToolTip,
                        chromeDriverTextField,
                        Browser.CHROME);

        chromeBinaryTextField = createTextField();
        chromeArgumentsTextField = createTextField();
        chromeArgumentsTextField.setEditable(false);

        confirmRemoveBrowserArgument = new AtomicBoolean();
        chromeArgumentsTableModel = new BrowserArgumentsTableModel();
        BrowserArgumentsDialog chromeArgumentsDialog =
                new BrowserArgumentsDialog(
                        parent, chromeArgumentsTableModel, confirmRemoveBrowserArgument);

        firefoxBinaryTextField = createTextField();
        firefoxArgumentsTextField = createTextField();
        firefoxArgumentsTextField.setEditable(false);

        firefoxArgumentsTableModel = new BrowserArgumentsTableModel();
        BrowserArgumentsDialog firefoxArgumentsDialog =
                new BrowserArgumentsDialog(
                        parent, firefoxArgumentsTableModel, confirmRemoveBrowserArgument);

        firefoxDriverTextField = createTextField();
        JButton firefoxDriverButton =
                createButtonFileChooser(selectFileButtonLabel, firefoxDriverTextField);
        JLabel firefoxDriverLabel =
                new JLabel(resourceBundle.getString("selenium.options.label.firefox.driver"));
        firefoxDriverLabel.setLabelFor(firefoxDriverTextField);
        firefoxProfileCombo = new JComboBox<>();
        temporaryBrowserProfile = resourceBundle.getString("selenium.options.combo.profile.temp");
        // Add the temp one to indicate this field is to be used
        firefoxProfileCombo.addItem(temporaryBrowserProfile);

        infoBundledFirefoxDriverLabel =
                createBundledWebDriverLabel(
                        infoBundledWebDriverlabel, infoBundledWebDriverToolTip, infoIcon);
        useBundledFirefoxDriverButton =
                createBundledWebDriverButton(
                        bundledWebDriverButtonLabel,
                        bundledWebDriverButtonToolTip,
                        infoBundledWebDriverToolTip,
                        firefoxDriverTextField,
                        Browser.FIREFOX);

        JPanel driversPanel = new JPanel();
        driversPanel.setBorder(
                BorderFactory.createTitledBorder(
                        null,
                        resourceBundle.getString("selenium.options.webdrivers.title"),
                        TitledBorder.DEFAULT_JUSTIFICATION,
                        TitledBorder.DEFAULT_POSITION,
                        FontUtils.getFont(FontUtils.Size.standard)));

        GroupLayout driversLayout = new GroupLayout(driversPanel);
        driversPanel.setLayout(driversLayout);

        driversLayout.setAutoCreateGaps(true);
        driversLayout.setAutoCreateContainerGaps(true);

        driversLayout.setHorizontalGroup(
                driversLayout
                        .createSequentialGroup()
                        .addGroup(
                                driversLayout
                                        .createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(chromeDriverLabel)
                                        .addComponent(firefoxDriverLabel))
                        .addGroup(
                                driversLayout
                                        .createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addGroup(
                                                driversLayout
                                                        .createSequentialGroup()
                                                        .addGroup(
                                                                driversLayout
                                                                        .createParallelGroup()
                                                                        .addComponent(
                                                                                chromeDriverTextField)
                                                                        .addComponent(
                                                                                infoBundledChromeDriverLabel))
                                                        .addGroup(
                                                                driversLayout
                                                                        .createParallelGroup()
                                                                        .addComponent(
                                                                                chromeDriverButton)
                                                                        .addComponent(
                                                                                useBundledChromeDriverButton)))
                                        .addGroup(
                                                driversLayout
                                                        .createSequentialGroup()
                                                        .addGroup(
                                                                driversLayout
                                                                        .createParallelGroup()
                                                                        .addComponent(
                                                                                firefoxDriverTextField)
                                                                        .addComponent(
                                                                                infoBundledFirefoxDriverLabel))
                                                        .addGroup(
                                                                driversLayout
                                                                        .createParallelGroup()
                                                                        .addComponent(
                                                                                firefoxDriverButton)
                                                                        .addComponent(
                                                                                useBundledFirefoxDriverButton)))));

        driversLayout.setVerticalGroup(
                driversLayout
                        .createSequentialGroup()
                        .addGroup(
                                driversLayout
                                        .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(chromeDriverLabel)
                                        .addComponent(chromeDriverTextField)
                                        .addComponent(chromeDriverButton))
                        .addGroup(
                                driversLayout
                                        .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(infoBundledChromeDriverLabel)
                                        .addComponent(useBundledChromeDriverButton))
                        .addGroup(
                                driversLayout
                                        .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(firefoxDriverLabel)
                                        .addComponent(firefoxDriverTextField)
                                        .addComponent(firefoxDriverButton))
                        .addGroup(
                                driversLayout
                                        .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(infoBundledFirefoxDriverLabel)
                                        .addComponent(useBundledFirefoxDriverButton)));

        JPanel binariesPanel = new JPanel();
        binariesPanel.setBorder(
                BorderFactory.createTitledBorder(
                        null,
                        resourceBundle.getString("selenium.options.binaries.title"),
                        TitledBorder.DEFAULT_JUSTIFICATION,
                        TitledBorder.DEFAULT_POSITION,
                        FontUtils.getFont(FontUtils.Size.standard)));

        JPanel chromePanel =
                createBinaryPanel(
                        resourceBundle,
                        chromeArgumentsDialog,
                        "chrome",
                        chromeBinaryTextField,
                        chromeArgumentsTextField,
                        chromeArgumentsTableModel,
                        new JComboBox<>());
        JPanel firefoxPanel =
                createBinaryPanel(
                        resourceBundle,
                        firefoxArgumentsDialog,
                        "firefox",
                        firefoxBinaryTextField,
                        firefoxArgumentsTextField,
                        firefoxArgumentsTableModel,
                        firefoxProfileCombo);

        GroupLayout binariesLayout = new GroupLayout(binariesPanel);
        binariesPanel.setLayout(binariesLayout);

        binariesLayout.setAutoCreateGaps(true);
        binariesLayout.setAutoCreateContainerGaps(true);

        binariesLayout.setHorizontalGroup(
                binariesLayout
                        .createParallelGroup()
                        .addComponent(chromePanel)
                        .addComponent(firefoxPanel));
        binariesLayout.setVerticalGroup(
                binariesLayout
                        .createSequentialGroup()
                        .addComponent(chromePanel)
                        .addComponent(firefoxPanel));

        JPanel browserExtPanel = new JPanel();
        GroupLayout browserExtLayout = new GroupLayout(browserExtPanel);
        browserExtPanel.setLayout(browserExtLayout);

        browserExtLayout.setAutoCreateGaps(true);
        browserExtLayout.setAutoCreateContainerGaps(true);

        browserExtModel = new OptionsBrowserExtensionsTableModel();

        browserExtPanel.setBorder(
                BorderFactory.createTitledBorder(
                        null,
                        resourceBundle.getString("selenium.options.extensions.title"),
                        TitledBorder.DEFAULT_JUSTIFICATION,
                        TitledBorder.DEFAULT_POSITION,
                        FontUtils.getFont(FontUtils.Size.standard)));

        BrowserExtMultipleOptionsPanel browserExtOptionsPanel =
                new BrowserExtMultipleOptionsPanel(this.browserExtModel, resourceBundle);

        browserExtLayout.setHorizontalGroup(
                browserExtLayout.createSequentialGroup().addComponent(browserExtOptionsPanel));
        browserExtLayout.setVerticalGroup(
                browserExtLayout.createSequentialGroup().addComponent(browserExtOptionsPanel));

        JPanel innerPanel = new JPanel();
        GroupLayout layout = new GroupLayout(innerPanel);
        innerPanel.setLayout(layout);

        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
                layout.createParallelGroup()
                        .addComponent(driversPanel)
                        .addComponent(binariesPanel)
                        .addComponent(browserExtPanel));
        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addComponent(driversPanel)
                        .addComponent(binariesPanel)
                        .addComponent(browserExtPanel));

        setLayout(new BorderLayout());
        add(
                new JScrollPane(
                        innerPanel,
                        ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                        ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER));
    }

    private static JPanel createBinaryPanel(
            ResourceBundle resourceBundle,
            BrowserArgumentsDialog browserArgumentsDialog,
            String browser,
            JTextField binaryTextField,
            JTextField argsTextField,
            BrowserArgumentsTableModel tableModel,
            JComboBox<String> profileCombo) {
        JButton binaryButton =
                createButtonFileChooser(
                        resourceBundle.getString("selenium.options.label.button.select.file"),
                        binaryTextField);
        JLabel binaryLabel = new JLabel(resourceBundle.getString("selenium.options.label.binary"));
        binaryLabel.setLabelFor(binaryTextField);

        JButton argsButton =
                new JButton(resourceBundle.getString("selenium.options.label.button.configure"));
        argsButton.addActionListener(
                e -> {
                    browserArgumentsDialog.setVisible(true);
                    updateArguments(tableModel, argsTextField);
                });
        JLabel argsLabel = new JLabel(resourceBundle.getString("selenium.options.label.args"));
        argsLabel.setLabelFor(argsTextField);
        JLabel profileLabel =
                new JLabel(resourceBundle.getString("selenium.options.label.profile"));
        profileLabel.setLabelFor(profileCombo);

        if (profileCombo.getModel().getSize() == 0) {
            profileCombo.setVisible(false);
            profileLabel.setVisible(false);
        }

        JPanel panel = new JPanel();
        panel.setBorder(
                BorderFactory.createTitledBorder(
                        null,
                        resourceBundle.getString("selenium.options.title." + browser),
                        TitledBorder.DEFAULT_JUSTIFICATION,
                        TitledBorder.DEFAULT_POSITION,
                        FontUtils.getFont(FontUtils.Size.standard)));

        GroupLayout layout = new GroupLayout(panel);
        panel.setLayout(layout);

        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(binaryLabel)
                                        .addComponent(argsLabel)
                                        .addComponent(profileLabel))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addComponent(binaryTextField)
                                        .addComponent(argsTextField)
                                        .addComponent(profileCombo))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.CENTER)
                                        .addComponent(
                                                binaryButton,
                                                argsButton.getMinimumSize().width,
                                                GroupLayout.DEFAULT_SIZE,
                                                GroupLayout.DEFAULT_SIZE)
                                        .addComponent(argsButton)));

        SequentialGroup sg =
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(binaryLabel)
                                        .addComponent(binaryTextField)
                                        .addComponent(binaryButton))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(argsLabel)
                                        .addComponent(argsTextField)
                                        .addComponent(argsButton))
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(profileLabel)
                                        .addComponent(profileCombo));

        layout.setVerticalGroup(sg);
        return panel;
    }

    private JButton createBundledWebDriverButton(
            String label,
            String toolTip,
            String disabledToolTip,
            JTextField bindTextField,
            Browser browser) {
        ZapButton button = new ZapButton(label);
        button.setToolTipText(toolTip);
        button.setDisabledToolTipText(disabledToolTip);
        button.addActionListener(new BundledWebDriverAction(bindTextField, browser));
        return button;
    }

    private JLabel createBundledWebDriverLabel(String text, String toolTip, Icon icon) {
        JLabel label = new JLabel(text);
        label.setIcon(icon);
        label.setToolTipText(toolTip);
        return label;
    }

    private static JTextField createTextField() {
        JTextField textField = new JTextField(20);
        return textField;
    }

    private static JButton createButtonFileChooser(String buttonLabel, JTextField bindTextField) {
        JButton button = new JButton(buttonLabel);
        button.addActionListener(new FileChooserAction(bindTextField));
        return button;
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        SeleniumOptions seleniumOptions = optionsParam.getParamSet(SeleniumOptions.class);

        boolean driverAvailable = Browser.hasBundledWebDriver(Browser.CHROME);
        infoBundledChromeDriverLabel.setVisible(!driverAvailable);
        useBundledChromeDriverButton.setEnabled(driverAvailable);

        chromeDriverTextField.setText(
                getEffectiveDriverPath(
                        Browser.CHROME, seleniumOptions.getChromeDriverPath(), driverAvailable));

        driverAvailable = Browser.hasBundledWebDriver(Browser.FIREFOX);
        infoBundledFirefoxDriverLabel.setVisible(!driverAvailable);
        useBundledFirefoxDriverButton.setEnabled(driverAvailable);

        firefoxDriverTextField.setText(
                getEffectiveDriverPath(
                        Browser.FIREFOX, seleniumOptions.getFirefoxDriverPath(), driverAvailable));

        firefoxProfileCombo.removeAllItems();
        firefoxProfileCombo.addItem(temporaryBrowserProfile);

        ProfileManager fxPm = extSelenium.getProfileManager(Browser.FIREFOX);
        if (fxPm != null) {
            List<String> profiles = fxPm.getProfiles();
            profiles.stream().forEach(firefoxProfileCombo::addItem);
        }
        firefoxProfileCombo.setSelectedItem(seleniumOptions.getFirefoxDefaultProfile());

        chromeBinaryTextField.setText(seleniumOptions.getChromeBinaryPath());
        chromeArgumentsTableModel.setArguments(
                seleniumOptions.getBrowserArguments(Browser.CHROME.getId()));
        updateArguments(chromeArgumentsTableModel, chromeArgumentsTextField);
        firefoxBinaryTextField.setText(seleniumOptions.getFirefoxBinaryPath());
        firefoxArgumentsTableModel.setArguments(
                seleniumOptions.getBrowserArguments(Browser.FIREFOX.getId()));
        updateArguments(firefoxArgumentsTableModel, firefoxArgumentsTextField);

        confirmRemoveBrowserArgument.set(seleniumOptions.isConfirmRemoveBrowserArgument());

        browserExtModel.setExtensions(seleniumOptions.getBrowserExtensions());
        directory = seleniumOptions.getLastDirectory();
    }

    private static void updateArguments(
            BrowserArgumentsTableModel tableModel, JTextField textField) {
        textField.setText(tableModel.getArgumentsAsString());
        textField.setCaretPosition(0);
    }

    private static String getEffectiveDriverPath(
            Browser browser, String driverPath, boolean bundledDriverAvailable) {
        if (driverPath.isEmpty()) {
            if (bundledDriverAvailable) {
                return Browser.getBundledWebDriverPath(browser);
            }
            return "";
        }

        if (!Browser.isBundledWebDriverPath(driverPath)) {
            return driverPath;
        }

        if (!bundledDriverAvailable) {
            return "";
        }

        if (Files.exists(Paths.get(driverPath))) {
            return driverPath;
        }

        return Browser.getBundledWebDriverPath(browser);
    }

    @Override
    public void validateParam(Object obj) throws Exception {}

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam optionsParam = (OptionsParam) obj;
        SeleniumOptions seleniumOptions = optionsParam.getParamSet(SeleniumOptions.class);

        seleniumOptions.setChromeBinaryPath(chromeBinaryTextField.getText());
        seleniumOptions.setBrowserArguments(
                Browser.CHROME.getId(), chromeArgumentsTableModel.getElements());
        seleniumOptions.setChromeDriverPath(chromeDriverTextField.getText());
        seleniumOptions.setFirefoxBinaryPath(firefoxBinaryTextField.getText());
        seleniumOptions.setBrowserArguments(
                Browser.FIREFOX.getId(), firefoxArgumentsTableModel.getElements());
        seleniumOptions.setFirefoxDriverPath(firefoxDriverTextField.getText());

        String firefoxDefaultProfile = "";
        if (firefoxProfileCombo.getSelectedIndex() > 0) {
            firefoxDefaultProfile = firefoxProfileCombo.getSelectedItem().toString();
        }
        seleniumOptions.setFirefoxDefaultProfile(firefoxDefaultProfile);

        seleniumOptions.setBrowserExtensions(browserExtModel.getElements());
        seleniumOptions.setLastDirectory(directory);

        seleniumOptions.setConfirmRemoveBrowserArgument(confirmRemoveBrowserArgument.get());
    }

    @Override
    public String getHelpIndex() {
        return "addon.selenium.options";
    }

    private static class FileChooserAction implements ActionListener {

        private final JTextField textField;

        public FileChooserAction(JTextField bindTextField) {
            this.textField = bindTextField;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            JFileChooser fileChooser = new JFileChooser();
            String path = textField.getText();
            if (path != null) {
                File file = new File(path);
                if (file.exists()) {
                    fileChooser.setSelectedFile(file);
                }
            }
            if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                final File selectedFile = fileChooser.getSelectedFile();

                textField.setText(selectedFile.getAbsolutePath());
            }
        }
    }

    private static class BundledWebDriverAction implements ActionListener {

        private final JTextField textField;
        private final Browser browser;

        public BundledWebDriverAction(JTextField bindTextField, Browser browser) {
            this.textField = bindTextField;
            this.browser = browser;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            textField.setText(Browser.getBundledWebDriverPath(browser));
        }
    }

    private static class ZapButton extends JButton {

        private static final long serialVersionUID = 1L;

        private String defaultToolTipText;
        private String disabledToolTipText;

        public ZapButton(String label) {
            super(label);
        }

        @Override
        public void setEnabled(boolean b) {
            super.setEnabled(b);
            updateCurrentToolTipText();
        }

        private void updateCurrentToolTipText() {
            super.setToolTipText(
                    (!isEnabled() && disabledToolTipText != null)
                            ? disabledToolTipText
                            : defaultToolTipText);
        }

        @Override
        public void setToolTipText(String text) {
            defaultToolTipText = text;
            updateCurrentToolTipText();
        }

        public void setDisabledToolTipText(String text) {
            disabledToolTipText = text;
            updateCurrentToolTipText();
        }
    }

    private static class BrowserExtMultipleOptionsPanel
            extends AbstractMultipleOptionsTablePanel<BrowserExtension> {
        private static final long serialVersionUID = 1L;

        private ResourceBundle resourceBundle;

        public BrowserExtMultipleOptionsPanel(
                AbstractMultipleOptionsTableModel<BrowserExtension> model,
                ResourceBundle resourceBundle) {
            super(model, false);
            this.resourceBundle = resourceBundle;

            getTable().setVisibleRowCount(5);
        }

        @Override
        public BrowserExtension showAddDialogue() {
            JFileChooser fileChooser = new JFileChooser(directory);
            fileChooser.setFileFilter(BrowserExtension.getFileNameExtensionFilter());
            if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                directory = file.getParent();
                return new BrowserExtension(file.toPath());
            }
            return null;
        }

        @Override
        public BrowserExtension showModifyDialogue(BrowserExtension e) {
            // Not supported
            return null;
        }

        @Override
        public boolean showRemoveDialogue(BrowserExtension e) {
            JCheckBox removeWithoutConfirmationCheckBox =
                    new JCheckBox(
                            resourceBundle.getString(
                                    "selenium.options.dialog.remove.label.checkbox"));
            Object[] messages = {
                resourceBundle.getString("selenium.options.dialog.remove.text"),
                removeWithoutConfirmationCheckBox
            };
            int option =
                    JOptionPane.showOptionDialog(
                            this.getParent(),
                            messages,
                            resourceBundle.getString("selenium.options.dialog.remove.title"),
                            JOptionPane.OK_CANCEL_OPTION,
                            JOptionPane.QUESTION_MESSAGE,
                            null,
                            new String[] {
                                resourceBundle.getString(
                                        "selenium.options.dialog.remove.button.remove"),
                                resourceBundle.getString(
                                        "selenium.options.dialog.remove.button.cancel")
                            },
                            null);

            if (option == JOptionPane.OK_OPTION) {
                setRemoveWithoutConfirmation(removeWithoutConfirmationCheckBox.isSelected());

                return true;
            }

            return false;
        }
    }
}
