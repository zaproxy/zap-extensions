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

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ResourceBundle;

import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.TitledBorder;

import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.utils.FontUtils;

/**
 * The GUI Selenium options panel.
 * <p>
 * It allows to change the following options:
 * <ul>
 * <li>The path to ChromeDriver;</li>
 * <li>The path to Firefox binary.</li>
 * <li>The path to Firefox driver (geckodriver).</li>
 * <li>The path to IEDriverServer;</li>
 * <li>The path to PhantomJS binary.</li>
 * </ul>
 * 
 * @see SeleniumOptions
 */
class SeleniumOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = -4918932139321106800L;

    private final JTextField chromeDriverTextField;
    private final JLabel infoBundledChromeDriverLabel;
    private final JButton useBundledChromeDriverButton;
    private final JTextField firefoxDriverTextField;
    private final JLabel infoBundledFirefoxDriverLabel;
    private final JButton useBundledFirefoxDriverButton;
    private final JTextField ieDriverTextField;
    private final JLabel infoBundledIeDriverLabel;
    private final JButton useBundledIeDriverButton;

    private final JTextField firefoxBinaryTextField;
    private final JTextField phantomJsBinaryTextField;

    public SeleniumOptionsPanel(ResourceBundle resourceBundle) {
        setName(resourceBundle.getString("selenium.options.title"));

        String selectFileButtonLabel = resourceBundle.getString("selenium.options.label.button.select.file");
        String bundledWebDriverButtonLabel = resourceBundle.getString("selenium.options.label.button.bundleddriver");
        String bundledWebDriverButtonToolTip = resourceBundle.getString("selenium.options.tooltip.button.bundleddriver");

        String infoBundledWebDriverlabel = resourceBundle.getString("selenium.options.label.nobundleddriver");
        String infoBundledWebDriverToolTip = resourceBundle.getString("selenium.options.tooltip.nobundleddriver");
        ImageIcon infoIcon = new ImageIcon(
                SeleniumOptionsPanel.class.getResource("/resource/icon/fugue/information-white.png"));

        chromeDriverTextField = createTextField();
        JButton chromeDriverButton = createButtonFileChooser(selectFileButtonLabel, chromeDriverTextField);
        JLabel chromeDriverLabel = new JLabel(resourceBundle.getString("selenium.options.label.driver.chrome"));
        chromeDriverLabel.setLabelFor(chromeDriverButton);

        infoBundledChromeDriverLabel = createBundledWebDriverLabel(
                infoBundledWebDriverlabel,
                infoBundledWebDriverToolTip,
                infoIcon);
        useBundledChromeDriverButton = createBundledWebDriverButton(
                bundledWebDriverButtonLabel,
                bundledWebDriverButtonToolTip,
                infoBundledWebDriverToolTip,
                chromeDriverTextField,
                Browser.CHROME);

        firefoxBinaryTextField = createTextField();
        JButton firefoxBinaryButton = createButtonFileChooser(selectFileButtonLabel, firefoxBinaryTextField);
        JLabel firefoxBinaryLabel = new JLabel(resourceBundle.getString("selenium.options.label.firefox.binary"));
        firefoxBinaryLabel.setLabelFor(firefoxBinaryTextField);

        firefoxDriverTextField = createTextField();
        JButton firefoxDriverButton = createButtonFileChooser(selectFileButtonLabel, firefoxDriverTextField);
        JLabel firefoxDriverLabel = new JLabel(resourceBundle.getString("selenium.options.label.firefox.driver"));
        firefoxDriverLabel.setLabelFor(firefoxDriverTextField);

        infoBundledFirefoxDriverLabel = createBundledWebDriverLabel(
                infoBundledWebDriverlabel,
                infoBundledWebDriverToolTip,
                infoIcon);
        useBundledFirefoxDriverButton = createBundledWebDriverButton(
                bundledWebDriverButtonLabel,
                bundledWebDriverButtonToolTip,
                infoBundledWebDriverToolTip,
                firefoxDriverTextField,
                Browser.FIREFOX);

        ieDriverTextField = createTextField();
        JButton ieDriverButton = createButtonFileChooser(selectFileButtonLabel, ieDriverTextField);
        JLabel ieDriverLabel = new JLabel(resourceBundle.getString("selenium.options.label.driver.ie"));
        ieDriverLabel.setLabelFor(ieDriverButton);

        infoBundledIeDriverLabel = createBundledWebDriverLabel(
                infoBundledWebDriverlabel,
                infoBundledWebDriverToolTip,
                infoIcon);
        useBundledIeDriverButton = createBundledWebDriverButton(
                bundledWebDriverButtonLabel,
                bundledWebDriverButtonToolTip,
                infoBundledWebDriverToolTip,
                ieDriverTextField,
                Browser.INTERNET_EXPLORER);

        phantomJsBinaryTextField = createTextField();
        JButton phantomJsBinaryButton = createButtonFileChooser(selectFileButtonLabel, phantomJsBinaryTextField);
        JLabel phantomJsBinaryLabel = new JLabel(resourceBundle.getString("selenium.options.label.phantomjs.binary"));
        phantomJsBinaryLabel.setLabelFor(phantomJsBinaryButton);

        JPanel driversPanel = new JPanel();
        driversPanel.setBorder(
                BorderFactory.createTitledBorder(
                        null,
                        resourceBundle.getString("selenium.options.webdrivers.title"),
                        TitledBorder.DEFAULT_JUSTIFICATION,
                        TitledBorder.DEFAULT_POSITION,
                        FontUtils.getFont(FontUtils.Size.standard),
                        Color.black));

        GroupLayout driversLayout = new GroupLayout(driversPanel);
        driversPanel.setLayout(driversLayout);

        driversLayout.setAutoCreateGaps(true);
        driversLayout.setAutoCreateContainerGaps(true);

        driversLayout.setHorizontalGroup(
                driversLayout.createSequentialGroup()
                        .addGroup(
                                driversLayout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(chromeDriverLabel)
                                        .addComponent(firefoxDriverLabel)
                                        .addComponent(ieDriverLabel))
                        .addGroup(
                                driversLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addGroup(
                                                driversLayout.createSequentialGroup()
                                                        .addGroup(
                                                                driversLayout.createParallelGroup()
                                                                        .addComponent(chromeDriverTextField)
                                                                        .addComponent(infoBundledChromeDriverLabel))
                                                        .addGroup(
                                                                driversLayout.createParallelGroup()
                                                                        .addComponent(chromeDriverButton)
                                                                        .addComponent(useBundledChromeDriverButton)))
                                        .addGroup(
                                                driversLayout.createSequentialGroup()
                                                        .addGroup(
                                                                driversLayout.createParallelGroup()
                                                                        .addComponent(firefoxDriverTextField)
                                                                        .addComponent(infoBundledFirefoxDriverLabel))
                                                        .addGroup(
                                                                driversLayout.createParallelGroup()
                                                                        .addComponent(firefoxDriverButton)
                                                                        .addComponent(useBundledFirefoxDriverButton)))
                                        .addGroup(
                                                driversLayout.createSequentialGroup()
                                                        .addGroup(
                                                                driversLayout.createParallelGroup()
                                                                        .addComponent(ieDriverTextField)
                                                                        .addComponent(infoBundledIeDriverLabel))
                                                        .addGroup(
                                                                driversLayout.createParallelGroup()
                                                                        .addComponent(ieDriverButton)
                                                                        .addComponent(useBundledIeDriverButton)))));

        driversLayout.setVerticalGroup(
                driversLayout.createSequentialGroup()
                        .addGroup(
                                driversLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(chromeDriverLabel)
                                        .addComponent(chromeDriverTextField)
                                        .addComponent(chromeDriverButton))
                        .addGroup(
                                driversLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(infoBundledChromeDriverLabel)
                                        .addComponent(useBundledChromeDriverButton))
                        .addGroup(
                                driversLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(firefoxDriverLabel)
                                        .addComponent(firefoxDriverTextField)
                                        .addComponent(firefoxDriverButton))
                        .addGroup(
                                driversLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(infoBundledFirefoxDriverLabel)
                                        .addComponent(useBundledFirefoxDriverButton))
                        .addGroup(
                                driversLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(ieDriverLabel)
                                        .addComponent(ieDriverTextField)
                                        .addComponent(ieDriverButton))
                        .addGroup(
                                driversLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(infoBundledIeDriverLabel)
                                        .addComponent(useBundledIeDriverButton)));

        JPanel binariesPanel = new JPanel();
        binariesPanel.setBorder(
                BorderFactory.createTitledBorder(
                        null,
                        resourceBundle.getString("selenium.options.binaries.title"),
                        TitledBorder.DEFAULT_JUSTIFICATION,
                        TitledBorder.DEFAULT_POSITION,
                        FontUtils.getFont(FontUtils.Size.standard),
                        Color.black));

        GroupLayout binariesLayout = new GroupLayout(binariesPanel);
        binariesPanel.setLayout(binariesLayout);

        binariesLayout.setAutoCreateGaps(true);
        binariesLayout.setAutoCreateContainerGaps(true);

        binariesLayout.setHorizontalGroup(
                binariesLayout.createSequentialGroup()
                        .addGroup(
                                binariesLayout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                        .addComponent(firefoxBinaryLabel)
                                        .addComponent(phantomJsBinaryLabel))
                        .addGroup(
                                binariesLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addGroup(
                                                binariesLayout.createSequentialGroup()
                                                        .addComponent(firefoxBinaryTextField)
                                                        .addComponent(firefoxBinaryButton))
                                        .addGroup(
                                                binariesLayout.createSequentialGroup()
                                                        .addComponent(phantomJsBinaryTextField)
                                                        .addComponent(phantomJsBinaryButton))));

        binariesLayout.setVerticalGroup(
                binariesLayout.createSequentialGroup()
                        .addGroup(
                                binariesLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(firefoxBinaryLabel)
                                        .addComponent(firefoxBinaryTextField)
                                        .addComponent(firefoxBinaryButton))
                        .addGroup(
                                binariesLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(phantomJsBinaryLabel)
                                        .addComponent(phantomJsBinaryTextField)
                                        .addComponent(phantomJsBinaryButton)));

        GroupLayout layout = new GroupLayout(this);
        setLayout(layout);

        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(layout.createParallelGroup().addComponent(driversPanel).addComponent(binariesPanel));
        layout.setVerticalGroup(layout.createSequentialGroup().addComponent(driversPanel).addComponent(binariesPanel));
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

        chromeDriverTextField
                .setText(getEffectiveDriverPath(Browser.CHROME, seleniumOptions.getChromeDriverPath(), driverAvailable));

        driverAvailable = Browser.hasBundledWebDriver(Browser.FIREFOX);
        infoBundledFirefoxDriverLabel.setVisible(!driverAvailable);
        useBundledFirefoxDriverButton.setEnabled(driverAvailable);

        firefoxDriverTextField
                .setText(getEffectiveDriverPath(Browser.FIREFOX, seleniumOptions.getFirefoxDriverPath(), driverAvailable));

        driverAvailable = Browser.hasBundledWebDriver(Browser.INTERNET_EXPLORER);
        infoBundledIeDriverLabel.setVisible(!driverAvailable);
        useBundledIeDriverButton.setEnabled(driverAvailable);

        ieDriverTextField
                .setText(getEffectiveDriverPath(Browser.INTERNET_EXPLORER, seleniumOptions.getIeDriverPath(), driverAvailable));

        firefoxBinaryTextField.setText(seleniumOptions.getFirefoxBinaryPath());
        phantomJsBinaryTextField.setText(seleniumOptions.getPhantomJsBinaryPath());
    }

    private static String getEffectiveDriverPath(Browser browser, String driverPath, boolean bundledDriverAvailable) {
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
    public void validateParam(Object obj) throws Exception {
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam optionsParam = (OptionsParam) obj;
        SeleniumOptions seleniumOptions = optionsParam.getParamSet(SeleniumOptions.class);

        seleniumOptions.setChromeDriverPath(chromeDriverTextField.getText());
        seleniumOptions.setFirefoxBinaryPath(firefoxBinaryTextField.getText());
        seleniumOptions.setFirefoxDriverPath(firefoxDriverTextField.getText());
        seleniumOptions.setIeDriverPath(ieDriverTextField.getText());
        seleniumOptions.setPhantomJsBinaryPath(phantomJsBinaryTextField.getText());
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
            super.setToolTipText((!isEnabled() && disabledToolTipText != null) ? disabledToolTipText : defaultToolTipText);
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
}
