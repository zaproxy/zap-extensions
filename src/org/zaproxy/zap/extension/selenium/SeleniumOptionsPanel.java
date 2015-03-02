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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ResourceBundle;

import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JTextField;

import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;

/**
 * The GUI Selenium options panel.
 * <p>
 * It allows to change the following options:
 * <ul>
 * <li>The path to ChromeDriver;</li>
 * <li>The path to IEDriverServer;</li>
 * <li>The path to PhantomJS binary.</li>
 * </ul>
 * 
 * @see SeleniumOptions
 */
class SeleniumOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = -4918932139321106800L;

    private final JTextField chromeDriverTextField;
    private final JTextField ieDriverTextField;
    private final JTextField phantomJsBinaryTextField;

    public SeleniumOptionsPanel(ResourceBundle resourceBundle) {
        setName(resourceBundle.getString("selenium.options.title"));

        GroupLayout layout = new GroupLayout(this);
        setLayout(layout);

        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        String selectFileButtonLabel = resourceBundle.getString("selenium.options.label.button.select.file");

        chromeDriverTextField = createTextField();
        JButton chromeDriverButton = createButtonFileChooser(selectFileButtonLabel, chromeDriverTextField);
        JLabel chromeDriverLabel = new JLabel(resourceBundle.getString("selenium.options.label.driver.chrome"));
        chromeDriverLabel.setLabelFor(chromeDriverButton);

        ieDriverTextField = createTextField();
        JButton ieDriverButton = createButtonFileChooser(selectFileButtonLabel, ieDriverTextField);
        JLabel ieDriverLabel = new JLabel(resourceBundle.getString("selenium.options.label.driver.ie"));
        ieDriverLabel.setLabelFor(ieDriverButton);

        phantomJsBinaryTextField = createTextField();
        JButton phantomJsBinaryButton = createButtonFileChooser(selectFileButtonLabel, phantomJsBinaryTextField);
        JLabel phantomJsBinaryLabel = new JLabel(resourceBundle.getString("selenium.options.label.phantomjs.binary"));
        phantomJsBinaryLabel.setLabelFor(phantomJsBinaryButton);

        layout.setHorizontalGroup(layout.createSequentialGroup()
                .addGroup(
                        layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                .addComponent(chromeDriverLabel)
                                .addComponent(ieDriverLabel)
                                .addComponent(phantomJsBinaryLabel))
                .addGroup(
                        layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addGroup(
                                        layout.createSequentialGroup()
                                                .addComponent(chromeDriverTextField)
                                                .addComponent(chromeDriverButton))
                                .addGroup(
                                        layout.createSequentialGroup()
                                                .addComponent(ieDriverTextField)
                                                .addComponent(ieDriverButton))
                                .addGroup(
                                        layout.createSequentialGroup()
                                                .addComponent(phantomJsBinaryTextField)
                                                .addComponent(phantomJsBinaryButton))));

        layout.setVerticalGroup(layout.createSequentialGroup()
                .addGroup(
                        layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(chromeDriverLabel)
                                .addComponent(chromeDriverTextField)
                                .addComponent(chromeDriverButton))
                .addGroup(
                        layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(ieDriverLabel)
                                .addComponent(ieDriverTextField)
                                .addComponent(ieDriverButton))
                .addGroup(
                        layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(phantomJsBinaryLabel)
                                .addComponent(phantomJsBinaryTextField)
                                .addComponent(phantomJsBinaryButton)));
    }

    private static JTextField createTextField() {
        JTextField textField = new JTextField(20);
        textField.setEditable(false);
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
        SeleniumOptions seleniumOptions = (SeleniumOptions) optionsParam.getParamSet(SeleniumOptions.class);

        chromeDriverTextField.setText(seleniumOptions.getChromeDriverPath());
        ieDriverTextField.setText(seleniumOptions.getIeDriverPath());
        phantomJsBinaryTextField.setText(seleniumOptions.getPhantomJsBinaryPath());
    }

    @Override
    public void validateParam(Object obj) throws Exception {
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam optionsParam = (OptionsParam) obj;
        SeleniumOptions seleniumOptions = (SeleniumOptions) optionsParam.getParamSet(SeleniumOptions.class);

        seleniumOptions.setChromeDriverPath(chromeDriverTextField.getText());
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
}
