/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.jython;

import java.io.File;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JTextField;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.python.google.common.base.Strings;

public class JythonOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = -2690686914494943483L;

    private JTextField modulesPathTextField;
    private JButton pathChooseButton;

    public JythonOptionsPanel() {
        super();
        this.initComponents();
    }

    private void initComponents() {
        super.setName(Constant.messages.getString("jython.options.title"));

        JLabel modulesPathLabel =
                new JLabel(Constant.messages.getString("jython.options.label.modulepath"));
        this.modulesPathTextField = new JTextField();
        this.pathChooseButton =
                new JButton(Constant.messages.getString("jython.options.label.choose"));

        GroupLayout layout = new GroupLayout(this);
        super.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);
        layout.setHorizontalGroup(
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addGroup(
                                layout.createSequentialGroup()
                                        .addComponent(modulesPathLabel)
                                        .addComponent(this.modulesPathTextField)
                                        .addComponent(this.pathChooseButton)));
        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addGroup(
                                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(modulesPathLabel)
                                        .addComponent(this.modulesPathTextField)
                                        .addComponent(this.pathChooseButton)));

        this.pathChooseButton.addActionListener(
                e -> {
                    JFileChooser chooser =
                            new JFileChooser(
                                    JythonOptionsPanel.this.modulesPathTextField.getText());
                    chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                    chooser.setAcceptAllFileFilterUsed(false);
                    if (JFileChooser.APPROVE_OPTION
                            == chooser.showOpenDialog(JythonOptionsPanel.this)) {
                        JythonOptionsPanel.this.modulesPathTextField.setText(
                                chooser.getSelectedFile().getPath());
                    }
                });
    }

    @Override
    public String getHelpIndex() {
        return "jython.options";
    }

    @Override
    public void initParam(Object object) {
        JythonOptionsParam jythonOptionsParam =
                ((OptionsParam) object).getParamSet(JythonOptionsParam.class);
        this.modulesPathTextField.setText(Strings.nullToEmpty(jythonOptionsParam.getModulePath()));
    }

    @Override
    public void saveParam(Object object) throws Exception {
        JythonOptionsParam jythonOptionsParam =
                ((OptionsParam) object).getParamSet(JythonOptionsParam.class);
        jythonOptionsParam.setModulePath(Strings.nullToEmpty(this.modulesPathTextField.getText()));
    }

    @Override
    public void validateParam(Object object) throws Exception {
        String modulesPathString = this.modulesPathTextField.getText();
        if (!Strings.isNullOrEmpty(modulesPathString)) {
            File modulesPath = new File(modulesPathString);
            if (!modulesPath.exists()) {
                throw new NoSuchFileException(
                        Constant.messages.getString(
                                "jython.options.error.modulepath.notexist", modulesPath));
            }
            if (!modulesPath.isDirectory()) {
                throw new NotDirectoryException(
                        Constant.messages.getString(
                                "jython.options.error.modulepath.notdirectory", modulesPath));
            }
        }
    }
}
