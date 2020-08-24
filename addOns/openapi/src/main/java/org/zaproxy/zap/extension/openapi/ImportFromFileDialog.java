/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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

import java.awt.GridBagConstraints;
import java.io.File;
import java.io.IOException;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.openapi.converter.swagger.InvalidUrlException;

public class ImportFromFileDialog extends ImportFromAbstractDialog {

    private static final long serialVersionUID = 1L;
    private static final String MESSAGE_PREFIX = "openapi.importfromfiledialog.";

    private JButton buttonChooseFile;

    public ImportFromFileDialog(JFrame parent, ExtensionOpenApi caller) {
        super(
                parent,
                caller,
                Constant.messages.getString(MESSAGE_PREFIX + "title"),
                Constant.messages.getString(MESSAGE_PREFIX + "labelfile"));
    }

    @Override
    protected void addFromFields(GridBagConstraints constraints) {
        constraints.gridwidth = 2;
        super.addFromFields(constraints);

        constraints.gridx = 3;
        constraints.gridwidth = 1;
        add(getButtonChooseFile(), constraints);
    }

    private JButton getButtonChooseFile() {
        if (buttonChooseFile == null) {
            buttonChooseFile =
                    new JButton(Constant.messages.getString(MESSAGE_PREFIX + "choosefilebutton"));

            buttonChooseFile.addActionListener(
                    e -> {
                        JFileChooser filechooser =
                                new JFileChooser(
                                        Model.getSingleton().getOptionsParam().getUserDirectory());
                        int state = filechooser.showOpenDialog(this);
                        if (state == JFileChooser.APPROVE_OPTION) {
                            try {
                                getFromField()
                                        .setText(filechooser.getSelectedFile().getCanonicalPath());
                                Model.getSingleton()
                                        .getOptionsParam()
                                        .setUserDirectory(filechooser.getCurrentDirectory());
                            } catch (IOException ex) {
                                showWarningDialog(
                                        Constant.messages.getString(MESSAGE_PREFIX + "badfile"));
                            }
                        }
                    });
        }
        return buttonChooseFile;
    }

    @Override
    protected boolean importDefinition() {
        File file = new File(getFromField().getText());

        if (!file.canRead()) {
            showWarningDialog(Constant.messages.getString(MESSAGE_PREFIX + "badfile"));
            return false;
        }

        try {
            caller.importOpenApiDefinition(file, getTargetField().getText(), true);
        } catch (InvalidUrlException e) {
            showWarningInvalidUrl(e.getUrl());
            return false;
        }

        return true;
    }
}
