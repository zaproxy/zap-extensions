/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.graphql;

import java.awt.GridBagConstraints;
import java.io.IOException;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;

public class ImportFromFileDialog extends ImportFromAbstractDialog {

    private static final long serialVersionUID = 1L;
    private static final String MESSAGE_PREFIX = "graphql.importfromfiledialog.";

    private JButton buttonChooseFile;

    public ImportFromFileDialog(JFrame parent) {
        super(
                parent,
                Constant.messages.getString(MESSAGE_PREFIX + "title"),
                Constant.messages.getString(MESSAGE_PREFIX + "labelfile"));
    }

    @Override
    protected void addSchemaFields(GridBagConstraints constraints) {
        constraints.gridwidth = 2;
        super.addSchemaFields(constraints);

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
                        int state = filechooser.showOpenDialog(View.getSingleton().getMainFrame());
                        if (state == JFileChooser.APPROVE_OPTION) {
                            try {
                                getSchemaField()
                                        .setText(filechooser.getSelectedFile().getCanonicalPath());
                                Model.getSingleton()
                                        .getOptionsParam()
                                        .setUserDirectory(filechooser.getCurrentDirectory());
                            } catch (IOException e1) {
                                showWarningDialog(
                                        Constant.messages.getString("graphql.error.filenotfound"));
                            }
                        }
                    });
        }
        return buttonChooseFile;
    }

    @Override
    protected boolean importDefinition() {
        try {
            getParser().importFile(getSchemaField().getText());
            return true;
        } catch (IOException e) {
            showWarningDialog(e.getMessage());
        }
        return false;
    }
}
