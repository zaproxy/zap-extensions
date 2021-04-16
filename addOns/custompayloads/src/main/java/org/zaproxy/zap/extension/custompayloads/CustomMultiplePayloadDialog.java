/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.custompayloads;

import java.awt.Window;
import java.io.File;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.DisplayUtils;

public class CustomMultiplePayloadDialog extends AbstractColumnDialog<CustomPayload> {

    private static final long serialVersionUID = 1L;
    private static final String SELECT_FILE_BUTTON =
            Constant.messages.getString(
                    "custompayloads.options.dialog.addMultiplePayload.selectFile.button.name");
    private static final String PREVENT_DUPLICATE_CHECK_BOX_FIELD =
            "custompayloads.options.dialog.addMultiplePayload.duplicates.checkbox.label";
    private JButton fileButton;
    private File multiplePayload;

    public CustomMultiplePayloadDialog(Window owner, CustomPayload payload) {
        super(
                owner,
                "custompayloads.options.dialog.addMultiplePayload.title",
                CustomPayloadColumns.createColumnsForMultiplePayloads(),
                payload,
                DisplayUtils.getScaledDimension(400, 180));
        this.fileButton = new JButton(SELECT_FILE_BUTTON);
        this.addCheckBoxField(PREVENT_DUPLICATE_CHECK_BOX_FIELD, true);
        this.addCustomComponent(fileButton);
        this.addFileButtonListener(fileButton);
    }

    public void addFileButtonListener(JButton fileButton) {
        fileButton.addActionListener(
                e -> {
                    JFileChooser chooser = new JFileChooser();
                    int result = chooser.showOpenDialog(this);

                    if (result == JFileChooser.APPROVE_OPTION) {
                        multiplePayload = chooser.getSelectedFile();
                    }
                });
    }

    public File getFile() {
        return this.multiplePayload;
    }

    public boolean isPreventDuplicates() {
        return this.getBoolValue(PREVENT_DUPLICATE_CHECK_BOX_FIELD);
    }

    @Override
    public String getSaveButtonText() {
        return Constant.messages.getString(
                "custompayloads.options.dialog.addMultiplePayload.add.button.name");
    }
}
