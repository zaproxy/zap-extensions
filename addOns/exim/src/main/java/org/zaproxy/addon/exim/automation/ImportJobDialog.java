/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.exim.automation;

import java.io.File;
import java.util.Arrays;
import java.util.Locale;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JFileChooser;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ImportJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "exim.automation.import.dialog.title";
    private static final String NAME_PARAM = "exim.automation.import.dialog.name";
    private static final String TYPE_PARAM = "exim.automation.import.dialog.type";
    private static final String FILE_NAME_PARAM = "exim.automation.import.dialog.filename";

    private ImportJob job;

    private DefaultComboBoxModel<ImportJob.TypeOption> typeOptionModel;

    public ImportJobDialog(ImportJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(500, 200));
        this.job = job;

        this.addTextField(NAME_PARAM, this.job.getData().getName());

        typeOptionModel = new DefaultComboBoxModel<>();
        Arrays.stream(ImportJob.TypeOption.values()).forEach(v -> typeOptionModel.addElement(v));
        ImportJob.TypeOption typeOption = null;
        if (this.job.getParameters().getType() != null) {
            typeOption =
                    ImportJob.TypeOption.valueOf(
                            this.job.getParameters().getType().toUpperCase(Locale.ROOT));
        } else {
            typeOption = ImportJob.TypeOption.HAR;
        }
        typeOptionModel.setSelectedItem(typeOption);
        this.addComboField(TYPE_PARAM, typeOptionModel);

        String fileName = this.job.getData().getParameters().getFileName();
        File f = null;
        if (fileName != null && !fileName.isEmpty()) {
            f = new File(fileName);
        }
        this.addFileSelectField(FILE_NAME_PARAM, f, JFileChooser.FILES_AND_DIRECTORIES, null);
        this.addPadding();
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        ImportJob.TypeOption typeOption = (ImportJob.TypeOption) typeOptionModel.getSelectedItem();
        this.job.getParameters().setType(typeOption.name().toLowerCase(Locale.ROOT));
        this.job.getParameters().setFileName(this.getStringValue(FILE_NAME_PARAM));
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }
}
