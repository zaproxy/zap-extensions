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
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JFileChooser;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.exim.Importer;
import org.zaproxy.addon.exim.ImporterType;
import org.zaproxy.addon.exim.urls.UrlExporter;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ImportJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "exim.automation.import.dialog.title";
    private static final String NAME_PARAM = "exim.automation.dialog.name";
    private static final String TYPE_PARAM = "exim.automation.dialog.type";
    private static final String FILE_NAME_PARAM = "exim.automation.dialog.filename";

    private ImportJob job;

    private DefaultComboBoxModel<ImportTypeOption> typeOptionModel;

    public ImportJobDialog(ImportJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(500, 200));
        this.job = job;

        this.addTextField(NAME_PARAM, this.job.getData().getName());

        typeOptionModel = new DefaultComboBoxModel<>();
        for (ImportTypeOption option : getImportTypeOptions()) {
            typeOptionModel.addElement(option);
        }
        String currentType = this.job.getParameters().getType();
        ImportTypeOption selected =
                getImportTypeOptions().stream()
                        .filter(o -> o.id().equalsIgnoreCase(currentType))
                        .findFirst()
                        .orElse(getImportTypeOptions().get(0));
        typeOptionModel.setSelectedItem(selected);
        this.addComboField(TYPE_PARAM, typeOptionModel);

        String fileName = this.job.getData().getParameters().getFileName();
        File f = null;
        if (fileName != null && !fileName.isEmpty()) {
            f = new File(fileName);
        }
        this.addFileSelectField(FILE_NAME_PARAM, f, JFileChooser.FILES_AND_DIRECTORIES, null);
        this.addPadding();
    }

    private static List<ImportTypeOption> getImportTypeOptions() {
        List<ImportTypeOption> options = new ArrayList<>();
        for (ImporterType type : Importer.getAvailableTypes()) {
            options.add(new ImportTypeOption(type.getId(), type.getName()));
        }
        options.add(
                new ImportTypeOption(
                        ImportJob.MODSEC2_TYPE,
                        Constant.messages.getString("exim.options.value.type.modsec2")));
        options.add(
                new ImportTypeOption(
                        UrlExporter.ID,
                        Constant.messages.getString("exim.options.value.type.url")));
        options.add(
                new ImportTypeOption(
                        ImportJob.ZAP_MESSAGES_TYPE,
                        Constant.messages.getString("exim.options.value.type.zapmessages")));
        return options;
    }

    @Override
    public void save() {
        this.job.getData().setName(getStringValue(NAME_PARAM));
        ImportTypeOption typeOption = (ImportTypeOption) typeOptionModel.getSelectedItem();
        this.job.getParameters().setType(typeOption.id().toLowerCase(Locale.ROOT));
        this.job.getParameters().setFileName(getStringValue(FILE_NAME_PARAM));
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }

    private record ImportTypeOption(String id, String displayName) {
        @Override
        public String toString() {
            return displayName;
        }
    }
}
