/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
import java.util.List;
import java.util.stream.Stream;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JFileChooser;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.exim.ExporterOptions;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ExportJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "exim.automation.export.dialog.title";
    private static final String NAME_PARAM = "exim.automation.dialog.name";
    private static final String CONTEXT_PARAM = "openapi.automation.dialog.context";
    private static final String TYPE_PARAM = "exim.automation.dialog.type";
    private static final String SOURCE_PARAM = "exim.automation.export.dialog.source";
    private static final String FILE_NAME_PARAM = "exim.automation.dialog.filename";

    private ExportJob job;

    private DefaultComboBoxModel<ExporterOptions.Type> typeOptionModel;
    private DefaultComboBoxModel<ExporterOptions.Source> sourceOptionModel;

    public ExportJobDialog(ExportJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(550, 250));
        this.job = job;

        this.addTextField(NAME_PARAM, this.job.getData().getName());

        List<String> contextNames = job.getEnv().getContextNames();
        contextNames.add(0, "");
        this.addComboField(CONTEXT_PARAM, contextNames, job.getParameters().getContext());

        typeOptionModel = new DefaultComboBoxModel<>();
        Stream.of(ExporterOptions.Type.values()).forEach(typeOptionModel::addElement);
        typeOptionModel.setSelectedItem(job.getParameters().getType());
        this.addComboField(TYPE_PARAM, typeOptionModel);

        String fileName = job.getData().getParameters().getFileName();
        File f = null;
        if (fileName != null && !fileName.isEmpty()) {
            f = new File(fileName);
        }
        this.addFileSelectField(FILE_NAME_PARAM, f, JFileChooser.FILES_AND_DIRECTORIES, null);

        sourceOptionModel = new DefaultComboBoxModel<>();
        Stream.of(ExporterOptions.Source.values()).forEach(sourceOptionModel::addElement);
        sourceOptionModel.setSelectedItem(job.getParameters().getSource());
        this.addComboField(SOURCE_PARAM, sourceOptionModel);

        this.addPadding();
    }

    @Override
    public void save() {
        this.job.getData().setName(getStringValue(NAME_PARAM));
        this.job.getParameters().setType((ExporterOptions.Type) typeOptionModel.getSelectedItem());
        this.job.getParameters().setFileName(getStringValue(FILE_NAME_PARAM));
        this.job
                .getParameters()
                .setSource((ExporterOptions.Source) sourceOptionModel.getSelectedItem());
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        if (ExporterOptions.Source.SITESTREE.equals(sourceOptionModel.getSelectedItem())
                && !ExporterOptions.Type.YAML.equals(typeOptionModel.getSelectedItem())) {
            return Constant.messages.getString(
                    "exim.automation.export.dialog.error.sitestree.type");
        } else if (!ExporterOptions.Source.SITESTREE.equals(sourceOptionModel.getSelectedItem())
                && ExporterOptions.Type.YAML.equals(typeOptionModel.getSelectedItem())) {
            return Constant.messages.getString(
                    "exim.automation.export.dialog.error.messages.type",
                    sourceOptionModel.getSelectedItem());
        }
        return null;
    }
}
