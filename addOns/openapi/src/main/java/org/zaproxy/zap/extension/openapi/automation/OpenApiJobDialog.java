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
package org.zaproxy.zap.extension.openapi.automation;

import java.awt.Component;
import java.io.File;
import javax.swing.JFileChooser;
import javax.swing.JTextField;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class OpenApiJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "openapi.automation.dialog.title";
    private static final String NAME_PARAM = "openapi.automation.dialog.name";
    private static final String API_FILE_PARAM = "openapi.automation.dialog.apifile";
    private static final String API_URL_PARAM = "openapi.automation.dialog.apiurl";
    private static final String TARGET_URL_PARAM = "openapi.automation.dialog.targeturl";

    private OpenApiJob job;

    public OpenApiJobDialog(OpenApiJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(500, 200));
        this.job = job;

        this.addTextField(NAME_PARAM, this.job.getData().getName());
        String fileName = this.job.getData().getParameters().getApiFile();
        File f = null;
        if (fileName != null && !fileName.isEmpty()) {
            f = new File(fileName);
        }
        this.addFileSelectField(API_FILE_PARAM, f, JFileChooser.FILES_AND_DIRECTORIES, null);
        // Cannot select the node as it might not be present in the Sites tree
        this.addNodeSelectField(API_URL_PARAM, null, true, false);
        Component apiUrlField = this.getField(API_URL_PARAM);
        if (apiUrlField instanceof JTextField) {
            ((JTextField) apiUrlField).setText(this.job.getParameters().getApiUrl());
        }
        // Cannot select the node as it might not be present in the Sites tree
        this.addNodeSelectField(TARGET_URL_PARAM, null, true, false);
        Component targetUrlField = this.getField(TARGET_URL_PARAM);
        if (targetUrlField instanceof JTextField) {
            ((JTextField) targetUrlField).setText(this.job.getParameters().getTargetUrl());
        }
        this.addPadding();
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getParameters().setApiFile(this.getStringValue(API_FILE_PARAM));
        this.job.getParameters().setApiUrl(this.getStringValue(API_URL_PARAM));
        this.job.getParameters().setTargetUrl(this.getStringValue(TARGET_URL_PARAM));
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }
}
