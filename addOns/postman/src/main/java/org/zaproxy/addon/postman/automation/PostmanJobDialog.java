/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.postman.automation;

import java.awt.Component;
import java.io.File;
import javax.swing.JFileChooser;
import javax.swing.JTextField;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class PostmanJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "postman.automation.dialog.title";
    private static final String NAME_PARAM = "postman.automation.dialog.name";
    private static final String COLLECTION_FILE_PARAM = "postman.automation.dialog.collectionfile";
    private static final String COLLECTION_URL_PARAM = "postman.automation.dialog.collectionurl";
    private static final String VARS_PARAM = "postman.automation.dialog.vars";

    private PostmanJob job;

    public PostmanJobDialog(PostmanJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(500, 250));
        this.job = job;

        this.addTextField(NAME_PARAM, this.job.getData().getName());
        String fileName = this.job.getData().getParameters().getCollectionFile();
        File f = null;
        if (fileName != null && !fileName.isEmpty()) {
            f = new File(fileName);
        }
        this.addFileSelectField(COLLECTION_FILE_PARAM, f, JFileChooser.FILES_AND_DIRECTORIES, null);

        this.addNodeSelectField(COLLECTION_URL_PARAM, null, true, false);
        Component collectionUrlField = this.getField(COLLECTION_URL_PARAM);
        if (collectionUrlField instanceof JTextField) {
            ((JTextField) collectionUrlField).setText(this.job.getParameters().getCollectionUrl());
        }

        this.addTextField(VARS_PARAM, this.job.getParameters().getVariables());
        this.addPadding();
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getParameters().setCollectionFile((this.getStringValue(COLLECTION_FILE_PARAM)));
        this.job.getParameters().setCollectionUrl(this.getStringValue(COLLECTION_URL_PARAM));
        this.job.getParameters().setVariables(this.getStringValue(VARS_PARAM));
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        return null;
    }
}
