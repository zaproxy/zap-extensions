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
package org.zaproxy.zap.extension.soap.automation;

import java.awt.Component;
import java.io.File;
import javax.swing.JFileChooser;
import javax.swing.JTextField;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class SoapJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "soap.automation.dialog.title";
    private static final String NAME_PARAM = "soap.automation.dialog.name";
    private static final String WSDL_FILE_PARAM = "soap.automation.dialog.wsdlfile";
    private static final String WSDL_URL_PARAM = "soap.automation.dialog.wsdlurl";

    private SoapJob job;

    public SoapJobDialog(SoapJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(500, 200));
        this.job = job;

        this.addTextField(NAME_PARAM, this.job.getData().getName());
        String fileName = this.job.getData().getParameters().getWsdlFile();
        File f = null;
        if (fileName != null && !fileName.isEmpty()) {
            f = new File(fileName);
        }
        this.addFileSelectField(WSDL_FILE_PARAM, f, JFileChooser.FILES_AND_DIRECTORIES, null);
        // Cannot select the node as it might not be present in the Sites tree
        this.addNodeSelectField(WSDL_URL_PARAM, null, true, false);
        Component urlField = this.getField(WSDL_URL_PARAM);
        if (urlField instanceof JTextField) {
            ((JTextField) urlField).setText(this.job.getParameters().getWsdlUrl());
        }
        this.addPadding();
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getParameters().setWsdlFile(this.getStringValue(WSDL_FILE_PARAM));
        this.job.getParameters().setWsdlUrl(this.getStringValue(WSDL_URL_PARAM));
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }
}
