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
package org.zaproxy.zap.extension.sequence.automation;

import java.io.File;
import javax.swing.JFileChooser;
import javax.swing.JTextField;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class SequenceImportJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "sequence.automation.import.dialog.title";
    private static final String JOB_NAME_PARAM = "sequence.automation.dialog.jobName";

    private static final String NAME_PARAM = "sequence.automation.import.dialog.name";
    private static final String PATH_PARAM = "sequence.automation.import.dialog.path";
    private static final String ASSERT_CODE_PARAM = "sequence.automation.import.dialog.assertCode";
    private static final String ASSERT_LENGTH_PARAM =
            "sequence.automation.import.dialog.assertLength";

    private SequenceImportJob job;

    public SequenceImportJobDialog(SequenceImportJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(500, 300));
        this.job = job;

        addTextField(JOB_NAME_PARAM, job.getData().getName());

        addTextField(NAME_PARAM, job.getParameters().getName());

        String fileName = job.getData().getParameters().getPath();
        File f = null;
        if (fileName != null && !fileName.isEmpty()) {
            f = new File(fileName);
        }
        addFileSelectField(PATH_PARAM, f, JFileChooser.FILES_AND_DIRECTORIES, null);

        addCheckBoxField(ASSERT_CODE_PARAM, JobUtils.unBox(job.getParameters().getAssertCode()));
        addTextField(ASSERT_LENGTH_PARAM, unbox(job.getParameters().getAssertLength()));
        ((AbstractDocument) ((JTextField) getField(ASSERT_LENGTH_PARAM)).getDocument())
                .setDocumentFilter(new IntFilter());

        addPadding();
    }

    private static String unbox(Integer value) {
        if (value == null) {
            return null;
        }
        return String.valueOf(value);
    }

    private static Integer box(String value) {
        if (value.isEmpty()) {
            return null;
        }
        return Integer.valueOf(value);
    }

    @Override
    public void save() {
        job.getData().setName(getStringValue(JOB_NAME_PARAM));

        job.getParameters().setName(getStringValue(NAME_PARAM));
        job.getParameters().setPath(getStringValue(PATH_PARAM));
        job.getParameters().setAssertCode(getBoolValue(ASSERT_CODE_PARAM));
        job.getParameters().setAssertLength(box(getStringValue(ASSERT_LENGTH_PARAM)));

        job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }

    private static class IntFilter extends DocumentFilter {

        @Override
        public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr)
                throws BadLocationException {
            String filteredString = stripNonIntChars(string);
            if (filteredString.isEmpty()) {
                return;
            }
            super.insertString(fb, offset, filteredString, attr);
        }

        private static String stripNonIntChars(String str) {
            return str.replaceAll("[^\\d]", "");
        }

        @Override
        public void replace(
                FilterBypass fb, int offset, int length, String text, AttributeSet attrs)
                throws BadLocationException {
            String filteredText = stripNonIntChars(text);
            if (filteredText.isEmpty()) {
                return;
            }
            super.replace(fb, offset, length, filteredText, attrs);
        }
    }
}
