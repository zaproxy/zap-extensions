/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.regextester.ui;

import java.awt.BorderLayout;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.regextester.ui.model.RegexModel;
import org.zaproxy.zap.extension.regextester.ui.util.SimpleDocumentListener;

@SuppressWarnings("serial")
public class TestValuePanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private static final String TEST_VALUE_HEADER =
            Constant.messages.getString("regextester.dialog.testvalueheader");

    private final JTextArea testValueField;
    private final SimpleDocumentListener documentListener =
            (SimpleDocumentListener) this::updateToModel;
    private RegexModel regexModel;
    private Runnable onTestValueChanged;

    public TestValuePanel(RegexModel regexModel, Runnable onTestValueChanged) {
        super(new BorderLayout());
        this.regexModel = regexModel;
        this.onTestValueChanged = onTestValueChanged;
        testValueField = new JTextArea();
        testValueField.setFont(RegexDialog.monoFont);
        testValueField.setLineWrap(true);
        testValueField.setWrapStyleWord(true);
        testValueField.setText(regexModel.getTestValue());
        testValueField.getDocument().addDocumentListener(documentListener);
        add(new JScrollPane(testValueField), BorderLayout.CENTER);
        setBorder(RegexDialog.createBorder(TEST_VALUE_HEADER));
    }

    private void updateToModel() {
        regexModel.setTestValue(testValueField.getText());
        onTestValueChanged.run();
    }
}
