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
import javax.swing.JTextField;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.regextester.ui.model.RegexModel;
import org.zaproxy.zap.extension.regextester.ui.util.SimpleDocumentListener;

@SuppressWarnings("serial")
public class RegexPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private static final String REGEX_HEADER =
            Constant.messages.getString("regextester.dialog.regexheader");

    private final JTextField regexField;
    private final SimpleDocumentListener documentListener =
            (SimpleDocumentListener) this::updateToModel;
    private RegexModel regexModel;
    private Runnable onRegexChanged;

    public RegexPanel(RegexModel regexModel, Runnable onRegexChanged) {
        super(new BorderLayout());
        this.regexModel = regexModel;
        this.onRegexChanged = onRegexChanged;
        regexField = new JTextField();
        regexField.setFont(RegexDialog.monoFont);
        regexField.setText(regexModel.getRegex());
        regexField.getDocument().addDocumentListener(documentListener);

        JPanel regexPanel = new JPanel(new BorderLayout());
        regexPanel.add(regexField, BorderLayout.CENTER);
        add(regexPanel, BorderLayout.CENTER);
        setBorder(RegexDialog.createBorder(REGEX_HEADER));
    }

    private void updateToModel() {
        regexModel.setRegex(regexField.getText());
        onRegexChanged.run();
    }
}
