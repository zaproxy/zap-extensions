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
import java.awt.Dimension;
import java.awt.Font;
import javax.swing.BorderFactory;
import javax.swing.JSplitPane;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.AbstractFrame;
import org.zaproxy.zap.extension.regextester.ui.model.RegexModel;
import org.zaproxy.zap.utils.FontUtils;

public class RegexDialog extends AbstractFrame {
    private static final long serialVersionUID = 1L;

    public static final Font monoFont = FontUtils.getFont("Monospaced");
    private static final String DIALOG_TITLE =
            Constant.messages.getString("regextester.dialog.title");

    private RegexPanel regexPanel;
    private MatchPanel matchPanel;
    private TestValuePanel testValuePanel;

    public RegexDialog(RegexModel regexModel) {
        setTitle(DIALOG_TITLE);
        this.regexPanel = new RegexPanel(regexModel, this::somethingChanged);
        this.testValuePanel = new TestValuePanel(regexModel, this::somethingChanged);
        this.matchPanel = new MatchPanel(regexModel);

        setPreferredSize(new Dimension(1024, 768));

        JSplitPane centerSplit =
                new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, testValuePanel, matchPanel);
        centerSplit.setResizeWeight(0.5);
        centerSplit.setBorder(BorderFactory.createEmptyBorder());

        getContentPane().add(regexPanel, BorderLayout.NORTH);
        getContentPane().add(centerSplit, BorderLayout.CENTER);
    }

    private void somethingChanged() {
        matchPanel.updateFromModel();
    }

    public static Border createBorder(String title) {
        TitledBorder titledBorder = BorderFactory.createTitledBorder(title);
        titledBorder.setBorder(BorderFactory.createEmptyBorder());

        return BorderFactory.createCompoundBorder(
                new EmptyBorder(10, 5, 5, 5),
                BorderFactory.createCompoundBorder(
                        titledBorder, BorderFactory.createEmptyBorder(5, 5, 5, 5)));
    }
}
