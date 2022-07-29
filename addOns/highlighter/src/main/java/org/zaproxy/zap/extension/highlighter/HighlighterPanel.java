/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2011 The ZAP Development Team
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
package org.zaproxy.zap.extension.highlighter;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.LinkedList;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.view.HighlightSearchEntry;
import org.zaproxy.zap.view.HighlighterManager;

/*
 * The main highlighter tab, used to configure highlights in the HighlightManager
 */
@SuppressWarnings("serial")
public class HighlighterPanel extends AbstractPanel implements ActionListener {
    private static final long serialVersionUID = -1085991554138327045L;
    private JPanel mainPanel;
    private JPanel userPanel;
    private JPanel buttonPanel;
    private HighlighterManager highlighter;
    private LinkedList<HighlightEntryLineUi> panelList;
    private HighlightEntryLineUi panelLineExtra;
    private HighlightSearchEntry extraHighlight;

    private static String BUTTON_APPLY = "Appy";

    public HighlighterPanel(ExtensionHighlighter extensionHighlighter) {
        init();
    }

    private void init() {
        highlighter = HighlighterManager.getInstance();
        panelList = new LinkedList<>();

        initUi();
    }

    private void initUi() {
        // This
        this.setLayout(new BorderLayout());
        this.setName("Highlighter");

        // mainPanel
        mainPanel = new JPanel(new BorderLayout());
        this.add(mainPanel);

        // 0: button panel
        initButtonPanel();
        mainPanel.add(buttonPanel, BorderLayout.PAGE_START);

        // 1: userPanel
        userPanel = new JPanel(new BorderLayout());
        reinit();
        mainPanel.add(new JScrollPane(userPanel));
    }

    private void initButtonPanel() {
        JButton button = null;
        buttonPanel = new JPanel();
        button = new JButton("Apply");
        button.setActionCommand(BUTTON_APPLY);
        button.addActionListener(this);
        buttonPanel.add(button);
        buttonPanel.setBorder(BorderFactory.createEtchedBorder());
    }

    private void reinit() {
        userPanel.removeAll();
        userPanel.add(initUserPanel(), BorderLayout.PAGE_START);
        mainPanel.validate();
        mainPanel.repaint();
    }

    private JPanel initUserPanel() {
        JPanel userGridPanel = new JPanel();
        userGridPanel.setLayout(new GridBagLayout());
        userGridPanel.setBorder(BorderFactory.createEtchedBorder());

        // line 0: Title
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.ipady = 1; // make this component tall
        c.weightx = 0.0;
        c.gridwidth = 1;
        c.gridy = 0;
        c.gridx = 0;
        userGridPanel.add(new JLabel("Highlighted strings:"), c);

        // Line >0: Content
        int n = 1;
        LinkedList<HighlightSearchEntry> newEntrys = highlighter.getHighlights();
        panelList = new LinkedList<>();

        for (HighlightSearchEntry entry : newEntrys) {
            HighlightEntryLineUi panelLine = new HighlightEntryLineUi(userGridPanel, n++, entry);
            panelList.add(panelLine);
        }

        extraHighlight = new HighlightSearchEntry();
        panelLineExtra = new HighlightEntryLineUi(userGridPanel, n + 1, extraHighlight);

        return userGridPanel;
    }

    private void applyAll() {
        LinkedList<HighlightSearchEntry> entrys = new LinkedList<>();

        // Save all UI elements
        for (HighlightEntryLineUi panelLine : panelList) {
            panelLine.save();
            HighlightSearchEntry entry = panelLine.getHighlightEntry();
            if (entry.getToken().length() > 0) {
                entrys.add(entry);
            }
        }

        // The new line
        panelLineExtra.save();
        if (extraHighlight.getToken().length() > 0) {
            entrys.add(panelLineExtra.getHighlightEntry());
        }

        // Store them in the highlight manager
        highlighter.reinitHighlights(entrys);

        // highlighter.writeConfigFile();
        reinit();
    }

    @Override
    public void actionPerformed(ActionEvent arg0) {
        if (arg0.getActionCommand().equals(BUTTON_APPLY)) {
            applyAll();
        }
    }
}
