/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.wstgmapper.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.Timer;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.wstgmapper.WstgMapperChecklistManager;
import org.zaproxy.addon.wstgmapper.model.WstgTest;
import org.zaproxy.addon.wstgmapper.model.WstgTestStatus;
import org.zaproxy.zap.utils.DesktopUtils;

/**
 * Detail view for the currently selected WSTG test.
 *
 * <p>It shows the bundled guidance and references for a test, and it lets the tester update status
 * and notes while delegating actual state changes back to the checklist manager.
 */
@SuppressWarnings("serial")
public class WstgDetailPanel extends JPanel {

    private final WstgMapperChecklistManager checklistManager;

    private final JLabel titleLabel;
    private final JLabel idLabel;
    private final JComboBox<WstgTestStatus> statusCombo;
    private final JTextArea objectivesArea;
    private final JTextArea notesArea;
    private final JTextArea referencesArea;
    private final JButton openReferenceButton;
    private final Timer saveTimer;

    private WstgTest currentTest;
    private boolean updating;

    public WstgDetailPanel(WstgMapperChecklistManager checklistManager) {
        this.checklistManager = checklistManager;
        setLayout(new BorderLayout());

        titleLabel = new JLabel(Constant.messages.getString("wstgmapper.detail.empty"));
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 16f));
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        idLabel = new JLabel();
        statusCombo = new JComboBox<>(WstgTestStatus.values());
        objectivesArea = createTextArea(5);
        notesArea = createTextArea(15);
        referencesArea = createTextArea(4);
        objectivesArea.setEditable(false);
        referencesArea.setEditable(false);
        openReferenceButton = new JButton(Constant.messages.getString("wstgmapper.detail.openRef"));
        openReferenceButton.setEnabled(false);

        JPanel idRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        idRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        idRow.add(new JLabel(Constant.messages.getString("wstgmapper.detail.id") + ":"));
        idRow.add(idLabel);

        JLabel statusLabel =
                new JLabel(Constant.messages.getString("wstgmapper.detail.status") + ":");
        statusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel statusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        statusRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        statusRow.add(statusCombo);

        openReferenceButton.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        headerPanel.add(titleLabel);
        headerPanel.add(idRow);
        headerPanel.add(statusLabel);
        headerPanel.add(statusRow);
        headerPanel.add(openReferenceButton);

        JPanel sectionsPanel = new JPanel();
        sectionsPanel.setLayout(new BoxLayout(sectionsPanel, BoxLayout.Y_AXIS));
        sectionsPanel.setBorder(BorderFactory.createEmptyBorder(0, 8, 8, 8));
        sectionsPanel.add(
                section(
                        Constant.messages.getString("wstgmapper.detail.objectives"),
                        objectivesArea));
        sectionsPanel.add(
                section(Constant.messages.getString("wstgmapper.detail.notes"), notesArea));
        sectionsPanel.add(
                section(
                        Constant.messages.getString("wstgmapper.detail.references"),
                        referencesArea));

        add(headerPanel, BorderLayout.NORTH);
        add(new JScrollPane(sectionsPanel), BorderLayout.CENTER);

        saveTimer = new Timer(200, e -> saveNotes());
        saveTimer.setRepeats(false);

        statusCombo.addActionListener(
                e -> {
                    if (!updating && currentTest != null) {
                        checklistManager.setTestStatus(
                                currentTest.getId(),
                                (WstgTestStatus) statusCombo.getSelectedItem());
                    }
                });
        notesArea.addFocusListener(
                new java.awt.event.FocusAdapter() {
                    @Override
                    public void focusLost(java.awt.event.FocusEvent e) {
                        saveTimer.restart();
                    }
                });
        openReferenceButton.addActionListener(e -> openCurrentReference());
    }

    public void showTest(WstgTest test) {
        if (currentTest != null) {
            saveTimer.stop();
            saveNotes();
        }
        currentTest = test;
        updating = true;
        try {
            if (test == null) {
                titleLabel.setText(Constant.messages.getString("wstgmapper.detail.empty"));
                idLabel.setText("");
                statusCombo.setSelectedItem(WstgTestStatus.NOT_TESTED);
                objectivesArea.setText("");
                notesArea.setText("");
                referencesArea.setText("");
                openReferenceButton.setEnabled(false);
                return;
            }

            titleLabel.setText(test.getName());
            idLabel.setText(test.getId());
            statusCombo.setSelectedItem(checklistManager.getTestStatus(test.getId()));
            objectivesArea.setText(toBulletList(test.getObjectives()));
            notesArea.setText(checklistManager.getTestNotes(test.getId()));
            referencesArea.setText(String.join("\n", safeList(test.getReferences())));
            openReferenceButton.setEnabled(
                    DesktopUtils.canOpenUrlInBrowser()
                            && !safeList(test.getReferences()).isEmpty());
        } finally {
            updating = false;
        }
    }

    public void refreshCurrentTest() {
        if (currentTest != null) {
            showTest(currentTest);
        }
    }

    public void cleanup() {
        saveTimer.stop();
        saveNotes();
    }

    public void openCurrentReference() {
        if (currentTest == null || safeList(currentTest.getReferences()).isEmpty()) {
            return;
        }
        DesktopUtils.openUrlInBrowser(currentTest.getReferences().get(0));
    }

    private void saveNotes() {
        if (currentTest != null) {
            checklistManager.setTestNotes(currentTest.getId(), notesArea.getText());
        }
    }

    private static JPanel section(String title, JTextArea textArea) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        panel.add(new JLabel(title), BorderLayout.NORTH);
        panel.add(new JScrollPane(textArea), BorderLayout.CENTER);
        return panel;
    }

    private static JTextArea createTextArea(int rows) {
        JTextArea area = new JTextArea(rows, 20);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        return area;
    }

    private static String toBulletList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (String value : values) {
            sb.append("- ").append(value).append('\n');
        }
        return sb.toString().trim();
    }

    private static List<String> safeList(List<String> values) {
        return values != null ? values : List.of();
    }
}
