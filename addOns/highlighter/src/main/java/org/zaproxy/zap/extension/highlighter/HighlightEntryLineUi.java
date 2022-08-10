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

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JColorChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.view.HighlightSearchEntry;

/*
 * A panel which specifies all values of an HighlightEntry in a JPanel,
 * with UI elements to input and output of its content.
 */
@SuppressWarnings("serial")
public class HighlightEntryLineUi extends AbstractPanel implements ActionListener {
    private static final long serialVersionUID = 1L;

    private JTextField searchField;
    private JButton colorBox;
    private JCheckBox activeCheck;
    private HighlightSearchEntry highlight;

    public HighlightEntryLineUi(JPanel gridPanel, int lineNr, HighlightSearchEntry highlight) {
        createUserPanelLine(gridPanel, lineNr, highlight);
        this.highlight = highlight;
    }

    public HighlightSearchEntry getHighlightEntry() {
        return highlight;
    }

    public void save() {
        // Token
        highlight.setToken(searchField.getText());

        // Color
        highlight.setColor(colorBox.getBackground());

        // isActive
        highlight.setActive(activeCheck.isSelected());
    }

    private void createUserPanelLine(JPanel gridPanel, int lineNr, HighlightSearchEntry highlight) {
        GridBagConstraints c = new GridBagConstraints();

        // Contraints
        c.fill = GridBagConstraints.HORIZONTAL;
        c.ipady = 0; // make this component tall
        c.weightx = 0.0;
        c.gridwidth = 1;
        c.gridy = lineNr;

        // 0: TextField
        c.gridx = 0;
        c.weightx = 1.0;
        searchField = new JTextField();
        searchField.setText(highlight.getToken());
        gridPanel.add(searchField, c);

        // 1: X
        c.gridx = 1;
        c.weightx = 0.0;
        JButton buttonx = new JButton("X");
        gridPanel.add(buttonx, c);

        // 1: Color
        c.gridx = 2;
        c.weightx = 0.0;
        c.ipadx = 20;
        c.insets = new Insets(0, 20, 0, 0); // top padding
        colorBox = null;
        colorBox = new JButton(" ");
        colorBox.setBackground(highlight.getColor());
        colorBox.setActionCommand("Color");
        colorBox.addActionListener(this);
        gridPanel.add(colorBox, c);

        // 2: Checkbox
        c.gridx = 3;
        c.weightx = 0.0;
        c.ipadx = 20;
        JPanel showPanel = new JPanel();
        JLabel label = new JLabel("Active");
        activeCheck = new JCheckBox();
        activeCheck.setSelected(highlight.isActive());
        showPanel.add(activeCheck);
        showPanel.add(label);
        gridPanel.add(showPanel, c);
    }

    @Override
    public void actionPerformed(ActionEvent arg0) {
        if (arg0.getActionCommand().equals("Color")) {
            Color c = null;
            c =
                    JColorChooser.showDialog(
                            this, "Choose Font Background Color", highlight.getColor());
            colorBox.setBackground(c);
        }
    }
}
