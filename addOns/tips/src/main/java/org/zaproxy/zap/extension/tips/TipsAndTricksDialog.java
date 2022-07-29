/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.tips;

import java.awt.Frame;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.awt.Point;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.utils.ZapTextArea;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class TipsAndTricksDialog extends AbstractDialog {

    private static final long serialVersionUID = -1L;

    private ExtensionTipsAndTricks ext;
    private JPanel jPanel = null;
    private JButton btnAllTips = null;
    private JButton btnNextTip = null;
    private JButton btnClose = null;
    private ZapTextArea txtTip = null;
    private JScrollPane scrollPane = null;
    private JPanel jPanel1 = null;
    private String lastTip = null;

    /** @throws HeadlessException */
    public TipsAndTricksDialog(ExtensionTipsAndTricks ext, Frame parent) throws HeadlessException {
        super(parent, true);
        this.ext = ext;
        initialize();
    }

    /** This method initializes this */
    private void initialize() {
        this.setVisible(false);
        this.setResizable(false);
        this.setModalityType(ModalityType.DOCUMENT_MODAL);
        this.setTitle(Constant.messages.getString("tips.dialog.title"));
        this.setContentPane(getJPanel());
        if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
            this.setSize(300, 235);
        }
        centreDialog();
        this.getRootPane().setDefaultButton(btnNextTip);
        pack();
    }

    public void displayTip() {
        String tip = ext.getRandomTip();
        while (tip.equals(lastTip)) {
            // Make sure we always get a new tip
            tip = ext.getRandomTip();
        }
        this.getTxtTip().setText(tip);
        // Scroll to the top
        this.getScrollPane().getViewport().setViewPosition(new Point(0, 0));
        lastTip = tip;
        this.setVisible(true);
    }

    /**
     * This method initializes jPanel
     *
     * @return javax.swing.JPanel
     */
    private JPanel getJPanel() {
        if (jPanel == null) {
            jPanel = new JPanel();
            jPanel.setLayout(new GridBagLayout());
            jPanel.add(getScrollPane(), LayoutHelper.getGBC(0, 0, 3, 1.0D, 1.0D));
            jPanel.add(getAllTipsButton(), LayoutHelper.getGBC(0, 2, 1, 0.0D, 0.0D));
            jPanel.add(new JLabel(), LayoutHelper.getGBC(1, 2, 1, 1.0D, 0.0D));
            jPanel.add(getButtonPanel(), LayoutHelper.getGBC(2, 2, 1, 0.0D, 0.0D));
        }
        return jPanel;
    }

    /**
     * This method initializes the 'next tip' button
     *
     * @return javax.swing.JButton
     */
    private JButton getAllTipsButton() {
        if (btnAllTips == null) {
            btnAllTips = new JButton();
            btnAllTips.setText(Constant.messages.getString("tips.button.allTips"));
            btnAllTips.addActionListener(e -> ExtensionHelp.showHelp("tips"));
        }
        return btnAllTips;
    }

    /**
     * This method initializes the 'next tip' button
     *
     * @return javax.swing.JButton
     */
    private JButton getNextTipButton() {
        if (btnNextTip == null) {
            btnNextTip = new JButton();
            btnNextTip.setText(Constant.messages.getString("tips.button.nextTip"));
            btnNextTip.addActionListener(e -> displayTip());
        }
        return btnNextTip;
    }
    /**
     * This method initializes the close button
     *
     * @return javax.swing.JButton
     */
    private JButton getCloseButton() {
        if (btnClose == null) {
            btnClose = new JButton();
            btnClose.setText(Constant.messages.getString("all.button.close"));
            btnClose.addActionListener(e -> TipsAndTricksDialog.this.setVisible(false));
        }
        return btnClose;
    }

    private JScrollPane getScrollPane() {
        if (scrollPane == null) {
            scrollPane = new JScrollPane();
            scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
            scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
            scrollPane.setMinimumSize(new java.awt.Dimension(300, 200));
            scrollPane.setPreferredSize(new java.awt.Dimension(300, 200));
            scrollPane.setViewportView(this.getTxtTip());
        }
        return scrollPane;
    }

    /**
     * This method initializes txtFind
     *
     * @return org.zaproxy.zap.utils.ZapTextField
     */
    private ZapTextArea getTxtTip() {
        if (txtTip == null) {
            txtTip = new ZapTextArea();
            txtTip.setEditable(false);
            txtTip.setLineWrap(true);
            txtTip.setWrapStyleWord(true);
        }
        return txtTip;
    }
    /**
     * This method initializes jPanel1
     *
     * @return javax.swing.JPanel
     */
    private JPanel getButtonPanel() {
        if (jPanel1 == null) {
            jPanel1 = new JPanel();
            jPanel1.setMinimumSize(new java.awt.Dimension(300, 35));
            jPanel1.add(getCloseButton(), null);
            jPanel1.add(getNextTipButton(), null);
        }
        return jPanel1;
    }
}
