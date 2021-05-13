/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.diff;

import java.awt.Color;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.AdjustmentEvent;
import java.awt.event.AdjustmentListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowEvent;
import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import javax.swing.text.Highlighter.HighlightPainter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.LayoutHelper;

public class DiffDialog extends AbstractDialog implements AdjustmentListener {

    private static final long serialVersionUID = 1L;
    private static final Logger logger = LogManager.getLogger(DiffDialog.class);

    private JPanel jPanel = null;
    private JTextArea txtDisplayLeft = null;
    private JTextArea txtDisplayRight = null;
    private JPanel footer = null;

    private JSplitPane jSplitPane = null;
    private JScrollPane jScrollPaneLeft = null;
    private JScrollPane jScrollPaneRight = null;
    private JLabel leftHeader = null;
    private JLabel rightHeader = null;
    private JCheckBox syncCheckbox = null;

    /** @throws HeadlessException */
    public DiffDialog() throws HeadlessException {
        super();
        initialize();
    }

    /**
     * @param arg0
     * @param arg1
     * @throws HeadlessException
     */
    public DiffDialog(Frame arg0, boolean arg1) throws HeadlessException {
        super(arg0, arg1);
        initialize();
    }

    /**
     * This method initializes this
     *
     * @return void
     */
    private void initialize() {
        this.setTitle(Constant.messages.getString("diff.title"));
        this.setContentPane(getJPanel());
        if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
            this.setSize(900, 700);
        }
        //  Handle escape key to close the dialog
        KeyStroke escape = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0, false);
        AbstractAction escapeAction =
                new AbstractAction() {
                    private static final long serialVersionUID = 1L;

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        DiffDialog.this.setVisible(false);
                    }
                };
        getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(escape, "ESCAPE");
        getRootPane().getActionMap().put("ESCAPE", escapeAction);

        pack();
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
            jPanel.setPreferredSize(new java.awt.Dimension(900, 700));
            jPanel.setMinimumSize(new java.awt.Dimension(900, 700));
            jPanel.add(
                    getJSplitPane(),
                    LayoutHelper.getGBC(
                            0,
                            0,
                            2,
                            1.0D,
                            1.0D,
                            GridBagConstraints.BOTH,
                            GridBagConstraints.EAST,
                            new Insets(2, 2, 2, 2)));
            jPanel.add(getFooter(), LayoutHelper.getGBC(0, 1, 2, 0.0D, 0.0D));
        }
        return jPanel;
    }

    private JPanel getFooter() {
        if (footer == null) {
            footer = new JPanel();
            footer.setLayout(new GridBagLayout());

            JButton close = new JButton(Constant.messages.getString("diff.diff.close.button"));
            close.addActionListener(
                    e ->
                            DiffDialog.this.dispatchEvent(
                                    new WindowEvent(DiffDialog.this, WindowEvent.WINDOW_CLOSING)));

            footer.add(
                    getSyncCheckbox(), LayoutHelper.getGBC(0, 0, 1, 0.0D, new Insets(2, 10, 2, 2)));
            footer.add(new JLabel(), LayoutHelper.getGBC(1, 0, 1, 1.0D)); // Spacer
            footer.add(close, LayoutHelper.getGBC(2, 0, 1, 0.0D, new Insets(2, 2, 2, 10)));
        }
        return footer;
    }

    private JCheckBox getSyncCheckbox() {
        if (syncCheckbox == null) {
            syncCheckbox = new JCheckBox(Constant.messages.getString("diff.diff.lock.check"));
            syncCheckbox.setSelected(true);
        }
        return syncCheckbox;
    }

    public void setLeftHeader(String header) {
        this.leftHeader.setText(header);
        this.leftHeader.setToolTipText(header);
    }

    public void setRightHeader(String header) {
        this.rightHeader.setText(header);
        this.rightHeader.setToolTipText(header);
    }

    private JTextArea getTxtDisplayLeft() {
        if (txtDisplayLeft == null) {
            txtDisplayLeft = new JTextArea();
            txtDisplayLeft.setEditable(false);
            txtDisplayLeft.setFont(FontUtils.getFont("Dialog"));
        }
        return txtDisplayLeft;
    }

    private JTextArea getTxtDisplayRight() {
        if (txtDisplayRight == null) {
            txtDisplayRight = new JTextArea();
            txtDisplayRight.setEditable(false);
            txtDisplayRight.setFont(FontUtils.getFont("Dialog"));
        }
        return txtDisplayRight;
    }

    protected void highlightLeftText(int start, int end) {
        this.highlightText(this.getTxtDisplayLeft(), start, end);
    }

    protected void highlightRightText(int start, int end) {
        this.highlightText(this.getTxtDisplayRight(), start, end);
    }

    private void highlightText(JTextArea area, int start, int end) {
        Highlighter hilite = area.getHighlighter();
        HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(Color.YELLOW);
        try {
            hilite.addHighlight(start, end, painter);
        } catch (BadLocationException e) {
            logger.error(e.getMessage(), e);
        }
    }

    protected int appendLeftText(String text, boolean highlight) {
        return this.appendText(this.getTxtDisplayLeft(), text, highlight);
    }

    protected int appendRightText(String text, boolean highlight) {
        return this.appendText(this.getTxtDisplayRight(), text, highlight);
    }

    private int appendText(JTextArea area, String text, boolean highlight) {

        int start = area.getDocument().getLength();

        if (text == null || text.length() == 0) {
            return start;
        }

        int end = start + text.length();

        try {

            area.getDocument().insertString(start, text, null);

            if (highlight) {
                Highlighter hilite = area.getHighlighter();
                HighlightPainter painter =
                        new DefaultHighlighter.DefaultHighlightPainter(Color.YELLOW);
                hilite.addHighlight(start, end - 1, painter);
            }

        } catch (BadLocationException e) {
            logger.error(e.getMessage(), e);
        }
        return end;
    }
    /**
     * This method initializes jScrollPane
     *
     * @return javax.swing.JScrollPane
     */
    private JSplitPane getJSplitPane() {
        if (jSplitPane == null) {

            jScrollPaneLeft = new JScrollPane();
            jScrollPaneLeft.setHorizontalScrollBarPolicy(
                    javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            jScrollPaneLeft.setVerticalScrollBarPolicy(
                    javax.swing.JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
            jScrollPaneLeft.setViewportView(getTxtDisplayLeft());
            jScrollPaneLeft.getHorizontalScrollBar().addAdjustmentListener(this);
            jScrollPaneLeft.getVerticalScrollBar().addAdjustmentListener(this);

            jScrollPaneRight = new JScrollPane();
            jScrollPaneRight.setHorizontalScrollBarPolicy(
                    javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            jScrollPaneRight.setVerticalScrollBarPolicy(
                    javax.swing.JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
            jScrollPaneRight.setViewportView(getTxtDisplayRight());
            jScrollPaneRight.getHorizontalScrollBar().addAdjustmentListener(this);
            jScrollPaneRight.getVerticalScrollBar().addAdjustmentListener(this);

            JPanel leftPanel = new JPanel();
            leftPanel.setLayout(new GridBagLayout());
            leftHeader = new JLabel();

            leftPanel.add(
                    leftHeader,
                    LayoutHelper.getGBC(
                            0,
                            0,
                            1,
                            1.0D,
                            0.0D,
                            GridBagConstraints.BOTH,
                            GridBagConstraints.EAST,
                            new Insets(2, 2, 2, 2)));
            leftPanel.add(jScrollPaneLeft, LayoutHelper.getGBC(0, 1, 1, 1.0D, 1.0D));

            JPanel rightPanel = new JPanel();
            rightPanel.setLayout(new GridBagLayout());
            rightHeader = new JLabel();

            rightPanel.add(
                    rightHeader,
                    LayoutHelper.getGBC(
                            0,
                            0,
                            1,
                            1.0D,
                            0.0D,
                            GridBagConstraints.BOTH,
                            GridBagConstraints.EAST,
                            new Insets(2, 2, 2, 2)));
            rightPanel.add(jScrollPaneRight, LayoutHelper.getGBC(0, 1, 1, 1.0D, 1.0D));

            jSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);

            jSplitPane.setDividerLocation(0.5D);
            jSplitPane.setResizeWeight(0.5D);
        }
        return jSplitPane;
    }

    @Override
    public void adjustmentValueChanged(AdjustmentEvent e) {
        if (getSyncCheckbox().isSelected()) {
            // 'Lock' the scrollbars together
            if (this.jScrollPaneLeft.getVerticalScrollBar().equals(e.getSource())) {
                this.jScrollPaneRight
                        .getVerticalScrollBar()
                        .setValue(this.jScrollPaneLeft.getVerticalScrollBar().getValue());
            } else if (this.jScrollPaneRight.getVerticalScrollBar().equals(e.getSource())) {
                this.jScrollPaneLeft
                        .getVerticalScrollBar()
                        .setValue(this.jScrollPaneRight.getVerticalScrollBar().getValue());
            } else if (this.jScrollPaneLeft.getHorizontalScrollBar().equals(e.getSource())) {
                this.jScrollPaneRight
                        .getHorizontalScrollBar()
                        .setValue(this.jScrollPaneLeft.getHorizontalScrollBar().getValue());
            } else if (this.jScrollPaneRight.getHorizontalScrollBar().equals(e.getSource())) {
                this.jScrollPaneLeft
                        .getHorizontalScrollBar()
                        .setValue(this.jScrollPaneRight.getHorizontalScrollBar().getValue());
            }
        }
    }

    public void clearPanels() {
        this.getTxtDisplayLeft().setText("");
        this.getTxtDisplayRight().setText("");
    }
}
