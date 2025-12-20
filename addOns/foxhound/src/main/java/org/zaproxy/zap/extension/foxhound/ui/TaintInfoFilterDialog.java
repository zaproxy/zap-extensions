/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.foxhound.ui;

import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.awt.Insets;
import java.util.List;
import java.util.stream.Stream;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants;
import org.zaproxy.zap.extension.foxhound.db.TaintInfoFilter;
import org.zaproxy.zap.extension.foxhound.taint.NamedAndTagged;
import org.zaproxy.zap.extension.foxhound.taint.SinkTag;
import org.zaproxy.zap.extension.foxhound.taint.SourceTag;
import org.zaproxy.zap.extension.foxhound.taint.TaintSinkType;
import org.zaproxy.zap.extension.foxhound.taint.TaintSourceType;
import org.zaproxy.zap.utils.ZapLabel;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class TaintInfoFilterDialog extends AbstractDialog {

    private static final long serialVersionUID = 1L;

    private JPanel jPanel = null;
    private JButton btnApply = null;
    private JButton btnCancel = null;
    private JPanel jPanel1 = null;
    private int exitResult = JOptionPane.CANCEL_OPTION;
    private final TaintInfoFilter filter = new TaintInfoFilter();

    private JButton btnReset = null;
    private JPanel jPanel2 = null;

    private List<String> sourceRawList = null;
    private List<String> sinkRawList = null;

    private JList<String> sourceList = null;
    private JList<String> sinkList = null;

    private JComboBox<String> sourceCombo;
    private JComboBox<String> sinkCombo;

    private JScrollPane sourceScroller = null;
    private JScrollPane sinkScroller = null;

    /**
     * @throws HeadlessException
     */
    public TaintInfoFilterDialog() throws HeadlessException {
        super();
        initialize();
    }

    /**
     * @param arg0
     * @param arg1
     * @throws HeadlessException
     */
    public TaintInfoFilterDialog(Frame arg0, boolean arg1) throws HeadlessException {
        super(arg0, arg1);
        initialize();
    }

    /** This method initializes this */
    private void initialize() {
        this.setContentPane(getJPanel());
        this.setVisible(false);
        this.setTitle(Constant.messages.getString("foxhound.filter.dialog.title"));
        if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
            this.setSize(800, 600);
        }
        centreDialog();
        this.getRootPane().setDefaultButton(btnApply);
        this.pack();
    }

    /**
     * This method initializes jPanel
     *
     * @return javax.swing.JPanel
     */
    private JPanel getJPanel() {
        if (jPanel == null) {
            GridBagConstraints gridBagConstraints12 = new GridBagConstraints();
            java.awt.GridBagConstraints gridBagConstraints11 = new GridBagConstraints();

            java.awt.GridBagConstraints gridBagConstraints6 = new GridBagConstraints();

            ZapLabel descLabel = new ZapLabel();
            descLabel.setLineWrap(true);
            descLabel.setWrapStyleWord(true);
            descLabel.setText(Constant.messages.getString("foxhound.filter.dialog.description"));

            jPanel = new JPanel();
            jPanel.setLayout(new GridBagLayout());

            gridBagConstraints6.gridwidth = 3;
            gridBagConstraints6.gridx = 0;
            gridBagConstraints6.gridy = 3;
            gridBagConstraints6.insets = new java.awt.Insets(5, 2, 5, 2);
            gridBagConstraints6.ipadx = 3;
            gridBagConstraints6.ipady = 3;
            gridBagConstraints11.gridx = 0;
            gridBagConstraints11.gridy = 0;
            gridBagConstraints11.insets = new java.awt.Insets(5, 10, 5, 10);
            gridBagConstraints11.weightx = 1.0D;
            gridBagConstraints11.gridwidth = 3;
            gridBagConstraints11.anchor = java.awt.GridBagConstraints.WEST;
            gridBagConstraints11.fill = java.awt.GridBagConstraints.HORIZONTAL;
            gridBagConstraints11.ipadx = 3;
            gridBagConstraints11.ipady = 3;
            gridBagConstraints12.gridx = 0;
            gridBagConstraints12.weighty = 1.0D;
            gridBagConstraints12.gridwidth = 3;
            gridBagConstraints12.gridy = 2;
            gridBagConstraints12.fill = java.awt.GridBagConstraints.BOTH;
            gridBagConstraints12.insets = new java.awt.Insets(2, 10, 2, 10);
            gridBagConstraints12.ipadx = 0;
            gridBagConstraints12.ipady = 1;
            jPanel.add(descLabel, gridBagConstraints11);
            jPanel.add(getJPanel2(), gridBagConstraints12);
            jPanel.add(getJPanel1(), gridBagConstraints6);
        }
        return jPanel;
    }

    /**
     * This method initializes btnApply
     *
     * @return javax.swing.JButton
     */
    private JButton getBtnApply() {
        if (btnApply == null) {
            btnApply = new JButton();
            btnApply.setText(Constant.messages.getString("history.filter.button.apply"));
            btnApply.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            filter.setSources(sourceList.getSelectedValuesList());
                            filter.setSinks(sinkList.getSelectedValuesList());
                            exitResult = JOptionPane.OK_OPTION;
                            TaintInfoFilterDialog.this.dispose();
                        }
                    });
        }
        return btnApply;
    }

    /**
     * This method initializes btnCancel
     *
     * @return javax.swing.JButton
     */
    private JButton getBtnCancel() {
        if (btnCancel == null) {
            btnCancel = new JButton();
            btnCancel.setText(Constant.messages.getString("all.button.cancel"));
            btnCancel.addActionListener(
                    new java.awt.event.ActionListener() {

                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {

                            exitResult = JOptionPane.CANCEL_OPTION;
                            TaintInfoFilterDialog.this.dispose();
                        }
                    });
        }
        return btnCancel;
    }

    /**
     * This method initializes jPanel1
     *
     * @return javax.swing.JPanel
     */
    private JPanel getJPanel1() {
        if (jPanel1 == null) {
            jPanel1 = new JPanel();
            jPanel1.add(getBtnCancel(), null);
            jPanel1.add(getBtnReset(), null);
            jPanel1.add(getBtnApply(), null);
        }
        return jPanel1;
    }

    public int showDialog() {
        this.setVisible(true);
        return exitResult;
    }

    /**
     * This method initializes btnReset
     *
     * @return javax.swing.JButton
     */
    private JButton getBtnReset() {
        if (btnReset == null) {
            btnReset = new JButton();
            btnReset.setText(Constant.messages.getString("history.filter.button.clear"));
            btnReset.addActionListener(
                    new java.awt.event.ActionListener() {

                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {

                            exitResult = JOptionPane.NO_OPTION;
                            // Unset everything
                            sourceList.setSelectedIndices(new int[0]);
                            sinkList.setSelectedIndices(new int[0]);
                            filter.reset();
                        }
                    });
        }
        return btnReset;
    }

    private Insets stdInset() {
        return new Insets(5, 5, 1, 5);
    }

    /**
     * This method initializes jPanel2
     *
     * @return javax.swing.JPanel
     */
    private JPanel getJPanel2() {
        if (jPanel2 == null) {
            jPanel2 = new JPanel();
            jPanel2.setLayout(new GridBagLayout());

            GridBagConstraints gbc00 = LayoutHelper.getGBC(0, 0, 1, 1.0, stdInset());
            GridBagConstraints gbc01 = LayoutHelper.getGBC(1, 0, 1, 1.0, stdInset());
            GridBagConstraints gbc10 = LayoutHelper.getGBC(0, 1, 1, 1.0, stdInset());
            GridBagConstraints gbc11 = LayoutHelper.getGBC(1, 1, 1, 1.0, stdInset());

            GridBagConstraints gbc20 =
                    LayoutHelper.getGBC(
                            0,
                            2,
                            1,
                            3,
                            1.0,
                            1.0,
                            GridBagConstraints.BOTH,
                            GridBagConstraints.NORTHWEST,
                            stdInset());
            GridBagConstraints gbc21 =
                    LayoutHelper.getGBC(
                            1,
                            2,
                            1,
                            3,
                            1.0,
                            1.0,
                            GridBagConstraints.BOTH,
                            GridBagConstraints.NORTHWEST,
                            stdInset());
            jPanel2.add(
                    new JLabel(Constant.messages.getString("foxhound.filter.dialog.sources")),
                    gbc00);
            jPanel2.add(
                    new JLabel(Constant.messages.getString("foxhound.filter.dialog.sinks")), gbc01);

            jPanel2.add(getSourceCombo(), gbc10);
            jPanel2.add(getSinkCombo(), gbc11);

            jPanel2.add(getSourceScroller(), gbc20);
            jPanel2.add(getSinkScroller(), gbc21);
        }
        return jPanel2;
    }

    private JScrollPane getSourceScroller() {
        if (sourceScroller == null) {
            sourceList =
                    new JList<String>(FoxhoundConstants.ALL_SOURCE_NAMES.toArray(new String[0]));
            sourceList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            sourceList.setLayoutOrientation(JList.VERTICAL);
            sourceScroller = new JScrollPane(sourceList);
        }
        return sourceScroller;
    }

    private JScrollPane getSinkScroller() {
        if (sinkScroller == null) {
            sinkList = new JList<String>(FoxhoundConstants.ALL_SINK_NAMES.toArray(new String[0]));
            sinkList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            sinkList.setLayoutOrientation(JList.VERTICAL);
            sinkScroller = new JScrollPane(sinkList);
        }
        return sinkScroller;
    }

    private JComboBox<String> getSourceCombo() {
        if (sourceCombo == null) {
            sourceCombo =
                    new JComboBox<>(
                            Stream.of(SourceTag.class.getEnumConstants())
                                    .map(SourceTag::name)
                                    .toList()
                                    .toArray(new String[0]));
            sourceCombo.addActionListener(
                    e -> {
                        String selected = (String) sourceCombo.getSelectedItem();
                        SourceTag sourceTag =
                                NamedAndTagged.getTagForString(selected, SourceTag.class);
                        sourceList.clearSelection();
                        if (sourceTag != null) {
                            int i = 0;
                            for (TaintSourceType t : FoxhoundConstants.ALL_SOURCES) {
                                if (t.isTagged(sourceTag)) {
                                    sourceList.addSelectionInterval(i, i);
                                }
                                i++;
                            }
                        }
                    });
        }
        return sourceCombo;
    }

    private JComboBox<String> getSinkCombo() {
        if (sinkCombo == null) {
            sinkCombo =
                    new JComboBox<>(
                            Stream.of(SinkTag.class.getEnumConstants())
                                    .map(SinkTag::name)
                                    .toList()
                                    .toArray(new String[0]));
            sinkCombo.addActionListener(
                    e -> {
                        String selected = (String) sinkCombo.getSelectedItem();
                        SinkTag sinkTag = NamedAndTagged.getTagForString(selected, SinkTag.class);
                        sinkList.clearSelection();
                        if (sinkTag != null) {
                            int i = 0;
                            for (TaintSinkType t : FoxhoundConstants.ALL_SINKS) {
                                if (t.isTagged(sinkTag)) {
                                    sinkList.addSelectionInterval(i, i);
                                }
                                i++;
                            }
                        }
                    });
        }
        return sinkCombo;
    }

    public TaintInfoFilter getFilter() {
        return this.filter;
    }
}
