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
package org.zaproxy.zap.extension.advancedencoder;

import java.awt.Color;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.JTextComponent;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.AbstractFrame;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.advancedencoder.processors.EncodeDecodeProcessors;
import org.zaproxy.zap.extension.advancedencoder.processors.EncodeDecodeResult;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ZapTextArea;

public class AdvancedEncodeDecodeDialog extends AbstractFrame implements WindowListener {

    public static final String ENCODE_DECODE_FIELD = "EncodeDecodeInputField";
    public static final String ENCODE_DECODE_RESULTFIELD = "EncodeDecodeResultField";
    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = Logger.getLogger(AdvancedEncodeDecodeDialog.class);
    private final EncodeDecodeProcessors encodeDecodeProcessors;
    private JTabbedPane jTabbed = null;
    private JPanel jPanel = null;
    private javax.swing.JToolBar panelToolbar = null;
    private List<TabModel> tabs = new ArrayList<>();
    private ZapTextArea inputField = null;
    private JButton addTabButton;
    private JButton addOutputButton;
    private AddEncodeDecodeTabDialog addTabDialog;
    private AddEncodeDecodeOutputPanelDialog addOutputDialog;
    private JButton deleteSelectedTabButton;
    private int globalOutputPanelIndex;
    private JButton resetButton;
    private static List<TabModel> defaultTabModels = new ArrayList<>();

    /**
     * @param tabModels
     * @throws HeadlessException
     */
    public AdvancedEncodeDecodeDialog(List<TabModel> tabModels) throws HeadlessException {
        super();
        encodeDecodeProcessors = new EncodeDecodeProcessors();
        initialize();
        setTabs(tabModels);
        defaultTabModels.addAll(tabModels);
    }

    public void setTabs(List<TabModel> tabModels) {
        for (int i = 0; i < getTabbedPane().getTabCount(); i++) {
            getTabbedPane().remove(i);
        }

        for (TabModel tabModel : tabModels) {
            List<OutputPanelModel> outputPanels = tabModel.getOutputPanels();
            tabModel.setOutputPanels(new ArrayList<>());
            addTab(tabModel, outputPanels);
        }
    }

    private void resetTabs() {
        getTabbedPane().removeAll();
        tabs = new ArrayList<>();
        defaultTabModels = new ArrayList<>();

        try {
            defaultTabModels.addAll(AdvancedEncoderConfig.resetConfig());
        } catch (ConfigurationException | IOException e) {
            LOGGER.warn("There was a problem loading the default advanced encoder config.", e);
        }
        for (TabModel tabModel : defaultTabModels) {
            List<OutputPanelModel> outputPanels = tabModel.getOutputPanels();
            tabModel.setOutputPanels(new ArrayList<>());
            addTab(tabModel, outputPanels);
        }

        try {
            AdvancedEncoderConfig.saveConfig(tabs);
        } catch (ConfigurationException | IOException e) {
            LOGGER.warn("There was a problem saving the advanced encoder config.", e);
        }
    }

    /** This method initializes this */
    private void initialize() {
        this.setAlwaysOnTop(false);
        this.setContentPane(getMainPanel());
        this.setTitle(Constant.messages.getString("advancedencoder.dialog.title"));
        this.addWindowListener(this);
    }

    private javax.swing.JToolBar getPanelToolbar() {
        if (panelToolbar == null) {

            panelToolbar = new javax.swing.JToolBar();
            panelToolbar.setLayout(new java.awt.GridBagLayout());
            panelToolbar.setEnabled(true);
            panelToolbar.setFloatable(false);
            panelToolbar.setRollover(true);
            panelToolbar.setPreferredSize(new java.awt.Dimension(800, 30));
            panelToolbar.setName("Advanced Encode Decode Toolbar");

            GridBagConstraints gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.insets = new java.awt.Insets(0, 0, 0, 0);
            gbc.anchor = java.awt.GridBagConstraints.WEST;

            panelToolbar.add(getAddTabButton(), gbc);
            ++gbc.gridx;

            panelToolbar.add(getDeleteSelectedTabButton(), gbc);
            ++gbc.gridx;

            panelToolbar.add(getAddOutputButton(), gbc);
            ++gbc.gridx;

            panelToolbar.add(new JLabel(), gbc);
            ++gbc.gridx;

            gbc.weightx = 1.0;
            gbc.weighty = 1.0;
            gbc.anchor = java.awt.GridBagConstraints.EAST;
            panelToolbar.add(new JLabel(), gbc);
            ++gbc.gridx;
            panelToolbar.add(getResetButton(), gbc);
        }
        return panelToolbar;
    }

    private JButton getDeleteSelectedTabButton() {
        if (deleteSelectedTabButton == null) {
            deleteSelectedTabButton = new JButton();
            deleteSelectedTabButton.addActionListener(e -> deleteSelectedTab());
            deleteSelectedTabButton.setIcon(
                    new ImageIcon(
                            ExtensionAdvancedEncoder.class.getResource(
                                    "/org/zaproxy/zap/extension/advancedencoder/resources/ui-tab--delete.png")));
            deleteSelectedTabButton.setToolTipText(
                    Constant.messages.getString("advancedencoder.dialog.deletetab"));
            DisplayUtils.scaleIcon(deleteSelectedTabButton);
        }
        return deleteSelectedTabButton;
    }

    private JButton getResetButton() {
        if (resetButton == null) {
            resetButton =
                    new JButton(
                            Constant.messages.getString(
                                    "advancedencoder.dialog.reset.button.title"));
            resetButton.addActionListener(e -> resetTabs());
            resetButton.setToolTipText(
                    Constant.messages.getString("advancedencoder.dialog.reset.button.tooltip"));
        }
        return resetButton;
    }

    private void deleteSelectedTab() {
        int selectedIndex = getTabbedPane().getSelectedIndex();
        getTabbedPane().remove(selectedIndex);
        tabs.remove(selectedIndex);
    }

    private JButton getAddTabButton() {
        if (addTabButton == null) {
            addTabButton = new JButton();
            addTabButton.addActionListener(e -> addTab());
            addTabButton.setIcon(
                    new ImageIcon(
                            ExtensionAdvancedEncoder.class.getResource(
                                    "/org/zaproxy/zap/extension/advancedencoder/resources/ui-tab--plus.png")));
            addTabButton.setToolTipText(
                    Constant.messages.getString("advancedencoder.dialog.addtab"));
            DisplayUtils.scaleIcon(addTabButton);
        }
        return addTabButton;
    }

    private int getIndex(TabModel tabModel) {
        return tabs.indexOf(tabModel);
    }

    private void addTab() {
        TabModel tabModel = showAddTabDialogue();
        if (tabModel != null) {
            addTab(tabModel, new ArrayList<>());
            SwingUtilities.invokeLater(() -> jPanel.repaint());
        }
    }

    private void addTab(TabModel tabModel, List<OutputPanelModel> outputPanelModels) {
        if (tabModel.getOutputPanels().size() > 0) {
            throw new IllegalArgumentException("Can not add Tab with output panels");
        }

        tabs.add(tabModel);
        int tabIndex = getIndex(tabModel);

        final JPanel jPanel = new JPanel();
        jPanel.setLayout(new GridBagLayout());
        getTabbedPane()
                .insertTab(
                        createTabTitle(tabModel),
                        null,
                        jPanel,
                        null,
                        getTabbedPane().getTabCount());
        getTabbedPane().setSelectedIndex(tabIndex);

        for (OutputPanelModel outputPanel : outputPanelModels) {
            addOutputPanel(outputPanel, tabIndex);
        }
    }

    private String createTabTitle(TabModel tabModel) {
        if (tabModel.getName().startsWith(EncodeDecodeProcessors.PREDEFINED_PREFIX)) {
            return Constant.messages.getString(tabModel.getName());
        }
        return tabModel.getName();
    }

    public TabModel showAddTabDialogue() {
        if (addTabDialog == null) {
            addTabDialog = new AddEncodeDecodeTabDialog(this);
            addTabDialog.pack();
        }

        addTabDialog.setVisible(true);
        String name = addTabDialog.getName();
        addTabDialog.clearFields();

        if (name != null) {
            TabModel tabModel = new TabModel();
            tabModel.setName(name);
            return tabModel;
        }
        return null;
    }

    private JButton getAddOutputButton() {
        if (addOutputButton == null) {
            addOutputButton = new JButton();
            addOutputButton.addActionListener(e -> addOutputPanelToCurrentTab());
            addOutputButton.setIcon(
                    new ImageIcon(
                            ExtensionAdvancedEncoder.class.getResource(
                                    "/org/zaproxy/zap/extension/advancedencoder/resources/ui-output--plus.png")));
            addOutputButton.setToolTipText(
                    Constant.messages.getString("advancedencoder.dialog.addoutput"));
            DisplayUtils.scaleIcon(addOutputButton);
        }
        return addOutputButton;
    }

    private void addOutputPanelToCurrentTab() {
        OutputPanelModel outputPanelModel = showAddOutputDialogue();
        if (outputPanelModel != null) {
            int tabIndex = getTabbedPane().getSelectedIndex();
            addOutputPanel(outputPanelModel, tabIndex);
            SwingUtilities.invokeLater(() -> jPanel.repaint());
        }
    }

    private void addOutputPanel(OutputPanelModel outputPanelModel, int tabIndex) {
        Component component = getTabbedPane().getComponentAt(tabIndex);
        if (component instanceof JPanel) {
            JPanel parentPanel = (JPanel) component;
            TabModel foundTab = getTabByIndex(tabIndex);
            foundTab.getOutputPanels().add(outputPanelModel);
            ZapTextArea outputField = newField(false);
            addField(parentPanel, outputField, createOutputPanelTitle(outputPanelModel));
            updateEncodeDecodeField(outputField, outputPanelModel);
        }
    }

    private String createOutputPanelTitle(OutputPanelModel outputPanelModel) {
        String processorId = outputPanelModel.getProcessorId();
        if (processorId.startsWith(EncodeDecodeProcessors.PREDEFINED_PREFIX)) {
            processorId = Constant.messages.getString(processorId);
        }

        if (outputPanelModel.getName().isEmpty()) {
            return processorId;
        }

        return outputPanelModel.getName() + " (" + processorId + ")";
    }

    private int getIndex(TabModel tabModel, OutputPanelModel outputPanelModel) {
        return tabModel.getOutputPanels().indexOf(outputPanelModel);
    }

    public void deleteOutputPanel(JTextComponent toDelete) {
        OutputPanelPosition outputPanelPos = findOutputPanel(toDelete);
        if (outputPanelPos == null) {
            LOGGER.warn("component for delete not found");
            return;
        }

        Component tab = getTabbedPane().getComponentAt(outputPanelPos.getTabIndex());
        if (tab instanceof JPanel) {
            JPanel parentPanel = (JPanel) tab;
            parentPanel.remove(outputPanelPos.getOutputPanelIndex());
            getTabByIndex(outputPanelPos.getTabIndex())
                    .getOutputPanels()
                    .remove(outputPanelPos.getOutputPanelIndex());
            SwingUtilities.invokeLater(() -> jPanel.repaint());
        }
    }

    private OutputPanelPosition findOutputPanel(JTextComponent searched) {
        for (int i = 0; i < getTabbedPane().getTabCount(); i++) {
            Component tab = getTabbedPane().getComponentAt(i);
            if (tab instanceof JPanel) {
                JPanel parentPanel = (JPanel) tab;
                for (int j = 0; j < parentPanel.getComponentCount(); j++) {
                    Component outputPanel = parentPanel.getComponent(j);
                    if (outputPanel.equals(searched.getParent().getParent())) {
                        return new OutputPanelPosition(i, j);
                    }
                }
            }
        }
        return null;
    }

    private TabModel getTabByIndex(int selectedTabIndex) {
        return tabs.get(selectedTabIndex);
    }

    public OutputPanelModel showAddOutputDialogue() {
        if (addOutputDialog == null) {
            addOutputDialog = new AddEncodeDecodeOutputPanelDialog(this, encodeDecodeProcessors);
            addOutputDialog.pack();
        }
        addOutputDialog.setVisible(true);
        String name = addOutputDialog.getName();
        String processorId = addOutputDialog.getProcessorId();

        addOutputDialog.clearFields();

        if (name != null) {
            OutputPanelModel outputPanelModel = new OutputPanelModel();
            outputPanelModel.setName(name);
            outputPanelModel.setProcessorId(processorId);
            return outputPanelModel;
        }
        return null;
    }

    private void addField(JPanel parent, JComponent c, String title) {
        final GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = globalOutputPanelIndex++;
        gbc.insets = new java.awt.Insets(1, 1, 1, 1);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 0.5D;
        gbc.weighty = 0.5D;

        final JScrollPane jsp = new JScrollPane();
        jsp.setViewportView(c);
        jsp.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        jsp.setBorder(
                BorderFactory.createTitledBorder(
                        null,
                        title,
                        TitledBorder.DEFAULT_JUSTIFICATION,
                        TitledBorder.DEFAULT_POSITION,
                        FontUtils.getFont(FontUtils.Size.standard),
                        java.awt.Color.black));

        parent.add(jsp, gbc);
    }

    private JTabbedPane getTabbedPane() {
        if (jTabbed == null) {
            jTabbed = new JTabbedPane();
            jTabbed.setPreferredSize(new java.awt.Dimension(800, 500));
        }
        return jTabbed;
    }

    /**
     * This method initializes jPanel
     *
     * @return javax.swing.JPanel
     */
    private JPanel getMainPanel() {
        if (jPanel == null) {

            // jPanel is the outside one
            jPanel = new JPanel();
            jPanel.setPreferredSize(new java.awt.Dimension(800, 600));
            jPanel.setLayout(new GridBagLayout());

            final GridBagConstraints gbcScrollPanel = new GridBagConstraints();
            gbcScrollPanel.gridx = 0;
            gbcScrollPanel.gridy = 1;
            gbcScrollPanel.insets = new java.awt.Insets(1, 1, 1, 1);
            gbcScrollPanel.anchor = GridBagConstraints.NORTHWEST;
            gbcScrollPanel.fill = GridBagConstraints.BOTH;
            gbcScrollPanel.weightx = 1.0D;
            gbcScrollPanel.weighty = 0.25D;

            final GridBagConstraints gbcTabPanel = new GridBagConstraints();
            gbcTabPanel.gridx = 0;
            gbcTabPanel.gridy = 3;
            gbcTabPanel.insets = new java.awt.Insets(1, 1, 1, 1);
            gbcTabPanel.anchor = GridBagConstraints.NORTHWEST;
            gbcTabPanel.fill = GridBagConstraints.BOTH;
            gbcTabPanel.weightx = 1.0D;
            gbcTabPanel.weighty = 1.0D;

            final JScrollPane scrollPanelWithInputField = new JScrollPane();
            scrollPanelWithInputField.setViewportView(getInputField());
            scrollPanelWithInputField.setHorizontalScrollBarPolicy(
                    ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
            scrollPanelWithInputField.setBorder(
                    BorderFactory.createTitledBorder(
                            null,
                            Constant.messages.getString("advancedencoder.dialog.field.input.label"),
                            TitledBorder.DEFAULT_JUSTIFICATION,
                            TitledBorder.DEFAULT_POSITION,
                            FontUtils.getFont(FontUtils.Size.standard),
                            java.awt.Color.black));

            final GridBagConstraints gbcToolbar = new GridBagConstraints();
            gbcToolbar.gridx = 0;
            gbcToolbar.gridy = 2;
            gbcToolbar.insets = new java.awt.Insets(1, 1, 1, 1);
            gbcToolbar.anchor = GridBagConstraints.NORTHWEST;
            gbcToolbar.fill = GridBagConstraints.BOTH;

            jPanel.add(scrollPanelWithInputField, gbcScrollPanel);
            jPanel.add(getPanelToolbar(), gbcToolbar);
            jPanel.add(getTabbedPane(), gbcTabPanel);
        }
        return jPanel;
    }

    private ZapTextArea newField(boolean editable) {
        final ZapTextArea field = new ZapTextArea();
        field.setLineWrap(true);
        field.setBorder(BorderFactory.createEtchedBorder());
        field.setEditable(editable);
        field.setName(ENCODE_DECODE_RESULTFIELD);

        field.addMouseListener(
                new java.awt.event.MouseAdapter() {
                    @Override
                    public void mousePressed(java.awt.event.MouseEvent e) {
                        if (SwingUtilities.isRightMouseButton(e)) {
                            View.getSingleton()
                                    .getPopupMenu()
                                    .show(e.getComponent(), e.getX(), e.getY());
                        }
                    }
                });

        return field;
    }

    private ZapTextArea getInputField() {
        if (inputField == null) {
            inputField = newField(true);
            inputField.setName(ENCODE_DECODE_FIELD);

            inputField
                    .getDocument()
                    .addDocumentListener(
                            new DocumentListener() {
                                @Override
                                public void insertUpdate(DocumentEvent documentEvent) {
                                    updateEncodeDecodeFields();
                                }

                                @Override
                                public void removeUpdate(DocumentEvent documentEvent) {
                                    updateEncodeDecodeFields();
                                }

                                @Override
                                public void changedUpdate(DocumentEvent documentEvent) {}
                            });

            inputField.addMouseListener(
                    new java.awt.event.MouseAdapter() {
                        @Override
                        public void mousePressed(java.awt.event.MouseEvent e) {
                            if (SwingUtilities.isRightMouseButton(e)) {
                                View.getSingleton()
                                        .getPopupMenu()
                                        .show(e.getComponent(), e.getX(), e.getY());
                            }
                        }
                    });
        }
        return inputField;
    }

    public void setInputField(String text) {
        this.getInputField().setText(text);
        this.updateEncodeDecodeFields();
    }

    private ZapTextArea findZapTextArea(OutputPanelPosition position) {
        Component currentTab = getTabbedPane().getComponentAt(position.getTabIndex());
        if (currentTab instanceof JPanel) {
            JPanel tabPanel = (JPanel) currentTab;
            Component component = tabPanel.getComponent(position.getOutputPanelIndex());
            if (component instanceof JScrollPane) {
                JScrollPane scrollPane = (JScrollPane) component;
                Component view = scrollPane.getViewport().getView();
                if (view instanceof ZapTextArea) {
                    return (ZapTextArea) view;
                }
            }
        }
        return null;
    }

    private void updateEncodeDecodeFields() {
        for (TabModel tab : tabs) {
            for (OutputPanelModel outputPanel : tab.getOutputPanels()) {
                ZapTextArea zapTextArea =
                        findZapTextArea(
                                new OutputPanelPosition(getIndex(tab), getIndex(tab, outputPanel)));
                if (zapTextArea != null) {
                    updateEncodeDecodeField(zapTextArea, outputPanel);
                }
            }
        }
    }

    private boolean updateEncodeDecodeField(ZapTextArea zapTextArea, OutputPanelModel outputPanel) {
        EncodeDecodeResult result;
        try {
            result =
                    encodeDecodeProcessors.process(
                            outputPanel.getProcessorId(), getInputField().getText());
        } catch (Exception e) {
            zapTextArea.setText(e.getMessage());
            zapTextArea.setBorder(BorderFactory.createLineBorder(Color.RED));
            zapTextArea.setEnabled(false);
            return false;
        }

        if (result == null) {
            zapTextArea.setText(
                    Constant.messages.getString("advancedencoder.dialog.encodedecode.notfound"));
            zapTextArea.setBorder(BorderFactory.createLineBorder(Color.RED));
            zapTextArea.setEnabled(false);
            return false;
        }

        if (result.hasError()) {
            zapTextArea.setText(result.getResult());
            zapTextArea.setBorder(BorderFactory.createEmptyBorder());
            zapTextArea.setEnabled(false);
            return false;
        }

        zapTextArea.setText(result.getResult());
        zapTextArea.setBorder(BorderFactory.createEmptyBorder());
        zapTextArea.setEnabled(true);
        return true;
    }

    private void saveSetting() {
        try {
            AdvancedEncoderConfig.saveConfig(tabs);
        } catch (Exception e) {
            LOGGER.error("Can not store Advanced Encoder Config", e);
        }
    }

    @Override
    public void windowOpened(WindowEvent e) {}

    @Override
    public void windowClosing(WindowEvent e) {
        saveSetting();
    }

    @Override
    public void windowClosed(WindowEvent e) {
        saveSetting();
    }

    @Override
    public void windowIconified(WindowEvent e) {
        saveSetting();
    }

    @Override
    public void windowDeiconified(WindowEvent e) {}

    @Override
    public void windowActivated(WindowEvent e) {}

    @Override
    public void windowDeactivated(WindowEvent e) {}

    private static class OutputPanelPosition {
        private int tabIndex;
        private int outputPanelIndex;

        public OutputPanelPosition(int tabIndex, int outputPanelIndex) {
            this.tabIndex = tabIndex;
            this.outputPanelIndex = outputPanelIndex;
        }

        public int getTabIndex() {
            return tabIndex;
        }

        public int getOutputPanelIndex() {
            return outputPanelIndex;
        }
    }
}
