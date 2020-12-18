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
package org.zaproxy.addon.encoder;

import java.awt.Color;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
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
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractFrame;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.encoder.processors.EncodeDecodeProcessors;
import org.zaproxy.addon.encoder.processors.EncodeDecodeResult;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ZapTextArea;

public class EncodeDecodeDialog extends AbstractFrame implements OptionsChangedListener {

    public static final String ENCODE_DECODE_FIELD = "EncodeDecodeInputField";
    public static final String ENCODE_DECODE_RESULTFIELD = "EncodeDecodeResultField";
    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = Logger.getLogger(EncodeDecodeDialog.class);
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

    public EncodeDecodeDialog(List<TabModel> tabModels) {
        super();
        encodeDecodeProcessors = new EncodeDecodeProcessors();
        init();
        setTabs(tabModels);

        addWindowListener(
                new WindowAdapter() {

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
                });
    }

    public void setTabs(List<TabModel> tabModels) {
        getTabbedPane().removeAll();

        for (TabModel tabModel : tabModels) {
            List<OutputPanelModel> outputPanels = tabModel.getOutputPanels();
            tabModel.setOutputPanels(new ArrayList<>());
            addTab(tabModel, outputPanels);
        }

        updatePanelState();
        if (!tabs.isEmpty()) {
            getTabbedPane().setSelectedIndex(0);
        }
    }

    /**
     * Updates the state of the buttons and requests focus in the input field.
     *
     * <p>Should be called after adding or removing a tab.
     */
    private void updatePanelState() {
        boolean tabsPresent = !tabs.isEmpty();
        getDeleteSelectedTabButton().setEnabled(tabsPresent);
        getAddOutputButton().setEnabled(tabsPresent);

        getInputField().requestFocusInWindow();
    }

    private void resetTabs() {
        tabs = new ArrayList<>();

        List<TabModel> defaultTabModels = new ArrayList<>();
        try {
            defaultTabModels.addAll(EncoderConfig.loadDefaultConfig());
        } catch (ConfigurationException | IOException e) {
            LOGGER.warn("There was a problem loading the default encoder config.", e);
        }

        setTabs(defaultTabModels);

        try {
            EncoderConfig.saveConfig(tabs);
        } catch (ConfigurationException | IOException e) {
            LOGGER.warn("There was a problem saving the encoder config.", e);
        }
    }

    /** This method initializes this */
    private void init() {
        this.setAlwaysOnTop(false);
        this.setContentPane(getMainPanel());
        this.setTitle(Constant.messages.getString("encoder.dialog.title"));
    }

    private javax.swing.JToolBar getPanelToolbar() {
        if (panelToolbar == null) {

            panelToolbar = new javax.swing.JToolBar();
            panelToolbar.setLayout(new java.awt.GridBagLayout());
            panelToolbar.setEnabled(true);
            panelToolbar.setFloatable(false);
            panelToolbar.setRollover(true);
            panelToolbar.setPreferredSize(new java.awt.Dimension(800, 30));
            panelToolbar.setName("Encode Decode Toolbar");

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
                            ExtensionEncoder.class.getResource(
                                    "/org/zaproxy/addon/encoder/resources/ui-tab--delete.png")));
            deleteSelectedTabButton.setToolTipText(
                    Constant.messages.getString("encoder.dialog.deletetab"));
            DisplayUtils.scaleIcon(deleteSelectedTabButton);
        }
        return deleteSelectedTabButton;
    }

    private JButton getResetButton() {
        if (resetButton == null) {
            resetButton =
                    new JButton(Constant.messages.getString("encoder.dialog.reset.button.title"));
            resetButton.addActionListener(
                    e -> {
                        int confirm =
                                View.getSingleton()
                                        .showConfirmDialog(
                                                this,
                                                Constant.messages.getString(
                                                        "encoder.dialog.reset.confirm"));
                        if (confirm == JOptionPane.OK_OPTION) {
                            resetTabs();
                        }
                    });
            resetButton.setToolTipText(
                    Constant.messages.getString("encoder.dialog.reset.button.tooltip"));
        }
        return resetButton;
    }

    private void deleteSelectedTab() {
        int selectedIndex = getTabbedPane().getSelectedIndex();
        if (selectedIndex != -1) {
            getTabbedPane().remove(selectedIndex);
            tabs.remove(selectedIndex);
            updatePanelState();
        }
    }

    private JButton getAddTabButton() {
        if (addTabButton == null) {
            addTabButton = new JButton();
            addTabButton.addActionListener(e -> addTab());
            addTabButton.setIcon(
                    new ImageIcon(
                            ExtensionEncoder.class.getResource(
                                    "/org/zaproxy/addon/encoder/resources/ui-tab--plus.png")));
            addTabButton.setToolTipText(Constant.messages.getString("encoder.dialog.addtab"));
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
            updatePanelState();
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
        String name = addTabDialog.getTabName();
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
                            ExtensionEncoder.class.getResource(
                                    "/org/zaproxy/addon/encoder/resources/ui-output--plus.png")));
            addOutputButton.setToolTipText(Constant.messages.getString("encoder.dialog.addoutput"));
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
        String name = addOutputDialog.getOutputPanelName();
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
                        FontUtils.getFont(FontUtils.Size.standard)));

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
                            Constant.messages.getString("encoder.dialog.field.input.label"),
                            TitledBorder.DEFAULT_JUSTIFICATION,
                            TitledBorder.DEFAULT_POSITION,
                            FontUtils.getFont(FontUtils.Size.standard)));

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
                    Constant.messages.getString("encoder.dialog.encodedecode.notfound"));
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
            EncoderConfig.saveConfig(tabs);
        } catch (Exception e) {
            LOGGER.error("Can not store Encoder Config", e);
        }
    }

    @Override
    public void optionsChanged(OptionsParam optionsParam) {
        updateEncodeDecodeFields();
    }

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
