/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.ui;

import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.awt.event.ItemEvent;
import java.util.ArrayList;
import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.ListModel;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;
import org.zaproxy.zap.extension.websocket.WebSocketMessage.Direction;
import org.zaproxy.zap.extension.websocket.utility.WebSocketUtils;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapTextField;

public class WebSocketUiHelper {
    private static final String SELECT_ALL_OPCODES =
            Constant.messages.getString("websocket.dialog.opcodes.select_all");

    private JComboBox<String> opcodeComboBox;
    private JList<String> opcodeList;
    private JScrollPane opcodeListScrollPane;

    private JCheckBox regexCheckbox;
    private JCheckBox caseIgnoreCheckbox;
    private JCheckBox inverseCheckbox;
    private ZapTextField patternTextField;

    private JList<WebSocketChannelDTO> channels;
    private JScrollPane channelsScrollPane;

    private JComboBox<WebSocketChannelDTO> channelsComboBox;
    private ChannelSortedListModel channelsModel;

    private JCheckBox outgoingCheckbox;
    private JCheckBox incomingCheckbox;
    private JComboBox<String> directionComboBox;

    private JCheckBox redirectionCheckBox;
    private JCheckBox trackingSessionCheckBox;
    private JCheckBox alwaysGenerateCheckBox;
    private JButton generateWebSocketKeyButton;
    private JLabel connectingLabel;
    private ZapTextField webSocketKeyField;

    // ************************************************************************
    // ***** HELPER

    public int getDialogWidth() {
        return 400;
    }

    public GridBagConstraints getLabelConstraints(int x, int y) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new java.awt.Insets(0, 5, 0, 5);
        gbc.gridx = x;
        gbc.gridy = y;
        return gbc;
    }

    public GridBagConstraints getFieldConstraints(int x, int y) {
        GridBagConstraints gbc = getLabelConstraints(x, y);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = 2;
        gbc.weightx = 1;
        return gbc;
    }

    public GridBagConstraints getDescriptionConstraints(int x, int y) {
        GridBagConstraints gbc = getLabelConstraints(x, y);
        gbc.insets = new Insets(5, 5, 10, 5);
        gbc.gridwidth = 3;
        gbc.weightx = 1;
        return gbc;
    }

    // ************************************************************************
    // ***** OPCODE

    public JLabel getOpcodeLabel() {
        return new JLabel(Constant.messages.getString("websocket.dialog.opcode"));
    }

    public JComboBox<String> getOpcodeSingleSelect() {
        if (opcodeComboBox == null) {
            opcodeComboBox = new JComboBox<>(getOpcodeModel());
        }
        return opcodeComboBox;
    }

    /** @return Null if '--All Opcodes--' is selected */
    public String getSelectedOpcode() {
        if (getOpcodeSingleSelect().getSelectedIndex() == 0) {
            return null;
        }
        return (String) getOpcodeSingleSelect().getSelectedItem();
    }

    /** @return Null if '--All Opcodes--' is selected */
    public Integer getSelectedOpcodeInteger() {
        if (getOpcodeSingleSelect().getSelectedIndex() == 0) {
            return null;
        }

        String opcodeString = (String) getOpcodeSingleSelect().getSelectedItem();

        for (int opcode : WebSocketMessage.getOpcodes()) {
            if (WebSocketMessage.opcode2string(opcode).equals(opcodeString)) {
                return opcode;
            }
        }
        return null;
    }

    public JScrollPane getOpcodeMultipleSelect() {
        if (opcodeListScrollPane == null) {
            opcodeListScrollPane = new JScrollPane(getOpcodeList());
        }
        return opcodeListScrollPane;
    }

    private JList<String> getOpcodeList() {
        if (opcodeList == null) {
            int itemsCount = WebSocketMessage.getOpcodes().size() + 1;

            opcodeList = new JList<>(getOpcodeModel());
            opcodeList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            opcodeList.setSelectedIndex(0);
            opcodeList.setLayoutOrientation(JList.VERTICAL);
            opcodeList.setVisibleRowCount(itemsCount);
        }
        return opcodeList;
    }

    private String[] getOpcodeModel() {
        int i = 0;
        String[] opcodes = new String[WebSocketMessage.getOpcodes().size() + 1];

        // all opcodes
        opcodes[i++] = SELECT_ALL_OPCODES;

        // specific opcode
        for (int opcode : WebSocketMessage.getOpcodes()) {
            opcodes[i++] = WebSocketMessage.opcode2string(opcode);
        }

        return opcodes;
    }

    /** @return Null if '--All Opcodes--' is selected */
    public List<String> getSelectedOpcodes() {
        boolean isSelectAll = false;
        List<String> values = new ArrayList<>();

        for (String value : opcodeList.getSelectedValuesList()) {
            if (value.equals(SELECT_ALL_OPCODES)) {
                isSelectAll = true;
                break;
            }

            values.add(value);
        }

        if (isSelectAll) {
            return null;
        }

        return values;
    }

    /** @return Null if '--All Opcodes--' is selected */
    public List<Integer> getSelectedOpcodeIntegers() {
        List<String> opcodes = getSelectedOpcodes();
        if (opcodes == null) {
            return null;
        }

        List<Integer> values = new ArrayList<>();
        for (int opcode : WebSocketMessage.getOpcodes()) {
            if (opcodes.contains(WebSocketMessage.opcode2string(opcode))) {
                values.add(opcode);
            }
        }
        return values;
    }

    public void setSelectedOpcodes(List<String> opcodes) {
        JList<String> opcodesList = getOpcodeList();
        if (opcodes == null || opcodes.contains(SELECT_ALL_OPCODES)) {
            opcodesList.setSelectedIndex(0);
        } else {
            int j = 0;
            int[] selectedIndices = new int[opcodes.size()];
            ListModel<String> model = opcodesList.getModel();
            for (int i = 0; i < model.getSize(); i++) {
                String item = model.getElementAt(i);
                if (opcodes.contains(item)) {
                    selectedIndices[j++] = i;
                }
            }
            opcodesList.setSelectedIndices(selectedIndices);
        }
    }

    // ************************************************************************
    // ***** CHANNEL

    public void setChannelsModel(ChannelSortedListModel channelsModel) {
        this.channelsModel = channelsModel;
    }

    public JLabel getChannelLabel() {
        return new JLabel(Constant.messages.getString("websocket.dialog.channel"));
    }

    public JComboBox<WebSocketChannelDTO> getChannelSingleSelect() {
        if (channelsComboBox == null) {
            // dropdown can be wider than JComboBox
            channelsComboBox =
                    new WiderDropdownJComboBox<>(new ComboBoxChannelModel(channelsModel), true);
            channelsComboBox.setRenderer(new ComboBoxChannelRenderer());

            // fixes width of JComboBox
            channelsComboBox.setPrototypeDisplayValue(
                    new WebSocketChannelDTO("XXXXXXXXXXXXXXXXXX"));
        }
        return channelsComboBox;
    }

    public void disableButtonsWhenComboBoxSelectedNull(JButton btnReopen, JButton btnReopenEdit) {
        channelsComboBox.addItemListener(
                itemEvent -> {
                    if (itemEvent.getStateChange() == ItemEvent.SELECTED
                            && getSelectedChannelId() == null) {
                        btnReopen.setEnabled(false);
                        btnReopenEdit.setEnabled(false);
                    } else if (!btnReopen.isEnabled()) {
                        btnReopen.setEnabled(true);
                        btnReopenEdit.setEnabled(true);
                    }
                });
    }

    /** @return Null if '--All Channels--' is selected */
    public Integer getSelectedChannelId() {
        if (getChannelSingleSelect().getSelectedIndex() == 0) {
            return null;
        }
        WebSocketChannelDTO channel =
                (WebSocketChannelDTO) getChannelSingleSelect().getSelectedItem();
        return channel.getId();
    }

    public WebSocketChannelDTO getSelectedChannelDTO() {
        if (getChannelSingleSelect().getSelectedIndex() == 0) {
            return null;
        }
        WebSocketChannelDTO channel =
                (WebSocketChannelDTO) getChannelSingleSelect().getSelectedItem();
        return channel;
    }

    public void setSelectedChannelId(Integer channelId) {
        if (channelId != null) {
            for (int i = 0; i < channelsModel.getSize(); i++) {
                WebSocketChannelDTO channel = channelsModel.getElementAt(i);
                if (channelId.equals(channel.getId())) {
                    channelsComboBox.setSelectedItem(channel);
                    return;
                }
            }
        }

        // set default value, if channelId is not found or none provided
        getChannelSingleSelect().setSelectedIndex(0);
    }

    public JScrollPane getChannelMultipleSelect() {
        if (channelsScrollPane == null) {
            channelsScrollPane = new JScrollPane(getChannelsList());
        }
        return channelsScrollPane;
    }

    private JList<WebSocketChannelDTO> getChannelsList() {
        if (channels == null) {
            int itemsCount = 4;

            channels = new JList<>(channelsModel);
            channels.setCellRenderer(new ComboBoxChannelRenderer());
            channels.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            channels.setSelectedIndex(0);
            channels.setLayoutOrientation(JList.VERTICAL);
            channels.setVisibleRowCount(itemsCount);

            // fixes width of JList
            channels.setPrototypeCellValue(new WebSocketChannelDTO("XXXXXXXXXXXXXXXXXX"));
        }
        return channels;
    }

    /** @return Null if '--All Channels--' is selected. */
    public List<Integer> getSelectedChannelIds() {
        boolean isSelectAll = false;
        List<Integer> values = new ArrayList<>();

        for (WebSocketChannelDTO value : channels.getSelectedValuesList()) {
            Integer channelId = value.getId();
            if (channelId == null) {
                isSelectAll = true;
                break;
            }
            values.add(channelId);
        }

        if (isSelectAll) {
            return null;
        }

        return values;
    }

    public void setSelectedChannelIds(List<Integer> channelIds) {
        JList<WebSocketChannelDTO> channelsList = getChannelsList();
        if (channelIds == null || channelIds.contains(-1)) {
            channelsList.setSelectedIndex(0);
        } else {
            int[] selectedIndices = new int[channelIds.size()];
            ListModel<WebSocketChannelDTO> model = channelsList.getModel();
            for (int i = 0, j = 0; i < model.getSize(); i++) {
                WebSocketChannelDTO channel = model.getElementAt(i);
                if (channelIds.contains(channel.getId())) {
                    selectedIndices[j++] = i;
                }
            }
            channelsList.setSelectedIndices(selectedIndices);
        }
    }

    public void requestFocusChannelComboBox() {
        channelsComboBox.requestFocus();
    }

    // ************************************************************************
    // ***** DIRECTION

    public JLabel getDirectionLabel() {
        return new JLabel(Constant.messages.getString("websocket.dialog.direction"));
    }

    public JPanel getDirectionPanel() {
        if (outgoingCheckbox == null) {
            JPanel panel = new JPanel();
            panel.add(getOutgoingCheckbox());
            panel.add(getIncomingCheckbox());
        }
        return (JPanel) outgoingCheckbox.getParent();
    }

    public JCheckBox getIncomingCheckbox() {
        if (incomingCheckbox == null) {
            incomingCheckbox =
                    new JCheckBox(
                            Constant.messages.getString("websocket.dialog.direction_incoming"));
            incomingCheckbox.setSelected(true);
        }
        return incomingCheckbox;
    }

    public JCheckBox getOutgoingCheckbox() {
        if (outgoingCheckbox == null) {
            outgoingCheckbox =
                    new JCheckBox(
                            Constant.messages.getString("websocket.dialog.direction_outgoing"));
            outgoingCheckbox.setSelected(true);
        }
        return outgoingCheckbox;
    }

    public Direction getDirection() {
        if (getOutgoingCheckbox().isSelected() && getIncomingCheckbox().isSelected()) {
            return null;
        } else if (getOutgoingCheckbox().isSelected()) {
            return Direction.OUTGOING;
        } else if (getIncomingCheckbox().isSelected()) {
            return Direction.INCOMING;
        }
        return null;
    }

    public void setDirection(Direction direction) {
        if (direction == null) {
            getOutgoingCheckbox().setSelected(true);
            getIncomingCheckbox().setSelected(true);
        } else if (direction.equals(Direction.OUTGOING)) {
            getOutgoingCheckbox().setSelected(true);
            getIncomingCheckbox().setSelected(false);
        } else if (direction.equals(Direction.INCOMING)) {
            getOutgoingCheckbox().setSelected(false);
            getIncomingCheckbox().setSelected(true);
        }
    }

    public JComboBox<String> getDirectionSingleSelect() {
        if (directionComboBox == null) {
            directionComboBox = new JComboBox<>(getDirectionModel());
        }
        return directionComboBox;
    }

    private String[] getDirectionModel() {
        String[] directions =
                new String[] {
                    Constant.messages.getString("websocket.filter.label.direction_outgoing"),
                    Constant.messages.getString("websocket.filter.label.direction_incoming"),
                };

        return directions;
    }

    public Boolean isDirectionSingleSelectOutgoing() {
        if (getDirectionSingleSelect().getSelectedIndex() == 0) {
            return true;
        }
        return false;
    }

    public void setDirectionSingleSelect(Boolean isOutgoing) {
        int index = (isOutgoing == null || isOutgoing) ? 0 : 1;
        getDirectionSingleSelect().setSelectedIndex(index);
    }

    // ************************************************************************
    // ***** PATTERN

    public JLabel getPatternLabel() {
        return new JLabel(Constant.messages.getString("websocket.dialog.pattern"));
    }

    public ZapTextField getPatternTextField() {
        if (patternTextField == null) {
            patternTextField = new ZapTextField();
        }

        return patternTextField;
    }

    public String getPattern() {
        if (patternTextField.getText() == null || patternTextField.getText().equals("")) {
            return null;
        } else {
            return patternTextField.getText();
        }
    }

    public void setPattern(String pattern) {
        patternTextField.setText(pattern);
    }

    public void setInverseCheckbox(boolean inverse) {
        this.inverseCheckbox.setSelected(inverse);
    }

    public JCheckBox getInverseCheckbox() {
        if (inverseCheckbox == null) {
            inverseCheckbox =
                    new JCheckBox(
                            Constant.messages.getString("websocket.filter.label.regex.inverse"));
        }
        return inverseCheckbox;
    }

    public void setCaseIgnoreCheckbox(boolean caseIgnore) {
        this.caseIgnoreCheckbox.setSelected(caseIgnore);
    }

    public JCheckBox getCaseIgnoreCheckbox() {
        if (caseIgnoreCheckbox == null) {
            caseIgnoreCheckbox =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "websocket.filter.label.regex.ignore_case"));
            caseIgnoreCheckbox.setSelected(false);
        }
        return caseIgnoreCheckbox;
    }

    public void setRegexCheckbox(boolean regex) {
        this.regexCheckbox.setSelected(regex);
    }

    public JCheckBox getRegexCheckbox() {
        if (regexCheckbox == null) {
            regexCheckbox =
                    new JCheckBox(
                            Constant.messages.getString("websocket.filter.label.regex.regex"));
            regexCheckbox.setSelected(true);
        }
        return regexCheckbox;
    }

    // ************************** MANUAL SEND DIALOG ***************************

    public JLabel getConnectingLabel(ImageIcon icon) {
        if (connectingLabel == null) {
            connectingLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "websocket.manual_send.adv_dialog.connecting"));
            connectingLabel.setIcon(icon);
        }
        return connectingLabel;
    }

    public JCheckBox getRedirectionCheckBox() {
        if (redirectionCheckBox == null) {
            redirectionCheckBox =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "websocket.manual_send.adv_dialog.redirect"));
        }
        return redirectionCheckBox;
    }

    public boolean isRedirection() {
        if (redirectionCheckBox == null) {
            return false;
        }
        return redirectionCheckBox.isSelected();
    }

    public JCheckBox getTrackingSessionCheckBox() {
        if (trackingSessionCheckBox == null) {
            trackingSessionCheckBox =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "websocket.manual_send.adv_dialog.tracking_session"));
        }
        return trackingSessionCheckBox;
    }

    public boolean isTrackingSession() {
        if (trackingSessionCheckBox == null) {
            return false;
        }
        return trackingSessionCheckBox.isSelected();
    }

    public ZapTextField getWebSocketKeyField() {
        if (webSocketKeyField == null) {
            webSocketKeyField = new ZapTextField();
        }
        return webSocketKeyField;
    }

    public void setSecWebSocketKeyField(String secWebSocketKey) {
        if (webSocketKeyField == null) {
            webSocketKeyField = new ZapTextField();
        }
        webSocketKeyField.setText(secWebSocketKey);
    }

    public JLabel getWebSocketKeyLabel() {
        return new JLabel(
                Constant.messages.getString("websocket.manual_send.adv_dialog.websocket_key"));
    }

    public String getWebSocketKey() {
        if (webSocketKeyField.getText().isEmpty()) {
            return null;
        } else {
            return webSocketKeyField.getText();
        }
    }

    public JButton getGenerateWebSocketKeyButton() {
        if (generateWebSocketKeyButton == null) {
            generateWebSocketKeyButton = new JButton();
            generateWebSocketKeyButton.setText(
                    Constant.messages.getString("websocket.manual_send.adv_dialog.generate_key"));
            generateWebSocketKeyButton.addActionListener(
                    actionEvent ->
                            webSocketKeyField.setText(WebSocketUtils.generateSecWebSocketKey()));
        }
        return generateWebSocketKeyButton;
    }

    public JCheckBox getAlwaysGenerateCheckBox() {
        if (alwaysGenerateCheckBox == null) {
            alwaysGenerateCheckBox =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "websocket.manual_send.adv_dialog.always_gen"));
        }
        alwaysGenerateCheckBox.setSelected(true);
        return alwaysGenerateCheckBox;
    }

    public boolean isAlwaysGenerate() {
        if (alwaysGenerateCheckBox == null) {
            return true;
        }
        return alwaysGenerateCheckBox.isSelected();
    }

    public JComponent createVerticalSeparator() {
        JSeparator x = new JSeparator(SwingConstants.VERTICAL);
        x.setPreferredSize(DisplayUtils.getScaledDimension(20, 20));
        return x;
    }
}
