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
package org.zaproxy.zap.extension.websocket.manualsend;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.io.IOException;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JToolBar;
import javax.swing.SwingWorker;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.manualrequest.ManualRequestEditorDialog;
import org.parosproxy.paros.extension.manualrequest.MessageSender;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.HttpPanel;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.client.RequestOutOfScopeException;
import org.zaproxy.zap.extension.websocket.ui.ChannelSortedListModel;
import org.zaproxy.zap.extension.websocket.ui.WebSocketUiHelper;
import org.zaproxy.zap.view.ZapMenuItem;

/** Send custom crafted WebSocket messages. */
@SuppressWarnings("serial")
public class ManualWebSocketSendEditorDialog extends ManualRequestEditorDialog {

    private static final long serialVersionUID = -5830450800029295419L;

    private ZapMenuItem menuItem;

    private WebSocketPanelSender sender;

    private WebSocketSendPanel requestPanel;
    private WebSocketMessagePanel wsMessagePanel;
    private ChannelSortedListModel channelsModel;

    private JToolBar controlToolbar;

    static final ImageIcon REOPEN_ICON;
    static final ImageIcon REOPEN_EDIT_ICON;
    static final ImageIcon WEBSOCKET_CONNECTING_ICON;

    static {
        REOPEN_ICON =
                new ImageIcon(
                        ManualWebSocketSendEditorDialog.class.getResource(
                                "/org/zaproxy/zap/extension/websocket/resources/icons/plug--plus.png"));
        REOPEN_EDIT_ICON =
                new ImageIcon(
                        ManualWebSocketSendEditorDialog.class.getResource(
                                "/org/zaproxy/zap/extension/websocket/resources/icons/plug--pencil.png"));
        WEBSOCKET_CONNECTING_ICON =
                new ImageIcon(
                        ManualWebSocketSendEditorDialog.class.getResource(
                                "/org/zaproxy/zap/extension/websocket/resources/icons/websocket_connecting.gif"));
    }

    public ManualWebSocketSendEditorDialog(
            ChannelSortedListModel channelsModel,
            WebSocketPanelSender sender,
            boolean isSendEnabled,
            String configurationKey)
            throws HeadlessException {
        super(isSendEnabled, configurationKey);

        this.channelsModel = channelsModel;
        this.sender = sender;

        initialize();
    }

    @Override
    protected void initialize() {
        super.initialize();

        getWindowPanel().add(getControlToolbar(), BorderLayout.NORTH);
    }

    private JToolBar getControlToolbar() {
        if (controlToolbar == null) {
            controlToolbar = new JToolBar();
            controlToolbar.setMargin(new Insets(5, 7, 5, 5));
            controlToolbar.setEnabled(true);
            controlToolbar.setFloatable(false);
            controlToolbar.setRollover(true);
            controlToolbar.setName("control_toolbar_top");
        }
        return controlToolbar;
    }

    @Override
    public Class<? extends Message> getMessageType() {
        return WebSocketMessageDTO.class;
    }

    @Override
    public Message getMessage() {
        WebSocketMessageDTO message = (WebSocketMessageDTO) getRequestPanel().getMessage();

        // set metadata first (opcode, channel, direction)
        wsMessagePanel.setMetadata(message);

        return message;
    }

    @Override
    public void setMessage(Message aMessage) {
        WebSocketMessageDTO message = (WebSocketMessageDTO) aMessage;
        if (message == null) {
            return;
        }

        getRequestPanel().setMessage(message);
        wsMessagePanel.setMessageMetadata(message);
    }

    @Override
    protected MessageSender getMessageSender() {
        return sender;
    }

    @Override
    protected WebSocketSendPanel getRequestPanel() {
        if (requestPanel == null) {
            requestPanel = new WebSocketSendPanel(true, configurationKey);
            requestPanel.setEnableViewSelect(true);
            requestPanel.loadConfig(Model.getSingleton().getOptionsParam().getConfig());
        }
        return requestPanel;
    }

    @Override
    protected Component getManualSendPanel() {
        if (wsMessagePanel == null) {
            wsMessagePanel =
                    new WebSocketMessagePanel(
                            channelsModel, getControlToolbar(), getRequestPanel(), sender);

            wsMessagePanel.addEndButton(getBtnSend());
            wsMessagePanel.addSeparator();

            wsMessagePanel.loadConfig();
        }
        return wsMessagePanel;
    }

    @Override
    protected void btnSendAction() {
        Message message = getMessage();
        send(message);
    }

    @Override
    protected void saveConfig() {
        wsMessagePanel.saveConfig();
    }

    @Override
    public ZapMenuItem getMenuItem() {
        if (menuItem == null) {
            menuItem = new ZapMenuItem("websocket.manual_send.menu");
            menuItem.addActionListener(
                    e -> {
                        Message message = getMessage();
                        if (message == null) {
                            setDefaultMessage();
                        } else if (message instanceof WebSocketMessageDTO
                                && ((WebSocketMessageDTO) message).getOpcode() == null) {
                            setDefaultMessage();
                        }
                        setVisible(true);
                    });
        }
        return menuItem;
    }

    @Override
    public void setDefaultMessage() {
        WebSocketMessageDTO msg = new WebSocketMessageDTO();
        msg.setOutgoing(true);
        msg.setOpcode(WebSocketMessage.OPCODE_TEXT);
        msg.setReadableOpcode(WebSocketMessage.opcode2string(msg.getOpcode()));

        setMessage(msg);
    }

    public void unload() {
        getRequestPanel().unload();
    }

    private static final class WebSocketMessagePanel extends JPanel {

        private static final long serialVersionUID = -3335708932021769432L;

        private static final Logger LOGGER =
                LogManager.getLogger(ManualWebSocketSendEditorDialog.class);

        private final HttpPanel messagePanel;

        private JButton btnReopen;
        private JButton btnReopenEdit;
        private JPanel reopenPanel;
        private JLabel connectingLabel;

        private WebSocketUiHelper wsUiHelper;
        private WebSocketPanelSender sender;

        public WebSocketMessagePanel(
                ChannelSortedListModel channelsModel,
                JToolBar controlToolbar,
                HttpPanel messagePanel,
                WebSocketPanelSender sender)
                throws IllegalArgumentException {
            super(new BorderLayout());
            if (messagePanel == null) {
                throw new IllegalArgumentException("The request panel cannot be null.");
            }

            // Could also add Input Field for new WebSocket channel with possibility
            // to set Origin header to some custom value

            this.messagePanel = messagePanel;
            this.sender = sender;

            wsUiHelper = new WebSocketUiHelper();
            wsUiHelper.setChannelsModel(channelsModel);

            setControlToolbar(controlToolbar);
        }

        private void setControlToolbar(JToolBar controlToolbar) {

            controlToolbar.add(wsUiHelper.getChannelLabel());
            controlToolbar.add(wsUiHelper.getChannelSingleSelect());
            wsUiHelper.getChannelSingleSelect().setSelectedIndex(0);

            if (sender != null) {
                controlToolbar.add(getBtnReopen());
                controlToolbar.add(getBtnReopenEdit(sender));
                wsUiHelper.disableButtonsWhenComboBoxSelectedNull(
                        getBtnReopen(), getBtnReopenEdit(sender));
            }

            controlToolbar.addSeparator(new Dimension(15, 21));

            controlToolbar.add(wsUiHelper.getOpcodeLabel());
            controlToolbar.add(wsUiHelper.getOpcodeSingleSelect());
            wsUiHelper
                    .getOpcodeSingleSelect()
                    .setSelectedItem(
                            WebSocketMessage.opcode2string(
                                    WebSocketMessage.OPCODE_TEXT)); // set TEXT per default

            controlToolbar.addSeparator(new Dimension(15, 21));

            controlToolbar.add(wsUiHelper.getDirectionLabel());
            controlToolbar.add(wsUiHelper.getDirectionSingleSelect());

            controlToolbar.addSeparator(new Dimension(15, 21));
            connectingLabel = wsUiHelper.getConnectingLabel(WEBSOCKET_CONNECTING_ICON);
            connectingLabel.setVisible(false);
            controlToolbar.add(connectingLabel);
        }

        public void setMessageMetadata(WebSocketMessageDTO message) {
            if (message.getChannel() != null && message.getChannel().getId() != null) {
                wsUiHelper.getChannelSingleSelect().setSelectedItem(message.getChannel());
            }

            if (message.getOpcode() != null) {
                wsUiHelper.getOpcodeSingleSelect().setSelectedItem(message.getReadableOpcode());
            }

            if (message.isOutgoing() != null) {
                wsUiHelper.setDirectionSingleSelect(message.isOutgoing());
            }
        }

        public void setMetadata(WebSocketMessageDTO msg) {
            msg.setChannel(wsUiHelper.getSelectedChannelDTO());
            msg.setOutgoing(wsUiHelper.isDirectionSingleSelectOutgoing());
            msg.setOpcode(wsUiHelper.getSelectedOpcodeInteger());
        }

        public void loadConfig() {
            messagePanel.loadConfig(Model.getSingleton().getOptionsParam().getConfig());
            add(messagePanel);
        }

        public void saveConfig() {
            messagePanel.saveConfig(Model.getSingleton().getOptionsParam().getConfig());
        }

        public void addSeparator() {
            messagePanel.addOptionsSeparator();
        }

        public void addEndButton(JButton button) {
            messagePanel.addOptions(button, HttpPanel.OptionsLocation.END);
        }

        private JButton getBtnReopen() {
            if (btnReopen == null) {
                btnReopen = new JButton();
                btnReopen.setIcon(REOPEN_ICON);
                btnReopen.setEnabled(true);
                btnReopen.setToolTipText(
                        Constant.messages.getString("websocket.manual_send.btn_reopen_hint"));
                btnReopen.addActionListener(
                        (ActionEvent e) -> {
                            isOnConnectingProgress(true);
                            String newSecWebSocketKey = null;

                            if (!wsUiHelper.isAlwaysGenerate()) {
                                newSecWebSocketKey = wsUiHelper.getWebSocketKey();
                            }

                            ReEstablishConnection reEstablishConnection =
                                    new ReEstablishConnection(newSecWebSocketKey);

                            reEstablishConnection.addPropertyChangeListener(
                                    propertyChangeEvent -> {
                                        if ((propertyChangeEvent.getNewValue()
                                                == SwingWorker.StateValue.DONE)) {
                                            isOnConnectingProgress(false);
                                            int channelId;
                                            try {
                                                channelId = reEstablishConnection.get();
                                                if (channelId < 0) {
                                                    if (channelId
                                                            == ReEstablishConnection
                                                                    .RETRIVING_HANDSHAKE_ERROR) {
                                                        // TODO: This message should be replaced
                                                        // when we are able to open websocket
                                                        // connection.
                                                        View.getSingleton()
                                                                .showWarningDialog(
                                                                        Constant.messages.getString(
                                                                                "websocket.manual_send.fail.retrieve"));
                                                    } else if (channelId
                                                            == ReEstablishConnection
                                                                    .REQUEST_OUT_OF_SCOPE) {
                                                        View.getSingleton()
                                                                .showWarningDialog(
                                                                        Constant.messages.getString(
                                                                                "websocket.manual_send.fail.out_of_scope"));
                                                    } else if (channelId
                                                            == ReEstablishConnection.IOEXCEPTION) {
                                                        View.getSingleton()
                                                                .showWarningDialog(
                                                                        Constant.messages.getString(
                                                                                "websocket.manual_send.fail.unable_reopen"));
                                                    }
                                                } else {
                                                    wsUiHelper.setSelectedChannelId(channelId);
                                                    wsUiHelper.requestFocusChannelComboBox();
                                                }
                                            } catch (Exception ex) {
                                                LOGGER.error(
                                                        "An error occurred when trying to re-establish a websocket connection",
                                                        ex);
                                            }
                                        }
                                    });

                            reEstablishConnection.execute();
                        });
            }
            return btnReopen;
        }

        private JButton getBtnReopenEdit(WebSocketPanelSender sender) {
            if (btnReopenEdit == null) {
                btnReopenEdit = new JButton();
                btnReopenEdit.setIcon(REOPEN_EDIT_ICON);
                btnReopenEdit.setEnabled(true);
                btnReopenEdit.setToolTipText(
                        Constant.messages.getString("websocket.manual_send.btn_reopen_edit_hint"));
                btnReopenEdit.addActionListener(
                        e -> {
                            try {
                                wsUiHelper.setSecWebSocketKeyField(
                                        sender.getWebSocketKey(wsUiHelper.getSelectedChannelId()));
                                JOptionPane.showMessageDialog(
                                        this,
                                        getReopenPanel(),
                                        Constant.messages.getString(
                                                "websocket.manual_send.adv_dialog.title"),
                                        JOptionPane.PLAIN_MESSAGE);
                            } catch (IllegalArgumentException e1) {
                                View.getSingleton()
                                        .showWarningDialog(
                                                Constant.messages.getString(
                                                        "websocket.manual_send.fail.invalid_channel"));
                            } catch (Exception e1) {
                                LOGGER.error(e1, e1);
                                View.getSingleton()
                                        .showWarningDialog(
                                                Constant.messages.getString(
                                                        "websocket.manual_send.fail.unable_reopen"));
                            }
                        });
            }
            return btnReopenEdit;
        }

        private JPanel getReopenPanel() {
            if (reopenPanel == null) {
                reopenPanel = new JPanel();
                reopenPanel.setLayout(new GridBagLayout());
                int y = 0;

                reopenPanel.add(
                        wsUiHelper.getRedirectionCheckBox(),
                        wsUiHelper.getFieldConstraints(0, y++));
                reopenPanel.add(
                        wsUiHelper.getTrackingSessionCheckBox(),
                        wsUiHelper.getFieldConstraints(0, y++));

                reopenPanel.add(
                        wsUiHelper.createVerticalSeparator(),
                        wsUiHelper.getFieldConstraints(0, y++));
                reopenPanel.add(
                        wsUiHelper.getWebSocketKeyLabel(), wsUiHelper.getLabelConstraints(0, y++));
                reopenPanel.add(
                        wsUiHelper.getWebSocketKeyField(), wsUiHelper.getFieldConstraints(0, y++));
                reopenPanel.add(
                        wsUiHelper.getAlwaysGenerateCheckBox(),
                        wsUiHelper.getFieldConstraints(0, y++));
                reopenPanel.add(
                        wsUiHelper.getGenerateWebSocketKeyButton(),
                        wsUiHelper.getFieldConstraints(0, y++));
            }
            return reopenPanel;
        }

        private void isOnConnectingProgress(boolean isOnProgress) {
            btnReopen.setEnabled(!isOnProgress);
            btnReopenEdit.setEnabled(!isOnProgress);
            connectingLabel.setVisible(isOnProgress);
        }

        class ReEstablishConnection extends SwingWorker<Integer, Boolean> {
            private String newSecWebSocketKey;

            protected ReEstablishConnection(String newSecWebSocketKey) {
                this.newSecWebSocketKey = newSecWebSocketKey;
            }

            public static final int RETRIVING_HANDSHAKE_ERROR = -1;
            public static final int IOEXCEPTION = -2;
            public static final int REQUEST_OUT_OF_SCOPE = -3;

            @Override
            protected Integer doInBackground() {
                int channelId;
                try {
                    channelId =
                            sender.reOpenChannel(
                                    wsUiHelper.getSelectedChannelId(),
                                    newSecWebSocketKey,
                                    wsUiHelper.isRedirection(),
                                    wsUiHelper.isTrackingSession());
                } catch (IllegalStateException e) {
                    LOGGER.debug(
                            "An error occurred while trying to retrieve the HTTP handshake from history",
                            e);
                    channelId = RETRIVING_HANDSHAKE_ERROR;
                } catch (IOException e) {
                    LOGGER.debug("Unable to re-establish the WebSocket Connection", e);
                    channelId = IOEXCEPTION;
                } catch (RequestOutOfScopeException e) {
                    channelId = REQUEST_OUT_OF_SCOPE;
                }
                return channelId;
            }
        }
    }
}
