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
package org.zaproxy.zap.extension.plugnhack.manualsend;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.HeadlessException;
import java.awt.Insets;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JToolBar;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.manualrequest.ManualRequestEditorDialog;
import org.parosproxy.paros.extension.manualrequest.MessageSender;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.httppanel.HttpPanel;
import org.zaproxy.zap.extension.httppanel.HttpPanelRequest;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.plugnhack.ClientMessage;
import org.zaproxy.zap.view.ZapMenuItem;

/** Send custom crafted WebSocket messages. */
@SuppressWarnings("serial")
public class ManualClientMessageSendEditorDialog extends ManualRequestEditorDialog {

    private static final long serialVersionUID = -5830450800029295419L;

    private ClientMessagePanelSender sender;

    private HttpPanelRequest requestPanel;
    private ClientMessagePanel wsMessagePanel;

    private JToolBar controlToolbar;

    public ManualClientMessageSendEditorDialog(
            ClientMessagePanelSender sender, boolean isSendEnabled, String configurationKey)
            throws HeadlessException {
        super(isSendEnabled, configurationKey);
        this.sender = sender;
        this.setTitle(Constant.messages.getString("plugnhack.resend.dialog.title"));

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
        return ClientMessage.class;
    }

    @Override
    public Message getMessage() {
        ClientMessage message = (ClientMessage) getRequestPanel().getMessage();

        // set metadata first (opcode, channel, direction)
        wsMessagePanel.setMetadata(message);

        return message;
    }

    @Override
    public void setMessage(Message aMessage) {
        ClientMessage message = (ClientMessage) aMessage;
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
    protected HttpPanelRequest getRequestPanel() {
        if (requestPanel == null) {
            requestPanel = new ClientMessageSendPanel(true, configurationKey);
            requestPanel.setEnableViewSelect(true);
            requestPanel.loadConfig(Model.getSingleton().getOptionsParam().getConfig());
        }
        return requestPanel;
    }

    @Override
    protected Component getManualSendPanel() {
        if (wsMessagePanel == null) {
            wsMessagePanel = new ClientMessagePanel(getControlToolbar(), getRequestPanel());

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
        // Not supported
        return null;
        /*
        if (menuItem == null) {
        	menuItem = new JMenuItem();
        	menuItem.setText("TODO Not supported!"); // TODO Constant.messages.getString("plugnhack.resend.menu"));
        	menuItem.addActionListener(new ActionListener() {

        		@Override
        		public void actionPerformed(ActionEvent e) {
        			Message message = getMessage();
        			if (message != null) {
        				setVisible(true);
        		    }
        		}
        	});
        }
        return menuItem;
        */
    }

    @Override
    public void setDefaultMessage() {
        // DO nothing - can currently only resend messages
    }

    private static final class ClientMessagePanel extends JPanel {

        private static final long serialVersionUID = -3335708932021769432L;

        private final HttpPanel messagePanel;

        public ClientMessagePanel(JToolBar controlToolbar, HttpPanel messagePanel)
                throws IllegalArgumentException {
            super(new BorderLayout());
            if (messagePanel == null) {
                throw new IllegalArgumentException("The request panel cannot be null.");
            }
            this.messagePanel = messagePanel;
        }

        public void setMessageMetadata(ClientMessage message) {}

        public void setMetadata(ClientMessage msg) {}

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
    }
}
