/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.addon.requester;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.EventQueue;
import java.awt.GridLayout;
import java.awt.HeadlessException;
import java.awt.event.KeyEvent;
import java.io.IOException;
import javax.net.ssl.SSLException;
import javax.swing.JButton;
import javax.swing.JPanel;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.option.OptionsParamView;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.HttpPanelRequest;
import org.zaproxy.zap.extension.httppanel.InvalidMessageDataException;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.view.HttpPanelManager;

/** Send custom crafted messages via HTTP or other TCP based protocols. */
public abstract class MessageEditorPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = LogManager.getLogger(MessageEditorPanel.class);

    private boolean isSendEnabled = true;

    protected String configurationKey;

    private JPanel panelWindow = null;

    private JButton btnSend = null;

    private boolean sending = false;

    /**
     * Non-abstract classes should call {@link #initialize()} in their constructor.
     *
     * @param isSendEnabled
     * @param configurationKey
     * @throws HeadlessException
     */
    protected MessageEditorPanel(boolean isSendEnabled, String configurationKey)
            throws HeadlessException {
        super();

        this.isSendEnabled = isSendEnabled;
        this.configurationKey = OptionsParamView.BASE_VIEW_KEY + "." + configurationKey + ".";
    }

    protected void initialize() {

        setLayout(new GridLayout(1, 1));

        add(getWindowPanel());
    }

    protected JPanel getWindowPanel() {
        if (panelWindow == null) {
            panelWindow = new JPanel();
            panelWindow.setLayout(new BorderLayout());

            panelWindow.add(getManualSendPanel());
        }

        return panelWindow;
    }

    protected abstract Component getManualSendPanel();

    public abstract void setDefaultMessage();

    public abstract void setMessage(Message aMessage);

    public abstract Message getMessage();

    /**
     * Unloads the panel by {@link #reset() reseting} it and removing the message panel from the
     * {@link HttpPanelManager}.
     */
    public void unload() {
        reset();

        HttpPanelManager.getInstance().removeRequestPanel(getMessagePanel());
    }

    /**
     * Resets the panel.
     *
     * <p>Clears the view of the message panel and {@link #setDefaultMessage() sets the default
     * message}.
     */
    public void reset() {
        getMessagePanel().clearView();
        setDefaultMessage();
    }

    protected void sendButtonTriggered() {
        if (sending) {
            // Can also be triggered by other buttons, eg in the Http Response tab
            return;
        }
        sending = true;
        try {
            btnSend.setEnabled(false);

            try {
                getMessagePanel().saveData();
            } catch (InvalidMessageDataException e1) {
                StringBuilder warnMessage = new StringBuilder(150);
                warnMessage.append(Constant.messages.getString("requester.warn.datainvalid"));
                String exceptionMessage = e1.getLocalizedMessage();
                if (exceptionMessage != null && !exceptionMessage.isEmpty()) {
                    warnMessage.append('\n').append(exceptionMessage);
                }
                View.getSingleton().showWarningDialog(this, warnMessage.toString());
                btnSend.setEnabled(true);
                return;
            }

            Mode mode = Control.getSingleton().getMode();
            if (mode.equals(Mode.safe)) {
                // Can happen if the user turns on safe mode with the dialog open
                View.getSingleton()
                        .showWarningDialog(
                                this, Constant.messages.getString("requester.warn.safemode"));
                btnSend.setEnabled(true);
                return;
            } else if (mode.equals(Mode.protect) && !getMessage().isInScope()) {
                // In protected mode and not in scope, so fail
                View.getSingleton()
                        .showWarningDialog(
                                this, Constant.messages.getString("requester.warn.outofscope"));
                btnSend.setEnabled(true);
                return;
            }

            btnSendAction();

        } finally {
            sending = false;
        }
    }

    protected JButton getBtnSend() {
        if (btnSend == null) {
            btnSend = new JButton();
            btnSend.setText(Constant.messages.getString("requester.button.send"));
            btnSend.setEnabled(isSendEnabled);
            btnSend.setMnemonic(KeyEvent.VK_ENTER);
            btnSend.setToolTipText(getBtnSendTooltip());
            btnSend.addActionListener(e -> sendButtonTriggered());
        }
        return btnSend;
    }

    protected static String getBtnSendTooltip() {
        return Constant.isMacOsX()
                ? Constant.messages.getString("requester.button.send.tooltip.mac")
                : Constant.messages.getString("requester.button.send.tooltip");
    }

    /** Do not forget to enable the send button again i */
    protected abstract void btnSendAction();

    protected abstract void sendMessage(Message message) throws IOException;

    protected void send(final Message aMessage) {
        final Thread t =
                new Thread(
                        () -> {
                            try {
                                sendMessage(aMessage);
                                postSend();
                            } catch (SSLException sslEx) {
                                StringBuilder strBuilder = new StringBuilder();

                                strBuilder.append(
                                        Constant.messages.getString(
                                                "network.httpsender.ssl.error.connect"));
                                strBuilder
                                        .append(
                                                ((HttpMessage) aMessage)
                                                        .getRequestHeader()
                                                        .getURI()
                                                        .toString())
                                        .append('\n');
                                strBuilder
                                        .append(
                                                Constant.messages.getString(
                                                        "network.httpsender.ssl.error.exception"))
                                        .append(sslEx.getMessage())
                                        .append('\n');
                                strBuilder
                                        .append(
                                                Constant.messages.getString(
                                                        "network.httpsender.ssl.error.exception.rootcause"))
                                        .append(ExceptionUtils.getRootCauseMessage(sslEx))
                                        .append('\n');
                                strBuilder.append(
                                        Constant.messages.getString(
                                                "network.httpsender.ssl.error.help",
                                                Constant.messages.getString(
                                                        "network.httpsender.ssl.error.help.url")));
                                LOGGER.debug(sslEx, sslEx);
                                View.getSingleton().showWarningDialog(this, strBuilder.toString());
                            } catch (Exception e) {
                                LOGGER.debug(e.getMessage(), e);
                                View.getSingleton().showWarningDialog(this, e.getMessage());
                            } finally {
                                btnSend.setEnabled(true);
                            }
                        });
        t.setPriority(Thread.NORM_PRIORITY);
        t.start();
    }

    protected void postSend() {
        EventQueue.invokeLater(getMessagePanel()::updateContent);
    }

    /** Saves the configuration of the panel. */
    public abstract void saveConfig();

    /**
     * Gets the panel that shows the message.
     *
     * @return the message panel.
     */
    protected abstract HttpPanelRequest getMessagePanel();
}
