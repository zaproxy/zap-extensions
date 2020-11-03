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
package org.zaproxy.zap.extension.requester;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.EventQueue;
import java.awt.GridLayout;
import java.awt.HeadlessException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JPanel;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.option.OptionsParamView;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.HttpPanelRequest;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.tab.Tab;
import org.zaproxy.zap.view.ZapMenuItem;

/** Send custom crafted messages via HTTP or other TCP based protocols. */
public abstract class ManualRequestEditorPanel extends JPanel implements Tab {
    private static final long serialVersionUID = 1L;

    private static final Logger logger = Logger.getLogger(ManualRequestEditorPanel.class);

    private boolean isSendEnabled = true;

    protected String configurationKey;

    private JPanel panelWindow = null;

    private JButton btnSend = null;

    /**
     * Non-abstract classes should call {@link #initialize()} in their constructor.
     *
     * @param isSendEnabled
     * @param configurationKey
     * @throws HeadlessException
     */
    public ManualRequestEditorPanel(boolean isSendEnabled, String configurationKey)
            throws HeadlessException {
        super();

        this.isSendEnabled = isSendEnabled;
        this.configurationKey = OptionsParamView.BASE_VIEW_KEY + "." + configurationKey + ".";

        // this.setPreferredSize(new Dimension(700, 800));
    }

    protected void initialize() {

        setLayout(new GridLayout(1, 1));

        add(getWindowPanel());
    }

    /**
     * Returns type of message it handles.
     *
     * @return
     */
    public abstract Class<? extends Message> getMessageType();

    /**
     * Message sender for the given {@link #getMessageType()}.
     *
     * @return
     */
    protected abstract MessageSender getMessageSender();

    /**
     * Menu item that calls this editor.
     *
     * @return
     */
    public abstract ZapMenuItem getMenuItem();

    protected JPanel getWindowPanel() {
        if (panelWindow == null) {
            panelWindow = new JPanel();
            panelWindow.setLayout(new BorderLayout());

            panelWindow.add(getManualSendPanel());
        }

        return panelWindow;
    }

    protected abstract Component getManualSendPanel();

    @Override
    public void setVisible(boolean show) {
        if (!show && getMessageSender() != null) {
            getMessageSender().cleanup();
        }

        super.setVisible(show);
    }

    public abstract void setDefaultMessage();

    public abstract void setMessage(Message aMessage);

    public abstract Message getMessage();

    public void clear() {
        getRequestPanel().clearView();
    }

    protected JButton getBtnSend() {
        if (btnSend == null) {
            btnSend = new JButton();
            btnSend.setText(Constant.messages.getString("manReq.button.send"));
            btnSend.setEnabled(isSendEnabled);
            btnSend.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            btnSend.setEnabled(false);

                            try {
                                getRequestPanel().saveData();
                            } catch (Exception e1) {
                                StringBuilder warnMessage = new StringBuilder(150);
                                warnMessage.append(
                                        Constant.messages.getString("requester.warn.datainvalid"));
                                String exceptionMessage = e1.getLocalizedMessage();
                                if (exceptionMessage != null && !exceptionMessage.isEmpty()) {
                                    warnMessage.append('\n').append(exceptionMessage);
                                }
                                View.getSingleton().showWarningDialog(warnMessage.toString());
                                btnSend.setEnabled(true);
                                return;
                            }

                            Mode mode = Control.getSingleton().getMode();
                            if (mode.equals(Mode.safe)) {
                                // Can happen if the user turns on safe mode with the dialog open
                                View.getSingleton()
                                        .showWarningDialog(
                                                Constant.messages.getString("manReq.safe.warning"));
                                btnSend.setEnabled(true);
                                return;
                            } else if (mode.equals(Mode.protect)) {
                                if (!getMessage().isInScope()) {
                                    // In protected mode and not in scope, so fail
                                    View.getSingleton()
                                            .showWarningDialog(
                                                    Constant.messages.getString(
                                                            "manReq.outofscope.warning"));
                                    btnSend.setEnabled(true);
                                    return;
                                }
                            }

                            btnSendAction();
                        }
                    });
        }
        return btnSend;
    }

    /** Do not forget to enable the send button again i */
    protected abstract void btnSendAction();

    protected void send(final Message aMessage) {
        final Thread t =
                new Thread(
                        new Runnable() {
                            @Override
                            public void run() {
                                try {
                                    getMessageSender().handleSendMessage(aMessage);
                                    postSend();
                                } catch (Exception e) {
                                    logger.warn(e.getMessage(), e);
                                    View.getSingleton().showWarningDialog(e.getMessage());
                                } finally {
                                    btnSend.setEnabled(true);
                                }
                            }
                        });
        t.setPriority(Thread.NORM_PRIORITY);
        t.start();
    }

    protected void postSend() {
        EventQueue.invokeLater(
                new Runnable() {

                    @Override
                    public void run() {
                        // redraw, as message may have changed after sending
                        getRequestPanel().updateContent();
                    }
                });
    }

    protected abstract void saveConfig();

    protected abstract HttpPanelRequest getRequestPanel();
}
