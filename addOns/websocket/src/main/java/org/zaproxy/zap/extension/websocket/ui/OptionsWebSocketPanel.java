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

import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.utils.FontUtils;

/**
 * The GUI WebSocket options panel.
 *
 * <p>It allows to change the following WebSocket options:
 *
 * <ul>
 *   <li>Forward Only - allows to avoid storing WebSocket communication.
 *   <li>Break on All - react on breakpoints set for all requests/responses.
 *   <li>Break on Ping/Pong - react on Ping & Pong messages that arrive while stepping or waiting
 *       for all requests/responses.
 *   <li>Remove header {@code Sec-WebSocket-Extensions} - when enabled it allows to properly process
 *       the WebSocket messages, as no further (and unsupported) transformation is done to them (for
 *       example, compression).
 * </ul>
 */
@SuppressWarnings("serial")
public class OptionsWebSocketPanel extends AbstractParamPanel {

    private static final long serialVersionUID = -7541236934312940852L;

    /** Name of this panel. */
    private static final String NAME = Constant.messages.getString("websocket.panel.title");

    private static final String LABEL_FORWARD_ALL =
            Constant.messages.getString("websocket.options.forward_all");
    private static final String LABEL_BREAK_ON_PING_PONG =
            Constant.messages.getString("websocket.options.break_on_ping_pong");
    private static final String LABEL_BREAK_ON_ALL =
            Constant.messages.getString("websocket.options.break_on_all");
    private static final String LABEL_REMOVE_EXTENSIONS_HEADER =
            Constant.messages.getString("websocket.options.remove_extensions");
    private static final String TOOLTIP_REMOVE_EXTENSIONS_HEADER =
            Constant.messages.getString("websocket.options.remove_extensions.tooltip");

    /** Represents the model containing current values. Is able to save back to config file. */
    private OptionsParamWebSocket wsParams;

    private JCheckBox checkBoxForwardAll;
    private JCheckBox checkBoxBreakOnPingPong;
    private JCheckBox checkBoxBreakOnAll;
    private JCheckBox checkBoxRemoveExtensionsHeader;

    public OptionsWebSocketPanel(OptionsParamWebSocket wsParams) {
        super();

        this.wsParams = wsParams;

        setName(NAME);

        setLayout(new FlowLayout(FlowLayout.LEADING, 0, 0));

        add(getPanel());
    }

    private Component getPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(2, 2, 2, 2));
        panel.setFont(FontUtils.getFont(FontUtils.Size.standard));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 2, 2, 2);
        panel.add(getCheckBoxForwardAll(), gbc);

        gbc = new GridBagConstraints();
        gbc.gridy = 1;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 2, 2, 2);
        panel.add(getCheckBoxBreakOnAll(), gbc);

        gbc = new GridBagConstraints();
        gbc.gridy = 2;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 2, 2, 2);
        panel.add(getCheckBoxBreakOnPingPong(), gbc);

        gbc = new GridBagConstraints();
        gbc.gridy = 3;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 2, 2, 2);
        panel.add(getCheckcheckBoxRemoveExtensionsHeader(), gbc);

        return panel;
    }

    private JCheckBox getCheckBoxForwardAll() {
        if (checkBoxForwardAll == null) {
            checkBoxForwardAll = new JCheckBox(LABEL_FORWARD_ALL);
        }
        return checkBoxForwardAll;
    }

    private Component getCheckBoxBreakOnAll() {
        if (checkBoxBreakOnAll == null) {
            checkBoxBreakOnAll = new JCheckBox(LABEL_BREAK_ON_ALL);
        }
        return checkBoxBreakOnAll;
    }

    private JCheckBox getCheckBoxBreakOnPingPong() {
        if (checkBoxBreakOnPingPong == null) {
            checkBoxBreakOnPingPong = new JCheckBox(LABEL_BREAK_ON_PING_PONG);
        }
        return checkBoxBreakOnPingPong;
    }

    private JCheckBox getCheckcheckBoxRemoveExtensionsHeader() {
        if (checkBoxRemoveExtensionsHeader == null) {
            checkBoxRemoveExtensionsHeader = new JCheckBox(LABEL_REMOVE_EXTENSIONS_HEADER);
            checkBoxRemoveExtensionsHeader.setToolTipText(TOOLTIP_REMOVE_EXTENSIONS_HEADER);
        }
        return checkBoxRemoveExtensionsHeader;
    }

    @Override
    public void initParam(Object obj) {
        checkBoxForwardAll.setSelected(wsParams.isForwardAll());
        checkBoxBreakOnAll.setSelected(wsParams.isBreakOnAll());
        checkBoxBreakOnPingPong.setSelected(wsParams.isBreakOnPingPong());
        checkBoxRemoveExtensionsHeader.setSelected(wsParams.isRemoveExtensionsHeader());
    }

    @Override
    public void validateParam(Object obj) {
        // no validation needed for these check boxes
    }

    @Override
    public void saveParam(Object obj) {
        wsParams.setForwardAll(checkBoxForwardAll.isSelected());
        wsParams.setBreakOnAll(checkBoxBreakOnAll.isSelected());
        wsParams.setBreakOnPingPong(checkBoxBreakOnPingPong.isSelected());
        wsParams.setRemoveExtensionsHeader(checkBoxRemoveExtensionsHeader.isSelected());
    }

    @Override
    public String getHelpIndex() {
        return "websocket.options";
    }
}
