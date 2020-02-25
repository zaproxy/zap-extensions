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
import java.sql.SQLException;
import java.util.regex.Pattern;
import javax.swing.JTable;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.view.ContextIncludePanel;
import org.zaproxy.zap.view.popup.ExtensionPopupMenuComponent;

public class PopupIncludeWebSocketInContextMenu extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = -2345060529128495874L;

    private static final Logger logger = Logger.getLogger(PopupIncludeWebSocketInContextMenu.class);

    private WebSocketPopupHelper wsPopupHelper;
    private Context context;

    public PopupIncludeWebSocketInContextMenu(Context context) {
        super(context.getName());
        this.context = context;

        initialize();
    }

    public PopupIncludeWebSocketInContextMenu() {
        super(Constant.messages.getString("context.new.title"));
        this.context = null;
        this.setPrecedeWithSeparator(true);

        initialize();
    }

    @Override
    public String getParentMenuName() {
        return PopupIncludeWebSocketContextMenu.MENU_NAME;
    }

    @Override
    public boolean isSubMenu() {
        return true;
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    private void initialize() {
        addActionListener(
                new java.awt.event.ActionListener() {
                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        try {
                            performAction();
                        } catch (Exception e) {
                            logger.error(e.getMessage(), e);
                        }
                    }
                });
    }

    protected void performAction() throws SQLException {
        WebSocketMessageDTO message = wsPopupHelper.getSelectedMessage();
        if (message != null) {
            String url = Pattern.quote(message.channel.getContextUrl());

            Session session = Model.getSingleton().getSession();
            if (context == null) {
                context = session.getNewContext(message.channel.host);
            }
            View.getSingleton().getSessionDialog().recreateUISharedContexts(session);

            Context uiSharedContext =
                    View.getSingleton().getSessionDialog().getUISharedContext(context.getIndex());
            uiSharedContext.addIncludeInContextRegex(url);

            View.getSingleton()
                    .showSessionDialog(
                            session, ContextIncludePanel.getPanelName(context.getIndex()), false);
        }
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        String invokerName = invoker.getName();
        if (invokerName != null && invokerName.equals(WebSocketMessagesView.PANEL_NAME)) {
            wsPopupHelper = new WebSocketPopupHelper((JTable) invoker);
            WebSocketMessageDTO message = wsPopupHelper.getSelectedMessage();

            if (message != null) {
                setEnabled(isEnabledForUrl(message.channel.getContextUrl()));
            } else {
                setEnabled(false);
            }

            return true;
        }
        return false;
    }

    private boolean isEnabledForUrl(String url) {
        if (context == null) {
            // New context
            return true;
        }
        if (context.isIncluded(url) || context.isExcluded(url)) {
            // Either explicitly included or excluded, so would have to change that regex in a non
            // trivial way to include!
            return false;
        }
        return true;
    }

    @Override
    public void dismissed(ExtensionPopupMenuComponent selectedMenuComponent) {
        View.getSingleton().getPopupList().remove(this);
    }
}
