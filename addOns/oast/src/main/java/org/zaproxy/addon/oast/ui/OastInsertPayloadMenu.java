/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.oast.ui;

import java.awt.Component;
import java.util.Map;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import javax.swing.text.JTextComponent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.addon.oast.OastService;
import org.zaproxy.zap.extension.ExtensionPopupMenu;

@SuppressWarnings("serial")
public class OastInsertPayloadMenu extends ExtensionPopupMenu {
    private static final long serialVersionUID = 2L;
    private static final Logger LOGGER = LogManager.getLogger(OastInsertPayloadMenu.class);
    private JTextComponent lastInvoker;

    public OastInsertPayloadMenu(ExtensionOast extension) {
        setText(Constant.messages.getString("oast.popup.menu.insertPayload"));
        for (Map.Entry<String, OastService> serviceEntry : extension.getOastServices().entrySet()) {
            String name = serviceEntry.getKey();
            OastService service = serviceEntry.getValue();
            JMenuItem menuItem = new JMenuItem(name);
            add(menuItem);
            menuItem.addActionListener(
                    e -> {
                        try {
                            lastInvoker.replaceSelection(service.getNewPayload());
                        } catch (Exception exception) {
                            LOGGER.warn(exception.getMessage(), exception);
                            View.getSingleton()
                                    .showWarningDialog(
                                            SwingUtilities.getWindowAncestor(lastInvoker),
                                            Constant.messages.getString(
                                                    "oast.popup.menu.warning",
                                                    exception.getLocalizedMessage()));
                        }
                    });
        }
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (invoker instanceof JTextComponent) {
            lastInvoker = (JTextComponent) invoker;
            setEnabled(((JTextComponent) invoker).isEditable());

            return true;
        }

        lastInvoker = null;
        return false;
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
