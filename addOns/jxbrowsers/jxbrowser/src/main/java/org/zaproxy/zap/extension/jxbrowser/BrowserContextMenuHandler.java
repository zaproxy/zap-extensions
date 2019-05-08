/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.jxbrowser;

import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JComponent;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.SwingUtilities;

import com.teamdev.jxbrowser.chromium.Browser;
import com.teamdev.jxbrowser.chromium.ContextMenuHandler;
import com.teamdev.jxbrowser.chromium.ContextMenuParams;

/**
 * A browser context menu. It is not i18n but can be run from the commandline for testing purposes.
 * @author psiinon
 *
 */
public class BrowserContextMenuHandler implements ContextMenuHandler {

    private final BrowserFrame frame;
    private final JComponent component;

    public BrowserContextMenuHandler(BrowserFrame frame, JComponent parentComponent) {
        this.frame = frame;
        this.component = parentComponent;
    }
    
    protected String getOpenInNewTabLabel() {
        return "Open link in new tab";
    }

    protected String getReloadLabel() {
        return "Reload";
    }

    public void showContextMenu(final ContextMenuParams params) {
        final JPopupMenu popupMenu = new JPopupMenu();
        if (!params.getLinkText().isEmpty()) {
            popupMenu.add(createMenuItem(getOpenInNewTabLabel(), new Runnable() {
                public void run() {
                    frame.addNewBrowserPanel(params.getLinkURL());
                }
            }));
        }

        final Browser browser = params.getBrowser();
        popupMenu.add(createMenuItem(getReloadLabel(), new Runnable() {
            public void run() {
                browser.reload();
            }
        }));

        final Point location = params.getLocation();
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                popupMenu.show(component, location.x, location.y);
            }
        });
    }

    private JMenuItem createMenuItem(String title, final Runnable action) {
        JMenuItem reloadMenuItem = new JMenuItem(title);
        reloadMenuItem.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                action.run();
            }
        });
        return reloadMenuItem;
    }
}