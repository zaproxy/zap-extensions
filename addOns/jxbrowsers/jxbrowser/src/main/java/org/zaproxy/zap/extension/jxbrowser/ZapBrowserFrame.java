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

import com.teamdev.jxbrowser.chromium.Browser;
import java.awt.Component;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.view.TabbedPanel2;

public class ZapBrowserFrame extends BrowserFrame {

    private static final long serialVersionUID = 1L;

    private static final Icon PLUS_ICON =
            new ImageIcon(TabbedPanel2.class.getResource("/resource/icon/fugue/plus.png"));

    public ZapBrowserFrame() {
        this(true, true);
    }

    public ZapBrowserFrame(boolean incToolbar, boolean supportTabs) {
        super(incToolbar, supportTabs);
    }

    public ZapBrowserFrame(
            final boolean incToolbar, final boolean supportTabs, boolean createBrowser) {
        super(incToolbar, supportTabs, createBrowser);
    }

    public ZapBrowserFrame(
            final boolean incToolbar,
            final boolean supportTabs,
            boolean createBrowser,
            boolean showNewTab) {
        super(incToolbar, supportTabs, createBrowser, showNewTab);
    }

    @Override
    protected BrowserPanel getNewBrowserPanel(boolean incToolbar) {
        return new ZapBrowserPanel(this, incToolbar);
    }

    @Override
    protected BrowserPanel getNewBrowserPanel(boolean incToolbar, Browser browser) {
        return new ZapBrowserPanel(this, incToolbar, browser);
    }

    @Override
    protected JTabbedPane getTabbedPane() {
        if (tabbedPane == null) {
            tabbedPane = new ZapTabbedPanel();
        }
        return tabbedPane;
    }

    @Override
    protected String getFirstPageHtml() {
        return Constant.messages.getString("jxbrowser.browser.firstpage");
    }

    @Override
    protected String getNewTabTitle() {
        return Constant.messages.getString("jxbrowser.browser.newtab");
    }

    @Override
    protected void addPlusTab() {
        getTabbedPane().addTab("", PLUS_ICON, new JPanel());
    }

    @Override
    protected void insertTab(Component component, int index) {
        ((ZapTabbedPanel) getTabbedPane()).addTab(getNewTabTitle(), null, component, true, index);
    }

    @Override
    protected void setWindowTitle(String title) {
        if (title == null) {
            this.setTitle(Constant.messages.getString("jxbrowser.browser.blanktitle"));
        } else {
            this.setTitle(Constant.messages.getString("jxbrowser.browser.title", title));
        }
    }

    @Override
    protected void titleChanged(BrowserPanel bp) {
        int index = tabbedPane.indexOfComponent(bp);

        if (index == tabbedPane.getSelectedIndex()) {
            String title = bp.getBrowser().getTitle();
            if (title.equals("about:blank")) {
                title = this.getNewTabTitle();
            }
            this.setWindowTitle(title);
            if (title.length() > 20) {
                title = title.substring(0, 20) + "...";
            }
            Component c = tabbedPane.getTabComponentAt(index);
            if (c instanceof TabbedPanelTab) {
                TabbedPanelTab tpt = (TabbedPanelTab) c;
                tpt.setTitle(title);
            } else {
                tabbedPane.setTitleAt(index, title);
            }
        }
    }
}
