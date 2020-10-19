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
package org.zaproxy.zap.extension.httpsinfo;

import java.awt.CardLayout;
import java.awt.Component;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.view.TabbedPanel2;

public class ExtensionHttpsInfo extends ExtensionAdaptor implements SessionChangedListener {

    public static final String NAME = "ExtensionHttpsInfo";
    public static final String ICON_PATH =
            "/org/zaproxy/zap/extension/httpsinfo/resources/icon.png";
    private static final List<Class<? extends Extension>> DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dep = new ArrayList<>(1);
        dep.add(ExtensionAlert.class);

        DEPENDENCIES = Collections.unmodifiableList(dep);
    }

    private MenuEntry httpsMenuEntry;
    private AbstractPanel httpsInfoPanel;
    private TabbedPanel2 httpsInfoTabsPanel;

    public ExtensionHttpsInfo() {
        super();
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("httpsinfo.ext.name");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            extensionHook.getHookMenu().addPopupMenuItem(getPopupMsgMenu());
            extensionHook.getHookView().addStatusPanel(getHttpsInfoPanel());
            extensionHook.addSessionListener(this);
        }
    }

    private MenuEntry getPopupMsgMenu() {
        if (httpsMenuEntry == null) {
            httpsMenuEntry =
                    new MenuEntry(
                            Constant.messages.getString("httpsinfo.rightclick.menuitem"), this);
            httpsMenuEntry.setIcon(new ImageIcon(ExtensionHttpsInfo.class.getResource(ICON_PATH)));
        }
        return httpsMenuEntry;
    }

    protected TabbedPanel2 getHttpsInfoTabsPanel() {
        if (httpsInfoTabsPanel == null) {
            httpsInfoTabsPanel =
                    new TabbedPanel2() {
                        private static final long serialVersionUID = -1422894398829082869L;

                        @Override
                        public void setVisible(Component component, boolean visible) {
                            if (!visible) {
                                removeTab((AbstractPanel) component);
                            }
                        }
                    };
        }
        return httpsInfoTabsPanel;
    }

    protected AbstractPanel getHttpsInfoPanel() {
        if (httpsInfoPanel == null) {
            httpsInfoPanel = new AbstractPanel();
            httpsInfoPanel.setLayout(new CardLayout());
            httpsInfoPanel.setName(Constant.messages.getString("httpsinfo.name"));
            httpsInfoPanel.setIcon(new ImageIcon(ExtensionHttpsInfo.class.getResource(ICON_PATH)));
            httpsInfoPanel.add(getHttpsInfoTabsPanel());
        }
        return httpsInfoPanel;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("httpsinfo.desc");
    }

    protected int getTabIndex(String tabName) {
        int idx = 0;
        for (; idx < getHttpsInfoTabsPanel().getTabCount(); idx++) {
            if (getHttpsInfoTabsPanel().getTabList().get(idx).getName().equals(tabName)) {
                break;
            }
        }
        return idx;
    }

    protected void addTab(HttpMessage msg) {
        String hostname = msg.getRequestHeader().getHostName();
        String tabName =
                hostname
                        + " - "
                        + (getHttpsInfoTabsPanel().getTabCount() == 0
                                ? 0
                                : getHttpsInfoTabsPanel().getTabCount());

        addTab(
                tabName,
                null,
                new HttpsInfoOutputPanel(msg),
                true,
                true,
                getHttpsInfoTabsPanel().getTabCount() == 0
                        ? 0
                        : getHttpsInfoTabsPanel().getTabCount());

        getHttpsInfoPanel().setTabFocus();
        getHttpsInfoTabsPanel()
                .setSelectedComponent(
                        getHttpsInfoTabsPanel().getTabList().get(getTabIndex(tabName)));
    }

    private void addTab(
            String title, Icon icon, Component c, boolean hideable, boolean visible, int index) {
        getHttpsInfoTabsPanel().addTab(title, icon, c, hideable, visible, index);
        getHttpsInfoTabsPanel().getTabList().get(index).setName(title);
    }

    @Override
    public void sessionAboutToChange(Session arg0) {}

    @Override
    public void sessionChanged(Session arg0) {
        getHttpsInfoTabsPanel().removeAll();
    }

    @Override
    public void sessionModeChanged(Mode arg0) {}

    @Override
    public void sessionScopeChanged(Session arg0) {}
}
