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
package org.zaproxy.zap.extension.wappalyzer;

import java.awt.Component;
import java.util.Map;
import java.util.regex.Pattern;
import javax.swing.JMenuItem;
import org.jdesktop.swingx.JXTable;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.ExtensionPopupMenu;
import org.zaproxy.zap.extension.search.ExtensionSearch;
import org.zaproxy.zap.view.popup.ExtensionPopupMenuComponent;

public class PopupMenuEvidence extends ExtensionPopupMenu {

    private static final long serialVersionUID = 1L;

    private ExtensionWappalyzer extension;

    public PopupMenuEvidence(ExtensionWappalyzer extension) {
        super(Constant.messages.getString("wappalyzer.search.popup"));
        this.extension = extension;
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        removeAll();

        if (invoker.getName() != null
                && invoker.getName().equals(TechPanel.PANEL_NAME)
                && ((JXTable) invoker).getSelectedRows().length < 2) {
            Application app = extension.getSelectedApp();
            if (app != null) {
                for (AppPattern p : app.getUrl()) {
                    addMenuItem(p.getJavaPattern(), ExtensionSearch.Type.URL);
                }
                for (Map<String, AppPattern> mp : app.getHeaders()) {
                    for (Map.Entry<String, AppPattern> entry : mp.entrySet()) {
                        Pattern p =
                                Pattern.compile(
                                        entry.getKey()
                                                + ".*"
                                                + entry.getValue().getJavaPattern().pattern());
                        addMenuItem(p, ExtensionSearch.Type.Header);
                    }
                }
                for (AppPattern p : app.getHtml()) {
                    addMenuItem(p.getJavaPattern(), ExtensionSearch.Type.Response);
                }
                for (Map<String, AppPattern> mp : app.getMetas()) {
                    for (Map.Entry<String, AppPattern> entry : mp.entrySet()) {
                        Pattern p =
                                Pattern.compile(
                                        entry.getKey()
                                                + ".*"
                                                + entry.getValue().getJavaPattern().pattern());
                        addMenuItem(p, ExtensionSearch.Type.Response);
                    }
                }
                for (AppPattern p : app.getScript()) {
                    addMenuItem(p.getJavaPattern(), ExtensionSearch.Type.Response);
                }
                for (AppPattern p : app.getCss()) {
                    addMenuItem(p.getJavaPattern(), ExtensionSearch.Type.Response);
                }
            }
            return getMenuComponentCount() != 0;
        }
        return false;
    }

    @Override
    public void dismissed(ExtensionPopupMenuComponent selectedMenuComponent) {
        removeAll();
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    private void addMenuItem(final Pattern pattern, final ExtensionSearch.Type type) {
        JMenuItem menuItem = new JMenuItem(pattern.pattern());
        menuItem.addActionListener(e -> extension.search(pattern, type));
        this.add(menuItem);
    }
}
