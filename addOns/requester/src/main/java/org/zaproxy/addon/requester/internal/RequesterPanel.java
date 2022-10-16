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
package org.zaproxy.addon.requester.internal;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.requester.ExtensionRequester;
import org.zaproxy.addon.requester.db.RequesterTabStorage;
import org.zaproxy.addon.requester.internal.tab.RequesterNumberedRenamableTabbedPane;

import java.awt.GridLayout;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

public class RequesterPanel extends AbstractPanel implements OptionsChangedListener {

    private static final long serialVersionUID = 1L;

    private RequesterNumberedRenamableTabbedPane tabbedPane = null;

    public RequesterPanel(ExtensionRequester extension) {
        super();
        this.setLayout(new GridLayout(1, 1));
        this.setSize(474, 251);
        this.setName(Constant.messages.getString("requester.panel.title"));
        this.setIcon(ExtensionRequester.getRequesterIcon());
        this.setDefaultAccelerator(
                extension
                        .getView()
                        .getMenuShortcutKeyStroke(KeyEvent.VK_R, InputEvent.ALT_DOWN_MASK, false));
        this.setMnemonic(Constant.messages.getChar("requester.panel.mnemonic"));
        this.setShowByDefault(true);
    }

    public RequesterNumberedRenamableTabbedPane getTabbedPane() {
        return tabbedPane;
    }

    public void load(RequesterTabStorage tabStorage) {
        // If it is already loaded, unload
        if (tabbedPane != null) {
            tabbedPane.unload();
            remove(tabbedPane);
        }

        // Load tabbed pane
        tabbedPane = new RequesterNumberedRenamableTabbedPane(tabStorage);
        this.add(tabbedPane);
    }

    public void newRequester(HttpMessage message) {
        getTabbedPane().newRequester(message);
    }

    public void unload() {
        getTabbedPane().unload();
    }

    @Override
    public void optionsChanged(OptionsParam optionsParam) {
        getTabbedPane().optionsChanged(optionsParam);
    }
}
