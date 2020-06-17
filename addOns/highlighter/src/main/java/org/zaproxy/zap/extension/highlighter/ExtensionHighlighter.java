/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2011 The ZAP Development Team
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
package org.zaproxy.zap.extension.highlighter;

import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

/*
 * Implements the Extension Interface for HighlighterManager and HighlighterPanel
 */
public class ExtensionHighlighter extends ExtensionAdaptor {

    public static final String NAME = "ExtensionHighlighter";
    private HighlighterPanel highlighterPanel;

    public ExtensionHighlighter() {
        this.setName(NAME);
        this.setOrder(69);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            extensionHook.getHookView().addStatusPanel(getHighlighterPanel());

            // TODO enable (and correct the key) once the add-on provides help
            // ExtensionHelp.enableHelpKey(getHighlighterPanel(), "ui.tabs.hilighter");
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    protected HighlighterPanel getHighlighterPanel() {
        if (highlighterPanel == null) {
            highlighterPanel = new HighlighterPanel(this);
        }
        return highlighterPanel;
    }
}
