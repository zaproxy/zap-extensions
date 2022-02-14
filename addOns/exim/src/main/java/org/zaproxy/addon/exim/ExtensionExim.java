/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.exim;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.exim.har.MenuImportHar;
import org.zaproxy.addon.exim.har.PopupMenuItemSaveHarMessage;
import org.zaproxy.addon.exim.log.MenuItemImportLogs;
import org.zaproxy.addon.exim.urls.MenuItemImportUrls;

public class ExtensionExim extends ExtensionAdaptor {

    public static final String STATS_PREFIX = "stats.exim.";
    public static final String EXIM_OUTPUT_ERROR = "exim.output.error";
    private static final String NAME = "ExtensionExim";

    public ExtensionExim() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            extensionHook.getHookMenu().addPopupMenuItem(new PopupMenuSaveRawMessage());
            extensionHook.getHookMenu().addPopupMenuItem(new PopupMenuSaveXmlMessage());
            extensionHook.getHookMenu().addPopupMenuItem(new PopupMenuItemSaveHarMessage());

            extensionHook.getHookMenu().addImportMenuItem(new MenuImportHar());
            extensionHook.getHookMenu().addImportMenuItem(new MenuItemImportUrls());
            extensionHook.getHookMenu().addImportMenuItem(new MenuItemImportLogs());
        }
        extensionHook.addApiImplementor(new ImportExportApi());
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("exim.description");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("exim.ui.name");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    public static void updateOutput(String messageKey, String filePath) {
        if (View.isInitialised()) {
            StringBuilder sb = new StringBuilder(128);
            sb.append(Constant.messages.getString(messageKey, filePath)).append('\n');
            View.getSingleton().getOutputPanel().append(sb.toString());
        }
    }
}
