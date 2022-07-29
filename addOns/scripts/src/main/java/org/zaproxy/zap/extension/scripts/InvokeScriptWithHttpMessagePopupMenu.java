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
package org.zaproxy.zap.extension.scripts;

import java.util.List;
import javax.swing.JMenuItem;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

@SuppressWarnings("serial")
public class InvokeScriptWithHttpMessagePopupMenu extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 2282358266003940700L;

    private ExtensionScriptsUI extension;

    /** This method initializes */
    public InvokeScriptWithHttpMessagePopupMenu(ExtensionScriptsUI extension) {
        super("ScriptsInvokeX", true);
        this.extension = extension;
    }

    /**/
    @Override
    public String getParentMenuName() {
        return Constant.messages.getString("scripts.runscript.popup");
    }

    @Override
    public boolean isSubMenu() {
        return true;
    }

    @Override
    public boolean isDummyItem() {
        return true;
    }

    @Override
    protected void performActions(HttpMessageContainer httpMessageContainer) {
        // Do nothing (avoids calling performAction for each message).
    }

    @Override
    protected void performAction(HttpMessage message) {
        // Nothing to do.
    }

    @Override
    protected boolean isButtonEnabledForSelectedMessages(
            HttpMessageContainer httpMessageContainer) {
        reCreateSubMenu();

        return false;
    }

    private void reCreateSubMenu() {
        final List<JMenuItem> mainPopupMenuItems = View.getSingleton().getPopupList();

        for (ScriptWrapper script :
                extension.getExtScript().getScripts(ExtensionScript.TYPE_TARGETED)) {
            ExtensionPopupMenuItem piicm = createPopupAddToScriptMenu(script);
            piicm.setMenuIndex(this.getMenuIndex());
            mainPopupMenuItems.add(piicm);
        }
    }

    private ExtensionPopupMenuItem createPopupAddToScriptMenu(ScriptWrapper script) {
        return new InvokeScriptWithHttpMessageMenu(extension, script);
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
