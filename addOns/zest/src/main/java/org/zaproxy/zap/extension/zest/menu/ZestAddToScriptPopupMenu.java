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
package org.zaproxy.zap.extension.zest.menu;

import java.util.List;
import javax.swing.JMenuItem;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHistoryReferenceContainer;
import org.zaproxy.zest.core.v1.ZestConditional;
import org.zaproxy.zest.core.v1.ZestElement;

public class ZestAddToScriptPopupMenu extends PopupMenuItemHistoryReferenceContainer {

    private static final long serialVersionUID = 2282358266003940700L;

    private ExtensionZest extension;

    /** This method initializes */
    public ZestAddToScriptPopupMenu(ExtensionZest extension) {
        super("AddToZestX", true);
        this.extension = extension;
    }

    /**/
    @Override
    public String getParentMenuName() {
        return Constant.messages.getString("zest.addto.popup", true);
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
    public void performHistoryReferenceActions(List<HistoryReference> hrefs) {}

    @Override
    public boolean isEnableForInvoker(Invoker invoker, HttpMessageContainer httpMessageContainer) {
        reCreateSubMenu();
        return true;
    }

    private void reCreateSubMenu() {
        final List<JMenuItem> mainPopupMenuItems = View.getSingleton().getPopupList();
        ScriptNode selNode = extension.getSelectedZestNode();
        ZestElement ze = extension.getSelectedZestElement();

        if (ze != null) {
            if (ze instanceof ZestConditional) {
                ExtensionPopupMenuItem piicm = createPopupAddToScriptMenu(selNode);
                piicm.setMenuIndex(this.getMenuIndex());
                mainPopupMenuItems.add(piicm);
            }
        }

        for (ScriptType st : extension.getExtScript().getScriptTypes()) {
            if (st.hasCapability(ScriptType.CAPABILITY_APPEND)) {
                for (ScriptNode node : extension.getZestScriptNodes(st.getName())) {
                    ExtensionPopupMenuItem piicm = createPopupAddToScriptMenu(node);
                    piicm.setMenuIndex(this.getMenuIndex());
                    mainPopupMenuItems.add(piicm);
                }
            }
        }
        // Add the 'new zest' menu
        ExtensionPopupMenuItem piicm = createPopupAddToScriptMenu();
        mainPopupMenuItems.add(piicm);
    }

    private ExtensionPopupMenuItem createPopupAddToScriptMenu() {
        return new ZestAddToScriptMenu(extension);
    }

    private ExtensionPopupMenuItem createPopupAddToScriptMenu(ScriptNode node) {
        return new ZestAddToScriptMenu(extension, node);
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    @Override
    public void performAction(HistoryReference href) {
        // Do nothing
    }
}
