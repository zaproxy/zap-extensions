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
package org.zaproxy.zap.extension.requester;

import java.awt.Component;
import javax.swing.ImageIcon;
import javax.swing.SwingUtilities;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookMenu;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.HttpPanel;
import org.zaproxy.zap.extension.httppanel.Message;

public class ExtensionRequester extends ExtensionAdaptor {

    public static final String NAME = "ExtensionRequester";

    private static final String RESOURCE = "/org/zaproxy/zap/extension/requester/resources";

    public static final ImageIcon REQUESTER_ICON =
            new ImageIcon(ExtensionRequester.class.getResource(RESOURCE + "/requester.png"));

    private RequesterPanel requesterPanel = null;
    private RightClickMsgMenuRequester popupMsgMenuRequester = null;

    private RequesterParam requesterParams;
    private RequesterOptionsPanel requesterOptionsPanel;

    public ExtensionRequester() {
        super(NAME);
        this.setOrder(211);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        extensionHook.addOptionsParamSet(getOptionsParam());
        if (getView() != null) {
            extensionHook.addOptionsChangedListener(getRequesterPanel());

            ExtensionHookView hookView = extensionHook.getHookView();
            hookView.addWorkPanel(getRequesterPanel());
            hookView.addOptionPanel(getOptionsPanel());
            // PopupMsgMenuItem
            ExtensionHookMenu menu = extensionHook.getHookMenu();
            menu.addPopupMenuItem(getPopupMsgMenuRequester());
            // ToolsMenuItem
            menu.addToolsMenuItem(new ToolsMenuItemRequester(this));
        }
    }

    private RequesterParam getOptionsParam() {
        if (requesterParams == null) {
            requesterParams = new RequesterParam();
        }
        return requesterParams;
    }

    private RequesterOptionsPanel getOptionsPanel() {
        if (requesterOptionsPanel == null) {
            requesterOptionsPanel = new RequesterOptionsPanel();
        }
        return requesterOptionsPanel;
    }

    /*
     * *Hack to get the selected Message. Used when using the Open in Requester keyboard shortcut.
     *  It returns the focused message at Requester or the message set in the main Request/Response panel
     */
    public Message getSelectedMsg() {
        Component focusedComponent = getView().getMainFrame().getFocusOwner();
        if (focusedComponent != null) {
            if (getView()
                    .getMainFrame()
                    .getFocusOwner()
                    .getClass()
                    .getName()
                    .startsWith("org.zaproxy.zap.extension.httppanel.view")) {
                Component httpPanel =
                        SwingUtilities.getAncestorOfClass(HttpPanel.class, focusedComponent);
                if (httpPanel != null) {
                    return ((HttpPanel) httpPanel).getMessage();
                }
            } else {
                return View.getSingleton().getRequestPanel().getMessage();
            }
        }
        return null;
    }

    private RightClickMsgMenuRequester getPopupMsgMenuRequester() {
        if (popupMsgMenuRequester == null) {
            popupMsgMenuRequester =
                    new RightClickMsgMenuRequester(
                            Constant.messages.getString("requester.rightclickmenu.label"));
            popupMsgMenuRequester.setExtension(this);
        }
        return popupMsgMenuRequester;
    }

    private RequesterPanel getRequesterPanel() {
        if (requesterPanel == null) {
            requesterPanel = new RequesterPanel(this);
        }
        return requesterPanel;
    }

    public void newRequesterPane(HttpMessage msg) {
        getRequesterPanel().newRequester(msg);
        if (getOptionsParam().isAutoFocus() == true) {
            getRequesterPanel().setTabFocus();
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (getView() != null) {
            getRequesterPanel().unload();
        }
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("requester.desc");
    }
}
