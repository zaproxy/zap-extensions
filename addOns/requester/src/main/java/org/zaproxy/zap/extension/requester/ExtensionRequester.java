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
import org.parosproxy.paros.extension.manualrequest.http.impl.ManualHttpRequestEditorDialog;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.requester.PopupMenuResendMessage;
import org.zaproxy.zap.extension.httppanel.HttpPanel;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.utils.DisplayUtils;

public class ExtensionRequester extends ExtensionAdaptor {

    public static final String NAME = "ExtensionRequester";

    private static final String RESOURCES_DIR = "resources/";

    private static ImageIcon requesterIcon;

    private static ImageIcon manualIcon;

    private RequesterPanel requesterPanel = null;
    private RightClickMsgMenuRequester popupMsgMenuRequester = null;

    private RequesterParam requesterParams;
    private RequesterOptionsPanel requesterOptionsPanel;

    private ManualHttpRequestEditorDialog resendDialog;

    public ExtensionRequester() {
        super(NAME);
        this.setOrder(211);
    }

    public static final ImageIcon getManualIcon() {
        if (manualIcon == null) {
            manualIcon = createIcon("hand.png");
        }
        return manualIcon;
    }

    private static ImageIcon createIcon(String relativePath) {
        return DisplayUtils.getScaledIcon(
                ExtensionRequester.class.getResource(RESOURCES_DIR + relativePath));
    }

    public static ImageIcon getRequesterIcon() {
        if (requesterIcon == null) {
            requesterIcon = createIcon("requester.png");
        }
        return requesterIcon;
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

            if (isDeprecated(org.zaproxy.zap.extension.stdmenus.PopupMenuResendMessage.class)) {
                resendDialog =
                        new ManualHttpRequestEditorDialog(true, "resend", "ui.dialogs.manreq");
                resendDialog.setTitle(Constant.messages.getString("requester.resend.dialog.title"));
                extensionHook.addOptionsChangedListener(resendDialog);

                PopupMenuResendMessage popupMenuResendMessage =
                        new PopupMenuResendMessage(
                                Constant.messages.getString("requester.resend.popup"),
                                getManualIcon(),
                                msg -> {
                                    resendDialog.setMessage(msg);
                                    resendDialog.setVisible(true);
                                });
                menu.addPopupMenuItem(popupMenuResendMessage);
            }
        }
    }

    private static boolean isDeprecated(Class<?> clazz) {
        return clazz.getAnnotation(Deprecated.class) != null;
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
        if (getOptionsParam().isAutoFocus()) {
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

            if (resendDialog != null) {
                resendDialog.dispose();
            }
        }
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("requester.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("requester.desc");
    }
}
