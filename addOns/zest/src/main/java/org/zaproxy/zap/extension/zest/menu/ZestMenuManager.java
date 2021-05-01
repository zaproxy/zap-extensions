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

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zest.core.v1.ZestClientAssignCookie;
import org.zaproxy.zest.core.v1.ZestClientElementAssign;
import org.zaproxy.zest.core.v1.ZestClientElementClear;
import org.zaproxy.zest.core.v1.ZestClientElementClick;
import org.zaproxy.zest.core.v1.ZestClientElementSendKeys;
import org.zaproxy.zest.core.v1.ZestClientElementSubmit;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestClientScreenshot;
import org.zaproxy.zest.core.v1.ZestClientSwitchToFrame;
import org.zaproxy.zest.core.v1.ZestClientWindowClose;
import org.zaproxy.zest.core.v1.ZestClientWindowHandle;
import org.zaproxy.zest.core.v1.ZestClientWindowOpenUrl;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ZestMenuManager {

    private ZestAddToScriptPopupMenu popupZestAddToMenu = null;
    private ZestCompareReqRespPopupMenu compareRequestPopupMenu = null;
    private ZestCompareReqRespPopupMenu compareResponsePopupMenu = null;

    private ZestAddActionPopupMenu popupAddActionMenu = null;
    private ZestAddAssertionPopupMenu popupAddAssertionMenu = null;
    private ZestAddAssignPopupMenu popupAddAssignMenu = null;
    private ZestAddConditionPopupMenu popupAddConditionMenu = null;
    private ZestAddExpressionPopupMenu popupAddExpressionMenu = null;
    private ZestAddLoopPopupMenu popupAddLoopMenu = null;
    private ZestAddCommentPopupMenu popupAddCommentMenu = null;
    private ZestAddControlPopupMenu popupAddReturnMenu = null;
    private ZestAddRequestPopupMenu popupAddRequestMenu = null;

    private ZestSurroundWithPopupMenu popupSurroundWithMenu = null;
    private ZestAddLoopPopupMenu popupAddLoopMenuLevel2 = null;

    private ZestPopupZestMove popupZestMoveUp = null;
    private ZestPopupZestMove popupZestMoveDown = null;
    private ZestPopupNodeCopyOrCut popupNodeCopy = null;
    private ZestPopupNodeCopyOrCut popupNodeCut = null;
    private ZestPopupNodePaste popupNodePaste = null;
    private ZestPopupCommentOnOff popupNodeComment = null;

    private ZestPopupZestDelete popupZestDelete = null;
    private ZestRedactPopupMenu popupRedact = null;
    private ZestPasteVariablePopupMenu popupPasteVar = null;
    private ZestParameterizePopupMenu popupParam = null;

    private ZestGenerateScriptFromAlertMenu popupGenAlertScript = null;

    private ZestRecordOnOffPopupMenu popupZestRecordOn = null;
    private ZestRecordOnOffPopupMenu popupZestRecordOff = null;
    private ZestRecordFromNodePopupMenu popupZestRecordFromNode = null;

    private ZestAddClientPopupMenu popupAddClientAssignCookieMenu = null;
    private ZestAddClientPopupMenu popupAddClientLaunchMenu = null;
    private ZestAddClientPopupMenu popupAddClientElementAssignMenu = null;
    private ZestAddClientPopupMenu popupAddClientElementClearMenu = null;
    private ZestAddClientPopupMenu popupAddClientElementClickMenu = null;
    private ZestAddClientPopupMenu popupAddClientElementSendKeysMenu = null;
    private ZestAddClientPopupMenu popupAddClientElementSubmitMenu = null;
    private ZestAddClientPopupMenu popupAddClientWindowMenu = null;
    private ZestAddClientPopupMenu popupAddClientWindowCloseMenu = null;
    private ZestAddClientPopupMenu popupAddClientWindowOpenUrlMenu = null;
    private ZestAddClientPopupMenu popupAddClientScreenshot;
    private ZestAddClientPopupMenu popupAddClientSwitchToFrameMenu = null;

    private ExtensionZest extension = null;

    public ZestMenuManager(ExtensionZest extension, ExtensionHook extensionHook) {
        this.extension = extension;

        extensionHook.getHookMenu().addPopupMenuItem(getPopupZestAddToMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getCompareRequestPopupMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getCompareResponsePopupMenu());

        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddRequestMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddActionMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddAssertionMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddAssignMenu());

        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddClientAssignCookieMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddClientLaunchMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddClientElementAssignMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddClientElementClearMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddClientElementClickMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddClientElementSendKeysMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddClientElementSubmitMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddClientScreenshot());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddClientSwitchToFrameMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddClientWindowMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddClientWindowCloseMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddClientWindowOpenUrlMenu());

        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddConditionMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddExpressionMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddLoopMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddCommentMenu());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupAddReturnMenu());

        extensionHook.getHookMenu().addPopupMenuItem(getPopupSurroundWithMenu());

        extensionHook.getHookMenu().addPopupMenuItem(getPopupNodeCut());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupNodeCopy());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupNodePaste());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupNodeComment());

        extensionHook.getHookMenu().addPopupMenuItem(getPopupZestMoveUp());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupZestMoveDown());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupZestDelete());

        extensionHook.getHookMenu().addPopupMenuItem(getPopupRedact());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupPasteVar());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupParam());

        extensionHook.getHookMenu().addPopupMenuItem(getPopupGenAlertScript());

        extensionHook.getHookMenu().addPopupMenuItem(getPopupZestRecordOn());
        extensionHook.getHookMenu().addPopupMenuItem(getPopupZestRecordOff());

        if (extension.isPlugNHackInstalled()) {
            extensionHook.getHookMenu().addPopupMenuItem(getPopupZestRecordFromNode());
        }
    }

    private ZestAddExpressionPopupMenu getPopupAddExpressionMenu() {
        if (popupAddExpressionMenu == null) {
            popupAddExpressionMenu = new ZestAddExpressionPopupMenu(this.extension);
        }
        return popupAddExpressionMenu;
    }

    private ZestAddActionPopupMenu getPopupAddActionMenu() {
        if (popupAddActionMenu == null) {
            popupAddActionMenu = new ZestAddActionPopupMenu(this.extension);
        }
        return popupAddActionMenu;
    }

    private ZestAddAssertionPopupMenu getPopupAddAssertionMenu() {
        if (popupAddAssertionMenu == null) {
            popupAddAssertionMenu = new ZestAddAssertionPopupMenu(this.extension);
        }
        return popupAddAssertionMenu;
    }

    private ZestAddAssignPopupMenu getPopupAddAssignMenu() {
        if (popupAddAssignMenu == null) {
            popupAddAssignMenu = new ZestAddAssignPopupMenu(this.extension);
        }
        return popupAddAssignMenu;
    }

    private ZestAddConditionPopupMenu getPopupAddConditionMenu() {
        if (popupAddConditionMenu == null) {
            popupAddConditionMenu = new ZestAddConditionPopupMenu(this.extension);
        }
        return popupAddConditionMenu;
    }

    protected ZestAddLoopPopupMenu getPopupAddLoopMenu() {
        if (popupAddLoopMenu == null) {
            popupAddLoopMenu = new ZestAddLoopPopupMenu(this.extension);
        }
        return popupAddLoopMenu;
    }

    protected ZestAddLoopPopupMenu getPopupAddLoopMenuLevel2() {
        if (popupAddLoopMenuLevel2 == null) {
            popupAddLoopMenuLevel2 = new ZestAddLoopPopupMenu(this.extension);
        }
        return popupAddLoopMenuLevel2;
    }

    private ZestSurroundWithPopupMenu getPopupSurroundWithMenu() {
        if (popupSurroundWithMenu == null) {
            popupSurroundWithMenu = new ZestSurroundWithPopupMenu(this.extension);
        }
        return popupSurroundWithMenu;
    }

    private ZestAddToScriptPopupMenu getPopupZestAddToMenu() {
        if (popupZestAddToMenu == null) {
            popupZestAddToMenu = new ZestAddToScriptPopupMenu(this.extension);
        }
        return popupZestAddToMenu;
    }

    private ZestAddCommentPopupMenu getPopupAddCommentMenu() {
        if (popupAddCommentMenu == null) {
            popupAddCommentMenu = new ZestAddCommentPopupMenu(this.extension);
        }
        return popupAddCommentMenu;
    }

    private ZestAddControlPopupMenu getPopupAddReturnMenu() {
        if (popupAddReturnMenu == null) {
            popupAddReturnMenu = new ZestAddControlPopupMenu(this.extension);
        }
        return popupAddReturnMenu;
    }

    private ZestCompareReqRespPopupMenu getCompareRequestPopupMenu() {
        if (compareRequestPopupMenu == null) {
            compareRequestPopupMenu = new ZestCompareReqRespPopupMenu(this.extension, true);
        }
        return compareRequestPopupMenu;
    }

    private ZestCompareReqRespPopupMenu getCompareResponsePopupMenu() {
        if (compareResponsePopupMenu == null) {
            compareResponsePopupMenu = new ZestCompareReqRespPopupMenu(this.extension, false);
        }
        return compareResponsePopupMenu;
    }

    private ZestPopupZestDelete getPopupZestDelete() {
        if (popupZestDelete == null) {
            popupZestDelete = new ZestPopupZestDelete(this.extension);
        }
        return popupZestDelete;
    }

    private ZestPopupZestMove getPopupZestMoveUp() {
        if (popupZestMoveUp == null) {
            popupZestMoveUp = new ZestPopupZestMove(this.extension, true);
        }
        return popupZestMoveUp;
    }

    private ZestPopupZestMove getPopupZestMoveDown() {
        if (popupZestMoveDown == null) {
            popupZestMoveDown = new ZestPopupZestMove(this.extension, false);
        }
        return popupZestMoveDown;
    }

    private ZestPopupNodeCopyOrCut getPopupNodeCopy() {
        if (popupNodeCopy == null) {
            popupNodeCopy = new ZestPopupNodeCopyOrCut(this.extension, false);
        }
        return popupNodeCopy;
    }

    private ZestPopupNodeCopyOrCut getPopupNodeCut() {
        if (popupNodeCut == null) {
            popupNodeCut = new ZestPopupNodeCopyOrCut(this.extension, true);
        }
        return popupNodeCut;
    }

    private ZestPopupNodePaste getPopupNodePaste() {
        if (popupNodePaste == null) {
            popupNodePaste = new ZestPopupNodePaste(this.extension);
        }
        return popupNodePaste;
    }

    private ZestPopupCommentOnOff getPopupNodeComment() {
        if (popupNodeComment == null) {
            popupNodeComment = new ZestPopupCommentOnOff(this.extension);
        }
        return popupNodeComment;
    }

    private ZestRedactPopupMenu getPopupRedact() {
        if (popupRedact == null) {
            popupRedact =
                    new ZestRedactPopupMenu(
                            this.extension, Constant.messages.getString("zest.redact.popup"));
        }
        return popupRedact;
    }

    private ZestPasteVariablePopupMenu getPopupPasteVar() {
        if (popupPasteVar == null) {
            popupPasteVar = new ZestPasteVariablePopupMenu(this.extension);
        }
        return popupPasteVar;
    }

    private ZestParameterizePopupMenu getPopupParam() {
        if (popupParam == null) {
            popupParam =
                    new ZestParameterizePopupMenu(
                            this.extension, Constant.messages.getString("zest.parameterize.popup"));
        }
        return popupParam;
    }

    private ZestGenerateScriptFromAlertMenu getPopupGenAlertScript() {
        if (popupGenAlertScript == null) {
            popupGenAlertScript = new ZestGenerateScriptFromAlertMenu(this.extension);
        }
        return popupGenAlertScript;
    }

    private ZestRecordOnOffPopupMenu getPopupZestRecordOn() {
        if (popupZestRecordOn == null) {
            popupZestRecordOn = new ZestRecordOnOffPopupMenu(this.extension, true);
        }
        return popupZestRecordOn;
    }

    private ZestRecordOnOffPopupMenu getPopupZestRecordOff() {
        if (popupZestRecordOff == null) {
            popupZestRecordOff = new ZestRecordOnOffPopupMenu(this.extension, false);
        }
        return popupZestRecordOff;
    }

    private ZestRecordFromNodePopupMenu getPopupZestRecordFromNode() {
        if (popupZestRecordFromNode == null) {
            popupZestRecordFromNode = new ZestRecordFromNodePopupMenu(this.extension);
        }
        return popupZestRecordFromNode;
    }

    private ZestAddRequestPopupMenu getPopupAddRequestMenu() {
        if (popupAddRequestMenu == null) {
            popupAddRequestMenu = new ZestAddRequestPopupMenu(this.extension);
        }
        return popupAddRequestMenu;
    }

    private ZestAddClientPopupMenu getPopupAddClientAssignCookieMenu() {
        if (popupAddClientAssignCookieMenu == null) {
            popupAddClientAssignCookieMenu =
                    new ZestAddClientPopupMenu(
                            this.extension, "zest.clientAssignCookie.popup", true) {
                        private static final long serialVersionUID = 1L;

                        @Override
                        public void showDialog(
                                ScriptNode parent, ScriptNode child, ZestStatement request) {
                            extension
                                    .getDialogManager()
                                    .showZestClientAssignCookieDialog(
                                            parent,
                                            child,
                                            request,
                                            new ZestClientAssignCookie(),
                                            true);
                        }
                    };
        }
        return popupAddClientAssignCookieMenu;
    }

    private ZestAddClientPopupMenu getPopupAddClientLaunchMenu() {
        if (popupAddClientLaunchMenu == null) {
            popupAddClientLaunchMenu =
                    new ZestAddClientPopupMenu(this.extension, "zest.clientLaunch.popup", false) {
                        private static final long serialVersionUID = 1L;

                        @Override
                        public void showDialog(
                                ScriptNode parent, ScriptNode child, ZestStatement request) {
                            extension
                                    .getDialogManager()
                                    .showZestClientLaunchDialog(
                                            parent, child, request, new ZestClientLaunch(), true);
                        }
                    };
        }
        return popupAddClientLaunchMenu;
    }

    private ZestAddClientPopupMenu getPopupAddClientElementAssignMenu() {
        if (popupAddClientElementAssignMenu == null) {
            popupAddClientElementAssignMenu =
                    new ZestAddClientPopupMenu(
                            this.extension, "zest.clientElementAssign.popup", true) {
                        private static final long serialVersionUID = 1L;

                        @Override
                        public void showDialog(
                                ScriptNode parent, ScriptNode child, ZestStatement request) {
                            extension
                                    .getDialogManager()
                                    .showZestClientElementAssignDialog(
                                            parent,
                                            child,
                                            request,
                                            new ZestClientElementAssign(),
                                            true);
                        }
                    };
        }
        return popupAddClientElementAssignMenu;
    }

    private ZestAddClientPopupMenu getPopupAddClientElementClearMenu() {
        if (popupAddClientElementClearMenu == null) {
            popupAddClientElementClearMenu =
                    new ZestAddClientPopupMenu(
                            this.extension, "zest.clientElementClear.popup", true) {
                        private static final long serialVersionUID = 1L;

                        @Override
                        public void showDialog(
                                ScriptNode parent, ScriptNode child, ZestStatement request) {
                            extension
                                    .getDialogManager()
                                    .showZestClientElementClearDialog(
                                            parent,
                                            child,
                                            request,
                                            new ZestClientElementClear(),
                                            true);
                        }
                    };
        }
        return popupAddClientElementClearMenu;
    }

    private ZestAddClientPopupMenu getPopupAddClientElementClickMenu() {
        if (popupAddClientElementClickMenu == null) {
            popupAddClientElementClickMenu =
                    new ZestAddClientPopupMenu(
                            this.extension, "zest.clientElementClick.popup", true) {
                        private static final long serialVersionUID = 1L;

                        @Override
                        public void showDialog(
                                ScriptNode parent, ScriptNode child, ZestStatement request) {
                            extension
                                    .getDialogManager()
                                    .showZestClientElementClickDialog(
                                            parent,
                                            child,
                                            request,
                                            new ZestClientElementClick(),
                                            true);
                        }
                    };
        }
        return popupAddClientElementClickMenu;
    }

    private ZestAddClientPopupMenu getPopupAddClientElementSendKeysMenu() {
        if (popupAddClientElementSendKeysMenu == null) {
            popupAddClientElementSendKeysMenu =
                    new ZestAddClientPopupMenu(
                            this.extension, "zest.clientElementSendKeys.popup", true) {
                        private static final long serialVersionUID = 1L;

                        @Override
                        public void showDialog(
                                ScriptNode parent, ScriptNode child, ZestStatement request) {
                            extension
                                    .getDialogManager()
                                    .showZestClientElementSendKeysDialog(
                                            parent,
                                            child,
                                            request,
                                            new ZestClientElementSendKeys(),
                                            true);
                        }
                    };
        }
        return popupAddClientElementSendKeysMenu;
    }

    private ZestAddClientPopupMenu getPopupAddClientElementSubmitMenu() {
        if (popupAddClientElementSubmitMenu == null) {
            popupAddClientElementSubmitMenu =
                    new ZestAddClientPopupMenu(
                            this.extension, "zest.clientElementSubmit.popup", true) {
                        private static final long serialVersionUID = 1L;

                        @Override
                        public void showDialog(
                                ScriptNode parent, ScriptNode child, ZestStatement request) {
                            extension
                                    .getDialogManager()
                                    .showZestClientElementSubmitDialog(
                                            parent,
                                            child,
                                            request,
                                            new ZestClientElementSubmit(),
                                            true);
                        }
                    };
        }
        return popupAddClientElementSubmitMenu;
    }

    private ZestAddClientPopupMenu getPopupAddClientScreenshot() {
        if (popupAddClientScreenshot == null) {
            popupAddClientScreenshot =
                    new ZestAddClientPopupMenu(
                            this.extension, "zest.clientScreenshot.popup", true) {
                        private static final long serialVersionUID = 1L;

                        @Override
                        public void showDialog(
                                ScriptNode parent, ScriptNode child, ZestStatement request) {
                            extension
                                    .getDialogManager()
                                    .showZestClientScreenshotDialog(
                                            parent,
                                            child,
                                            request,
                                            new ZestClientScreenshot(),
                                            true);
                        }
                    };
        }
        return popupAddClientScreenshot;
    }

    private ZestAddClientPopupMenu getPopupAddClientSwitchToFrameMenu() {
        if (popupAddClientSwitchToFrameMenu == null) {
            popupAddClientSwitchToFrameMenu =
                    new ZestAddClientPopupMenu(
                            this.extension, "zest.ClientSwitchToFrame.popup", false) {
                        private static final long serialVersionUID = 1L;

                        @Override
                        public void showDialog(
                                ScriptNode parent, ScriptNode child, ZestStatement request) {
                            extension
                                    .getDialogManager()
                                    .showZestClientSwitchToFrameDialog(
                                            parent,
                                            child,
                                            request,
                                            new ZestClientSwitchToFrame(),
                                            true);
                        }
                    };
        }
        return popupAddClientSwitchToFrameMenu;
    }

    private ZestAddClientPopupMenu getPopupAddClientWindowMenu() {
        if (popupAddClientWindowMenu == null) {
            popupAddClientWindowMenu =
                    new ZestAddClientPopupMenu(this.extension, "zest.clientWindow.popup", false) {
                        private static final long serialVersionUID = 1L;

                        @Override
                        public void showDialog(
                                ScriptNode parent, ScriptNode child, ZestStatement request) {
                            extension
                                    .getDialogManager()
                                    .showZestClientWindowHandleDialog(
                                            parent,
                                            child,
                                            request,
                                            new ZestClientWindowHandle(),
                                            true);
                        }
                    };
        }
        return popupAddClientWindowMenu;
    }

    private ZestAddClientPopupMenu getPopupAddClientWindowCloseMenu() {
        if (popupAddClientWindowCloseMenu == null) {
            popupAddClientWindowCloseMenu =
                    new ZestAddClientPopupMenu(
                            this.extension, "zest.clientWindowClose.popup", true) {
                        private static final long serialVersionUID = 1L;

                        @Override
                        public void showDialog(
                                ScriptNode parent, ScriptNode child, ZestStatement request) {
                            extension
                                    .getDialogManager()
                                    .showZestClientWindowCloseDialog(
                                            parent,
                                            child,
                                            request,
                                            new ZestClientWindowClose(),
                                            true);
                        }
                    };
        }
        return popupAddClientWindowCloseMenu;
    }

    private ZestAddClientPopupMenu getPopupAddClientWindowOpenUrlMenu() {
        if (popupAddClientWindowOpenUrlMenu == null) {
            popupAddClientWindowOpenUrlMenu =
                    new ZestAddClientPopupMenu(
                            this.extension, "zest.clientWindowOpenUrl.popup", true) {
                        private static final long serialVersionUID = 1L;

                        @Override
                        public void showDialog(
                                ScriptNode parent, ScriptNode child, ZestStatement request) {
                            extension
                                    .getDialogManager()
                                    .showZestClientWindowOpenUrlDialog(
                                            parent,
                                            child,
                                            request,
                                            new ZestClientWindowOpenUrl(),
                                            true);
                        }
                    };
        }
        return popupAddClientWindowOpenUrlMenu;
    }
}
