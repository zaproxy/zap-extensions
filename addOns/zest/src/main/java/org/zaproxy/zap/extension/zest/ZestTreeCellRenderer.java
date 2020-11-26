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
package org.zaproxy.zap.extension.zest;

import java.awt.Component;
import javax.swing.ImageIcon;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellRenderer;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.OverlayIcon;
import org.zaproxy.zest.core.v1.ZestActionFail;
import org.zaproxy.zest.core.v1.ZestActionGlobalVariableRemove;
import org.zaproxy.zest.core.v1.ZestActionGlobalVariableSet;
import org.zaproxy.zest.core.v1.ZestActionIntercept;
import org.zaproxy.zest.core.v1.ZestActionInvoke;
import org.zaproxy.zest.core.v1.ZestActionPrint;
import org.zaproxy.zest.core.v1.ZestActionScan;
import org.zaproxy.zest.core.v1.ZestActionSleep;
import org.zaproxy.zest.core.v1.ZestAssertion;
import org.zaproxy.zest.core.v1.ZestAssignment;
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
import org.zaproxy.zest.core.v1.ZestComment;
import org.zaproxy.zest.core.v1.ZestConditional;
import org.zaproxy.zest.core.v1.ZestControlLoopBreak;
import org.zaproxy.zest.core.v1.ZestControlLoopNext;
import org.zaproxy.zest.core.v1.ZestControlReturn;
import org.zaproxy.zest.core.v1.ZestElement;
import org.zaproxy.zest.core.v1.ZestExpression;
import org.zaproxy.zest.core.v1.ZestLoop;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestStatement;

/**
 * Custom renderer for {@link ZestScriptsPanel} to set custom icons and tooltips. If you want
 * tooltips you have to enable them via: <code>
 * ToolTipManager.sharedInstance().registerComponent(tree);</code>
 */
public class ZestTreeCellRenderer extends DefaultTreeCellRenderer {

    private static final ImageIcon REQUEST_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            Constant.class.getResource(
                                    "/resource/icon/16/105.png"))); // Blue right arrow
    private static final ImageIcon ACTION_FAIL_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            Constant.class.getResource(
                                    "/resource/icon/16/050.png"))); // Warning triangle
    private static final ImageIcon ACTION_INTERCEPT_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            Constant.class.getResource("/resource/icon/16/101.png"))); // Red X
    private static final ImageIcon ACTION_INVOKE_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            Constant.class.getResource("/resource/icon/16/059.png"))); // Script
    private static final ImageIcon ACTION_SCAN_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            Constant.class.getResource("/resource/icon/16/093.png"))); // Flame
    private static final ImageIcon ACTION_SLEEP_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/hourglass.png")));
    private static final ImageIcon ACTION_PRINT_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/printer.png")));
    private static final ImageIcon ACTION_GLOBAL_VAR_SET_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/globe-plus.png")));
    private static final ImageIcon ACTION_GLOBAL_VAR_REMOVE_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/globe-minus.png")));
    private static final ImageIcon ASSIGNMENT_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/pin.png")));
    private static final ImageIcon ASSERT_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/balance.png")));
    private static final ImageIcon CONDITION_ELSE_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/diamond-arrow-down-right.png")));
    private static final ImageIcon CONDITION_THEN_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/diamond-arrow-up-right.png")));
    private static final ImageIcon CONDITION_IF_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/condition_if.png")));
    private static final ImageIcon LOOP_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/loop.png")));
    private static final ImageIcon EXPRESSION_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/expression.png")));
    private static final ImageIcon COMMENT_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/balloon.png")));
    private static final ImageIcon CONTROL_RETURN_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/arrow-return-180.png")));
    private static final ImageIcon CONTROL_LOOP_BREAK_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/arrow-turn-180.png")));
    private static final ImageIcon CONTROL_LOOP_NEXT_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/arrow-turn-180-left.png")));

    private static final ImageIcon CLIENT_COOKIE_PIN_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/cookie-pin.png")));

    private static final ImageIcon CLIENT_ELEMENT_ASSIGN_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/ui-text-field-pin.png")));
    private static final ImageIcon CLIENT_ELEMENT_CLEAR_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/ui-text-field.png")));
    private static final ImageIcon CLIENT_ELEMENT_CLICK_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/mouse.png")));
    private static final ImageIcon CLIENT_ELEMENT_SEND_KEYS_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/ui-text-field-fill.png")));
    private static final ImageIcon CLIENT_ELEMENT_SUBMIT_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/ui-text-field-submit.png")));

    private static final ImageIcon CLIENT_SCREENSHOT_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/camera.png")));
    private static final ImageIcon CLIENT_FRAME_SWITCH_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/applications-blue.png")));
    private static final ImageIcon CLIENT_WINDOW_PIN_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/application-pin.png")));
    private static final ImageIcon CLIENT_WINDOW_OPEN_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/application-plus.png")));
    private static final ImageIcon CLIENT_WINDOW_OPEN_URL_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/application-arrow.png")));
    private static final ImageIcon CLIENT_WINDOW_CLOSE_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/application-cross.png")));

    private static final ImageIcon CROSS_OVERLAY_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/cross-overlay.png")));
    private static final ImageIcon PENCIL_OVERLAY_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/pencil-overlay.png")));
    private static final ImageIcon TICK_OVERLAY_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/tick-overlay.png")));
    private static final ImageIcon WARNING_OVERLAY_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/exclamation-overlay.png")));
    private static final ImageIcon RECORD_OVERLAY_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(
                            ZestTreeCellRenderer.class.getResource(
                                    "/org/zaproxy/zap/extension/zest/resources/icons/cassette-red-small-overlay.png")));

    private static final long serialVersionUID = -4278691012245035225L;

    private static final Logger logger = Logger.getLogger(ZestTreeCellRenderer.class);

    public ZestTreeCellRenderer() {}

    /** Sets custom tree node logos. */
    @Override
    public Component getTreeCellRendererComponent(
            JTree tree,
            Object value,
            boolean sel,
            boolean expanded,
            boolean leaf,
            int row,
            boolean hasFocus) {

        super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

        ScriptNode scriptNode = null;
        if (value instanceof ScriptNode) {
            scriptNode = (ScriptNode) value;
            Object obj = scriptNode.getUserObject();
            // Reset the tooltip
            this.setToolTipText(null);

            if (obj != null && obj instanceof ZestScriptWrapper) {
                OverlayIcon icon =
                        new OverlayIcon(DisplayUtils.getScaledIcon(ExtensionZest.ZEST_ICON));
                ZestScriptWrapper script = (ZestScriptWrapper) obj;

                // Copied from ScriptsTreeCellRenderer as we want to add an additional overlay
                if (!scriptNode.isTemplate()) {
                    if (script.isChanged()) {
                        icon.add(PENCIL_OVERLAY_ICON);
                    }
                    if (script.isError()) {
                        icon.add(WARNING_OVERLAY_ICON);
                    }
                    if (script.getType().isEnableable()) {
                        if (script.isEnabled()) {
                            icon.add(TICK_OVERLAY_ICON);
                        } else {
                            icon.add(CROSS_OVERLAY_ICON);
                        }
                    }
                }

                if (script.isRecording()) {
                    icon.add(RECORD_OVERLAY_ICON);
                }

                setIcon(icon);

            } else if (obj != null && obj instanceof ZestElementWrapper) {
                ZestElementWrapper zew = (ZestElementWrapper) obj;

                if (zew.getElement() != null) {
                    ZestElement za = zew.getElement();

                    if (za instanceof ZestStatement && !((ZestStatement) za).isEnabled()) {
                        this.setEnabled(false);
                    }

                    if (za instanceof ZestConditional) {
                        switch (zew.getShadowLevel()) {
                            case 0:
                                setIcon(CONDITION_IF_ICON);
                                break;
                            case 1:
                                setIcon(CONDITION_THEN_ICON);
                                break;
                            case 2:
                                setIcon(CONDITION_ELSE_ICON);
                                break;
                        }
                    } else if (za instanceof ZestRequest) {
                        setIcon(REQUEST_ICON);
                    } else if (za instanceof ZestAssertion) {
                        setIcon(ASSERT_ICON);
                    } else if (za instanceof ZestActionFail) {
                        setIcon(ACTION_FAIL_ICON);
                    } else if (za instanceof ZestActionIntercept) {
                        setIcon(ACTION_INTERCEPT_ICON);
                    } else if (za instanceof ZestActionInvoke) {
                        setIcon(ACTION_INVOKE_ICON);
                    } else if (za instanceof ZestActionPrint) {
                        setIcon(ACTION_PRINT_ICON);
                    } else if (za instanceof ZestActionScan) {
                        setIcon(ACTION_SCAN_ICON);
                    } else if (za instanceof ZestActionSleep) {
                        setIcon(ACTION_SLEEP_ICON);
                    } else if (za instanceof ZestActionGlobalVariableSet) {
                        setIcon(ACTION_GLOBAL_VAR_SET_ICON);
                    } else if (za instanceof ZestActionGlobalVariableRemove) {
                        setIcon(ACTION_GLOBAL_VAR_REMOVE_ICON);
                    } else if (za instanceof ZestAssignment) {
                        setIcon(ASSIGNMENT_ICON);
                    } else if (za instanceof ZestComment) {
                        setIcon(COMMENT_ICON);
                        // Ensure newlines work while not allow any other nasties to get displayed
                        String tooltip =
                                "<html>"
                                        + StringEscapeUtils.escapeHtml(
                                                        ((ZestComment) za).getComment())
                                                .replace("\n", "<br>")
                                        + "</html>";
                        this.setToolTipText(tooltip);
                    } else if (za instanceof ZestLoop) {
                        setIcon(LOOP_ICON);
                    } else if (za instanceof ZestExpression) {
                        setIcon(EXPRESSION_ICON);
                    } else if (za instanceof ZestControlReturn) {
                        setIcon(CONTROL_RETURN_ICON);
                    } else if (za instanceof ZestControlLoopBreak) {
                        setIcon(CONTROL_LOOP_BREAK_ICON);
                    } else if (za instanceof ZestControlLoopNext) {
                        setIcon(CONTROL_LOOP_NEXT_ICON);
                    } else if (za instanceof ZestClientAssignCookie) {
                        setIcon(CLIENT_COOKIE_PIN_ICON);
                    } else if (za instanceof ZestClientElementAssign) {
                        setIcon(CLIENT_ELEMENT_ASSIGN_ICON);
                    } else if (za instanceof ZestClientElementClear) {
                        setIcon(CLIENT_ELEMENT_CLEAR_ICON);
                    } else if (za instanceof ZestClientElementClick) {
                        setIcon(CLIENT_ELEMENT_CLICK_ICON);
                    } else if (za instanceof ZestClientElementSendKeys) {
                        setIcon(CLIENT_ELEMENT_SEND_KEYS_ICON);
                    } else if (za instanceof ZestClientElementSubmit) {
                        setIcon(CLIENT_ELEMENT_SUBMIT_ICON);
                    } else if (za instanceof ZestClientLaunch) {
                        setIcon(CLIENT_WINDOW_OPEN_ICON);
                    } else if (za instanceof ZestClientScreenshot) {
                        setIcon(CLIENT_SCREENSHOT_ICON);
                    } else if (za instanceof ZestClientSwitchToFrame) {
                        setIcon(CLIENT_FRAME_SWITCH_ICON);
                    } else if (za instanceof ZestClientWindowHandle) {
                        setIcon(CLIENT_WINDOW_PIN_ICON);
                    } else if (za instanceof ZestClientWindowClose) {
                        setIcon(CLIENT_WINDOW_CLOSE_ICON);
                    } else if (za instanceof ZestClientWindowOpenUrl) {
                        setIcon(CLIENT_WINDOW_OPEN_URL_ICON);
                    } else {
                        logger.error(
                                "Unrecognised element element class="
                                        + zew.getElement().getClass().getCanonicalName());
                    }
                }
            }
        }

        return this;
    }
}
