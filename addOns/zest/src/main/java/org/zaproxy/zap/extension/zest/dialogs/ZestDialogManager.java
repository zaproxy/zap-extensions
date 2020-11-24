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
package org.zaproxy.zap.extension.zest.dialogs;

import java.awt.CardLayout;
import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.net.MalformedURLException;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.swing.event.TreeSelectionListener;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptUI;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestElementWrapper;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestZapRunner;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;
import org.zaproxy.zest.core.v1.ZestAction;
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
import org.zaproxy.zest.core.v1.ZestControl;
import org.zaproxy.zest.core.v1.ZestControlReturn;
import org.zaproxy.zest.core.v1.ZestElement;
import org.zaproxy.zest.core.v1.ZestExpression;
import org.zaproxy.zest.core.v1.ZestLoop;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;
import org.zaproxy.zest.core.v1.ZestStructuredExpression;
import org.zaproxy.zest.impl.ZestScriptEngineFactory;

public class ZestDialogManager extends AbstractPanel {

    private static final long serialVersionUID = 1L;
    private static final Logger logger = Logger.getLogger(ZestDialogManager.class);

    private ExtensionZest extension = null;
    private ScriptUI scriptUI = null;

    private ZestScriptsDialog scriptDialog = null;
    private ZestRecordScriptDialog recordDialog = null;
    private ZestRequestDialog requestDialog = null;
    private ZestAssertionsDialog assertionsDialog = null;
    private ZestAssignmentDialog assignmentDialog = null;
    private ZestActionDialog actionDialog = null;
    private ZestExpressionDialog conditionDialog = null;
    private ZestCommentDialog commentDialog = null;
    private ZestLoopDialog loopDialog = null;
    private ZestRedactDialog redactDialog = null;
    private ZestControlDialog controlDialog = null;
    private ZestParameterizeDialog paramDialog = null;
    private ZestRunScriptWithParamsDialog runScriptDialog = null;

    private ZestClientAssignCookieDialog clientAssignCookieDialog = null;
    private ZestClientLaunchDialog clientLaunchDialog = null;
    private ZestClientElementAssignDialog clientElementAssignDialog = null;
    private ZestClientElementClearDialog clientElementClearDialog = null;
    private ZestClientElementClickDialog clientElementClickDialog = null;
    private ZestClientElementSendKeysDialog clientElementSendKeysDialog = null;
    private ZestClientElementSubmitDialog clientElementSubmitDialog = null;
    private ZestClientWindowHandleDialog clientWindowDialog = null;
    private ZestClientWindowCloseDialog clientWindowCloseDialog = null;
    private ZestClientWindowOpenUrlDialog clientWindowOpenUrlDialog = null;
    private ZestClientSwitchToFrameDialog clientSwitchToFrameDialog = null;
    private ZestClientScreenshotDialog clientScreenshotDialog;

    private MouseAdapter mouseListener;
    private TreeSelectionListener treeSelectionListener;

    public ZestDialogManager(ExtensionZest extension, ScriptUI scriptUI) {
        super();
        this.extension = extension;
        this.scriptUI = scriptUI;
        initialize();
    }

    private static ZestRequest getPreviousZestRequest(ScriptNode currentNode) {
        ScriptNode previous = (ScriptNode) currentNode.getPreviousSibling();
        while (previous != null) {
            Object element = ZestZapUtils.getElement(previous);
            if (element instanceof ZestRequest) {
                return (ZestRequest) element;
            }
            previous = (ScriptNode) previous.getPreviousSibling();
        }
        return null;
    }

    private void initialize() {
        this.setLayout(new CardLayout());
        this.setName(Constant.messages.getString("zest.scripts.panel.title"));
        this.setIcon(ExtensionZest.ZEST_ICON);

        mouseListener =
                new java.awt.event.MouseAdapter() {

                    @Override
                    public void mouseClicked(java.awt.event.MouseEvent e) {
                        if (e.getClickCount() > 1) {
                            // Its a double click - edit the node
                            ScriptNode sn = scriptUI.getSelectedNode();
                            if (sn == null || sn.getUserObject() == null) {
                                return;
                            }

                            ScriptNode parent = sn.getParent();

                            if (sn.getUserObject() instanceof ZestScriptWrapper) {
                                showZestEditScriptDialog(
                                        sn, (ZestScriptWrapper) sn.getUserObject(), null, false);

                            } else if (sn.getUserObject() instanceof ZestElementWrapper) {
                                ZestElementWrapper zew = (ZestElementWrapper) sn.getUserObject();

                                if (zew != null
                                        && zew.getElement() != null
                                        && ZestZapUtils.getShadowLevel(sn) == 0) {
                                    Object obj = zew.getElement();
                                    if (obj instanceof ZestRequest) {
                                        showZestEditRequestDialog(parent, sn);
                                    } else if (obj instanceof ZestAssertion) {
                                        showZestAssertionDialog(
                                                parent, sn, (ZestAssertion) obj, false);
                                    } else if (obj instanceof ZestAssignment) {
                                        ZestRequest req = getPreviousZestRequest(sn);
                                        showZestAssignDialog(
                                                parent, sn, req, (ZestAssignment) obj, false);
                                    } else if (obj instanceof ZestAction) {
                                        showZestActionDialog(
                                                parent, sn, null, (ZestAction) obj, false);
                                    } else if (obj instanceof ZestExpression) {
                                        LinkedList<ScriptNode> nodes = new LinkedList<>();
                                        nodes.add(sn);
                                        showZestExpressionDialog(
                                                parent,
                                                nodes,
                                                null,
                                                (ZestExpression) obj,
                                                false,
                                                false,
                                                false);
                                    } else if (obj instanceof ZestComment) {
                                        showZestCommentDialog(
                                                parent, sn, null, (ZestComment) obj, false);
                                    } else if (obj instanceof ZestLoop<?>) {
                                        LinkedList<ScriptNode> nodes = new LinkedList<>();
                                        nodes.add(sn);
                                        showZestLoopDialog(
                                                parent,
                                                nodes,
                                                null,
                                                (ZestLoop<?>) obj,
                                                false,
                                                false);
                                    } else if (obj instanceof ZestControlReturn) {
                                        showZestControlDialog(
                                                parent, sn, null, (ZestControlReturn) obj, false);
                                    } else if (obj instanceof ZestClientAssignCookie) {
                                        showZestClientAssignCookieDialog(
                                                parent,
                                                sn,
                                                null,
                                                (ZestClientAssignCookie) obj,
                                                false);
                                    } else if (obj instanceof ZestClientLaunch) {
                                        showZestClientLaunchDialog(
                                                parent, sn, null, (ZestClientLaunch) obj, false);
                                    } else if (obj instanceof ZestClientElementAssign) {
                                        showZestClientElementAssignDialog(
                                                parent,
                                                sn,
                                                null,
                                                (ZestClientElementAssign) obj,
                                                false);
                                    } else if (obj instanceof ZestClientElementClear) {
                                        showZestClientElementClearDialog(
                                                parent,
                                                sn,
                                                null,
                                                (ZestClientElementClear) obj,
                                                false);
                                    } else if (obj instanceof ZestClientElementClick) {
                                        showZestClientElementClickDialog(
                                                parent,
                                                sn,
                                                null,
                                                (ZestClientElementClick) obj,
                                                false);
                                    } else if (obj instanceof ZestClientElementSendKeys) {
                                        showZestClientElementSendKeysDialog(
                                                parent,
                                                sn,
                                                null,
                                                (ZestClientElementSendKeys) obj,
                                                false);
                                    } else if (obj instanceof ZestClientElementSubmit) {
                                        showZestClientElementSubmitDialog(
                                                parent,
                                                sn,
                                                null,
                                                (ZestClientElementSubmit) obj,
                                                false);
                                    } else if (obj instanceof ZestClientWindowHandle) {
                                        showZestClientWindowHandleDialog(
                                                parent,
                                                sn,
                                                null,
                                                (ZestClientWindowHandle) obj,
                                                false);
                                    } else if (obj instanceof ZestClientWindowClose) {
                                        showZestClientWindowCloseDialog(
                                                parent,
                                                sn,
                                                null,
                                                (ZestClientWindowClose) obj,
                                                false);
                                    } else if (obj instanceof ZestClientWindowOpenUrl) {
                                        showZestClientWindowOpenUrlDialog(
                                                parent,
                                                sn,
                                                null,
                                                (ZestClientWindowOpenUrl) obj,
                                                false);
                                    } else if (obj instanceof ZestClientSwitchToFrame) {
                                        showZestClientSwitchToFrameDialog(
                                                parent,
                                                sn,
                                                null,
                                                (ZestClientSwitchToFrame) obj,
                                                false);
                                    } else if (obj instanceof ZestClientScreenshot) {
                                        showZestClientScreenshotDialog(
                                                parent,
                                                sn,
                                                null,
                                                (ZestClientScreenshot) obj,
                                                false);
                                    }
                                }
                            }
                        }
                    }
                };
        this.scriptUI.addMouseListener(mouseListener);

        treeSelectionListener = e -> displayHttpMessageOfSelectedNode();
        scriptUI.addSelectionListener(treeSelectionListener);
    }

    private void displayHttpMessageOfSelectedNode() {
        ScriptNode sn = scriptUI.getSelectedNode();
        ZestElement ze = ZestZapUtils.getElement(sn);
        if (ze == null) {
            return;
        }
        if (ze instanceof ZestRequest) {
            // Show the original request and response
            extension.displayMessage((ZestRequest) ze);
        }
    }

    public void showZestEditScriptDialog(
            ScriptNode parentNode, ZestScriptWrapper script, boolean add) {
        this.showZestEditScriptDialog(parentNode, script, null, add);
    }

    public void showZestEditScriptDialog(
            ScriptNode parentNode, ZestScriptWrapper script, boolean add, int showtab) {
        this.showZestEditScriptDialog(parentNode, script, null, add);
        this.scriptDialog.requestTabFocus(showtab);
    }

    public void showZestEditScriptDialog(
            ScriptNode parentNode, ZestScriptWrapper script, String prefix, boolean add) {
        if (scriptDialog == null) {
            scriptDialog =
                    new ZestScriptsDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(500, 500));
        } else if (scriptDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(scriptDialog);
            return;
        }
        boolean chooseType = false;

        if (script == null) {
            ScriptWrapper sw = new ScriptWrapper();
            sw.setEngine(extension.getZestEngineWrapper());
            sw.setEngineName(ZestScriptEngineFactory.NAME);
            sw.setType(extension.getExtScript().getScriptType(ExtensionScript.TYPE_STANDALONE));
            sw.setLoadOnStart(true);
            chooseType = true;
            script = new ZestScriptWrapper(sw);
            try {
                script.getZestScript().setPrefix(prefix);
            } catch (MalformedURLException e) {
                logger.error(e.getMessage(), e);
            }
        }
        scriptDialog.init(parentNode, script, add, chooseType);
        scriptDialog.setVisible(true);
    }

    public void showZestRecordScriptDialog(SiteNode node) {
        if (recordDialog == null) {
            recordDialog =
                    new ZestRecordScriptDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(500, 500));
        } else if (recordDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(recordDialog);
            return;
        }

        recordDialog.init(node);
        recordDialog.setVisible(true);
    }

    public void showZestEditRequestDialog(ScriptNode parent, ScriptNode request) {
        if (requestDialog == null) {
            requestDialog =
                    new ZestRequestDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(500, 700));
        } else if (requestDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(requestDialog);
            return;
        } else {
        }
        requestDialog.init(parent, request);
        requestDialog.setVisible(true);
    }

    public void showZestAssertionDialog(
            ScriptNode parent, ScriptNode child, ZestAssertion assertion, boolean add) {
        if (assertionsDialog == null) {
            assertionsDialog =
                    new ZestAssertionsDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
        } else if (assertionsDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(assertionsDialog);
            return;
        }
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        assertionsDialog.init(script, parent, child, assertion, add);
        assertionsDialog.setVisible(true);
    }

    public void showZestActionDialog(
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestAction action,
            boolean add) {
        if (actionDialog == null) {
            actionDialog =
                    new ZestActionDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(400, 400));
        } else if (actionDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(actionDialog);
            return;
        }

        actionDialog.init(
                extension.getZestTreeModel().getScriptWrapper(parent),
                parent,
                child,
                req,
                action,
                add);
        actionDialog.setVisible(true);
    }

    public void showZestAssignDialog(
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestAssignment assign,
            boolean add) {
        if (assignmentDialog == null) {
            assignmentDialog =
                    new ZestAssignmentDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
        } else if (assignmentDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(assignmentDialog);
            return;
        }
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        assignmentDialog.init(script, parent, child, req, assign, add);
        assignmentDialog.setVisible(true);
    }

    public void showZestCommentDialog(
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestComment comment,
            boolean add) {
        if (commentDialog == null) {
            commentDialog =
                    new ZestCommentDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
        } else if (commentDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(commentDialog);
            return;
        }
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        commentDialog.init(script, parent, child, req, comment, add);
        commentDialog.setVisible(true);
    }

    public void showZestControlDialog(
            ScriptNode parent, ScriptNode child, ZestRequest req, ZestControl ctrl, boolean add) {
        if (controlDialog == null) {
            controlDialog =
                    new ZestControlDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
        } else if (controlDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(controlDialog);
            return;
        }
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        controlDialog.init(script, parent, child, req, ctrl, add);
        controlDialog.setVisible(true);
    }

    public void showZestExpressionDialog(
            ScriptNode parent,
            List<ScriptNode> children,
            ZestStatement stmt,
            ZestExpression expr,
            boolean add,
            boolean surround,
            boolean addToNewCondition) {
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        if (expr instanceof ZestStructuredExpression) {
            return;
        } else {
            if (conditionDialog == null) {
                conditionDialog =
                        new ZestExpressionDialog(
                                extension,
                                View.getSingleton().getMainFrame(),
                                new Dimension(300, 200));
            } else if (conditionDialog.isVisible()) {
                // Already being displayed, bring to the front but dont overwrite anything
                bringToFront(conditionDialog);
                return;
            }
            conditionDialog.init(
                    script, parent, children, stmt, expr, add, surround, addToNewCondition);
            conditionDialog.setVisible(true);
        }
    }

    public void showZestLoopDialog(
            ScriptNode parent,
            List<ScriptNode> children,
            ZestStatement stmt,
            ZestLoop<?> loop,
            boolean add,
            boolean surround) {
        if (loopDialog == null) {
            loopDialog =
                    new ZestLoopDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(400, 300));
        } else if (loopDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(loopDialog);
            return;
        }
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        loopDialog.init(script, parent, children, stmt, loop, add, surround);
        loopDialog.setVisible(true);
    }

    public void addDeferedMessage(HttpMessage msg) {
        scriptDialog.addDeferedMessage(msg);
    }

    public ZestRedactDialog showZestRedactDialog(ScriptNode node, String replace) {
        if (redactDialog == null) {
            redactDialog =
                    new ZestRedactDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
        }
        redactDialog.init(node, replace);
        redactDialog.setVisible(true);
        return redactDialog;
    }

    public ZestParameterizeDialog showZestParameterizeDialog(
            ZestScriptWrapper script, ScriptNode node, ZestRequest request, String replace) {
        if (paramDialog == null) {
            paramDialog =
                    new ZestParameterizeDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(400, 200));
        }
        paramDialog.init(script, node, request, replace);
        paramDialog.setVisible(true);
        return paramDialog;
    }

    public Map<String, String> showRunScriptDialog(
            ZestZapRunner runner, ZestScript script, Map<String, String> params) {
        if (runScriptDialog == null) {
            runScriptDialog =
                    new ZestRunScriptWithParamsDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(400, 200));
        }
        runScriptDialog.init(runner, script, params);
        runScriptDialog.setVisible(true);
        return runScriptDialog.getParams();
    }

    public void showZestClientAssignCookieDialog(
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestClientAssignCookie client,
            boolean add) {
        if (clientAssignCookieDialog == null) {
            clientAssignCookieDialog =
                    new ZestClientAssignCookieDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
        } else if (clientAssignCookieDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(clientAssignCookieDialog);
            return;
        }
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        clientAssignCookieDialog.init(script, parent, child, req, client, add);
        clientAssignCookieDialog.setVisible(true);
    }

    public void showZestClientLaunchDialog(
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestClientLaunch client,
            boolean add) {
        if (clientLaunchDialog == null) {
            clientLaunchDialog =
                    new ZestClientLaunchDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(400, 300));
        } else if (clientLaunchDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(clientLaunchDialog);
            return;
        }
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        clientLaunchDialog.init(script, parent, child, req, client, add);
        clientLaunchDialog.setVisible(true);
    }

    public void showZestClientElementAssignDialog(
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestClientElementAssign client,
            boolean add) {
        if (clientElementAssignDialog == null) {
            clientElementAssignDialog =
                    new ZestClientElementAssignDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(300, 240));
        } else if (clientElementAssignDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(clientElementAssignDialog);
            return;
        }
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        clientElementAssignDialog.init(script, parent, child, req, client, add);
        clientElementAssignDialog.setVisible(true);
    }

    public void showZestClientElementClearDialog(
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestClientElementClear client,
            boolean add) {
        if (clientElementClearDialog == null) {
            clientElementClearDialog =
                    new ZestClientElementClearDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
        } else if (clientElementClearDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(clientElementClearDialog);
            return;
        }
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        clientElementClearDialog.init(script, parent, child, req, client, add);
        clientElementClearDialog.setVisible(true);
    }

    public void showZestClientElementClickDialog(
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestClientElementClick client,
            boolean add) {
        if (clientElementClickDialog == null) {
            clientElementClickDialog =
                    new ZestClientElementClickDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
        } else if (clientElementClickDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(clientElementClickDialog);
            return;
        }
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        clientElementClickDialog.init(script, parent, child, req, client, add);
        clientElementClickDialog.setVisible(true);
    }

    public void showZestClientElementSendKeysDialog(
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestClientElementSendKeys client,
            boolean add) {
        if (clientElementSendKeysDialog == null) {
            clientElementSendKeysDialog =
                    new ZestClientElementSendKeysDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
        } else if (clientElementSendKeysDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(clientElementSendKeysDialog);
            return;
        }
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        clientElementSendKeysDialog.init(script, parent, child, req, client, add);
        clientElementSendKeysDialog.setVisible(true);
    }

    public void showZestClientElementSubmitDialog(
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestClientElementSubmit client,
            boolean add) {
        if (clientElementSubmitDialog == null) {
            clientElementSubmitDialog =
                    new ZestClientElementSubmitDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
        } else if (clientElementSubmitDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(clientElementSubmitDialog);
            return;
        }
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        clientElementSubmitDialog.init(script, parent, child, req, client, add);
        clientElementSubmitDialog.setVisible(true);
    }

    public void showZestClientWindowHandleDialog(
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestClientWindowHandle client,
            boolean add) {
        if (clientWindowDialog == null) {
            clientWindowDialog =
                    new ZestClientWindowHandleDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
        } else if (clientWindowDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(clientWindowDialog);
            return;
        }
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        clientWindowDialog.init(script, parent, child, req, client, add);
        clientWindowDialog.setVisible(true);
    }

    public void showZestClientWindowCloseDialog(
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestClientWindowClose client,
            boolean add) {
        if (clientWindowCloseDialog == null) {
            clientWindowCloseDialog =
                    new ZestClientWindowCloseDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
        } else if (clientWindowCloseDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(clientWindowCloseDialog);
            return;
        }
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        clientWindowCloseDialog.init(script, parent, child, req, client, add);
        clientWindowCloseDialog.setVisible(true);
    }

    public void showZestClientWindowOpenUrlDialog(
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestClientWindowOpenUrl client,
            boolean add) {
        if (clientWindowOpenUrlDialog == null) {
            clientWindowOpenUrlDialog =
                    new ZestClientWindowOpenUrlDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
        } else if (clientWindowOpenUrlDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(clientWindowOpenUrlDialog);
            return;
        }
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        clientWindowOpenUrlDialog.init(script, parent, child, req, client, add);
        clientWindowOpenUrlDialog.setVisible(true);
    }

    public void showZestClientScreenshotDialog(
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestClientScreenshot client,
            boolean add) {
        if (clientScreenshotDialog == null) {
            clientScreenshotDialog =
                    new ZestClientScreenshotDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
        } else if (clientScreenshotDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(clientScreenshotDialog);
            return;
        }
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        clientScreenshotDialog.init(script, parent, child, req, client, add);
        clientScreenshotDialog.setVisible(true);
    }

    public void showZestClientSwitchToFrameDialog(
            ScriptNode parent,
            ScriptNode child,
            ZestStatement req,
            ZestClientSwitchToFrame client,
            boolean add) {
        if (clientSwitchToFrameDialog == null) {
            clientSwitchToFrameDialog =
                    new ZestClientSwitchToFrameDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(300, 200));
        } else if (clientSwitchToFrameDialog.isVisible()) {
            // Already being displayed, bring to the front but dont overwrite anything
            bringToFront(clientSwitchToFrameDialog);
            return;
        }
        ZestScriptWrapper script = extension.getZestTreeModel().getScriptWrapper(parent);
        clientSwitchToFrameDialog.init(script, parent, child, req, client, add);
        clientSwitchToFrameDialog.setVisible(true);
    }

    private void bringToFront(StandardFieldsDialog dialog) {
        dialog.toFront();
        dialog.requestFocus();
    }

    public void unload() {
        scriptUI.removeMouseListener(mouseListener);
        scriptUI.removeSelectionListener(treeSelectionListener);

        if (scriptDialog != null) {
            scriptDialog.dispose();
        }
        if (recordDialog != null) {
            recordDialog.dispose();
        }
        if (requestDialog != null) {
            requestDialog.dispose();
        }
        if (assertionsDialog != null) {
            assertionsDialog.dispose();
        }
        if (assignmentDialog != null) {
            assignmentDialog.dispose();
        }
        if (actionDialog != null) {
            actionDialog.dispose();
        }
        if (conditionDialog != null) {
            conditionDialog.dispose();
        }
        if (commentDialog != null) {
            commentDialog.dispose();
        }
        if (loopDialog != null) {
            loopDialog.dispose();
        }
        if (redactDialog != null) {
            redactDialog.dispose();
        }
        if (controlDialog != null) {
            controlDialog.dispose();
        }
        if (paramDialog != null) {
            paramDialog.dispose();
        }
        if (runScriptDialog != null) {
            runScriptDialog.dispose();
        }

        if (clientAssignCookieDialog != null) {
            clientAssignCookieDialog.dispose();
        }
        if (clientLaunchDialog != null) {
            clientLaunchDialog.dispose();
        }
        if (clientElementAssignDialog != null) {
            clientElementAssignDialog.dispose();
        }
        if (clientElementClearDialog != null) {
            clientElementClearDialog.dispose();
        }
        if (clientElementClickDialog != null) {
            clientElementClickDialog.dispose();
        }
        if (clientElementSendKeysDialog != null) {
            clientElementSendKeysDialog.dispose();
        }
        if (clientElementSubmitDialog != null) {
            clientElementSubmitDialog.dispose();
        }
        if (clientWindowDialog != null) {
            clientWindowDialog.dispose();
        }
        if (clientWindowCloseDialog != null) {
            clientWindowCloseDialog.dispose();
        }
        if (clientWindowOpenUrlDialog != null) {
            clientWindowOpenUrlDialog.dispose();
        }
        if (clientSwitchToFrameDialog != null) {
            clientSwitchToFrameDialog.dispose();
        }
    }
}
