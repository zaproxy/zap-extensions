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
 *   http://www.apache.org/licenses/LICENSE-2.0 
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
import java.net.MalformedURLException;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestAction;
import org.mozilla.zest.core.v1.ZestAssertion;
import org.mozilla.zest.core.v1.ZestAssignment;
import org.mozilla.zest.core.v1.ZestComment;
import org.mozilla.zest.core.v1.ZestControl;
import org.mozilla.zest.core.v1.ZestControlReturn;
import org.mozilla.zest.core.v1.ZestElement;
import org.mozilla.zest.core.v1.ZestExpression;
import org.mozilla.zest.core.v1.ZestLoop;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestStatement;
import org.mozilla.zest.core.v1.ZestStructuredExpression;
import org.mozilla.zest.impl.ZestScriptEngineFactory;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
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

public class ZestDialogManager extends AbstractPanel {

	private static final long serialVersionUID = 1L;
	private static final Logger logger = Logger
			.getLogger(ZestDialogManager.class);

	private ExtensionZest extension = null;
	private ScriptUI scriptUI = null;

	private ZestScriptsDialog scriptDialog = null;
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

	// private ZestComplexConditionDialog complexConditionDialog = null;

	public ZestDialogManager(ExtensionZest extension, ScriptUI scriptUI) {
		super();
		this.extension = extension;
		this.scriptUI = scriptUI;
		initialize();
	}

	private void initialize() {
		this.setLayout(new CardLayout());
		this.setName(Constant.messages.getString("zest.scripts.panel.title"));
		this.setIcon(ExtensionZest.ZEST_ICON);

		this.scriptUI.addMouseListener(new java.awt.event.MouseAdapter() {
			@Override
			public void mousePressed(java.awt.event.MouseEvent e) {
			}

			@Override
			public void mouseReleased(java.awt.event.MouseEvent e) {
				mouseClicked(e);
			}

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
						showZestEditScriptDialog(sn,
								(ZestScriptWrapper) sn.getUserObject(), null,
								false, false);

					} else if (sn.getUserObject() instanceof ZestElementWrapper) {
						ZestElementWrapper zew = (ZestElementWrapper) sn
								.getUserObject();

						if (zew != null && zew.getElement() != null
								&& ZestZapUtils.getShadowLevel(sn) == 0) {
							Object obj = zew.getElement();
							if (obj instanceof ZestRequest) {
								showZestEditRequestDialog(parent, sn);
							} else if (obj instanceof ZestAssertion) {
								showZestAssertionDialog(parent, sn,
										(ZestAssertion) obj, false);
							} else if (obj instanceof ZestAssignment) {
								ScriptNode prev = (ScriptNode) sn
										.getPreviousSibling();
								ZestRequest req = null;
								if (prev != null
										&& ZestZapUtils.getElement(prev) instanceof ZestRequest) {
									req = (ZestRequest) ZestZapUtils
											.getElement(prev);
								}
								showZestAssignDialog(parent, sn, req,
										(ZestAssignment) obj, false);
							} else if (obj instanceof ZestAction) {
								showZestActionDialog(parent, sn, null,
										(ZestAction) obj, false);
							} else if (obj instanceof ZestExpression) {LinkedList<ScriptNode> nodes=new LinkedList<>();
								nodes.add(sn);
								showZestExpressionDialog(parent, nodes, null,
										(ZestExpression) ((ZestExpression) obj), false, false, false);
							} else if (obj instanceof ZestComment) {
								showZestCommentDialog(parent, sn, null,
										(ZestComment) obj, false);
							} else if (obj instanceof ZestLoop<?>) {
								LinkedList<ScriptNode> nodes = new LinkedList<>();
								nodes.add(sn);
								showZestLoopDialog(parent, nodes, null,
										(ZestLoop<?>) obj, false, false);
							} else if (obj instanceof ZestControlReturn) {
								showZestControlDialog(parent, sn, null,
										(ZestControlReturn) obj, false);
							}
						}
					}
				} else {
					// Single click
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

			}
		});

	}

	public void showZestEditScriptDialog(ScriptNode parentNode,
			ZestScriptWrapper script, boolean add, boolean record) {
		this.showZestEditScriptDialog(parentNode, script, null, add, record);
	}

	public void showZestEditScriptDialog(ScriptNode parentNode,
			ZestScriptWrapper script, boolean add, int showtab) {
		this.showZestEditScriptDialog(parentNode, script, null, add, false);
		this.scriptDialog.requestTabFocus(showtab);
	}

	public void showZestEditScriptDialog(ScriptNode parentNode,
			ZestScriptWrapper script, String prefix, boolean add, boolean record) {
		if (scriptDialog == null) {
			scriptDialog = new ZestScriptsDialog(extension, View.getSingleton()
					.getMainFrame(), new Dimension(500, 500));
		} else if (scriptDialog.isVisible()) {
			// Already being displayed, dont overwrite anything
			return;
		}

		if (script == null) {
			ScriptWrapper sw = new ScriptWrapper();
			sw.setEngine(extension.getZestEngineWrapper());
			sw.setEngineName(ZestScriptEngineFactory.NAME);
			sw.setType(extension.getExtScript().getScriptType(
					ExtensionScript.TYPE_STANDALONE));
			script = new ZestScriptWrapper(sw);
			script.setRecording(record);
			try {
				script.getZestScript().setPrefix(prefix);
			} catch (MalformedURLException e) {
				logger.error(e.getMessage(), e);
			}
			scriptDialog.init(parentNode, script, add);

		} else {
			scriptDialog.init(parentNode, script, add);
		}
		scriptDialog.setVisible(true);
	}

	public void showZestEditRequestDialog(ScriptNode parent, ScriptNode request) {
		if (requestDialog == null) {
			requestDialog = new ZestRequestDialog(extension, View
					.getSingleton().getMainFrame(), new Dimension(500, 700));
		} else if (requestDialog.isVisible()) {
			// Already being displayed, dont overwrite anything
			return;
		} else {
		}
		requestDialog.init(parent, request);
		requestDialog.setVisible(true);
	}

	public void showZestAssertionDialog(ScriptNode parent, ScriptNode child,
			ZestAssertion assertion, boolean add) {
		if (assertionsDialog == null) {
			assertionsDialog = new ZestAssertionsDialog(extension, View
					.getSingleton().getMainFrame(), new Dimension(300, 200));
		} else if (assertionsDialog.isVisible()) {
			// Already being displayed, dont overwrite anything
			return;
		}
		ZestScript script = extension.getZestTreeModel()
				.getScriptWrapper(parent).getZestScript();
		assertionsDialog.init(script, parent, child, assertion, add);
		assertionsDialog.setVisible(true);
	}

	public void showZestActionDialog(ScriptNode parent, ScriptNode child,
			ZestRequest req, ZestAction action, boolean add) {
		if (actionDialog == null) {
			actionDialog = new ZestActionDialog(extension,
					View.getSingleton().getMainFrame(), new Dimension(400, 300));
		} else if (actionDialog.isVisible()) {
			// Already being displayed, dont overwrite anything
			return;
		}

		actionDialog.init(
				extension.getZestTreeModel().getScriptWrapper(parent), parent,
				child, req, action, add);
		actionDialog.setVisible(true);
	}

	public void showZestAssignDialog(ScriptNode parent, ScriptNode child,
			ZestRequest req, ZestAssignment assign, boolean add) {
		if (assignmentDialog == null) {
			assignmentDialog = new ZestAssignmentDialog(extension, View
					.getSingleton().getMainFrame(), new Dimension(300, 200));
		} else if (assignmentDialog.isVisible()) {
			// Already being displayed, dont overwrite anything
			return;
		}
		ZestScriptWrapper script = extension.getZestTreeModel()
				.getScriptWrapper(parent);
		assignmentDialog.init(script, parent, child, req, assign, add);
		assignmentDialog.setVisible(true);
	}

	public void showZestCommentDialog(ScriptNode parent, ScriptNode child,
			ZestRequest req, ZestComment comment, boolean add) {
		if (commentDialog == null) {
			commentDialog = new ZestCommentDialog(extension, View
					.getSingleton().getMainFrame(), new Dimension(300, 200));
		} else if (commentDialog.isVisible()) {
			// Already being displayed, dont overwrite anything
			return;
		}
		ZestScriptWrapper script = extension.getZestTreeModel()
				.getScriptWrapper(parent);
		commentDialog.init(script, parent, child, req, comment, add);
		commentDialog.setVisible(true);
	}

	public void showZestControlDialog(ScriptNode parent, ScriptNode child,
			ZestRequest req, ZestControl ctrl, boolean add) {
		if (controlDialog == null) {
			controlDialog = new ZestControlDialog(extension, View
					.getSingleton().getMainFrame(), new Dimension(300, 200));
		} else if (controlDialog.isVisible()) {
			// Already being displayed, dont overwrite anything
			return;
		}
		ZestScriptWrapper script = extension.getZestTreeModel()
				.getScriptWrapper(parent);
		controlDialog.init(script, parent, child, req, ctrl, add);
		controlDialog.setVisible(true);
	}

	public void showZestExpressionDialog(ScriptNode parent,
			List<ScriptNode> children, ZestStatement stmt, ZestExpression expr,
			boolean add, boolean surround, boolean addToNewCondition) {
		ZestScript script = extension.getZestTreeModel()
				.getScriptWrapper(parent).getZestScript();
		if (expr instanceof ZestStructuredExpression) {
			return;
		} else {
			if (conditionDialog == null) {
				conditionDialog = new ZestExpressionDialog(extension, View
						.getSingleton().getMainFrame(), new Dimension(300, 200));
			} else if (conditionDialog.isVisible()) {
				// Already being displayed, dont overwrite anything
				return;
			}
			conditionDialog.init(script, parent, children, stmt, expr, add,
					surround, addToNewCondition);
			conditionDialog.setVisible(true);
		}
	}

	public void showZestLoopDialog(ScriptNode parent,
			List<ScriptNode> children, ZestStatement stmt, ZestLoop<?> loop,
			boolean add, boolean surround) {
		if (loopDialog == null) {
			loopDialog = new ZestLoopDialog(extension, View.getSingleton()
					.getMainFrame(), new Dimension(400, 300));
		} else if (loopDialog.isVisible()) {
			// Already being displayed, dont overwrite anything
			return;
		}
		loopDialog.init(parent, children, stmt, loop, add, surround);
		loopDialog.setVisible(true);
	}

	public void addDeferedMessage(HttpMessage msg) {
		scriptDialog.addDeferedMessage(msg);
	}

	public ZestRedactDialog showZestRedactDialog(ScriptNode node, String replace) {
		if (redactDialog == null) {
			redactDialog = new ZestRedactDialog(extension, View.getSingleton()
					.getMainFrame(), new Dimension(300, 200));
		}
		redactDialog.init(node, replace);
		redactDialog.setVisible(true);
		return redactDialog;
	}
	
	public ZestParameterizeDialog showZestParameterizeDialog(
            ZestScriptWrapper script, ScriptNode node, ZestRequest request, String replace) {
	    if (paramDialog == null) {
	    	paramDialog = new ZestParameterizeDialog(extension, View.getSingleton()
	                            .getMainFrame(), new Dimension(400, 200));
	    }
	    paramDialog.init(script, node, request, replace);
	    paramDialog.setVisible(true);
	    return paramDialog;
	}

	public Map<String, String> showRunScriptDialog(ZestZapRunner runner, ZestScript  script, Map<String, String> params) {
		if (runScriptDialog == null) {
			runScriptDialog = new ZestRunScriptWithParamsDialog(extension, View.getSingleton()
                    .getMainFrame(), new Dimension(400, 200));
		}
		runScriptDialog.init(runner, script, params);
		runScriptDialog.setVisible(true);
		return runScriptDialog.getParams();
	}
}
