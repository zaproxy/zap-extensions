/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP development team
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
package org.zaproxy.zap.extension.zest;

import java.awt.Component;
import java.awt.EventQueue;
import java.awt.event.MouseAdapter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.swing.ImageIcon;

import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestActionFail;
import org.mozilla.zest.core.v1.ZestAssertion;
import org.mozilla.zest.core.v1.ZestAssignFieldValue;
import org.mozilla.zest.core.v1.ZestConditional;
import org.mozilla.zest.core.v1.ZestContainer;
import org.mozilla.zest.core.v1.ZestElement;
import org.mozilla.zest.core.v1.ZestExpressionLength;
import org.mozilla.zest.core.v1.ZestExpressionStatusCode;
import org.mozilla.zest.core.v1.ZestFieldDefinition;
import org.mozilla.zest.core.v1.ZestJSON;
import org.mozilla.zest.core.v1.ZestLoop;
import org.mozilla.zest.core.v1.ZestLoopFile;
import org.mozilla.zest.core.v1.ZestLoopInteger;
import org.mozilla.zest.core.v1.ZestLoopString;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestResponse;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestScript.Type;
import org.mozilla.zest.core.v1.ZestStatement;
import org.mozilla.zest.core.v1.ZestVariables;
import org.mozilla.zest.impl.ZestScriptEngineFactory;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.anticsrf.AntiCsrfToken;
import org.zaproxy.zap.extension.anticsrf.ExtensionAntiCSRF;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptEventListener;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.zest.dialogs.ZestDialogManager;
import org.zaproxy.zap.extension.zest.menu.ZestMenuManager;

public class ExtensionZest extends ExtensionAdaptor implements ProxyListener,
		ScriptEventListener {

	public static final String NAME = "ExtensionZest";
	public static final ImageIcon ZEST_ICON = new ImageIcon(
			ExtensionZest.class
					.getResource("/org/zaproxy/zap/extension/zest/resource/fruit-orange.png"));

	public static final String HTTP_HEADER_X_SECURITY_PROXY = "X-Security-Proxy";
	public static final String VALUE_RECORD = "record";

	private static final Logger logger = Logger.getLogger(ExtensionZest.class);

	private ZestResultsPanel zestResultsPanel = null;

	private ZestTreeModel zestTreeModel = null;
	private ZestDialogManager dialogManager = null;
	private ZestEngineWrapper zestEngineWrapper = null;

	private ExtensionScript extScript = null;
	private ExtensionAntiCSRF extAcsrf = null;
	private ZestScript lastRunScript = null;
	private HttpMessage lastSelectedMessage = null;
	private Map<String, String> acsrfTokenToVar = new HashMap<String, String>();

	private ZestFuzzerDelegate fuzzerMessenger = null;

	// Cut-n-paste stuff
	private List<ScriptNode> cnpNodes = null;
	private boolean cutNodes = false;

	public ExtensionZest() {
		super();
		initialize();
	}

	/**
	 * @param name
	 */
	public ExtensionZest(String name) {
		super(name);
	}

	/**
	 * This method initializes this
	 */
	private void initialize() {
		this.setName(NAME);
		this.setOrder(73); // Almost looks like ZE ;)
	}

	@Override
	public void hook(ExtensionHook extensionHook) {
		super.hook(extensionHook);

		// extensionHook.addOptionsParamSet(getScriptParam());

		if (getView() != null) {
			extensionHook.addProxyListener(this);

			extensionHook.getHookView().addStatusPanel(
					this.getZestResultsPanel());

			this.dialogManager = new ZestDialogManager(this, this
					.getExtScript().getScriptUI());
			new ZestMenuManager(this, extensionHook);
		}

		ScriptEngineManager mgr = new ScriptEngineManager();
		ScriptEngine se = mgr.getEngineByName(ZestScriptEngineFactory.NAME);
		if (se != null) {
			// Looks like this only works if the Zest lib is in the top level
			// lib directory
			zestEngineWrapper = new ZestEngineWrapper(se);
			this.getExtScript().registerScriptEngineWrapper(zestEngineWrapper);
		} else {
			// Needed for when the Zest lib is in an add-on (usual case)
			ZestScriptEngineFactory zsef = new ZestScriptEngineFactory();
			zestEngineWrapper = new ZestEngineWrapper(zsef.getScriptEngine());
			this.getExtScript().registerScriptEngineWrapper(zestEngineWrapper);
		}
		this.getExtScript().addListener(this);

		if (this.getExtScript().getScriptUI() != null) {
			ZestTreeCellRenderer renderer = new ZestTreeCellRenderer();
			this.getExtScript().getScriptUI()
					.addRenderer(ZestElementWrapper.class, renderer);
			this.getExtScript().getScriptUI()
					.disableScriptDialog(ZestScriptWrapper.class);
		}
	}

	public ZestFuzzerDelegate getFuzzerDelegate() {
		if (fuzzerMessenger == null) {
			fuzzerMessenger = new ZestFuzzerDelegate();
		}
		return fuzzerMessenger;
	}

	@Override
	public void optionsLoaded() {
		// Convert scripts loaded on start into real Zest scripts
		for (ScriptType type : this.getExtScript().getScriptTypes()) {
			for (ScriptWrapper script : this.getExtScript().getScripts(type)) {
				if (script.getEngineName().equals(ZestScriptEngineFactory.NAME)) {
					this.scriptAdded(script, false);
				}
			}
		}
	}

	public ZestEngineWrapper getZestEngineWrapper() {
		return zestEngineWrapper;
	}

	@Override
	public boolean canUnload() {
		return true;
	}

	public ExtensionScript getExtScript() {
		if (extScript == null) {
			extScript = (ExtensionScript) Control.getSingleton()
					.getExtensionLoader().getExtension(ExtensionScript.NAME);
		}
		return extScript;
	}

	public ExtensionAntiCSRF getExtACSRF() {
		if (extAcsrf == null) {
			extAcsrf = (ExtensionAntiCSRF) Control.getSingleton()
					.getExtensionLoader().getExtension(ExtensionAntiCSRF.NAME);
		}
		return extAcsrf;
	}

	public ZestDialogManager getDialogManager() {
		return dialogManager;
	}

	private ZestResultsPanel getZestResultsPanel() {
		if (zestResultsPanel == null) {
			zestResultsPanel = new ZestResultsPanel(this);
		}
		return zestResultsPanel;
	}

	public ZestTreeModel getZestTreeModel() {
		if (zestTreeModel == null) {
			zestTreeModel = new ZestTreeModel(this.getExtScript()
					.getTreeModel());
		}
		return zestTreeModel;
	}

	public void redact(ScriptNode node, String replace, String replaceWith,
			boolean recurse) {
		if (ZestZapUtils.getElement(node) instanceof ZestRequest) {
			ZestRequest request = (ZestRequest) ZestZapUtils.getElement(node);
			this.replaceInResponse(request, replace, replaceWith);
			this.updated(node);
		}
		if (recurse) {
			for (int i = 0; i < node.getChildCount(); i++) {
				this.redact((ScriptNode) node.getChildAt(i), replace,
						replaceWith, true);
			}
		}
		// Good chance the current response has been changed
		this.refreshMessage();
	}

	public void setToken(ZestScriptWrapper script, ZestRequest request,
			String replace, String token, boolean replaceInCurrent,
			boolean replaceInAdded) {
		// TODO add default value
		script.getZestScript().getParameters().addVariable(token, replace);
		token = script.getZestScript().getParameters().getTokenStart() + token
				+ script.getZestScript().getParameters().getTokenEnd();
		if (replaceInCurrent) {
			ZestStatement stmt = script.getZestScript().getNext();
			while (stmt != null) {
				if (stmt instanceof ZestRequest) {
					this.replaceInRequest((ZestRequest) stmt, replace, token);
				}
				stmt = stmt.getNext();
			}
		} else {
			this.replaceInRequest(request, replace, token);
			// this.updated(node);
			// TODO
			// this.update(script.getZestScript(), request);
		}
		if (replaceInAdded) {
			// TODO support tokens in added reqs
		}
		// Good chance the current response has been changed
		if (View.isInitialised()) {
			this.refreshMessage();
			// TODO select token tab
			// this.dialogManager.showZestEditScriptDialog(script,
			// ZestScript.Type.Targeted);
		}
	}

	private void replaceInResponse(ZestRequest request, String replace,
			String replaceWith) {
		ZestResponse resp = request.getResponse();
		if (resp != null) {
			request.setResponse(new ZestResponse(request.getUrl(), resp
					.getHeaders().replace(replace, replaceWith), resp.getBody()
					.replace(replace, replaceWith), +resp.getStatusCode(), resp
					.getResponseTimeInMs()));
		}

	}

	private void replaceInRequest(ZestRequest request, String replace,
			String replaceWith) {
		ZestResponse resp = request.getResponse();
		if (resp != null) {
			try {
				request.setUrl(new URL(request.getUrl().toString()
						.replace(replace, replaceWith)));
			} catch (MalformedURLException e) {
				logger.error(e.getMessage(), e);
			}
			request.setHeaders(request.getHeaders().replace(replace,
					replaceWith));
			request.setData(request.getData().replace(replace, replaceWith));
		}
	}

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("zest.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_HOMEPAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}

	public ScriptNode add(ZestScriptWrapper script, boolean display) {
		logger.debug("add script " + script.getName());

		ScriptNode node = this.getExtScript().addScript(script, display);
		this.display(script, node, true);
		return node;
	}

	public void display(ZestScriptWrapper script, ScriptNode node,
			boolean expand) {
		if (View.isInitialised() && this.getExtScript().getScriptUI() != null) {
			this.getExtScript().getScriptUI().selectNode(node, expand);
			this.getExtScript().getScriptUI().displayScript(script);
		}
	}

	public void display(ScriptNode node, boolean expand) {
		logger.debug("Display node=" + node.getNodeName() + " expand=" + expand);
		if (View.isInitialised() && this.getExtScript().getScriptUI() != null) {
			this.getExtScript()
					.getScriptUI()
					.displayScript(
							this.getZestTreeModel().getScriptWrapper(node));
			this.getExtScript().getScriptUI().selectNode(node, expand);
		}
	}

	public void updated(ScriptNode node) {
		logger.debug("Updated node=" + node.getNodeName());
		this.getZestTreeModel().update(node);
		ZestScriptWrapper sw = this.getZestTreeModel().getScriptWrapper(node);
		sw.setContents(ZestJSON.toString(sw.getZestScript()));
		sw.setChanged(true);
	}

	public List<ScriptNode> getAllZestScriptNodes() {
		List<ScriptNode> list = new ArrayList<ScriptNode>();

		for (ScriptType type : this.getExtScript().getScriptTypes()) {
			for (ScriptNode node : this.getExtScript().getTreeModel()
					.getNodes(type.getName())) {
				if (ZestZapUtils.isZestNode(node)) {
					list.add(node);
				}
			}
		}
		return Collections.unmodifiableList(list);
	}

	public List<ScriptNode> getZestScriptNodes(String type) {
		List<ScriptNode> list = new ArrayList<ScriptNode>();

		for (ScriptNode node : this.getExtScript().getTreeModel()
				.getNodes(type)) {
			if (ZestZapUtils.isZestNode(node)) {
				list.add(node);
			}
		}
		return Collections.unmodifiableList(list);
	}

	public List<ScriptWrapper> getZestScripts(String type) {
		List<ScriptWrapper> list = new ArrayList<ScriptWrapper>();
		for (ScriptWrapper sw : this.getExtScript().getScripts(type)) {
			if (sw.getEngineName().equals(ZestScriptEngineFactory.NAME)) {
				list.add(sw);
			}
		}
		return Collections.unmodifiableList(list);
	}

	public void addToParent(ScriptNode parent, SiteNode sn, String prefix) {
		try {
			this.addToParent(parent, sn.getHistoryReference().getHttpMessage(),
					prefix);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}
	}

	public void addToParent(ScriptNode parent, HttpMessage msg, String prefix) {
		if (parent == null) {
			// They're gone for the 'new script' option...
			logger.debug("addToParent parent=null msg="
					+ msg.getRequestHeader().getURI());
			this.dialogManager.showZestEditScriptDialog(null, null,
					ZestScript.Type.Active, prefix, true);
			if (msg != null) {
				this.dialogManager.addDeferedMessage(msg);
			}
		} else {
			logger.debug("addToParent parent=" + parent.getNodeName() + " msg="
					+ msg.getRequestHeader().getURI());

			try {
				ZestRequest req = ZestZapUtils.toZestRequest(msg, false);
				ZestScriptWrapper zsw = this.getZestTreeModel()
						.getScriptWrapper(parent);

				ZestScript script = zsw.getZestScript();
				ZestElement parentZe = ZestZapUtils.getElement(parent);

				if (parentZe instanceof ZestScript) {
					script.add(req);
				} else if (parentZe instanceof ZestConditional) {
					if (ZestZapUtils.isShadow(parent)) {
						((ZestConditional) ZestZapUtils.getElement(parent))
								.addElse(req);
					} else {
						((ZestConditional) ZestZapUtils.getElement(parent))
								.addIf(req);
					}
				} else if (parentZe instanceof ZestLoop<?>) {
					((ZestLoop<?>) ZestZapUtils.getElement(parent))
							.addStatement(req);
				} else {
					throw new IllegalArgumentException(
							"Unexpected parent node: "
									+ parentZe.getElementType() + " "
									+ parent.getNodeName());
				}

				if (zsw.isIncStatusCodeAssertion()) {
					req.addAssertion(new ZestAssertion(
							new ZestExpressionStatusCode(msg
									.getResponseHeader().getStatusCode())));

				}
				if (zsw.isIncLengthAssertion()) {
					req.addAssertion(new ZestAssertion(
							new ZestExpressionLength(
									ZestVariables.RESPONSE_BODY, msg
											.getResponseBody().length(), zsw
											.getLengthApprox())));
				}

				if (getExtACSRF() != null) {
					// Identify and CSRF tokens being used
					List<AntiCsrfToken> acsrfTokens = getExtACSRF().getTokens(
							msg);
					for (AntiCsrfToken acsrf : acsrfTokens) {
						String var = acsrfTokenToVar.get(acsrf.getValue());
						if (var != null) {
							logger.debug("Replacing ACSRF value "
									+ acsrf.getValue() + " with variable "
									+ var);
							this.replaceInRequest(req, acsrf.getValue(), script
									.getParameters().getTokenStart()
									+ var
									+ script.getParameters().getTokenEnd());
						}
					}
				}

				// Update tree
				ScriptNode reqNode = this.getZestTreeModel().addToNode(parent,
						req);

				if (getExtACSRF() != null) {
					// Create assignments for any ACSRF tokens
					Source src = new Source(msg.getResponseHeader().toString()
							+ msg.getResponseBody().toString());
					List<AntiCsrfToken> acsrfTokens = getExtACSRF()
							.getTokensFromResponse(msg, src);
					for (AntiCsrfToken acsrf : acsrfTokens) {
						ZestAssignFieldValue zafv = new ZestAssignFieldValue();
						int id = 1;
						Set<String> names = script.getVariableNames();
						while (names.contains("csrf" + id)) {
							id++;
						}
						zafv.setVariableName("csrf" + id);
						ZestFieldDefinition fd = new ZestFieldDefinition();
						fd.setFormIndex(acsrf.getFormIndex());
						fd.setFieldName(acsrf.getName());
						// Record mapping of value to variable name for later
						// replacement
						logger.debug("Recording ACSRF value "
								+ acsrf.getValue() + " against variable "
								+ zafv.getVariableName());
						acsrfTokenToVar.put(acsrf.getValue(),
								zafv.getVariableName());
						zafv.setFieldDefinition(fd);
						this.addToParent(parent, zafv);
					}
				}

				this.updated(reqNode);
				this.display(reqNode, false);

			} catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
		}
	}

	public void addToRequest(ScriptNode node, ZestRequest req,
			ZestAssertion assertion) {
		req.addAssertion(assertion);
		if (node != null) {
			ScriptNode child = this.getZestTreeModel().addToNode(node,
					assertion);
			this.updated(child);
			this.display(child, false);
		} else {
			throw new IllegalArgumentException(
					"Failed to find ZestRequest in tree "
							+ ZestZapUtils.toUiString(req));
		}
	}

	public void addAfterRequest(ZestScript script, ScriptNode childNode,
			ZestStatement existingChild, ZestStatement newChild) {
		script.add(script.getIndex(existingChild) + 1, newChild);
		ScriptNode child = this.getZestTreeModel().addAfterNode(childNode,
				newChild);
		this.updated(child);
		this.display(child, false);
	}

	public final ScriptNode addToParent(ScriptNode parent,
			ZestStatement newChild) {
		logger.debug("addToParent parent=" + parent.getNodeName() + " new="
				+ newChild.getElementType());
		ScriptNode node;

		if (ZestZapUtils.getElement(parent) instanceof ZestScript) {
			ZestScript zc = (ZestScript) ZestZapUtils.getElement(parent);
			zc.add(newChild);
			node = this.getZestTreeModel().addToNode(parent, newChild);
		} else if (ZestZapUtils.getElement(parent) instanceof ZestConditional) {
			ZestConditional zc = (ZestConditional) ZestZapUtils
					.getElement(parent);

			if (ZestZapUtils.isShadow(parent)) {
				zc.addElse(newChild);
			} else {
				zc.addIf(newChild);
			}
			node = this.getZestTreeModel().addToNode(parent, newChild);

		} else if (ZestZapUtils.getElement(parent) instanceof ZestLoop<?>) {
			ZestLoop<?> zl = (ZestLoop<?>) ZestZapUtils.getElement(parent);
			zl.addStatement(newChild);
			node = this.getZestTreeModel().addToNode(parent, newChild);
		} else {
			throw new IllegalArgumentException("Unexpected parent node: "
					+ ZestZapUtils.getElement(parent) + " "
					+ parent.getNodeName());
		}
		this.updated(node);
		this.display(node, false);
		return node;
	}

	public void addAfterRequest(ScriptNode parent, ScriptNode childNode,
			ZestStatement existingChild, ZestStatement newChild) {
		logger.debug("addAfterRequest parent=" + parent.getNodeName()
				+ " existing=" + existingChild.getElementType() + " new="
				+ newChild.getElementType());

		if (ZestZapUtils.getElement(parent) instanceof ZestScript) {
			this.addAfterRequest((ZestScript) ZestZapUtils.getElement(parent),
					childNode, existingChild, newChild);

		} else if (ZestZapUtils.getElement(parent) instanceof ZestConditional) {
			ZestConditional zc = (ZestConditional) ZestZapUtils
					.getElement(parent);

			if (ZestZapUtils.isShadow(parent)) {
				zc.addElse(zc.getIndex(existingChild) + 1, newChild);
			} else {
				zc.addIf(zc.getIndex(existingChild) + 1, newChild);
			}
			ScriptNode child = this.getZestTreeModel().addAfterNode(parent,
					newChild);
			this.updated(child);
			this.display(child, false);
		} else if (ZestZapUtils.getElement(parent) instanceof ZestLoopFile
				|| ZestZapUtils.getElement(parent) instanceof ZestLoopString
				|| ZestZapUtils.getElement(parent) instanceof ZestLoopInteger) {
			ZestLoop<?> zl=(ZestLoop<?>) ZestZapUtils.getElement(parent);
			zl.addStatement(newChild);
			ScriptNode child = this.getZestTreeModel().addAfterNode(parent,
					newChild);
			this.updated(child);
			this.display(child, false);
		} else {
			throw new IllegalArgumentException("Unexpected parent node: "
					+ ZestZapUtils.getElement(parent) + " "
					+ parent.getNodeName());
		}
	}

	public void notifyAlert(Alert alert) {
		if (View.isInitialised()) {
			int row = this.getZestResultsPanel().getModel()
					.getIndex(alert.getMessage());
			if (row >= 0) {
				ZestResultWrapper zrw = (ZestResultWrapper) this
						.getZestResultsPanel().getModel()
						.getHistoryReference(row);
				zrw.setMessage(alert.getAlert());
				zrw.setPassed(false);
				this.getZestResultsPanel().getModel()
						.fireTableRowsUpdated(row, row);
			}
		}
	}

	public void notifyChanged(ZestResultWrapper lastResult) {
		if (View.isInitialised()) {
			try {
				int row = this.getZestResultsPanel().getModel()
						.getIndex(lastResult.getHttpMessage());
				if (row >= 0) {
					this.getZestResultsPanel().getModel()
							.fireTableRowsUpdated(row, row);
				}
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
		}
	}

	public void delete(ScriptNode node) {
		ScriptNode parent = (ScriptNode) node.getParent();
		this.getZestTreeModel().delete(node);
		this.updated(parent);
		this.display(parent, true);
	}

	public void moveNodeUp(ScriptNode node) {
		ScriptNode prev = (ScriptNode) node.getPreviousSibling();
		if (prev != null && ZestZapUtils.isShadow(prev)) {
			prev = (ScriptNode) prev.getPreviousSibling();
		}
		if (prev == null) {
			logger.error("Cant move node up " + node.getNodeName());
			return;
		}
		if (ZestZapUtils.getElement(node) instanceof ZestScript) {
			// Ignore
		} else if (ZestZapUtils.getElement(node) instanceof ZestStatement) {
			ZestStatement req = (ZestStatement) ZestZapUtils.getElement(node);
			ZestContainer parent = (ZestContainer) ZestZapUtils.getElement(node
					.getParent());
			int index = parent.getIndex(req);
			parent.move(index - 1, req);
			this.getZestTreeModel().switchNodes(prev, node);
			if (View.isInitialised()
					&& this.getExtScript().getScriptUI() != null) {
				this.getExtScript().getScriptUI()
						.selectNode(node.getParent(), true);
			}
			this.updated(node);
			this.display(node, false);
		} else if (ZestZapUtils.getElement(node.getParent()) instanceof ZestRequest) {
			ZestRequest parent = (ZestRequest) ZestZapUtils.getElement(node
					.getParent());
			parent.moveUp(ZestZapUtils.getElement(node));
			this.getZestTreeModel().switchNodes(prev, node);
			if (View.isInitialised()
					&& this.getExtScript().getScriptUI() != null) {
				this.getExtScript().getScriptUI()
						.selectNode(node.getParent(), true);
			}
			this.updated(node);
			this.display(node, false);
		}
	}

	public void moveNodeDown(ScriptNode node) {
		ScriptNode next = (ScriptNode) node.getNextSibling();
		if (next != null && ZestZapUtils.isShadow(next)) {
			next = (ScriptNode) next.getNextSibling();
		}
		if (next == null) {
			logger.error("Cant move node down " + node.getNodeName());
			return;
		}
		if (ZestZapUtils.getElement(node) instanceof ZestScript) {
			// Ignore
		} else if (ZestZapUtils.getElement(node) instanceof ZestStatement) {
			ZestStatement req = (ZestStatement) ZestZapUtils.getElement(node);
			ZestContainer parent = (ZestContainer) ZestZapUtils.getElement(node
					.getParent());
			int index = parent.getIndex(req);
			parent.move(index + 1, req);
			this.getZestTreeModel().switchNodes(node, next);
			if (View.isInitialised()
					&& this.getExtScript().getScriptUI() != null) {
				this.getExtScript().getScriptUI()
						.selectNode(node.getParent(), true);
			}
			this.updated(node);
			this.display(node, false);

		} else if (ZestZapUtils.getElement(node.getParent()) instanceof ZestRequest) {
			ZestRequest parent = (ZestRequest) ZestZapUtils.getElement(node
					.getParent());
			parent.moveUp(ZestZapUtils.getElement(node));
			this.getZestTreeModel().switchNodes(node, next);
			if (View.isInitialised()
					&& this.getExtScript().getScriptUI() != null) {
				this.getExtScript().getScriptUI()
						.selectNode(node.getParent(), true);
			}
			this.updated(node);
			this.display(node, false);
		}
	}

	public boolean isSelectedZestOriginalRequestMessage(Message message) {
		if (message == null) {
			return false;
		}
		return View.getSingleton().getRequestPanel().getMessage() != null
				&& View.getSingleton().getRequestPanel().getMessage()
						.hashCode() == message.hashCode()
				&& this.isSelectedMessage(message);
	}

	public boolean isSelectedZestOriginalResponseMessage(Message message) {
		if (message == null) {
			return false;
		}
		return View.getSingleton().getResponsePanel().getMessage() != null
				&& View.getSingleton().getResponsePanel().getMessage()
						.hashCode() == message.hashCode()
				&& this.isSelectedMessage(message);
	}

	public ScriptNode getSelectedZestNode() {
		if (this.getExtScript().getScriptUI() == null) {
			return null;
		}
		if (ZestZapUtils.isZestNode(this.getExtScript().getScriptUI()
				.getSelectedNode())) {
			return this.getExtScript().getScriptUI().getSelectedNode();
		}
		return null;
	}

	public ZestElement getSelectedZestElement() {
		if (this.getExtScript().getScriptUI() == null) {
			return null;
		}
		return ZestZapUtils.getElement(this.getExtScript().getScriptUI()
				.getSelectedNode());
	}

	public List<ZestElement> getSelectedZestElements() {
		if (this.getExtScript().getScriptUI() == null) {
			return null;
		}
		List<ScriptNode> nodes = this.getExtScript().getScriptUI()
				.getSelectedNodes();
		LinkedList<ZestElement> elems = new LinkedList<>();
		for (ScriptNode node : nodes) {
			elems.add(ZestZapUtils.getElement(node));
		}
		return Collections.unmodifiableList(elems);
	}

	public boolean isSelectedZestRequestMessage(Message message) {
		if (message == null) {
			return false;
		}
		return View.getSingleton().getRequestPanel().getMessage() != null
				&& View.getSingleton().getRequestPanel().getMessage()
						.hashCode() == message.hashCode()
				&& this.getZestResultsPanel().isSelectedMessage(message);
	}

	public boolean isSelectedZestResponseMessage(Message message) {
		if (message == null) {
			return false;
		}
		return View.getSingleton().getResponsePanel().getMessage() != null
				&& View.getSingleton().getResponsePanel().getMessage()
						.hashCode() == message.hashCode()
				&& this.getZestResultsPanel().isSelectedMessage(message);
	}

	public boolean isScriptTree(Component component) {
		return this.getExtScript().getScriptUI() != null
				&& component != null
				&& this.getExtScript().getScriptUI().getTreeName()
						.equals(component.getName());
	}

	@Override
	public int getArrangeableListenerOrder() {
		return 0;
	}

	@Override
	public boolean onHttpRequestSend(HttpMessage msg) {
		return true;
	}

	
	private ScriptNode getDefaultStandAloneScript() {
		ScriptNode node = this.getSelectedZestNode();
		if (node != null) {
			// Theres a selected Zest node, is it a standalone one?
			ZestScriptWrapper script = this.getZestTreeModel().getScriptWrapper(node);
			if (script != null && ExtensionScript.TYPE_STANDALONE.equals(script.getTypeName())) {
				// right type, use if or the script if its not a container
				if (ZestZapUtils.getElement(node) instanceof ZestContainer) {
					return node;
				} else {
					return this.getZestTreeModel().getScriptWrapperNode(node);
				}
			}
			
		}
		// Is there already a default standalone Zest script
		for (ScriptNode zn : this.getZestScriptNodes(ExtensionScript.TYPE_STANDALONE)) {
			if (this.zestTreeModel.getScriptWrapper(zn).getName().equals(
					Constant.messages.getString("zest.targeted.script.default"))) {
				return zn;
			}
		}
		// No, create one
		ScriptWrapper sw = new ScriptWrapper();
		sw.setName(Constant.messages.getString("zest.targeted.script.default"));
		sw.setEngine(this.getZestEngineWrapper());
		sw.setEngineName(ZestScriptEngineFactory.NAME);
		sw.setType(this.getExtScript().getScriptType(
				ExtensionScript.TYPE_STANDALONE));
		ZestScriptWrapper script = new ZestScriptWrapper(sw);
		return this.add(script, false); 
	}
	 
	@Override
	public boolean onHttpResponseReceive(final HttpMessage msg) {
		String secProxyHeader = msg.getRequestHeader().getHeader(
				HTTP_HEADER_X_SECURITY_PROXY);
		if (secProxyHeader != null) {
			String[] vals = secProxyHeader.split(",");
			for (String val : vals) {
				if (VALUE_RECORD.equalsIgnoreCase(val.trim())) {
					// TODO check script prefix??
					
					EventQueue.invokeLater(new Runnable() {
						@Override
						public void run() {
							try {
								addToParent(getDefaultStandAloneScript(), msg, null);	
							} catch (Exception e) {
								logger.error(e.getMessage(), e);
							}
						}});
						
					break;
				}
			}
		}
		return true;
	}

	public void setCnpNodes(List<ScriptNode> cnpNodes) {
		this.cnpNodes = cnpNodes;
	}

	public void setCut(boolean cut) {
		this.cutNodes = cut;
	}

	public void pasteToNode(ScriptNode parent) {
		if (this.cnpNodes != null) {
			ScriptNode lastNode = null;
			for (int i = 0; i < cnpNodes.size(); i++) {
				lastNode = this.addToParent(parent,
						((ZestStatement) ZestZapUtils.getElement(cnpNodes
								.get(i))).deepCopy());
				if (cutNodes && !ZestZapUtils.isShadow(cnpNodes.get(i))) {
					this.delete(cnpNodes.get(i));
				}
			}
			refreshNode(parent);// refreshes the subtree starting from the
								// parent
			// Display the last node, otherwise the parent will be displayed if
			// we've done a delete
			this.display(lastNode, false);
		}
	}

	public void refreshNode(ScriptNode node) {
		if (node.isLeaf()) {
			return;
		} else {
			for (int i = 0; i < node.getChildCount(); i++) {
				this.getZestTreeModel().update((ScriptNode) node.getChildAt(i));
				refreshNode((ScriptNode) node.getChildAt(i));
			}
		}
	}

	private boolean canPasteIntoPassiveElement(ScriptNode node) {
		if (!(ZestZapUtils.getElement(node) instanceof ZestConditional)
				&& !(ZestZapUtils.getElement(node) instanceof ZestActionFail)) {
			return false;
		}
		for (int i = 0; i < node.getChildCount(); i++) {
			if (!canPasteIntoPassiveElement((ScriptNode) node.getChildAt(i))) {
				return false;
			}
		}
		if (node.getNextSibling() != null
				&& ZestZapUtils.isShadow((ScriptNode) node.getNextSibling())) {
			// The next node is a shadow one, eg an else node - need to check
			// this too
			if (!canPasteIntoPassiveElement(((ScriptNode) node.getNextSibling()))) {
				return false;
			}
		}
		return true;
	}

	public boolean canPasteNodesTo(ScriptNode node) {
		if (this.cnpNodes == null) {
			return false;
		}
		boolean isPassive = false;

		ZestScriptWrapper script = this.getZestTreeModel().getScriptWrapper(
				node);

		if (ExtensionPassiveScan.SCRIPT_TYPE_PASSIVE.equals(script.getType())) {
			isPassive = true;
		}

		for (ScriptNode cnpNode : this.cnpNodes) {
			if (cnpNode.isNodeDescendant(node)) {
				// Cant paste into a descendant of one of the cut/copied nodes
				return false;
			}
			if (isPassive && !this.canPasteIntoPassiveElement(cnpNode)) {
				return false;
			}
		}
		return true;
	}

	protected void refreshMessage() {
		ZestElement ze = this.getSelectedZestElement();
		if (ze != null && ze instanceof ZestRequest) {
			displayMessage((ZestRequest) ze);
		} else {
			clearMessage();
		}
	}

	public void displayMessage(ZestRequest ze) {
		if (!View.isInitialised()) {
			return;
		}
		try {
			lastSelectedMessage = ZestZapUtils.toHttpMessage(ze,
					ze.getResponse());
			if (lastSelectedMessage == null) {
				return;
			}

			if (lastSelectedMessage.getRequestHeader() != null) {
				logger.debug("displayMessage "
						+ lastSelectedMessage.getRequestHeader().getURI());
			} else {
				logger.debug("displayMessage null header");
			}

			if (lastSelectedMessage.getRequestHeader() == null) {
				View.getSingleton().getRequestPanel().clearView(true);
			} else {
				View.getSingleton().getRequestPanel()
						.setMessage(lastSelectedMessage);
			}

			if (lastSelectedMessage.getResponseHeader() == null) {
				View.getSingleton().getResponsePanel().clearView(false);
			} else {
				View.getSingleton().getResponsePanel()
						.setMessage(lastSelectedMessage, true);
			}
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}
	}

	private void clearMessage() {
		if (!View.isInitialised()) {
			return;
		}
		View.getSingleton().getRequestPanel().clearView(true);
		View.getSingleton().getResponsePanel().clearView(false);
		lastSelectedMessage = null;
	}

	public List<ScriptNode> getSelectedZestNodes() {
		List<ScriptNode> list = new ArrayList<ScriptNode>();
		if (this.getExtScript().getScriptUI() == null) {
			return list;
		}
		for (ScriptNode node : this.getExtScript().getScriptUI()
				.getSelectedNodes()) {
			if (ZestZapUtils.isZestNode(node)) {
				list.add(node);
			}
		}
		return Collections.unmodifiableList(list);
	}

	public void addResultToList(ZestResultWrapper href) {
		this.getZestResultsPanel().getModel().add(href);
		this.getZestResultsPanel().setTabFocus();
	}

	public void failLastResult(Exception e) {
		int lastRow = this.getZestResultsPanel().getModel().getRowCount() - 1;
		ZestResultWrapper zrw = (ZestResultWrapper) this.getZestResultsPanel()
				.getModel().getHistoryReference(lastRow);
		zrw.setPassed(false);
		// TODO use toUiFailureString varient?
		// zrw.setMessage(ZestZapUtils.toUiFailureString(za, response));
		zrw.setMessage(e.getMessage());
		this.getZestResultsPanel().getModel()
				.fireTableRowsUpdated(lastRow, lastRow);

	}

	public boolean isSelectedMessage(Message msg) {
		return lastSelectedMessage != null && lastSelectedMessage.equals(msg);
	}

	public void addMouseListener(MouseAdapter adapter) {
	}

	@Override
	public void preInvoke(ScriptWrapper script) {
		ScriptEngineWrapper ewrap = this.getExtScript().getEngineWrapper(
				ZestScriptEngineFactory.NAME);
		if (ewrap == null) {
			logger.error("Failed to find engine Mozilla Zest");
		} else if (script instanceof ZestScriptWrapper) {
			ScriptEngine engine = ewrap.getEngine();
			ZestScriptEngineFactory zsef = (ZestScriptEngineFactory) engine
					.getFactory();
			zsef.setRunner(new ZestZapRunner(this, (ZestScriptWrapper) script));
			clearResults();
			this.lastRunScript = ((ZestScriptWrapper) script).getZestScript();
		}
	}
	
	public void clearResults() {
		if (View.isInitialised()) {
			// Clear the previous results
			this.getZestResultsPanel().getModel().removeAllElements();
		}
	}

	@Override
	public void refreshScript(ScriptWrapper script) {
		// Ignore
	}

	@Override
	public void scriptAdded(ScriptWrapper script, boolean display) {
		if (View.isInitialised() && this.getExtScript().getScriptUI() != null
				&& script.getEngineName().equals(ZestScriptEngineFactory.NAME)) {

			ScriptNode typeNode = this.getExtScript().getTreeModel()
					.getTypeNode(script.getTypeName());
			if (typeNode == null) {
				logger.error("Failed to find type node: "
						+ script.getTypeName());

				typeNode = this.getExtScript().getTreeModel()
						.getTypeNode(ExtensionScript.TYPE_STANDALONE);
			}
			logger.debug("Adding Zest script to tree");

			ZestScriptWrapper zsw = new ZestScriptWrapper(script);
			if (zsw.getName() == null) {
				zsw.setName(script.getName());
			}

			ScriptNode parentNode = this.getExtScript().getTreeModel()
					.getNodeForScript(script);
			parentNode.setUserObject(zsw);

			this.getZestTreeModel().addScript(parentNode, zsw);
			this.updated(parentNode);

			// Map between ZAP script types and Zest script types - ZAP supports
			// more!
			Type ztype;
			switch (script.getType().getName()) {
			case ExtensionActiveScan.SCRIPT_TYPE_ACTIVE:
				ztype = Type.Active;
				break;
			case ExtensionPassiveScan.SCRIPT_TYPE_PASSIVE:
				ztype = Type.Passive;
				break;
			case ExtensionScript.TYPE_TARGETED:
				ztype = Type.Targeted;
				break;
			case ExtensionScript.TYPE_STANDALONE:
			default:
				ztype = Type.StandAlone;
				break;
			}

			if (display) {
				this.display(zsw, parentNode, true);
				this.dialogManager.showZestEditScriptDialog(parentNode, zsw,
						ztype, false);
			}
		}
	}

	@Override
	public void scriptRemoved(ScriptWrapper script) {
		// Ignore

	}

	@Override
	public void scriptChanged(ScriptWrapper script) {
		// Ignore
	}

	@Override
	public void scriptError(ScriptWrapper script) {
		// Ignore
	}

	@Override
	public void scriptSaved(ScriptWrapper script) {
		// Ignore
	}

	public ZestScript getLastRunScript() {
		return lastRunScript;
	}

}