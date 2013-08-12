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
import java.awt.event.MouseAdapter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.swing.ImageIcon;

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestActionFail;
import org.mozilla.zest.core.v1.ZestActionFailException;
import org.mozilla.zest.core.v1.ZestAssertion;
import org.mozilla.zest.core.v1.ZestAssignFailException;
import org.mozilla.zest.core.v1.ZestConditional;
import org.mozilla.zest.core.v1.ZestContainer;
import org.mozilla.zest.core.v1.ZestElement;
import org.mozilla.zest.core.v1.ZestExpressionLength;
import org.mozilla.zest.core.v1.ZestExpressionStatusCode;
import org.mozilla.zest.core.v1.ZestInvalidCommonTestException;
import org.mozilla.zest.core.v1.ZestJSON;
import org.mozilla.zest.core.v1.ZestLoop;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestResponse;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestScript.Type;
import org.mozilla.zest.core.v1.ZestStatement;
import org.mozilla.zest.impl.ZestScriptEngineFactory;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
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

public class ExtensionZest extends ExtensionAdaptor implements ZestRunnerListener, ProxyListener, ScriptEventListener {
	
	public static final String NAME = "ExtensionZest";
	public static final ImageIcon ZEST_ICON = new ImageIcon(ExtensionZest.class.getResource("/org/zaproxy/zap/extension/zest/resource/fruit-orange.png"));
	
	public static final String HTTP_HEADER_X_SECURITY_PROXY = "X-Security-Proxy";
	public static final String VALUE_RECORD = "record";

	private static final Logger logger = Logger.getLogger(ExtensionZest.class);
	
	private ZestResultsPanel zestResultsPanel = null;
	
	private ZestZapRunner runner = null;
	private ZestTreeModel zestTreeModel = null;
	private ZestDialogManager dialogManager = null;
	private ZestEngineWrapper zestEngineWrapper = null;

	private ExtensionScript extScript = null;
	private HttpMessage lastMessageDisplayed = null;
	private ZestScript lastRunScript = null;
	
	private ZestFuzzerDelegate fuzzerMessenger=null;
	
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
        this.setOrder(73);	// Almost looks like ZE ;)
	}
	
	@Override
	public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);

	    //extensionHook.addOptionsParamSet(getScriptParam());
	    
	    if (getView() != null) {
		    extensionHook.addProxyListener(this);
		    
	    	extensionHook.getHookView().addStatusPanel(this.getZestResultsPanel());

            this.dialogManager = new ZestDialogManager(this, this.getExtScript().getScriptUI()); 
            new ZestMenuManager(this, extensionHook);
	    }
        
        ScriptEngineManager mgr = new ScriptEngineManager();
        ScriptEngine se = mgr.getEngineByName(ZestScriptEngineFactory.NAME);
        if (se != null) {
        	// Looks like this only works if the Zest lib is in the top level lib directory
        	zestEngineWrapper = new ZestEngineWrapper(se);
            this.getExtScript().registerScriptEngineWrapper(zestEngineWrapper);

			if (se.getFactory() instanceof ZestScriptEngineFactory) {
				ZestScriptEngineFactory zsef = (ZestScriptEngineFactory) se.getFactory();
				zsef.setRunner(this.getRunner());
			} else {
	        	logger.error("Factory not an instance of ZestScriptEngineFactory: " + se.getFactory().getClass().getCanonicalName());
			}
        
        } else {
        	// Needed for when the Zest lib is in an add-on (usual case)
        	ZestScriptEngineFactory zsef = new ZestScriptEngineFactory();
			zsef.setRunner(this.getRunner());
        	zestEngineWrapper = new ZestEngineWrapper(zsef.getScriptEngine());
            this.getExtScript().registerScriptEngineWrapper(zestEngineWrapper);
        	
        }
        this.getExtScript().addListener(this);
        
        if (this.getExtScript().getScriptUI() != null) {
            ZestTreeCellRenderer renderer = new ZestTreeCellRenderer();
        	this.getExtScript().getScriptUI().addRenderer(ZestElementWrapper.class, renderer);
        	this.getExtScript().getScriptUI().disableScriptDialog(ZestScriptWrapper.class);
        }
	}
	
	public ZestFuzzerDelegate getFuzzerDelegate(){
		if(fuzzerMessenger==null){
			fuzzerMessenger=new ZestFuzzerDelegate("LoopDialogFuzz", this);
//			fuzzerMessenger=new ZestFuzzerMessenger();
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
			extScript = (ExtensionScript) Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.NAME);
		}
		return extScript;
	}
	
	public ZestDialogManager getDialogManager() {
		return dialogManager;
	}


	private ZestResultsPanel getZestResultsPanel() {
		if ( zestResultsPanel == null) {
			 zestResultsPanel = new ZestResultsPanel(this);
		}
		return  zestResultsPanel;
	}
	
	public ZestTreeModel getZestTreeModel() {
		if (zestTreeModel == null) {
			zestTreeModel = new ZestTreeModel(this.getExtScript().getTreeModel());
		}
		return zestTreeModel;
	}
	
	public void redact (ZestScript script, ZestRequest request, ZestResponse response, String replace,
			String replaceWith, boolean replaceInCurrent, boolean replaceInAdded) {
		if (replaceInCurrent) {
			ZestStatement stmt = script.getNext();
			while (stmt != null) {
				if (stmt instanceof ZestRequest) {
					this.replaceInResponse((ZestRequest)stmt, replace, replaceWith);
					stmt = stmt.getNext();
				}
			}
		} else {
			this.replaceInResponse(request, replace, replaceWith);
			// TODO
			//this.update(script, request);
		}
		if (replaceInAdded) {
			// TODO support redact in added reqs
		}
		// Good chance the current response has been changed
		this.refreshMessage();
	}

	public void setToken (ZestScriptWrapper script, ZestRequest request, String replace,
			String token, boolean replaceInCurrent, boolean replaceInAdded) {
		// TODO add default value
		script.getZestScript().getTokens().addToken(token, replace);
		token = script.getZestScript().getTokens().getTokenStart() + token + script.getZestScript().getTokens().getTokenEnd(); 
		if (replaceInCurrent) {
			ZestStatement stmt = script.getZestScript().getNext();
			while (stmt != null) {
				if (stmt instanceof ZestRequest) {
					this.replaceInRequest((ZestRequest)stmt, replace, token);
				}
				stmt = stmt.getNext();
			}
		} else {
			this.replaceInRequest(request, replace, token);
			//this.updated(node);
			// TODO
			//this.update(script.getZestScript(), request);
		}
		if (replaceInAdded) {
			// TODO support tokens in added reqs
		}
		// Good chance the current response has been changed
		if (View.isInitialised()) {
			this.refreshMessage();
			// TODO select token tab
			//this.dialogManager.showZestEditScriptDialog(script, ZestScript.Type.Targeted);
		}
	}

	private void replaceInResponse (ZestRequest request, String replace, String replaceWith) {
		ZestResponse resp = request.getResponse();
		if (resp != null) {
			request.setResponse(new ZestResponse(
					request.getUrl(),
					resp.getHeaders().replace(replace, replaceWith),
					resp.getBody().replace(replace, replaceWith), +
					resp.getStatusCode(),
					resp.getResponseTimeInMs()));
		}
		
	}

	private void replaceInRequest (ZestRequest request, String replace, String replaceWith) {
		ZestResponse resp = request.getResponse();
		if (resp != null) {
			try {
				request.setUrl(new URL(request.getUrl().toString().replace(replace, replaceWith)));
			} catch (MalformedURLException e) {
				logger.error(e.getMessage(), e);
			}
			request.setHeaders(request.getHeaders().replace(replace, replaceWith));
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
	
	public ScriptNode add (ZestScriptWrapper script) {
		logger.debug("add script " + script.getName());
		
		ScriptNode node = this.getExtScript().addScript(script);
		this.display(script, node, true);
		return node;
	}

	public void display (ZestScriptWrapper script, ScriptNode node, boolean expand) {
		if (View.isInitialised() && this.getExtScript().getScriptUI() != null) {
			this.getExtScript().getScriptUI().selectNode(node, expand);
			this.getExtScript().getScriptUI().displayScript(script);
		}
	}

	public void display (ScriptNode node, boolean expand) {
		logger.debug("Display node=" + node.getNodeName() + " expand=" + expand);
		if (View.isInitialised() && this.getExtScript().getScriptUI() != null) {
			this.getExtScript().getScriptUI().displayScript(this.getZestTreeModel().getScriptWrapper(node));
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
			for (ScriptNode node : this.getExtScript().getTreeModel().getNodes(type.getName())) {
				if (ZestZapUtils.isZestNode(node)) {
					list.add(node);
				}
			}
		}
		return Collections.unmodifiableList(list);
	}

	public List<ScriptNode> getZestScriptNodes(String type) {
		List<ScriptNode> list = new ArrayList<ScriptNode>();
		
		for (ScriptNode node : this.getExtScript().getTreeModel().getNodes(type)) {
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

	private ZestRequest msgToZestRequest(HttpMessage msg) throws MalformedURLException {
		ZestRequest req = new ZestRequest();
		req.setUrl(new URL(msg.getRequestHeader().getURI().toString()));
		req.setMethod(msg.getRequestHeader().getMethod());
		this.setHeaders(req, msg);
		req.setData(msg.getRequestBody().toString());
		req.setResponse(new ZestResponse(
				req.getUrl(),
				msg.getResponseHeader().toString(), 
				msg.getResponseBody().toString(),
				msg.getResponseHeader().getStatusCode(),
				msg.getTimeElapsedMillis()));
		return req;
	}

	public void addToParent(ScriptNode parent, SiteNode sn, String prefix) {
		try {
			this.addToParent(parent, sn.getHistoryReference().getHttpMessage(), prefix);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}
	}

	public void addToParent(ScriptNode parent, HttpMessage msg, String prefix) {
		if (parent == null) {
			// They're gone for the 'new script' option...
			logger.debug("addToParent parent=null msg=" + msg.getRequestHeader().getURI());
			this.dialogManager.showZestEditScriptDialog(null, null, ZestScript.Type.Targeted, prefix);
			if (msg != null) {
				this.dialogManager.addDeferedMessage(msg);
			}
		} else {
			logger.debug("addToParent parent=" + parent.getNodeName() + " msg=" + msg.getRequestHeader().getURI());
			
			try {
				ZestRequest req = this.msgToZestRequest(msg);
				ZestScriptWrapper zsw = this.getZestTreeModel().getScriptWrapper(parent);
				
				ZestScript script = zsw.getZestScript();
				ZestElement parentZe = ZestZapUtils.getElement(parent);
				
				if (parentZe instanceof ZestScript) {
					script.add(req);
				} else if (parentZe instanceof ZestConditional) {
					if (ZestZapUtils.isShadow(parent)) {
						((ZestConditional)ZestZapUtils.getElement(parent)).addElse(req);
					} else {
						((ZestConditional)ZestZapUtils.getElement(parent)).addIf(req);
					}
				} else if (parentZe instanceof ZestLoop) {
						((ZestLoop<?>)ZestZapUtils.getElement(parent)).addStatement(req);
				} 
				else {
					throw new IllegalArgumentException("Unexpected parent node: " + 
							parentZe.getElementType() + " " + parent.getNodeName());
				}
				
				if (zsw.isIncStatusCodeAssertion()) {
					req.addAssertion(
							new ZestAssertion(
									new ZestExpressionStatusCode(msg.getResponseHeader().getStatusCode())));
					
				}
				if (zsw.isIncLengthAssertion()) {
					req.addAssertion(
							new ZestAssertion(
									new ZestExpressionLength(msg.getResponseBody().length(), zsw.getLengthApprox())));
				}
			
				// Update tree
				ScriptNode reqNode = this.getZestTreeModel().addToNode(parent, req);

				this.updated(reqNode);
				this.display(reqNode, false);
				
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
		}
	}
	
	private void setHeaders(ZestRequest req, HttpMessage msg) {
		// TODO filter some headers out??
		String [] headers = msg.getRequestHeader().getHeadersAsString().split(HttpHeader.CRLF);
		StringBuilder sb = new StringBuilder();
		for (String header : headers) {
			if (header.toLowerCase().startsWith(HttpHeader.CONTENT_TYPE.toLowerCase())) {
				sb.append(header);
				sb.append(HttpHeader.CRLF);
			}
		}
		req.setHeaders(sb.toString());
	}
	
	public void addToRequest(ScriptNode node, ZestRequest req, ZestAssertion assertion) {
		req.addAssertion(assertion);
		if (node != null) {
			ScriptNode child = this.getZestTreeModel().addToNode(node, assertion);
			this.updated(child);
			this.display(child, false);
		} else {
			throw new IllegalArgumentException("Failed to find ZestRequest in tree " + ZestZapUtils.toUiString(req));
		}
	}

	public void addAfterRequest(ZestScript script, ScriptNode childNode, ZestStatement existingChild, ZestStatement newChild) {
		script.add(script.getIndex(existingChild)+1, newChild);
		ScriptNode child = this.getZestTreeModel().addAfterNode(childNode, newChild);
		this.updated(child);
		this.display(child, false);
	}
	
	public final ScriptNode addToParent(ScriptNode parent, ZestStatement newChild) {
		logger.debug("addToParent parent=" + parent.getNodeName() + " new=" + newChild.getElementType());
		ScriptNode node;
		
		if (ZestZapUtils.getElement(parent) instanceof ZestScript) {
			ZestScript zc = (ZestScript)ZestZapUtils.getElement(parent);
			zc.add(newChild);
			node = this.getZestTreeModel().addToNode(parent, newChild);			
		} else if (ZestZapUtils.getElement(parent) instanceof ZestConditional) {
			ZestConditional zc = (ZestConditional)ZestZapUtils.getElement(parent);
			
			if (ZestZapUtils.isShadow(parent)) {
				zc.addElse(newChild);
			} else {
				zc.addIf(newChild);
			}
			node = this.getZestTreeModel().addToNode(parent, newChild);
			
		} else if (ZestZapUtils.getElement(parent) instanceof ZestLoop){
			ZestLoop<?> zl=(ZestLoop<?>) ZestZapUtils.getElement(parent);
			zl.addStatement(newChild);
			node= this.getZestTreeModel().addToNode(parent, newChild);
		}	else {
			throw new IllegalArgumentException("Unexpected parent node: " + ZestZapUtils.getElement(parent) + " " + parent.getNodeName());
		}
		this.updated(node);
		this.display(node, false);
		return node;
	}

	public void addAfterRequest(ScriptNode parent, ScriptNode childNode, ZestStatement existingChild, ZestStatement newChild) {
		logger.debug("addAfterRequest parent=" + parent.getNodeName() + 
				" existing=" + existingChild.getElementType() + " new=" + newChild.getElementType());
		
		if (ZestZapUtils.getElement(parent) instanceof ZestScript) {
			this.addAfterRequest((ZestScript)ZestZapUtils.getElement(parent), 
					childNode, existingChild, newChild);
			
		} else if (ZestZapUtils.getElement(parent) instanceof ZestConditional) {
			ZestConditional zc = (ZestConditional)ZestZapUtils.getElement(parent);
			
			if (ZestZapUtils.isShadow(parent)) {
				zc.addElse(zc.getIndex(existingChild)+1, newChild);
			} else {
				zc.addIf(zc.getIndex(existingChild)+1, newChild);
			}
			ScriptNode child = this.getZestTreeModel().addAfterNode(parent, newChild);
			this.updated(child);
			this.display(child, false);
		} else {
			throw new IllegalArgumentException("Unexpected parent node: " + ZestZapUtils.getElement(parent) + " " + parent.getNodeName());
		}
	}

	@Override
	public void notifyResponse(ZestResultWrapper href) {
		if (View.isInitialised()) {
			this.getZestResultsPanel().getModel().add(href);
			this.getZestResultsPanel().setTabFocus();
			
		} else {
			// TODO i18n for cmdline??
			try {
				System.out.println("Response: " + href.getURI() + " passed = " + href.isPassed() + " code=" + href.getStatusCode());
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
		}
	}
	
	public void notifyActionFail (ZestActionFailException e) {
		if (View.isInitialised()) {
			int lastRow = this.getZestResultsPanel().getModel().getRowCount()-1;
			ZestResultWrapper zrw = (ZestResultWrapper)this.getZestResultsPanel().getModel().getHistoryReference(lastRow);
			zrw.setPassed(false);
			// TODO use toUiFailureString varient?
			//zrw.setMessage(ZestZapUtils.toUiFailureString(za, response));
			zrw.setMessage(e.getMessage());

			this.getZestResultsPanel().getModel().fireTableRowsUpdated(lastRow, lastRow);
			
		} else {
			// TODO i18n for cmdline??
			// TODO check type first? toUiFailureString as above?
			System.out.println("Action: failed: " + e.getMessage());
		}
	}
	
	public void notifyAssignFail (ZestAssignFailException e) {
		if (View.isInitialised()) {
			int lastRow = this.getZestResultsPanel().getModel().getRowCount()-1;
			ZestResultWrapper zrw = (ZestResultWrapper)this.getZestResultsPanel().getModel().getHistoryReference(lastRow);
			zrw.setPassed(false);
			// TODO use toUiFailureString varient?
			//zrw.setMessage(ZestZapUtils.toUiFailureString(za, response));
			zrw.setMessage(e.getMessage());

			this.getZestResultsPanel().getModel().fireTableRowsUpdated(lastRow, lastRow);
			
		} else {
			// TODO i18n for cmdline??
			// TODO check type first? toUiFailureString as above?
			System.out.println("Assign: failed: " + e.getMessage());
		}
	}
	
	public void notifyZestInvalidCommonTestFail (ZestInvalidCommonTestException e) {
		if (View.isInitialised()) {
			int lastRow = this.getZestResultsPanel().getModel().getRowCount()-1;
			ZestResultWrapper zrw = (ZestResultWrapper)this.getZestResultsPanel().getModel().getHistoryReference(lastRow);
			zrw.setPassed(false);
			// TODO use toUiFailureString varient?
			//zrw.setMessage(ZestZapUtils.toUiFailureString(za, response));
			zrw.setMessage(e.getMessage());

			this.getZestResultsPanel().getModel().fireTableRowsUpdated(lastRow, lastRow);
			
		} else {
			// TODO i18n for cmdline??
			// TODO check type first? toUiFailureString as above?
			System.out.println("Action: failed: " + e.getMessage());
		}
	}
	
	public void notifyAlert(Alert alert) {
		if (View.isInitialised()) {
			int row = this.getZestResultsPanel().getModel().getIndex(alert.getMessage());
			if (row >= 0) {
				ZestResultWrapper zrw = (ZestResultWrapper) this.getZestResultsPanel().getModel().getHistoryReference(row);
				zrw.setMessage(alert.getAlert());
				zrw.setPassed(false);
				this.getZestResultsPanel().getModel().fireTableRowsUpdated(row, row);
			}
		}
	}

	public void notifyChanged(ZestResultWrapper lastResult) {
		if (View.isInitialised()) {
			try {
				int row = this.getZestResultsPanel().getModel().getIndex(lastResult.getHttpMessage());
				if (row >= 0) {
					this.getZestResultsPanel().getModel().fireTableRowsUpdated(row, row);
				}
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
		}
	}


	@Override
	public void notifyComplete() {
		// Ignore
	}

	public void delete(ScriptNode node) {
		ScriptNode parent = (ScriptNode)node.getParent();
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
			ZestStatement req = (ZestStatement)ZestZapUtils.getElement(node);
			ZestContainer parent = (ZestContainer)ZestZapUtils.getElement(node.getParent());
			int index = parent.getIndex(req);
			parent.move(index-1, req);
			this.getZestTreeModel().switchNodes(prev, node);
			if (View.isInitialised() && this.getExtScript().getScriptUI() != null) {
				this.getExtScript().getScriptUI().selectNode(node.getParent(), true);
			}
			this.updated(node);
			this.display(node, false);
		} else if (ZestZapUtils.getElement(node.getParent()) instanceof ZestRequest) {
			ZestRequest parent = (ZestRequest)ZestZapUtils.getElement(node.getParent());
			parent.moveUp(ZestZapUtils.getElement(node));
			this.getZestTreeModel().switchNodes(prev, node);
			if (View.isInitialised() && this.getExtScript().getScriptUI() != null) {
				this.getExtScript().getScriptUI().selectNode(node.getParent(), true);
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
			ZestStatement req = (ZestStatement)ZestZapUtils.getElement(node);
			ZestContainer parent = (ZestContainer)ZestZapUtils.getElement(node.getParent());
			int index = parent.getIndex(req);
			parent.move(index+1, req);
			this.getZestTreeModel().switchNodes(node, next);
			if (View.isInitialised() && this.getExtScript().getScriptUI() != null) {
				this.getExtScript().getScriptUI().selectNode(node.getParent(), true);
			}
			this.updated(node);
			this.display(node, false);

		} else if (ZestZapUtils.getElement(node.getParent()) instanceof ZestRequest) {
			ZestRequest parent = (ZestRequest)ZestZapUtils.getElement(node.getParent());
			parent.moveUp(ZestZapUtils.getElement(node));
			this.getZestTreeModel().switchNodes(node, next);
			if (View.isInitialised() && this.getExtScript().getScriptUI() != null) {
				this.getExtScript().getScriptUI().selectNode(node.getParent(), true);
			}
			this.updated(node);
			this.display(node, false);
		}
	}

	public boolean isSelectedZestOriginalRequestMessage(Message message) {
		if (message == null) {
			return false;
		}
		return View.getSingleton().getRequestPanel().getMessage() != null &&
				View.getSingleton().getRequestPanel().getMessage().hashCode() == message.hashCode() &&
				this.isSelectedMessage(message);
	}
	
	public boolean isSelectedZestOriginalResponseMessage(Message message) {
		if (message == null) {
			return false;
		}
		return View.getSingleton().getResponsePanel().getMessage() != null &&
				View.getSingleton().getResponsePanel().getMessage().hashCode() == message.hashCode() &&
				this.isSelectedMessage(message);
	}
	
	public ScriptNode getSelectedZestNode() {
		if (this.getExtScript().getScriptUI() == null) {
			return null;
		}
		if (ZestZapUtils.isZestNode(this.getExtScript().getScriptUI().getSelectedNode())) {
			return this.getExtScript().getScriptUI().getSelectedNode();
		}
		return null;
	}

	public ZestElement getSelectedZestElement() {
		if (this.getExtScript().getScriptUI() == null) {
			return null;
		}
		return ZestZapUtils.getElement(this.getExtScript().getScriptUI().getSelectedNode());
	}
	
	public List<ZestElement> getSelectedZestElements(){
		if (this.getExtScript().getScriptUI() == null) {
			return null;
		}
		List<ScriptNode> nodes=this.getExtScript().getScriptUI().getSelectedNodes();
		LinkedList<ZestElement> elems=new LinkedList<>();
		for(ScriptNode node:nodes){
			elems.add(ZestZapUtils.getElement(node));
		}
		return Collections.unmodifiableList(elems);
	}


	public boolean isSelectedZestRequestMessage(Message message) {
		if (message == null) {
			return false;
		}
		return View.getSingleton().getRequestPanel().getMessage() != null &&
				View.getSingleton().getRequestPanel().getMessage().hashCode() == message.hashCode() &&
				this.getZestResultsPanel().isSelectedMessage(message);
	}

	public boolean isSelectedZestResponseMessage(Message message) {
		if (message == null) {
			return false;
		}
		return View.getSingleton().getResponsePanel().getMessage() != null &&
				View.getSingleton().getResponsePanel().getMessage().hashCode() == message.hashCode() &&
				this.getZestResultsPanel().isSelectedMessage(message);
	}
	
	public boolean isScriptTree(Component component) {
		return this.getExtScript().getScriptUI() != null && 
				component != null &&
				this.getExtScript().getScriptUI().getTreeName().equals(component.getName()); 
	}

	@Override
	public int getArrangeableListenerOrder() {
		return 0;
	}

	@Override
	public boolean onHttpRequestSend(HttpMessage msg) {
		return true;
	}
	/*
	private ZestScriptWrapper getDefaultScript() {
		List<ZestScriptWrapper> scripts = this.getScripts();
		if (scripts.size() > 0) {
			return scripts.get(0);
		}
		ZestScriptWrapper script = new ZestScriptWrapper("Default", "", ZestScript.Type.Targeted);
		this.add(script);
		return script;
		
	}
*/
	@Override
	public boolean onHttpResponseReceive(HttpMessage msg) {
		String secProxyHeader = msg.getRequestHeader().getHeader(HTTP_HEADER_X_SECURITY_PROXY);
		if (secProxyHeader != null) {
			String [] vals = secProxyHeader.split(",");
			for (String val : vals) {
				if (VALUE_RECORD.equalsIgnoreCase(val.trim())) {
					/*
					try {
						ZestScriptWrapper script = this.getDefaultScript();
						ZestRequest req = this.msgToZestRequest(msg);

						if (script.isIncStatusCodeAssertion()) {
							ZestAssertStatusCode codeAssert = new ZestAssertStatusCode(msg.getResponseHeader().getStatusCode());
							req.addAssertion(codeAssert);
							
						}
						if (script.isIncLengthAssertion()) {
							ZestAssertLength lenAssert = new ZestAssertLength(msg.getResponseBody().length(), 0);
							lenAssert.setApprox(script.getLengthApprox());
							req.addAssertion(lenAssert);
						}

						this.addToParent(this.getScriptNode(script), req);
						
					} catch (MalformedURLException e) {
						logger.error(e.getMessage(), e);
					}
					*/
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
			for (int i=0; i<cnpNodes.size(); i++) {
				lastNode = this.addToParent(parent, ((ZestStatement) ZestZapUtils.getElement(cnpNodes.get(i))).deepCopy());
				if (cutNodes && !ZestZapUtils.isShadow(cnpNodes.get(i))) {
					this.delete(cnpNodes.get(i));
				}
			}
			refreshNode(parent);//refreshes the subtree starting from the parent
			// Display the last node, otherwise the parent will be displayed if we've done a delete
			this.display(lastNode, false);
		}
	}
	public void refreshNode(ScriptNode node){
		if(node.isLeaf()){
			return;
		}
		else{
			for(int i=0; i<node.getChildCount(); i++){
				this.getZestTreeModel().update((ScriptNode)node.getChildAt(i));
				refreshNode((ScriptNode)node.getChildAt(i));
			}
		}
	}
	
	private boolean canPasteIntoPassiveElement(ScriptNode node) {
		if ( ! (ZestZapUtils.getElement(node) instanceof ZestConditional) &&
				! (ZestZapUtils.getElement(node) instanceof ZestActionFail)) {
			return false;
		}
		for (int i=0; i < node.getChildCount(); i++) {
			if (! canPasteIntoPassiveElement((ScriptNode)node.getChildAt(i))) {
				return false;
			}
		}
		if ( node.getNextSibling() != null &&
				ZestZapUtils.isShadow((ScriptNode)node.getNextSibling())) {
			// The next node is a shadow one, eg an else node - need to check this too
			if (! canPasteIntoPassiveElement(((ScriptNode)node.getNextSibling()))) {
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
		
		ZestScriptWrapper script = this.getZestTreeModel().getScriptWrapper(node);
		
		if (ExtensionPassiveScan.SCRIPT_TYPE_PASSIVE.equals(script.getType())) {
			isPassive = true;
		// TODO
		/*
		} else if (node.isChildOf(ZestTreeElement.Type.PASSIVE_SCRIPT)) {
			// Can only paste into common section of passive scripts
			return false;
		*/
		}
		
		for (ScriptNode cnpNode : this.cnpNodes) {
			if (cnpNode.isNodeDescendant(node)) {
				// Cant paste into a descendant of one of the cut/copied nodes
				return false;
			}
			if (isPassive && ! this.canPasteIntoPassiveElement(cnpNode)) {
				return false;
			}
		}
		return true;
	}

    protected void refreshMessage() {
	    ZestElement ze = this.getSelectedZestElement();
        if (ze != null && ze instanceof ZestRequest) {
        	displayMessage((ZestRequest)ze); 
        } else {
        	clearMessage();
        }
    }

    private void displayMessage(ZestRequest ze) {
    	if (! View.isInitialised()) {
    		return;
    	}
		try {
			lastMessageDisplayed = ZestZapUtils.toHttpMessage(ze, ze.getResponse());
			if (lastMessageDisplayed == null) {
				return;
			}
			
	    	if (lastMessageDisplayed.getRequestHeader() != null) {
	    		logger.debug("displayMessage " + lastMessageDisplayed.getRequestHeader().getURI());
	    	} else {
	    		logger.debug("displayMessage null header");
	    	}
	    	
	        if (lastMessageDisplayed.getRequestHeader() != null && lastMessageDisplayed.getRequestHeader().isEmpty()) {
	            View.getSingleton().getRequestPanel().clearView(true);
	        } else {
	        	View.getSingleton().getRequestPanel().setMessage(lastMessageDisplayed);
	        }
	        
	        if (lastMessageDisplayed.getResponseHeader() != null && lastMessageDisplayed.getResponseHeader().isEmpty()) {
	        	View.getSingleton().getResponsePanel().clearView(false);
	        } else {
	        	View.getSingleton().getResponsePanel().setMessage(lastMessageDisplayed, true);
	        }
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}
    }
    
    private void clearMessage() {
    	if (! View.isInitialised()) {
    		return;
    	}
        View.getSingleton().getRequestPanel().clearView(true);
    	View.getSingleton().getResponsePanel().clearView(false);
    	this.lastMessageDisplayed = null;
    }
//    public boolean isSelectedZestNode(ScriptNode node){
//    	for(ScriptNode tmpNode:getSelectedZestNodes()){
//    		if(tmpNode.equals(node)){
//    			return true;
//    		}
//    	}
//    	return false;
//    }
	public List<ScriptNode> getSelectedZestNodes() {
		List<ScriptNode> list = new ArrayList<ScriptNode>();
		if (this.getExtScript().getScriptUI() == null) {
			return list;
		}
		for (ScriptNode node : this.getExtScript().getScriptUI().getSelectedNodes()) {
			if (ZestZapUtils.isZestNode(node)) {
				list.add(node);
			}
		}
		return Collections.unmodifiableList(list);
	}
	
	public boolean isSelectedMessage(Message msg) {
		return false;
	}
	
	public void addMouseListener(MouseAdapter adapter) {
	}

	private ZestZapRunner getRunner() {
		if (runner == null) {
			runner = new ZestZapRunner(this);
			runner.addListener(this);
		}
		return runner;
	}
	
	@Override
	public void preInvoke(ScriptWrapper script) {
		ScriptEngineWrapper ewrap = this.getExtScript().getEngineWrapper(ZestScriptEngineFactory.NAME);
		if (ewrap == null) {
			logger.error("Failed to find engine Mozilla Zest");
		} else {
			ScriptEngine engine = ewrap.getEngine();
			ZestScriptEngineFactory zsef = (ZestScriptEngineFactory) engine.getFactory();
			zsef.setRunner(this.getRunner());
			if (View.isInitialised()) {
				// Clear the previous results
				this.getZestResultsPanel().getModel().removeAllElements();
			}
			if (script instanceof ZestScriptWrapper) {
				this.lastRunScript = ((ZestScriptWrapper)script).getZestScript();
			}
		}
	}

	@Override
	public void refreshScript(ScriptWrapper script) {
		// Ignore
	}

	@Override
	public void scriptAdded(ScriptWrapper script, boolean display) {
		if (View.isInitialised() && 
				this.getExtScript().getScriptUI() != null &&
				script.getEngineName().equals(ZestScriptEngineFactory.NAME)) {

			ScriptNode typeNode = this.getExtScript().getTreeModel().getTypeNode(script.getTypeName());
			if (typeNode == null) {
				logger.error("Failed to find type node: " + script.getTypeName());
				
				typeNode = this.getExtScript().getTreeModel().getTypeNode("standalone");
			}
			logger.debug("Adding Zest script to tree");
			
	        ZestScriptWrapper zsw = new ZestScriptWrapper(script);
	        if (zsw.getName() == null) {
	        	zsw.setName(script.getName());
	        }

			ScriptNode parentNode = this.getExtScript().getTreeModel().getNodeForScript(script);
			parentNode.setUserObject(zsw);

	        this.getZestTreeModel().addScript(parentNode, zsw);
	        this.updated(parentNode);

	        // TODO support other types!
	    	Type ztype = Type.Targeted;
	    	/*
	    	switch (script.getType().getName()) {
	    	case 
	    	}
	    	*/
	    	if (display) {
		        this.display(zsw, parentNode, true);
	    		this.dialogManager.showZestEditScriptDialog(parentNode, zsw, ztype);
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
