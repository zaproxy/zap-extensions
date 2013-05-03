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

import java.awt.Dimension;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.swing.ImageIcon;

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestActionFail;
import org.mozilla.zest.core.v1.ZestActionFailException;
import org.mozilla.zest.core.v1.ZestAssertLength;
import org.mozilla.zest.core.v1.ZestAssertStatusCode;
import org.mozilla.zest.core.v1.ZestAssertion;
import org.mozilla.zest.core.v1.ZestConditional;
import org.mozilla.zest.core.v1.ZestContainer;
import org.mozilla.zest.core.v1.ZestElement;
import org.mozilla.zest.core.v1.ZestInvalidCommonTestException;
import org.mozilla.zest.core.v1.ZestJSON;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestResponse;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestStatement;
import org.mozilla.zest.core.v1.ZestTransformation;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.zest.dialogs.ZestRedactDialog;
import org.zaproxy.zap.extension.zest.dialogs.ZestTokenizeDialog;

public class ExtensionZest extends ExtensionAdaptor implements ZestRunnerListener, CommandLineListener, ProxyListener {
	
	public static final String NAME = "ExtensionZest";
	public static final ImageIcon ZEST_ICON = new ImageIcon(ExtensionZest.class.getResource("/org/zaproxy/zap/extension/zest/resource/fruit-orange.png"));
	
	public static final String HTTP_HEADER_X_SECURITY_PROXY = "X-Security-Proxy";
	public static final String VALUE_RECORD = "record";

	private static final Logger logger = Logger.getLogger(ExtensionZest.class);
	
	private ZestScriptsPanel zestScriptsPanel = null;
	private ZestResultsPanel zestResultsPanel = null;
	//private ZestDetailsPanel zestDetailsPanel = null;
	private ZestTreeModel treeModel = null;
	private ZestAddAssertionPopupMenu addAssertionPopupMenu = null;
	private ZestAddActionPopupMenu addActionPopupMenu = null;
	private ZestAddConditionPopupMenu addConditionPopupMenu = null;
	private ZestAddTransformationPopupMenu addTransformationPopupMenu = null;
	private ZestAddToScriptPopupMenu popupZestAddToMenu = null;
	private ZestCompareResponsePopupMenu compareResponsePopupMenu = null;
	private ZestPopupZestClose popupZestClose = null;
	private ZestPopupZestDelete popupZestDelete = null;
	private ZestPopupZestMove popupZestMoveUp = null;
	private ZestPopupZestMove popupZestMoveDown = null;
	
	private ZestPopupNodeCopyOrCut popupNodeCopy = null;
	private ZestPopupNodeCopyOrCut popupNodeCut = null;
	private ZestPopupNodePaste popupNodePaste = null;
	
	private ZestOriginalRequestPopupMenu redactRequestPopupMenu = null;
	private ZestOriginalRequestPopupMenu tokenizePopupMenu = null;
	private ZestScript lastRunScript = null;
	private ZestRedactDialog redactDialog = null;
	private ZestTokenizeDialog tokenizeDialog = null;
	
	//private ZestReqRespPopupMenu popupReqRespMenu = null;

	private ZestRunnerThread runner = null;

	// Cut-n-paste stuff
	private List<ZestNode> cnpNodes = null;
	private boolean cutNodes = false;


	private CommandLineArgument[] arguments = new CommandLineArgument[1];
    private static final int ARG_ZEST_IDX = 0;

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
		    
	    	//extensionHook.getHookView().addWorkPanel(this.getZestDetailsPanel());
	    	extensionHook.getHookView().addSelectPanel(this.getZestScriptsPanel());
	    	extensionHook.getHookView().addStatusPanel(this.getZestResultsPanel());
	    	
			extensionHook.getHookMenu().addPopupMenuItem(getAddTransformationPopupMenu());
			extensionHook.getHookMenu().addPopupMenuItem(getAddAssertionPopupMenu());
			extensionHook.getHookMenu().addPopupMenuItem(getAddActionPopupMenu());
			extensionHook.getHookMenu().addPopupMenuItem(getAddConditionPopupMenu());
			
			extensionHook.getHookMenu().addPopupMenuItem(getPopupZestAddToMenu());
			
			extensionHook.getHookMenu().addPopupMenuItem(getCompareResponsePopupMenu());
			
            extensionHook.getHookMenu().addPopupMenuItem(getPopupNodeCut ());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupNodeCopy ());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupNodePaste ());

            extensionHook.getHookMenu().addPopupMenuItem(getPopupZestMoveUp ());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupZestMoveDown ());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupZestClose ());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupZestDelete ());
            
            extensionHook.getHookMenu().addPopupMenuItem(getTokenizePopupMenu());
            extensionHook.getHookMenu().addPopupMenuItem(getRedactRequestPopupMenu());
            
	    }
	    
        extensionHook.addCommandLine(getCommandLineArguments());

	}
	/*
    @Override
	public boolean canUnload() {
    	return true;
    }
	
    @Override
	public void unload() {
	    if (getView() != null) {
	    	Control.getSingleton().getExtensionLoader().removeWorkPanel(getConsolePanel());
	    	Control.getSingleton().getExtensionLoader().removeToolsMenuItem(getMenuConsoleLink());
	    }
	}
*/
	
    private CommandLineArgument[] getCommandLineArguments() {
        arguments[ARG_ZEST_IDX] = new CommandLineArgument("-zest", 1, null, "", "-zest [zest_script_path]: DESC TBA and TBI.");
        return arguments;
    }


	protected ZestScriptsPanel getZestScriptsPanel() {
		if (zestScriptsPanel == null) {
			zestScriptsPanel = new ZestScriptsPanel(this);
		}
		return zestScriptsPanel;
	}
	
	private ZestResultsPanel getZestResultsPanel() {
		if ( zestResultsPanel == null) {
			 zestResultsPanel = new ZestResultsPanel(this);
		}
		return  zestResultsPanel;
	}
/*
	private ZestDetailsPanel getZestDetailsPanel() {
		if ( zestDetailsPanel == null) {
			 zestDetailsPanel = new ZestDetailsPanel(this);
		}
		return  zestDetailsPanel;
	}
*/
	private ZestAddToScriptPopupMenu getPopupZestAddToMenu() {
		if (popupZestAddToMenu == null) {
			popupZestAddToMenu = new ZestAddToScriptPopupMenu(this);
		}
		return popupZestAddToMenu;
	}

	private ZestAddTransformationPopupMenu getAddTransformationPopupMenu() {
		if (addTransformationPopupMenu == null) {
			addTransformationPopupMenu = new ZestAddTransformationPopupMenu(this);
		}
		return addTransformationPopupMenu;
	}

	private ZestAddAssertionPopupMenu getAddAssertionPopupMenu() {
		if (addAssertionPopupMenu == null) {
			addAssertionPopupMenu = new ZestAddAssertionPopupMenu(this);
		}
		return addAssertionPopupMenu;
	}

	private ZestAddActionPopupMenu getAddActionPopupMenu() {
		if (addActionPopupMenu == null) {
			addActionPopupMenu = new ZestAddActionPopupMenu(this);
		}
		return addActionPopupMenu;
	}
	
	private ZestAddConditionPopupMenu getAddConditionPopupMenu() {
		if (addConditionPopupMenu == null) {
			addConditionPopupMenu = new ZestAddConditionPopupMenu(this);
		}
		return addConditionPopupMenu;
	}
	
	private ZestCompareResponsePopupMenu getCompareResponsePopupMenu() {
		if (compareResponsePopupMenu == null) {
			compareResponsePopupMenu = new ZestCompareResponsePopupMenu(this);
		}
		return compareResponsePopupMenu;
	}
	
	private ZestPopupZestMove getPopupZestMoveUp () {
		if (popupZestMoveUp == null) {
			popupZestMoveUp = new ZestPopupZestMove(this, true); 
		}
		return popupZestMoveUp;
	}

	private ZestPopupZestMove getPopupZestMoveDown () {
		if (popupZestMoveDown == null) {
			popupZestMoveDown = new ZestPopupZestMove(this, false); 
		}
		return popupZestMoveDown;
	}
	
	private ZestPopupNodeCopyOrCut getPopupNodeCopy () {
		if (popupNodeCopy == null) {
			popupNodeCopy = new ZestPopupNodeCopyOrCut(this, false);
		}
		return popupNodeCopy;
	}
	
	private ZestPopupNodeCopyOrCut getPopupNodeCut () {
		if (popupNodeCut == null) {
			popupNodeCut = new ZestPopupNodeCopyOrCut(this, true);
		}
		return popupNodeCut;
	}
	
	private ZestPopupNodePaste getPopupNodePaste () {
		if (popupNodePaste == null) {
			popupNodePaste = new ZestPopupNodePaste(this);
		}
		return popupNodePaste;
	}


	private ZestPopupZestClose getPopupZestClose () {
		if (popupZestClose == null) {
			popupZestClose = new ZestPopupZestClose(this); 
		}
		return popupZestClose;
	}
	
	private ZestPopupZestDelete getPopupZestDelete () {
		if (popupZestDelete == null) {
			popupZestDelete = new ZestPopupZestDelete(this); 
		}
		return popupZestDelete;
	}
	
	private ZestOriginalRequestPopupMenu getTokenizePopupMenu() {
		if (tokenizePopupMenu == null) {
			tokenizePopupMenu = new ZestOriginalRequestPopupMenu(this, Constant.messages.getString("zest.token.popup"));
			tokenizePopupMenu.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                	ZestNode node = getZestScriptsPanel().getSelectedNode();
                	if (node != null && node.getZestElement() instanceof ZestRequest) {
                		ZestRequest request = (ZestRequest)node.getZestElement();
                		
	                	if (tokenizeDialog == null) {
	                		tokenizeDialog = new ZestTokenizeDialog(ExtensionZest.this, View.getSingleton().getMainFrame(), new Dimension(300, 300));
	                	}
                    	tokenizeDialog.init(getScriptWrapper(node), request, tokenizePopupMenu.getSelectedText());
	                	tokenizeDialog.setVisible(true);
                	}
                	
                }
            });

		}
		return tokenizePopupMenu;
	}
	
	private ZestOriginalRequestPopupMenu getRedactRequestPopupMenu() {
		if (redactRequestPopupMenu == null) {
			redactRequestPopupMenu = new ZestOriginalRequestPopupMenu(this, Constant.messages.getString("zest.redact.popup"));
			redactRequestPopupMenu.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                	ZestNode node = getZestScriptsPanel().getSelectedNode();
                	if (node != null && node.getZestElement() instanceof ZestRequest) {
                		ZestRequest request = (ZestRequest)node.getZestElement();
                		
                    	if (redactDialog == null) {
                    		redactDialog = new ZestRedactDialog(ExtensionZest.this, View.getSingleton().getMainFrame(), new Dimension(300, 300));
                    	}
                    	
                    	redactDialog.init(getScriptWrapper(node), request, request.getResponse(), tokenizePopupMenu.getSelectedText());
                    	redactDialog.setVisible(true);
                	}
                }
            });

		}
		return redactRequestPopupMenu;
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
			this.update(script, request);
		}
		if (replaceInAdded) {
			// TODO support redact in added reqs
		}
		// Good chance the current response has been changed
		this.getZestScriptsPanel().refreshMessage();
	}

	public void setToken (ZestScriptWrapper script, ZestRequest request, String replace,
			String token, boolean replaceInCurrent, boolean replaceInAdded) {
		// TODO add default value
		script.getTokens().addToken(token, replace);
		token = script.getTokens().getTokenStart() + token + script.getTokens().getTokenEnd(); 
		if (replaceInCurrent) {
			ZestStatement stmt = script.getNext();
			while (stmt != null) {
				if (stmt instanceof ZestRequest) {
					this.replaceInRequest((ZestRequest)stmt, replace, token);
				}
				stmt = stmt.getNext();
			}
		} else {
			this.replaceInRequest(request, replace, token);
			this.update(script, request);
		}
		if (replaceInAdded) {
			// TODO support tokens in added reqs
		}
		// Good chance the current response has been changed
		if (View.isInitialised()) {
			this.getZestScriptsPanel().refreshMessage();
			// TODO select token tab
			this.getZestScriptsPanel().showZestEditScriptDialog(script, false);
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

	/* Nor currently used
	private ZestReqRespPopupMenu getPopupReqRespMenu () {
		if (popupReqRespMenu == null) {
			popupReqRespMenu = new ZestReqRespPopupMenu(this);
		}
		return popupReqRespMenu;
	}
	*/

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
	
	protected ZestTreeModel getTreeModel() {
		if (this.treeModel == null) {
			this.treeModel = new ZestTreeModel();
		}
		return this.treeModel;
	}
	
	public void add (ZestScriptWrapper script) {
		logger.debug("add script " + script.getTitle());
		ZestNode node = this.getTreeModel().addScript(script);
		if (View.isInitialised()) {
			this.getZestScriptsPanel().setTabFocus();
			this.getZestScriptsPanel().expand(node);
		}
	}

	public void update(ZestScriptWrapper script) {
		logger.debug("update script " + script.getTitle());
		this.getTreeModel().update(script);
		this.scriptUpdated(script, this.getZestNode(script));
		if (View.isInitialised()) {
			this.getZestScriptsPanel().setTabFocus();
		}
	}

	public void remove(ZestScriptWrapper script) {
		this.getTreeModel().removeScript(script);
	}

	public void update(ZestElement parent, ZestElement child) {
		this.getTreeModel().update(parent, child);
		this.statementUpdated(parent);
	}

	protected List<ZestNode> getScriptNodes() {
		return this.getTreeModel().getScriptNodes();
	}

	public List<ZestScriptWrapper> getScripts() {
		List<ZestScriptWrapper> list = new ArrayList<ZestScriptWrapper>();
		for (ZestNode node : this.getTreeModel().getScriptNodes()) {
			if (node.getZestElement() instanceof ZestScriptWrapper) {
				list.add((ZestScriptWrapper)node.getZestElement());
			}
		}
		return list;
	}
	
	public List<ZestScriptWrapper> getPscanScripts() {
		List<ZestScriptWrapper> list = new ArrayList<ZestScriptWrapper>();
		for (ZestNode node : this.getTreeModel().getPscanNodes()) {
			if (node.getZestElement() instanceof ZestScriptWrapper) {
				list.add((ZestScriptWrapper)node.getZestElement());
			}
		}
		return list;
	}
	
	public ZestNode getZestNode(ZestElement element) {
		return this.getTreeModel().getZestNode(element);
	}

	public void addToScript(ZestScriptWrapper script, SiteNode sn) {
		this.addToScript(this.getZestNode(script), sn);
	}

	public void addToScript(ZestNode parent, SiteNode sn) {
		this.addToParent(parent, sn, null);
		this.scriptUpdated(this.getScriptWrapper(parent), parent);
	}
	
	private void scriptUpdated(ZestScriptWrapper script, ZestNode scriptNode) {
		if (! script.isUpdated()) {
			script.setUpdated(true);
			this.getTreeModel().nodeChanged(scriptNode);
			if (View.isInitialised()) {
				this.getZestScriptsPanel().setButtonStates();
			}
		}
	}
	
	private void statementUpdated(ZestElement req) {
		this.nodeUpdated(this.getZestNode(req));
	}
	
	private void nodeUpdated(ZestNode node) {
        while (node != null) {
        	if (node.getZestElement() instanceof ZestScriptWrapper) {
    	        this.scriptUpdated(((ZestScriptWrapper)node.getZestElement()), node);
    	        break;
        	}
        	node = (ZestNode) node.getParent();
        }
	}

	protected ZestScriptWrapper getScriptWrapper(ZestNode node) {
		if (node == null || node.getZestElement() == null) {
			return null;
		}
		if (node.getZestElement() instanceof ZestScriptWrapper) {
			return (ZestScriptWrapper) node.getZestElement();
		}
		return this.getScriptWrapper((ZestNode)node.getParent());
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
	
	public void addToParent(ZestNode parent, SiteNode sn, String prefix) {
		if (parent == null) {
			// They're gone for the 'new script' option...
			this.getZestScriptsPanel().showZestEditScriptDialog(null, false, prefix);
			this.getZestScriptsPanel().addDeferedNode(sn);
		} else {
			
			try {
				HttpMessage msg = sn.getHistoryReference().getHttpMessage();
				ZestRequest req = this.msgToZestRequest(msg);

				ZestElement ze = parent.getZestElement();
				ZestScriptWrapper script = null;
				if (ze instanceof ZestScriptWrapper) {
					script = (ZestScriptWrapper)ze;
					script.add(req);
				} else if (ze instanceof ZestConditional) {
					if (parent.isShadow()) {
						((ZestConditional)ze).addElse(req);
					} else {
						((ZestConditional)ze).addIf(req);
					}
					script = this.getScriptWrapper(parent);
				} else {
					throw new IllegalArgumentException("Unexpected parent node: " + ze.getElementType() + " " + parent.getNodeName());
				}
				
				if (script.isIncStatusCodeAssertion()) {
					ZestAssertStatusCode codeAssert = new ZestAssertStatusCode(msg.getResponseHeader().getStatusCode());
					req.addAssertion(codeAssert);
					
				}
				if (script.isIncLengthAssertion()) {
					ZestAssertLength lenAssert = new ZestAssertLength(msg.getResponseBody().length(), 0);
					lenAssert.setApprox(script.getLengthApprox());
					req.addAssertion(lenAssert);
				}
				
				// Update tree
				this.getTreeModel().addToNode(parent, req);
				if (View.isInitialised()) {
					this.getZestScriptsPanel().expand(parent);
				}
				this.scriptUpdated(script, parent);
				
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
	
	public void addToRequest(ZestRequest req, ZestAssertion assertion) {
		req.addAssertion(assertion);
		ZestNode node = this.getZestNode(req);
		if (node != null) {
			ZestNode child = this.getTreeModel().addToNode(node, assertion);
			this.nodeUpdated(child);
		} else {
			logger.error("Failed to find ZestRequest in tree " + ZestZapUtils.toUiString(req));
		}
	}

	public void addAfterRequest(ZestScript script, ZestStatement existingChild, ZestStatement newChild) {
		script.add(script.getIndex(existingChild)+1, newChild);
		ZestNode node = this.getZestNode(existingChild);
		if (node != null) {
			ZestNode child = this.getTreeModel().addAfterNode(node, newChild);
			this.nodeUpdated(child);
		} else {
			logger.error("Failed to find ZestRequest in tree " + ZestZapUtils.toUiString(existingChild));
		}
	}

	public void addToParent(ZestNode parent, ZestStatement newChild) {
		logger.debug("addToParent parent=" + parent.getNodeName() + " new=" + newChild.getElementType());
		ZestNode node;
		
		if (parent.getZestElement() instanceof ZestScript) {
			ZestScript zc = (ZestScript)parent.getZestElement();
			zc.add(newChild);
			node = this.getTreeModel().addToNode(parent, newChild);
			
		} else if (parent.getZestElement() instanceof ZestConditional) {
			ZestConditional zc = (ZestConditional)parent.getZestElement();
			
			if (parent.isShadow()) {
				zc.addElse(newChild);
			} else {
				zc.addIf(newChild);
			}
			node = this.getTreeModel().addToNode(parent, newChild);
			
		} else if (ZestTreeElement.Type.COMMON_TESTS.equals(parent.getTreeType())) {
			ZestScript zc = (ZestScript)parent.getParent().getZestElement();
			zc.addCommonTest(newChild);
			node = this.getTreeModel().addToNode(parent, newChild);
			
		} else {
			throw new IllegalArgumentException("Unexpected parent node: " + parent.getZestElement().getElementType() + " " + parent.getNodeName());
		}
		this.nodeUpdated(node);
	}

	public void addAfterRequest(ZestNode parent, ZestStatement existingChild, ZestStatement newChild) {
		logger.debug("addAfterRequest parent=" + parent.getNodeName() + 
				" existing=" + existingChild.getElementType() + " new=" + newChild.getElementType());
		
		if (parent.getZestElement() instanceof ZestScript) {
			this.addAfterRequest((ZestScript)parent.getZestElement(), existingChild, newChild);
			
		} else if (parent.getZestElement() instanceof ZestConditional) {
			ZestConditional zc = (ZestConditional)parent.getZestElement();
			
			if (parent.isShadow()) {
				zc.addElse(zc.getIndex(existingChild)+1, newChild);
			} else {
				zc.addIf(zc.getIndex(existingChild)+1, newChild);
			}
			ZestNode node = this.getZestNode(existingChild);
			if (node != null) {
				ZestNode child = this.getTreeModel().addAfterNode(node, newChild);
				this.nodeUpdated(child);
			} else {
				logger.error("Failed to find ZestRequest in tree " + ZestZapUtils.toUiString(existingChild));
			}
		} else {
			throw new IllegalArgumentException("Unexpected parent node: " + parent.getZestElement().getElementType() + " " + parent.getNodeName());
		}
	}

	public void addToRequest(ZestRequest req, ZestTransformation transformation) {
		req.addTransformation(transformation);
		ZestNode node = this.getZestNode(req);
		if (node != null) {
			ZestNode child = this.getTreeModel().addToNode(node, transformation);
			this.nodeUpdated(child);
		} else {
			logger.error("Failed to find ZestRequest in tree " + ZestZapUtils.toUiString(req));
		}
	}

	public void runScript(ZestScript script) {
		if (runner != null) {
			// last one still going..
			return;
		}
		this.lastRunScript = script;
		runner = new ZestRunnerThread(this, script);
		runner.addListener(this);
		
		if (View.isInitialised()) {
			this.getZestResultsPanel().getModel().removeAllElements();
			this.getZestResultsPanel().setTabFocus();
		}
		runner.start();
		
	}
	
	public boolean isScriptRunning() {
		return runner != null && ! runner.isStop();
	}

	public boolean isScriptPaused() {
		return runner != null && runner.isPaused();
	}

	public void pauseScript() {
		if (! this.isScriptRunning()) {
			return;
		}
		this.runner.pause();
	}

	public void resumeScript() {
		if (! this.isScriptPaused()) {
			return;
		}
		this.runner.resume();
	}

	public void stopScript() {
		if (! this.isScriptRunning()) {
			return;
		}
		this.runner.stop();
	}

	@Override
	public void notifyResponse(ZestResultWrapper href) {
		if (View.isInitialised()) {
			this.getZestResultsPanel().getModel().add(href);
			
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
		this.runner = null;
		if (View.isInitialised()) {
			this.getZestScriptsPanel().setButtonStates();
		}
	}

	public void saveScript(ZestScriptWrapper script, File file) throws IOException {
		script.setGeneratedBy(Constant.PROGRAM_NAME + " " + Constant.PROGRAM_VERSION);
		
	    BufferedWriter fw = new BufferedWriter(new FileWriter(file, false));
        fw.append(ZestJSON.toString(script.deepCopy()));
        fw.close();
        script.setFile(file);
        script.setUpdated(false);
	}
	
	public ZestScriptWrapper loadScript(File file) throws IOException {
	    BufferedReader fr = new BufferedReader(new FileReader(file));
	    StringBuilder sb = new StringBuilder();
        String line;
        while ((line = fr.readLine()) != null) {
            sb.append(line);
        }
        fr.close();
        ZestScriptWrapper zsw = new ZestScriptWrapper((ZestScript) ZestJSON.fromString(sb.toString()));
        zsw.setUpdated(false);
        zsw.setFile(file);
	    return zsw;
	}
	
/*	
	protected void showScriptsPanel(ZestScript script) {
		this.getZestDetailsPanel().showScriptPage(script);
		this.getZestDetailsPanel().requestFocus();
	}
*/

	public void delete(ZestNode node) {
		ZestNode parent = (ZestNode)node.getParent();
		this.getTreeModel().delete(node);
		this.nodeUpdated(parent);
	}

	public void moveNodeUp(ZestNode node) {
		ZestNode prev = (ZestNode) node.getPreviousSibling();
		if (prev != null && prev.isShadow()) {
			prev = (ZestNode) prev.getPreviousSibling();
		}
		if (prev == null) {
			logger.error("Cant move node up " + node.getNodeName());
			return;
		}
		if (node.getZestElement() instanceof ZestScript) {
			// Ignore
		} else if (node.getZestElement() instanceof ZestStatement) {
			ZestStatement req = (ZestStatement)node.getZestElement();
			ZestContainer parent = (ZestContainer)((ZestNode)node.getParent()).getZestElement();
			int index = parent.getIndex(req);
			parent.move(index-1, req);
			this.getTreeModel().switchNodes(prev, node);
			if (View.isInitialised()) {
				this.getZestScriptsPanel().expand((ZestNode)node.getParent());
				this.getZestScriptsPanel().select(node);
			}
			this.nodeUpdated(node);
		} else if (((ZestNode)node.getParent()).getZestElement() instanceof ZestRequest) {
			((ZestRequest)((ZestNode)node.getParent()).getZestElement()).moveUp(node.getZestElement());
			this.getTreeModel().switchNodes(prev, node);
			if (View.isInitialised()) {
				this.getZestScriptsPanel().expand((ZestNode)node.getParent());
				this.getZestScriptsPanel().select(node);
			}
			this.nodeUpdated(node);
		}
	}

	public void moveNodeDown(ZestNode node) {
		ZestNode next = (ZestNode) node.getNextSibling();
		if (next != null && next.isShadow()) {
			next = (ZestNode) next.getNextSibling();
		}
		if (next == null) {
			logger.error("Cant move node down " + node.getNodeName());
			return;
		}
		if (node.getZestElement() instanceof ZestScript) {
			// Ignore
		} else if (node.getZestElement() instanceof ZestStatement) {
			ZestStatement req = (ZestStatement)node.getZestElement();
			ZestContainer parent = (ZestContainer)((ZestNode)node.getParent()).getZestElement();
			int index = parent.getIndex(req);
			parent.move(index+1, req);
			this.getTreeModel().switchNodes(node, next);
			if (View.isInitialised()) {
				this.getZestScriptsPanel().expand((ZestNode)node.getParent());
				this.getZestScriptsPanel().select(node);
			}
			this.nodeUpdated(node);

		} else if (((ZestNode)node.getParent()).getZestElement() instanceof ZestRequest) {
			((ZestRequest)((ZestNode)node.getParent()).getZestElement()).moveDown(node.getZestElement());
			this.getTreeModel().switchNodes(node, next);
			if (View.isInitialised()) {
				this.getZestScriptsPanel().expand((ZestNode)node.getParent());
				this.getZestScriptsPanel().select(node);
			}
			this.nodeUpdated(node);
		}
	}

	public ZestScript getLastRunScript() {
		return lastRunScript;
	}

	@Override
	public void execute(CommandLineArgument[] args) {
        if (arguments[ARG_ZEST_IDX].isEnabled()) {
		    CommandLineArgument arg = arguments[ARG_ZEST_IDX];
            // ZAP: Removed unnecessary cast.
            File f = new File(arg.getArguments().get(0));
            
            if (f.exists()) {
                try {
	            	ZestScriptWrapper script = this.loadScript(f);
	            	this.runScript(script);
                } catch (Exception e) {
                	// ZAP: Log the exception
                	logger.error(e.getMessage(), e);
                }
            } else {
        		// TODO i18n cmdline
        		System.out.println("No such file: " + f.getAbsolutePath());
            }
            
        } else {
            return;
        }

	}
	public boolean isSelectedZestOriginalRequestMessage(Message message) {
		if (message == null) {
			return false;
		}
		return View.getSingleton().getRequestPanel().getMessage() != null &&
				View.getSingleton().getRequestPanel().getMessage().hashCode() == message.hashCode() &&
				this.getZestScriptsPanel().isSelectedMessage(message);
	}
	
	public boolean isSelectedZestOriginalResponseMessage(Message message) {
		if (message == null) {
			return false;
		}
		return View.getSingleton().getResponsePanel().getMessage() != null &&
				View.getSingleton().getResponsePanel().getMessage().hashCode() == message.hashCode() &&
				this.getZestScriptsPanel().isSelectedMessage(message);
	}
	
	protected ZestNode getSelectedScriptsNode() {
		return this.getZestScriptsPanel().getSelectedNode();
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

	@Override
	public int getArrangeableListenerOrder() {
		return 0;
	}

	@Override
	public boolean onHttpRequestSend(HttpMessage msg) {
		return true;
	}
	
	private ZestScriptWrapper getDefaultScript() {
		List<ZestScriptWrapper> scripts = this.getScripts();
		if (scripts.size() > 0) {
			return scripts.get(0);
		}
		ZestScriptWrapper script = new ZestScriptWrapper("Default", "", ZestScript.Type.Targeted);
		this.add(script);
		return script;
		
	}

	@Override
	public boolean onHttpResponseReceive(HttpMessage msg) {
		String secProxyHeader = msg.getRequestHeader().getHeader(HTTP_HEADER_X_SECURITY_PROXY);
		if (secProxyHeader != null) {
			String [] vals = secProxyHeader.split(",");
			for (String val : vals) {
				if (VALUE_RECORD.equalsIgnoreCase(val.trim())) {
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

						this.addToParent(this.getZestNode(script), req);
						
					} catch (MalformedURLException e) {
						logger.error(e.getMessage(), e);
					}
				}
			}
		}
		return true;
	}
	
	public void setCnpNodes(List<ZestNode> cnpNodes) {
		this.cnpNodes = cnpNodes;
	}

	public void setCut(boolean cut) {
		this.cutNodes = cut;
	}

	public void pasteToNode(ZestNode parent) {
		if (this.cnpNodes != null) {
			for (ZestNode node : this.cnpNodes) {
				this.addToParent(parent, ((ZestStatement) node.getZestElement()).deepCopy());
				if (cutNodes) {
					this.delete(node);
				}
			}
		}
	}
	
	private boolean canPasteIntoPassiveElement(ZestNode node) {
		if ( ! (node.getZestElement() instanceof ZestConditional) &&
				! (node.getZestElement() instanceof ZestActionFail)) {
			return false;
		}
		for (int i=0; i < node.getChildCount(); i++) {
			if (! canPasteIntoPassiveElement((ZestNode)node.getChildAt(i))) {
				return false;
			}
		}
		if ( node.getNextSibling() != null &&
				((ZestNode)node.getNextSibling()).isShadow()) {
			// The next node is a shadow one, eg an else node - need to check this too
			if (! canPasteIntoPassiveElement(((ZestNode)node.getNextSibling()))) {
				return false;
			}
		}
		return true;
	}

	public boolean canPasteNodesTo(ZestNode node) {
		if (this.cnpNodes == null) {
			return false;
		}
		boolean isPassive = false;
		if (node.isChildOf(ZestTreeElement.Type.COMMON_TESTS)) {
			isPassive = true;
		} else if (node.isChildOf(ZestTreeElement.Type.PASSIVE_SCRIPT)) {
			// Can only paste into common section of passive scripts
			return false;
		}
		
		for (ZestNode cnpNode : this.cnpNodes) {
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

}
