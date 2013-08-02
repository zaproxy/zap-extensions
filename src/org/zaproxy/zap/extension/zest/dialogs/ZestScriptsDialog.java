/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2013 ZAP development team
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

import java.awt.Dimension;
import java.awt.Frame;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestAuthentication;
import org.mozilla.zest.core.v1.ZestHttpAuthentication;
import org.mozilla.zest.core.v1.ZestJSON;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestScript;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.encoder.Base64;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ZestScriptsDialog extends StandardFieldsDialog {

	private static final String FIELD_TITLE = "zest.dialog.script.label.title"; 
	private static final String FIELD_PREFIX = "zest.dialog.script.label.prefix"; 
	private static final String FIELD_DESC = "zest.dialog.script.label.desc";
	private static final String FIELD_AUTH_SITE = "zest.dialog.script.label.authsite";
	private static final String FIELD_AUTH_REALM = "zest.dialog.script.label.authrealm";
	private static final String FIELD_AUTH_USER = "zest.dialog.script.label.authuser";
	private static final String FIELD_AUTH_PASSWORD = "zest.dialog.script.label.authpwd";
	private static final String FIELD_STATUS = "zest.dialog.script.label.statuscode";
	private static final String FIELD_LENGTH = "zest.dialog.script.label.length";
	private static final String FIELD_APPROX = "zest.dialog.script.label.approx";
	private static final String FIELD_LOAD = "zest.dialog.script.label.load";

	private static final Logger logger = Logger.getLogger(ZestScriptsDialog.class);

	private static final long serialVersionUID = 1L;

	private ExtensionZest extension = null;
	private ScriptNode parentNode = null;
	private ZestScriptWrapper scriptWrapper = null;
	private ZestScript script = null;
	private boolean add = false;
	private ZestScript.Type type;

	private ScriptTokensTableModel tokensModel = null;

	private List<HttpMessage> deferedMessages = new ArrayList<HttpMessage>();

	public ZestScriptsDialog(ExtensionZest ext, Frame owner, Dimension dim) {
		super(owner, "zest.dialog.script.add.title", dim,
				new String[] {
					"zest.dialog.script.tab.main",
					"zest.dialog.script.tab.tokens",
					"zest.dialog.script.tab.auth",
					"zest.dialog.script.tab.defaults"});
		this.extension = ext;
	}

	public void init (ScriptNode parentNode, ZestScriptWrapper scriptWrapper, boolean add, ZestScript.Type type) {
		this.parentNode = parentNode;
		this.scriptWrapper = scriptWrapper;
		this.script = scriptWrapper.getZestScript();
		this.add = add;
		this.type = type;

		this.removeAllFields();
		
		if (add) {
			this.setTitle(Constant.messages.getString("zest.dialog.script.add.title"));
		} else {
			this.setTitle(Constant.messages.getString("zest.dialog.script.edit.title"));
		}
		this.addTextField(0, FIELD_TITLE, script.getTitle());
		this.addTextField(0, FIELD_PREFIX, script.getPrefix());
		this.addCheckBoxField(0, FIELD_LOAD, scriptWrapper.isLoadOnStart());
		this.addMultilineField(0, FIELD_DESC, script.getDescription());
		
		this.getTokensModel().setValues(script.getTokens().getTokens());
		this.addTableField(1, this.getTokensModel());
		
		if (ZestScript.Type.Targeted.equals(type)) {
			// These fields are only relevant for targeted scripts, not passive scan rules
			boolean addedAuth = false;
			if (script.getAuthentication() != null && script.getAuthentication().size() > 0) {
				// Just support one for now
				ZestAuthentication auth = script.getAuthentication().get(0);
				if (auth instanceof ZestHttpAuthentication) {
					ZestHttpAuthentication zha = (ZestHttpAuthentication) auth;
					this.addTextField(2, FIELD_AUTH_SITE, zha.getSite());
					this.addTextField(2, FIELD_AUTH_REALM, zha.getRealm());
					this.addTextField(2, FIELD_AUTH_USER, zha.getUsername());
					this.addTextField(2, FIELD_AUTH_PASSWORD, zha.getPassword());
					this.addPadding(2);
					addedAuth = true;
				}
			}
			if (! addedAuth) {
				this.addTextField(2, FIELD_AUTH_SITE, "");
				this.addTextField(2, FIELD_AUTH_REALM, "");
				this.addTextField(2, FIELD_AUTH_USER, "");
				this.addTextField(2, FIELD_AUTH_PASSWORD, "");
				this.addPadding(2);
			}
			
			this.addCheckBoxField(3, FIELD_STATUS, scriptWrapper.isIncStatusCodeAssertion());
			this.addCheckBoxField(3, FIELD_LENGTH, scriptWrapper.isIncLengthAssertion());
			this.addNumberField(3, FIELD_APPROX, 0, 100, scriptWrapper.getLengthApprox());
			this.addPadding(3);
		}
		
		//this.requestFocus(FIELD_TITLE);
	}

	
	private ScriptTokensTableModel getTokensModel() {
		if (tokensModel == null) {
			tokensModel = new ScriptTokensTableModel();
		}
		return tokensModel;
	}

	public void save() {
		script.setTitle(this.getStringValue(FIELD_TITLE));
		script.setDescription(this.getStringValue(FIELD_DESC));
		if (script.getPrefix() == null || ! script.getPrefix().equals(this.getStringValue(FIELD_PREFIX))) {
			try {
				script.setPrefix(this.getStringValue(FIELD_PREFIX));
			} catch (MalformedURLException e) {
				logger.error(e.getMessage(), e);
			}
		}
		
		scriptWrapper.setName(script.getTitle());
		scriptWrapper.setDescription(script.getDescription());
		scriptWrapper.setContents(ZestJSON.toString(script));
		scriptWrapper.setLoadOnStart(this.getBoolValue(FIELD_LOAD));

		script.setType(type);
		if (ZestScript.Type.Targeted.equals(type)) {
			scriptWrapper.setIncStatusCodeAssertion(this.getBoolValue(FIELD_STATUS));
			scriptWrapper.setIncLengthAssertion(this.getBoolValue(FIELD_LENGTH));
			scriptWrapper.setLengthApprox(this.getIntValue(FIELD_APPROX));
			
			Map<String, String> tokens = new HashMap<String, String>();
			for (String[] nv : getTokensModel().getValues()) {
				tokens.put(nv[0], nv[1]);
			}
			
			script.getTokens().setTokens(tokens);
			
			// Just support one auth for now
			script.setAuthentication(new ArrayList<ZestAuthentication>());
			if (! this.isEmptyField(FIELD_AUTH_SITE)) {
				ZestHttpAuthentication zha = new ZestHttpAuthentication();
				zha.setSite(this.getStringValue(FIELD_AUTH_SITE));
				zha.setRealm(this.getStringValue(FIELD_AUTH_REALM));
				zha.setUsername(this.getStringValue(FIELD_AUTH_USER));
				zha.setPassword(this.getStringValue(FIELD_AUTH_PASSWORD));
				script.addAuthentication(zha);
			}
		} else if (ZestScript.Type.Active.equals(type)) {
			// Create a template simple script
			script.getTokens().addToken("target.value", "__replace__");
			ZestRequest req = new ZestRequest();
			req.setMethod("{{target.method}}");
			req.setUrlToken("{{target.url}}");
			req.setHeaders("{{target.headers}}");
			req.setData("{{target.body}}");
			script.add(req);
		}

		if (add) {
			parentNode = extension.add(scriptWrapper);
			// Add any defered messages
			for (HttpMessage msg : deferedMessages) {
				logger.debug("Adding defered message: " + msg.getRequestHeader().getURI().toString());
				extension.addToParent(parentNode, msg, null);
			}
			deferedMessages.clear();
		}
		extension.updated(parentNode);
	}

	@Override
	public String validateFields() {
		if (this.isEmptyField(FIELD_TITLE)) {
			return Constant.messages.getString("zest.dialog.script.error.title");
		}
		if (!this.isEmptyField(FIELD_PREFIX)) {
			try {
				new URL(this.getStringValue(FIELD_PREFIX));
			} catch (Exception e) {
				return Constant.messages.getString("zest.dialog.script.error.prefix");
			}
		}

		return null;
	}

	public void addDeferedMessage(HttpMessage msg) {
		this.deferedMessages.add(msg);
		
		if (this.isEmptyField(FIELD_AUTH_SITE)) {
			try {
				// Check to see if basic authentication was used
				HttpRequestHeader header = msg.getRequestHeader();
				String auth = header.getHeader(HttpHeader.AUTHORIZATION);
				if (auth != null && auth.length() > 0) {
					if (auth.toLowerCase().startsWith("basic ")) {
						String userPword = new String(Base64.decode(auth.substring(6)));
						int colon = userPword.indexOf(":");
						if (colon > 0) {
							this.setFieldValue(FIELD_AUTH_SITE, header.getHostName());
							this.setFieldValue(FIELD_AUTH_USER, userPword.substring(0, colon));
							this.setFieldValue(FIELD_AUTH_PASSWORD, userPword.substring(colon+1));
						}
					}
				}
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
		}
	}

}
