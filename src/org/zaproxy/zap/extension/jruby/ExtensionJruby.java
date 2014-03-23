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
package org.zaproxy.zap.extension.jruby;

import java.net.MalformedURLException;
import java.net.URL;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.swing.ImageIcon;

import org.jruby.embed.jsr223.JRubyEngineFactory;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEventListener;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class ExtensionJruby extends ExtensionAdaptor implements ScriptEventListener {

	public static final String NAME = "ExtensionJruby";
	public static final ImageIcon RUBY_ICON = new ImageIcon(
			ExtensionJruby.class.getResource("/org/zaproxy/zap/extension/jruby/resource/ruby.png"));

	private ExtensionScript extScript = null;
	private ScriptEngine rubyScriptEngine = null;

	public ExtensionJruby() {
		super();
		initialize();
	}

	/**
	 * @param name
	 */
	public ExtensionJruby(String name) {
		super(name);
	}

	/**
	 * This method initializes this
	 */
	private void initialize() {
		this.setName(NAME);
		this.setOrder(76);
	}

	@Override
	public void hook(ExtensionHook extensionHook) {
		super.hook(extensionHook);

		if (this.getRubyScriptEngine() == null) {
			JRubyEngineFactory factory = new JRubyEngineFactory();
			this.rubyScriptEngine = factory.getScriptEngine();
			this.getExtScript().registerScriptEngineWrapper(new JrubyEngineWrapper(this.rubyScriptEngine));
		}

		this.getExtScript().addListener(this);
	}

	@Override
	public boolean canUnload() {
		return false;
	}
	
	private ScriptEngine getRubyScriptEngine() {
		if (this.rubyScriptEngine == null) {
			ScriptEngineManager mgr = new ScriptEngineManager();
			this.rubyScriptEngine = mgr.getEngineByExtension("rb");
		}
		return this.rubyScriptEngine;
	}

	private ExtensionScript getExtScript() {
		if (extScript == null) {
			extScript = (ExtensionScript) Control.getSingleton()
					.getExtensionLoader().getExtension(ExtensionScript.NAME);
		}
		return extScript;
	}


	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("jruby.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_HOMEPAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}
	
	@Override
	public void preInvoke(ScriptWrapper script) {
		// Ignore
	}

	@Override
	public void refreshScript(ScriptWrapper script) {
		// Ignore
	}

	@Override
	public void scriptAdded(ScriptWrapper script, boolean arg1) {
		
		if (this.getRubyScriptEngine() != null &&
				this.getRubyScriptEngine().getFactory().getEngineName().equals(script.getEngineName())) {

			// Replace the standard ScriptWrapper with a JrubyScriptWrapper as
			// JRuby seems to handle interfaces differently from other JSR223 languages
			ScriptNode parentNode = this.getExtScript().getTreeModel().getNodeForScript(script);
			
			JrubyScriptWrapper jsw = new JrubyScriptWrapper();
			jsw.setName(script.getName());
			jsw.setType(script.getType());
			jsw.setContents(script.getContents());
			jsw.setDescription(script.getDescription());
			jsw.setEnabled(script.isEnabled());
			jsw.setEngine(script.getEngine());
			jsw.setFile(script.getFile());
			jsw.setLoadOnStart(script.isLoadOnStart());
			
			parentNode.setUserObject(jsw);
		}

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
	public void scriptRemoved(ScriptWrapper script) {
		// Ignore
	}

	@Override
	public void scriptSaved(ScriptWrapper script) {
		// Ignore
	}

	@Override
	public void templateAdded(ScriptWrapper script, boolean arg1) {
		// Ignore
	}

	@Override
	public void templateRemoved(ScriptWrapper script) {
		// Ignore
	}
}
