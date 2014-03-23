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
package org.zaproxy.zap.extension.jython;

import java.net.MalformedURLException;
import java.net.URL;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.swing.ImageIcon;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.python.jsr223.PyScriptEngineFactory;
import org.zaproxy.zap.extension.script.ExtensionScript;

public class ExtensionJython extends ExtensionAdaptor {

	public static final String NAME = "ExtensionJython";
	public static final ImageIcon PYTHON_ICON = new ImageIcon(
			ExtensionJython.class.getResource("/org/zaproxy/zap/extension/jython/resource/python.png"));

	private ExtensionScript extScript = null;

	public ExtensionJython() {
		super();
		initialize();
	}

	/**
	 * @param name
	 */
	public ExtensionJython(String name) {
		super(name);
	}

	/**
	 * This method initializes this
	 */
	private void initialize() {
		this.setName(NAME);
		this.setOrder(74);
	}

	@Override
	public void hook(ExtensionHook extensionHook) {
		super.hook(extensionHook);


		ScriptEngineManager mgr = new ScriptEngineManager();
		
		ScriptEngine se = mgr.getEngineByExtension("py");

		if (se == null) {
			PyScriptEngineFactory factory = new PyScriptEngineFactory();
			this.getExtScript().registerScriptEngineWrapper(new JythonEngineWrapper(factory.getScriptEngine()));
		}
	}

	@Override
	public boolean canUnload() {
		return false;
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
		return Constant.messages.getString("jython.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_HOMEPAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}
}
