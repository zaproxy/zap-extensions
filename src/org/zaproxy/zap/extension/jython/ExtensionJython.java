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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.swing.ImageIcon;

import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.model.OptionsParam;
import org.python.core.Py;
import org.python.google.common.base.Strings;
import org.python.jsr223.PyScriptEngineFactory;
import org.zaproxy.zap.extension.script.ExtensionScript;

public class ExtensionJython extends ExtensionAdaptor implements OptionsChangedListener {

	public static final String NAME = "ExtensionJython";
	public static final ImageIcon PYTHON_ICON = new ImageIcon(
			ExtensionJython.class.getResource("/org/zaproxy/zap/extension/jython/resources/python.png"));

	private static final List<Class<?>> EXTENSION_DEPENDENCIES;

	static {
		List<Class<?>> dependencies = new ArrayList<>(1);
		dependencies.add(ExtensionScript.class);
		EXTENSION_DEPENDENCIES = Collections.unmodifiableList(dependencies);
	}

	private ExtensionScript extScript = null;
	private JythonOptionsParam jythonOptionsParam;
	private String modulePath;

	public ExtensionJython() {
		super(NAME);
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
		
		this.jythonOptionsParam = new JythonOptionsParam();
		extensionHook.addOptionsParamSet(this.jythonOptionsParam);
		if (null != super.getView()) {
			extensionHook.getHookView().addOptionPanel(new JythonOptionsPanel());
		}
		
		extensionHook.addOptionsChangedListener(this);
	}
	
	@Override
	public void optionsLoaded() {
		super.optionsLoaded();

		this.modulePath = this.jythonOptionsParam.getModulePath();
		if (!Strings.isNullOrEmpty(this.modulePath)) {
			Py.getSystemState().path.add(this.modulePath);
		}
	}
	
	@Override
	public void optionsChanged(OptionsParam optionsParam) {
		if (StringUtils.equals(this.modulePath, this.jythonOptionsParam.getModulePath())) {
			// not changed. nothing to do.
			return;
		}
		
		// remove the old path
		if (!Strings.isNullOrEmpty(this.modulePath)) {
			Py.getSystemState().path.remove(this.modulePath);
		}

		// add the new path
		this.modulePath = this.jythonOptionsParam.getModulePath();
		if (!Strings.isNullOrEmpty(this.modulePath)) {
			Py.getSystemState().path.add(this.modulePath);
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

	@Override
	public List<Class<?>> getDependencies() {
		return EXTENSION_DEPENDENCIES;
	}
}
