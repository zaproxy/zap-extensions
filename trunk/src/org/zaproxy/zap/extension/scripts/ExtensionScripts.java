/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP development team
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
package org.zaproxy.zap.extension.scripts;

import java.io.StringWriter;
import java.io.Writer;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.ResourceBundle;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.swing.JMenuItem;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.utils.DesktopUtils;

public class ExtensionScripts extends ExtensionAdaptor {
	
	public static final String NAME = "ExtensionScripts";
	private static final String LANG_ENGINE_SEP = " : ";
	protected static final String SCRIPT_CONSOLE_HOME_PAGE = "http://code.google.com/p/zaproxy/wiki/ScriptConsole";
	
	private ConsolePanel consolePanel = null;
	private ScriptEngineManager mgr = new ScriptEngineManager();
	private ScriptParam scriptParam = null;
	private JMenuItem menuConsoleLink = null;
	
    private static ResourceBundle messages = null;

    public ExtensionScripts() {
        super();
 		initialize();
    }

    /**
     * @param name
     */
    public ExtensionScripts(String name) {
        super(name);
    }

	/**
	 * This method initializes this
	 */
	private void initialize() {
        this.setName(NAME);
        this.setOrder(60);
        // Load extension specific language files - these are held in the extension jar
        messages = ResourceBundle.getBundle(
        		this.getClass().getPackage().getName() + ".Messages", Constant.getLocale());
	}
	
	@Override
	public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);

	    extensionHook.addOptionsParamSet(getScriptParam());
	    
	    if (getView() != null) {
	        ExtensionHookView pv = extensionHook.getHookView();
	        pv.addWorkPanel(getConsolePanel());
	        extensionHook.getHookMenu().addToolsMenuItem(getMenuConsoleLink());
	    }
	}
	
	private ConsolePanel getConsolePanel() {
		if (consolePanel == null) {
			consolePanel = new ConsolePanel(this);
		    consolePanel.setName(ExtensionScripts.getMessageString("scripts.panel.title"));
		}
		return consolePanel;
	}
	
	public List<String> getScriptingEngines() {
		List <String> engineNames = new ArrayList<>();
		List<ScriptEngineFactory> engines = mgr.getEngineFactories();
		for (ScriptEngineFactory engine : engines) {
			engineNames.add(engine.getLanguageName() + LANG_ENGINE_SEP + engine.getEngineName());
		}
		Collections.sort(engineNames);
		return engineNames;
	}

	public String runScript (String engineName, String script) throws ScriptException {
		StringWriter writer = new StringWriter();
		this.runScript(engineName, script, writer);		
		return writer.toString();
	}

	public void runScript (String engineName, String script, Writer writer) throws ScriptException {
		
		try {
			
			String name = engineName.substring(0, engineName.indexOf(LANG_ENGINE_SEP));
			ScriptEngine engine = mgr.getEngineByName(name);
			
			if (engine == null) {
				throw new ScriptException("Failed to find script engine: " + name);
			}

		    engine.getContext().setWriter(writer);

			engine.eval(script);
			
		} catch (ScriptException e) {
			throw e;
		} catch (Exception e) {
			throw new ScriptException(e);
		}
	}

	protected ScriptParam getScriptParam() {
		if (this.scriptParam == null) {
			this.scriptParam = new ScriptParam();
			// NASTY! Need to find a cleaner way of getting the configs to load before the UI
			this.scriptParam.load(Model.getSingleton().getOptionsParam().getConfig());
		}
		return this.scriptParam;
	}

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return getMessageString("scripts.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_HOMEPAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}
	
	private JMenuItem getMenuConsoleLink() {
        if (menuConsoleLink == null) {
        	menuConsoleLink = new JMenuItem();
        	menuConsoleLink.setText(getMessageString("scripts.topmenu.tools.consoleLink"));

        	menuConsoleLink.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
            		// Open the Script Console wiki page using the default browser
                	DesktopUtils.openUrlInBrowser(SCRIPT_CONSOLE_HOME_PAGE);
                }
            });
        }
        return menuConsoleLink;
	}

	public static String getMessageString (String key) {
		if (messages == null) {
			return null;
		}
		return messages.getString(key);
	}

}
