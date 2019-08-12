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
package org.zaproxy.zap.extension.jruby;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.swing.ImageIcon;
import org.jruby.embed.jsr223.JRubyEngineFactory;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEventListener;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class ExtensionJruby extends ExtensionAdaptor implements ScriptEventListener {

    public static final String NAME = "ExtensionJruby";
    public static final ImageIcon RUBY_ICON;

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionScript.class);
        EXTENSION_DEPENDENCIES = Collections.unmodifiableList(dependencies);

        RUBY_ICON =
                View.isInitialised()
                        ? new ImageIcon(
                                ExtensionJruby.class.getResource(
                                        "/org/zaproxy/zap/extension/jruby/resources/ruby.png"))
                        : null;
    }

    private ExtensionScript extScript = null;
    private ScriptEngine rubyScriptEngine = null;
    private JrubyEngineWrapper engineWrapper;

    public ExtensionJruby() {
        super(NAME);
        this.setOrder(76);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (this.getRubyScriptEngine() == null) {
            JRubyEngineFactory factory = new JRubyEngineFactory();
            this.rubyScriptEngine = factory.getScriptEngine();
            engineWrapper = new JrubyEngineWrapper(this.rubyScriptEngine, getDefaultTemplates());
            this.getExtScript().registerScriptEngineWrapper(engineWrapper);
        }

        this.getExtScript().addListener(this);
    }

    private List<Path> getDefaultTemplates() {
        AddOn addOn = getAddOn();
        if (addOn == null) {
            // Probably running from source...
            return Collections.emptyList();
        }

        List<String> files = addOn.getFiles();
        if (files == null || files.isEmpty()) {
            return Collections.emptyList();
        }

        ArrayList<Path> defaultTemplates = new ArrayList<>(files.size());
        Path zapHome = Paths.get(Constant.getZapHome());
        for (String file : files) {
            if (file.startsWith(ExtensionScript.TEMPLATES_DIR)) {
                defaultTemplates.add(zapHome.resolve(file));
            }
        }
        defaultTemplates.trimToSize();
        return defaultTemplates;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        if (rubyScriptEngine != null) {
            String engineName = rubyScriptEngine.getFactory().getEngineName();
            for (ScriptType type : this.getExtScript().getScriptTypes()) {
                for (ScriptWrapper script : this.getExtScript().getScripts(type)) {
                    if (script.getEngineName().equals(engineName)) {
                        if (script instanceof JrubyScriptWrapper) {
                            ScriptNode node =
                                    this.getExtScript().getTreeModel().getNodeForScript(script);
                            node.setUserObject(((JrubyScriptWrapper) script).getOriginal());
                        }
                    }
                }
            }
        }

        getExtScript().removeListener(this);

        if (engineWrapper != null) {
            getExtScript().removeScriptEngineWrapper(engineWrapper);
        }
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
            extScript =
                    (ExtensionScript)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionScript.NAME);
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
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
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

        if (this.getRubyScriptEngine() != null
                && this.getRubyScriptEngine()
                        .getFactory()
                        .getEngineName()
                        .equals(script.getEngineName())) {

            // Replace the standard ScriptWrapper with a JrubyScriptWrapper as
            // JRuby seems to handle interfaces differently from other JSR223 languages
            ScriptNode parentNode = this.getExtScript().getTreeModel().getNodeForScript(script);

            parentNode.setUserObject(new JrubyScriptWrapper(script));
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
