/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.groovy;

import groovy.lang.GroovyClassLoader;
import java.util.ArrayList;
import java.util.List;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import javax.swing.ImageIcon;
import org.codehaus.groovy.jsr223.GroovyScriptEngineFactory;
import org.codehaus.groovy.jsr223.GroovyScriptEngineImpl;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.zaproxy.zap.control.ExtensionFactory;
import org.zaproxy.zap.extension.script.DefaultEngineWrapper;

public class GroovyEngineWrapper extends DefaultEngineWrapper {

    private final ScriptEngineFactory factory;
    private final GroovyClassLoader classLoader;

    public GroovyEngineWrapper() {
        this(new GroovyScriptEngineFactory());
    }

    private GroovyEngineWrapper(GroovyScriptEngineFactory factory) {
        super(factory);
        this.factory = factory;
        // Use AddOnLoader as parent class loader to allow access to (all) add-on classes.
        this.classLoader =
                new GroovyClassLoader(
                        new AddOnClassLoaderWrapper(ExtensionFactory.getAddOnLoader()));
    }

    @Override
    public ImageIcon getIcon() {
        return ExtensionGroovy.GROOVY_ICON;
    }

    @Override
    public String getSyntaxStyle() {
        return SyntaxConstants.SYNTAX_STYLE_GROOVY;
    }

    @Override
    public List<String> getExtensions() {
        List<String> list = new ArrayList<>();
        list.add("groovy");
        return list;
    }

    @Override
    public boolean isRawEngine() {
        return false;
    }

    @Override
    public ScriptEngine getEngine() {
        GroovyScriptEngineImpl scriptEngine =
                (GroovyScriptEngineImpl) this.factory.getScriptEngine();
        scriptEngine.setClassLoader(classLoader);
        return scriptEngine;
    }
}
