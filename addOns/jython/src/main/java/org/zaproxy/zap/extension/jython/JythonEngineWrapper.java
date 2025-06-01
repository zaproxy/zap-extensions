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
package org.zaproxy.zap.extension.jython;

import java.util.ArrayList;
import java.util.List;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import javax.swing.ImageIcon;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.python.core.Py;
import org.zaproxy.zap.extension.script.DefaultEngineWrapper;

public class JythonEngineWrapper extends DefaultEngineWrapper {

    private final JythonOptionsParam options;

    public JythonEngineWrapper(JythonOptionsParam options, ScriptEngineFactory engineFactory) {
        super(engineFactory);

        this.options = options;
    }

    @Override
    public ImageIcon getIcon() {
        return ExtensionJython.PYTHON_ICON;
    }

    @Override
    public String getSyntaxStyle() {
        return SyntaxConstants.SYNTAX_STYLE_PYTHON;
    }

    @Override
    public List<String> getExtensions() {
        List<String> list = new ArrayList<>();
        list.add("py");
        return list;
    }

    @Override
    public boolean isRawEngine() {
        return false;
    }

    @Override
    public ScriptEngine getEngine() {
        ScriptEngine engine = super.getEngine();
        Py.getSystemState().path.append(Py.newString(options.getModulePath()));
        return engine;
    }
}
