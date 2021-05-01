/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.graaljs;

import com.oracle.truffle.js.scriptengine.GraalJSEngineFactory;
import com.oracle.truffle.js.scriptengine.GraalJSScriptEngine;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import javax.script.ScriptEngine;
import javax.script.ScriptException;
import javax.swing.ImageIcon;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.graalvm.polyglot.Context;
import org.zaproxy.zap.extension.script.DefaultEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class GraalJsEngineWrapper extends DefaultEngineWrapper {

    private final List<Path> defaultTemplates;
    private final ImageIcon icon;

    public GraalJsEngineWrapper(List<Path> defaultTemplates, ImageIcon icon) {
        super(new GraalJSEngineFactory());

        this.defaultTemplates = Objects.requireNonNull(defaultTemplates);
        this.icon = icon;
    }

    @Override
    public ImageIcon getIcon() {
        return icon;
    }

    @Override
    public String getSyntaxStyle() {
        return SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT;
    }

    @Override
    public ScriptEngine getEngine() {
        Context.Builder contextBuilder =
                Context.newBuilder("js")
                        .allowExperimentalOptions(true)
                        .option("js.syntax-extensions", "true")
                        .option("js.load", "true")
                        .option("js.print", "true")
                        .option("js.nashorn-compat", "true")
                        .allowAllAccess(true);

        ScriptEngine se = GraalJSScriptEngine.create(null, contextBuilder);

        // Force use of own (add-on) class loader
        // https://github.com/graalvm/graaljs/issues/182
        ClassLoader previousContextClassLoader = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
        try {
            se.eval("");
        } catch (ScriptException ignore) {
        } finally {
            Thread.currentThread().setContextClassLoader(previousContextClassLoader);
        }
        return se;
    }

    @Override
    public boolean isRawEngine() {
        return false;
    }

    @Override
    public boolean isDefaultTemplate(ScriptWrapper script) {
        if (script.getFile() == null) {
            return false;
        }

        return defaultTemplates.contains(script.getFile().toPath());
    }
}
