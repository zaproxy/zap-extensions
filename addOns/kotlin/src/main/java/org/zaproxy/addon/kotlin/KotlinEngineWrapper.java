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
package org.zaproxy.addon.kotlin;

import java.util.Collections;
import java.util.List;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptException;
import javax.swing.ImageIcon;
import kotlin.script.experimental.jsr223.KotlinJsr223DefaultScriptEngineFactory;
import kotlin.script.experimental.jsr223.KotlinJsr223DefaultScriptEngineFactoryKt;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.zaproxy.zap.control.ExtensionFactory;
import org.zaproxy.zap.extension.script.DefaultEngineWrapper;

public class KotlinEngineWrapper extends DefaultEngineWrapper {

    static {
        System.setProperty(
                KotlinJsr223DefaultScriptEngineFactoryKt
                        .KOTLIN_JSR223_RESOLVE_FROM_CLASSLOADER_PROPERTY,
                "true");
    }

    private final EngineClassLoader classLoader;

    public KotlinEngineWrapper() {
        this(ExtensionFactory.getAddOnLoader());
    }

    KotlinEngineWrapper(ClassLoader fallbackClassLoader) {
        super(new KotlinJsr223DefaultScriptEngineFactory());
        this.classLoader = new EngineClassLoader(getClass().getClassLoader(), fallbackClassLoader);
    }

    @Override
    public ImageIcon getIcon() {
        return ExtensionKotlin.KOTLIN_ICON;
    }

    @Override
    public String getSyntaxStyle() {
        return SyntaxConstants.SYNTAX_STYLE_NONE;
    }

    @Override
    public boolean isRawEngine() {
        return false;
    }

    @Override
    public List<String> getExtensions() {
        return Collections.singletonList("kts");
    }

    @Override
    public ScriptEngine getEngine() {
        return init(super.getEngine());
    }

    /**
     * Initialises the script engine with custom class loader and function overrides.
     *
     * @param scriptEngine the script engine to initialise
     * @return the script engine initialised
     */
    private ScriptEngine init(ScriptEngine scriptEngine) {
        ClassLoader currentClassLoader = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(classLoader);
        try {
            scriptEngine
                    .getBindings(ScriptContext.ENGINE_SCOPE)
                    .put("ZapScriptContext", scriptEngine.getContext());
            // Note that this also forces the initialisation/usage of the custom class loader.
            scriptEngine.eval(
                    "fun print(msg: Any) { ZapScriptContext.writer.write(\"$msg\") }"
                            + "fun println(msg: Any) { print(\"$msg\\n\") }");
        } catch (ScriptException ignore) {
        } finally {
            Thread.currentThread().setContextClassLoader(currentClassLoader);
        }
        return scriptEngine;
    }

    private static class EngineClassLoader extends ClassLoader {

        private final ClassLoader addOn;
        private final ClassLoader fallback;

        EngineClassLoader(ClassLoader addOn, ClassLoader fallback) {
            this.addOn = addOn;
            this.fallback = fallback;
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            try {
                return addOn.loadClass(name);
            } catch (ClassNotFoundException ignore) {
            }
            return fallback.loadClass(name);
        }
    }
}
