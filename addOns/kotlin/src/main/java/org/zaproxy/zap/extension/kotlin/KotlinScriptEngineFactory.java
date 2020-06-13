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
package org.zaproxy.zap.extension.kotlin;

import java.io.File;
import java.util.List;
import javax.script.Bindings;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import kotlin.jvm.JvmClassMappingKt;
import kotlin.reflect.KClass;
import kotlin.script.experimental.jvm.util.JvmClasspathUtilKt;
import org.jetbrains.kotlin.cli.common.repl.KotlinJsr223JvmScriptEngineFactoryBase;
import org.jetbrains.kotlin.cli.common.repl.ScriptArgsWithTypes;
import org.jetbrains.kotlin.script.jsr223.KotlinJsr223JvmLocalScriptEngine;
import org.jetbrains.kotlin.script.jsr223.KotlinStandardJsr223ScriptTemplate;

public class KotlinScriptEngineFactory extends KotlinJsr223JvmScriptEngineFactoryBase {

    private final List<File> jars;

    public KotlinScriptEngineFactory(ClassLoader classLoader, String zapJar) {
        List<File> clJars =
                JvmClasspathUtilKt.scriptCompilationClasspathFromContextOrStdlib(
                        new String[] {"kotlin-stdlib"}, classLoader, true);
        if (zapJar != null) {
            clJars.add(new File(zapJar));
        }
        jars = clJars;
    }

    @Override
    public ScriptEngine getScriptEngine() {
        return new KotlinJsr223JvmLocalScriptEngine(
                this,
                jars,
                KotlinStandardJsr223ScriptTemplate.class.getName(),
                (ctx, types) ->
                        new ScriptArgsWithTypes(
                                new Bindings[] {ctx.getBindings(ScriptContext.ENGINE_SCOPE)},
                                types),
                new KClass<?>[] {JvmClassMappingKt.getKotlinClass(Bindings.class)});
    }
}
