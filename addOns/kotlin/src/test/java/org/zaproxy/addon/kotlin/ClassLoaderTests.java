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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.zaproxy.addon.kotlin.TestUtils.getScriptContents;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Paths;
import javax.script.Compilable;
import javax.script.CompiledScript;
import javax.script.ScriptEngine;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.ZAP;

public class ClassLoaderTests {

    private static final String testClassName = "testclasspath.TestClassOne";

    private ClassLoader testFallbackClassLoader() throws Exception {
        String testClasspath =
                Paths.get(
                                getClass()
                                        .getResource("/org/zaproxy/addon/kotlin/testclasspath")
                                        .getFile())
                        .getParent()
                        .toString();
        return new URLClassLoader(new URL[] {new URL("file://" + testClasspath + "/")});
    }

    @Test
    public void shouldLoadClassesFromProvidedClassLoader() throws Exception {

        ClassLoader currentClassLoader = Thread.currentThread().getContextClassLoader();

        assertThrows(
                ClassNotFoundException.class, () -> currentClassLoader.loadClass(testClassName));

        ClassLoader fallbackClassloader = testFallbackClassLoader();

        Class<?> clz = fallbackClassloader.loadClass(testClassName);

        assertEquals(testClassName, clz.getName());

        KotlinEngineWrapper kew = new KotlinEngineWrapper(fallbackClassloader);

        ScriptEngine se = kew.getEngine();
        Compilable c = (Compilable) se;

        String script1 = getScriptContents("classloaderTest1.kts");
        CompiledScript cs = c.compile(script1);
        Object retVal1 = cs.eval();

        assertSame(retVal1.getClass(), String.class);
        assertEquals(retVal1, "testone");

        String script2 = getScriptContents("classloaderTest2.kts");
        Object retVal2 = c.compile(script2).eval();

        assertSame(ZAP.class, retVal2);
    }
}
