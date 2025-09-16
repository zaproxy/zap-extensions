/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.testutils;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.script.Compilable;
import javax.script.Invocable;
import javax.script.ScriptEngine;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public interface ScriptScanRuleTestUtils {

    Path getScriptPath() throws Exception;

    ScriptEngineWrapper getScriptEngineWrapper();

    default void setUpExtScript() throws Exception {
        ExtensionScript mockExtScript = mock(ExtensionScript.class);
        lenient()
                .doAnswer(invocation -> getScriptInterface(invocation.getArgument(1)))
                .when(mockExtScript)
                .getInterface(any(ScriptWrapper.class), any());
        if (Control.getSingleton() != null) {
            Control.getSingleton().getExtensionLoader().addExtension(mockExtScript);
        }
    }

    default <T> T getScriptInterface(Class<T> clazz) throws Exception {
        ScriptEngine scriptEngine = getScriptEngineWrapper().getEngine();
        if (Control.getSingleton() != null) {
            scriptEngine.put("control", Control.getSingleton());
        }
        if (Model.getSingleton() != null) {
            scriptEngine.put("model", Model.getSingleton());
        }
        try (Reader reader = Files.newBufferedReader(getScriptPath(), StandardCharsets.UTF_8)) {
            ((Compilable) scriptEngine).compile(reader).eval();
        }
        return ((Invocable) scriptEngine).getInterface(clazz);
    }
}
