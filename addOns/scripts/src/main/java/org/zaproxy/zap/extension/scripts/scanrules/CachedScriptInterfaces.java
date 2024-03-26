/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.zap.extension.scripts.scanrules;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.script.ScriptException;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;

class CachedScriptInterfaces {

    private ExtensionScript extScript;
    private final ScriptWrapper script;
    private int currentModCount;
    private final Map<Class<?>, Object> interfaces = new HashMap<>();

    CachedScriptInterfaces(ScriptWrapper script) {
        this.script = script;
        this.currentModCount = script.getModCount();
    }

    <T> T getInterface(ScriptWrapper script, Class<T> clazz) throws ScriptException, IOException {
        Object iface;
        if (hasChanged() || !interfaces.containsKey(clazz)) {
            iface = getExtScript().getInterface(script, clazz);
            interfaces.put(clazz, iface);
        } else {
            iface = interfaces.get(clazz);
        }
        return clazz.cast(iface);
    }

    private boolean hasChanged() {
        if (interfaces.isEmpty()) {
            return true;
        }
        int previousModCount = currentModCount;
        currentModCount = script.getModCount();
        return previousModCount != currentModCount;
    }

    private ExtensionScript getExtScript() {
        if (extScript == null) {
            extScript =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        }
        return extScript;
    }
}
