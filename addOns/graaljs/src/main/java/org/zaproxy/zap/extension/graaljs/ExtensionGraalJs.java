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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.ImageIcon;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.script.ExtensionScript;

public class ExtensionGraalJs extends ExtensionAdaptor {

    public static final String NAME = "ExtensionGraalJs";

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionScript.class);
        EXTENSION_DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    private GraalJsEngineWrapper engineWrapper;

    public ExtensionGraalJs() {
        super(NAME);
    }

    @Override
    public String getUIName() {
        return getMessages().getString("graaljs.ext.name");
    }

    @Override
    public String getDescription() {
        return getMessages().getString("graaljs.ext.desc");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        ClassLoader previousContextClassLoader = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
        try {
            engineWrapper =
                    new GraalJsEngineWrapper(Collections.emptyList(), createScriptEngineIcon());
        } finally {
            Thread.currentThread().setContextClassLoader(previousContextClassLoader);
        }
        getExtScript().registerScriptEngineWrapper(engineWrapper);
    }

    private ImageIcon createScriptEngineIcon() {
        if (hasView()) {
            return new ImageIcon(getClass().getResource("resources/icons/graal.png"));
        }
        return null;
    }

    private static ExtensionScript getExtScript() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        getExtScript().removeScriptEngineWrapper(engineWrapper);
    }
}
