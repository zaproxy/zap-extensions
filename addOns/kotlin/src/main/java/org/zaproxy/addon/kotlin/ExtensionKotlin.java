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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.ImageIcon;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ExtensionScript;

public class ExtensionKotlin extends ExtensionAdaptor {

    public static final String NAME = "ExtensionKotlin";

    static final ImageIcon KOTLIN_ICON;
    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionScript.class);
        EXTENSION_DEPENDENCIES = Collections.unmodifiableList(dependencies);

        KOTLIN_ICON =
                View.isInitialised()
                        ? new ImageIcon(ExtensionKotlin.class.getResource("resources/kotlin.png"))
                        : null;
    }

    private KotlinEngineWrapper engineWrapper;

    public ExtensionKotlin() {
        super(NAME);
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("kotlin.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("kotlin.desc");
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        engineWrapper = new KotlinEngineWrapper();
        getExtScript().registerScriptEngineWrapper(engineWrapper);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }

    private ExtensionScript getExtScript() {
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

    @Override
    public boolean supportsDb(String type) {
        return true;
    }
}
