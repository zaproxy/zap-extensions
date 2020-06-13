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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.swing.*;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.control.AddOnLoader;
import org.zaproxy.zap.control.ExtensionFactory;
import org.zaproxy.zap.extension.script.ExtensionScript;

public class ExtensionKotlin extends ExtensionAdaptor {

    public static final String NAME = "ExtensionKotlin";
    public static final int EXTENSION_ORDER = 9999;
    public static final ImageIcon KOTLIN_ICON;
    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES;
    private static final Logger LOGGER = Logger.getLogger(ExtensionKotlin.class);

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionScript.class);
        EXTENSION_DEPENDENCIES = Collections.unmodifiableList(dependencies);

        KOTLIN_ICON =
                View.isInitialised()
                        ? new ImageIcon(
                                ExtensionKotlin.class.getResource(
                                        "/org/zaproxy/zap/extension/kotlin/resources/kotlin.png"))
                        : null;
    }

    public ExtensionKotlin() {
        super(NAME);
        setOrder(EXTENSION_ORDER);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        LOGGER.debug("Hooking Kotlin Scripting Extension");
        String zapJar = ZAP.class.getProtectionDomain().getCodeSource().getLocation().getFile();

        LOGGER.debug("Loading Kotlin engine...");
        AddOnLoader addonLoader = ExtensionFactory.getAddOnLoader();
        Arrays.stream(addonLoader.getURLs()).forEach(LOGGER::debug);
        KotlinScriptEngineFactory factory = new KotlinScriptEngineFactory(addonLoader, zapJar);
        getExtScript().registerScriptEngineWrapper(new KotlinEngineWrapper(factory));
        LOGGER.debug("Kotlin engine loaded.");
    }

    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }

    private ExtensionScript getExtScript() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
    }
}
