/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.groovy;

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

public class ExtensionGroovy extends ExtensionAdaptor {

    public static final String NAME = "ExtensionGroovy";
    public static final int EXTENSION_ORDER = 83;
    public static final ImageIcon GROOVY_ICON;
    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionScript.class);
        EXTENSION_DEPENDENCIES = Collections.unmodifiableList(dependencies);

        GROOVY_ICON =
                View.isInitialised()
                        ? new ImageIcon(
                                ExtensionGroovy.class.getResource(
                                        "/org/zaproxy/zap/extension/groovy/resources/groovy.png"))
                        : null;
    }

    private ExtensionScript extScript = null;
    private GroovyEngineWrapper groovyEngine = null;

    public ExtensionGroovy() {
        super(NAME);
        this.setOrder(EXTENSION_ORDER);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        groovyEngine = new GroovyEngineWrapper();
        getExtScript().registerScriptEngineWrapper(groovyEngine);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        if (groovyEngine != null) {
            getExtScript().removeScriptEngineWrapper(groovyEngine);
        }
    }

    private ExtensionScript getExtScript() {
        if (extScript == null) {
            extScript =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        }
        return extScript;
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("groovy.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("groovy.desc");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }
}
