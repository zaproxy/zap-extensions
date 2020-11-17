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

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.ImageIcon;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;

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
                    new GraalJsEngineWrapper(getDefaultTemplates(), createScriptEngineIcon());
        } finally {
            Thread.currentThread().setContextClassLoader(previousContextClassLoader);
        }
        getExtScript().registerScriptEngineWrapper(engineWrapper);
    }

    private List<Path> getDefaultTemplates() {
        AddOn addOn = getAddOn();
        if (addOn == null) {
            // Probably running from source...
            return Collections.emptyList();
        }

        List<String> files = addOn.getFiles();
        if (files == null || files.isEmpty()) {
            return Collections.emptyList();
        }

        ArrayList<Path> defaultTemplates = new ArrayList<>(files.size());
        Path zapHome = Paths.get(Constant.getZapHome());
        for (String file : files) {
            if (file.startsWith(ExtensionScript.TEMPLATES_DIR)) {
                defaultTemplates.add(zapHome.resolve(file));
            }
        }
        defaultTemplates.trimToSize();
        return defaultTemplates;
    }

    @Override
    public void optionsLoaded() {
        AddOn addOn = getAddOn();
        if (addOn == null) {
            // Probably running from source...
            return;
        }

        List<String> files = addOn.getFiles();
        if (files == null || files.isEmpty()) {
            return;
        }

        // Correct the engine name - if Oracle Nashorn is installed then that will get chosen based
        // on the .js extension
        for (String file : files) {
            if (file.startsWith(ExtensionScript.TEMPLATES_DIR)) {
                Path path = Paths.get(file);
                ScriptWrapper sw =
                        getExtScript().getTreeModel().getTemplate(path.getFileName().toString());
                if (sw != null) {
                    sw.setEngine(engineWrapper);
                }
            }
        }
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
