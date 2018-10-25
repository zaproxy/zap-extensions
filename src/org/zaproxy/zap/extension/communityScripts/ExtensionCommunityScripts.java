/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.communityScripts;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.zaproxy.zap.extension.script.ExtensionScript;

/**
 * Community Scripts Extension - a packaged version of https://github.com/zaproxy/community-scripts
 *
 * @author psiinon
 */
public class ExtensionCommunityScripts extends ExtensionAdaptor {

    private File scriptDir = new File(Constant.getZapHome(), "community-scripts");

    private static final List<Class<? extends Extension>> DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionScript.class);

        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    @Override
    public String getAuthor() {
        return "ZAP Community";
    }

    @Override
    public String getName() {
        return "ExtensionCommunityScripts";
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("communityScripts.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("communityScripts.desc");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void postInit() {
        addScripts();
    }

    private void addScripts() {
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionScript.class)
                .addScriptsFromDir(scriptDir);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionScript.class)
                .removeScriptsFromDir(scriptDir);
    }
}
