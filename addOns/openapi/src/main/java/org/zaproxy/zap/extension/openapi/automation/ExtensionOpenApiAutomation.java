/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi.automation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.zap.extension.openapi.ExtensionOpenApi;

public class ExtensionOpenApiAutomation extends ExtensionAdaptor {

    public static final String NAME = "ExtensionOpenApiAutomation";

    private static final List<Class<? extends Extension>> DEPENDENCIES;

    private OpenApiJob job;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(2);
        dependencies.add(ExtensionOpenApi.class);
        dependencies.add(ExtensionAutomation.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    public ExtensionOpenApiAutomation() {
        super(NAME);
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        ExtensionAutomation extAuto =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);
        job = new OpenApiJob();
        extAuto.registerAutomationJob(job);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        ExtensionAutomation extAuto =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);

        extAuto.unregisterAutomationJob(job);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("openapi.automation.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("openapi.automation.name");
    }
}
