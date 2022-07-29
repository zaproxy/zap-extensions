/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi.formhandler;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.formhandler.ExtensionFormHandler;
import org.zaproxy.zap.extension.openapi.ExtensionOpenApi;
import org.zaproxy.zap.model.ValueGenerator;

public class ExtensionOpenApiFormHandler extends ExtensionAdaptor {

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            Collections.unmodifiableList(
                    Arrays.asList(ExtensionFormHandler.class, ExtensionOpenApi.class));

    @Override
    public String getUIName() {
        return Constant.messages.getString("openapi.formhandler.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("openapi.formhandler.desc");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        ValueGenerator valueGenerator =
                getExtension(ExtensionFormHandler.class).getValueGenerator();
        getExtension(ExtensionOpenApi.class).setValueGenerator(valueGenerator);
    }

    private static <T extends Extension> T getExtension(Class<T> clazz) {
        return Control.getSingleton().getExtensionLoader().getExtension(clazz);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        getExtension(ExtensionOpenApi.class).setValueGenerator(null);
    }
}
