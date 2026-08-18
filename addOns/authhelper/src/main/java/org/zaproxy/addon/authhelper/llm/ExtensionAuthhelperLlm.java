/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.llm;

import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.authhelper.AuthUtils;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;

public class ExtensionAuthhelperLlm extends ExtensionAdaptor {

    public static final String NAME = "ExtensionAuthhelperLlm";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionLlm.class, ExtensionSelenium.class);

    private static final Logger LOGGER = LogManager.getLogger(ExtensionAuthhelperLlm.class);

    public static final AiAssistedAuthenticationMethodType AI_ASSISTED_AUTH_TYPE =
            new AiAssistedAuthenticationMethodType();

    public ExtensionAuthhelperLlm() {
        super(NAME);
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
    }

    @Override
    public void optionsLoaded() {
        ExtensionAuthentication extAuth = AuthUtils.getExtension(ExtensionAuthentication.class);
        if (extAuth != null) {
            extAuth.getAuthenticationMethodTypes().add(AI_ASSISTED_AUTH_TYPE);
            LOGGER.debug("Loaded AI assisted auth type.");
        }
    }

    @Override
    public void unload() {
        ExtensionAuthentication extAuth = AuthUtils.getExtension(ExtensionAuthentication.class);
        if (extAuth != null) {
            extAuth.getAuthenticationMethodTypes().remove(AI_ASSISTED_AUTH_TYPE);
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("authhelper.llm.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("authhelper.llm.name");
    }
}
