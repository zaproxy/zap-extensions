/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.jwt;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.jwt.ui.JWTOptionsPanel;

/**
 * @author KSASAN preetkaran20@gmail.com
 * @since TODO add version
 */
public class JWTExtension extends ExtensionAdaptor {

    protected static final Logger LOGGER = Logger.getLogger(JWTExtension.class);

    @Override
    public String getAuthor() {
        return "KSASAN preetkaran20@gmail.com";
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        JWTI18n.init();
        try {
            extensionHook.addOptionsParamSet(getJWTConfiguration());
            extensionHook.getHookView().addOptionPanel(new JWTOptionsPanel());
            LOGGER.debug("JWT Extension loaded successfully");
        } catch (Exception e) {
            LOGGER.error("JWT Extension can't be loaded. Configuration not found or invalid", e);
        }
    }

    private JWTConfiguration getJWTConfiguration() {
        return JWTConfiguration.getInstance();
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public boolean canUnload() {
        return true;
    }
}
