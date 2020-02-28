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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.MalformedURLException;
import java.net.URL;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.jwt.ui.JWTOptionsPanel;
import org.zaproxy.zap.extension.jwt.ui.JWTSettingsUI;
import org.zaproxy.zap.view.ZapMenuItem;

/**
 * @author KSASAN preetkaran20@gmail.com
 * @since TODO add version
 */
public class JWTExtension extends ExtensionAdaptor {

    protected static final Logger LOGGER = Logger.getLogger(JWTExtension.class);

    @Override
    public URL getURL() {
        try {
            return new URL(Constant.ZAP_HOMEPAGE);
        } catch (MalformedURLException e) {
            return null;
        }
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        JWTI18n.init();
        try {
            extensionHook.addOptionsParamSet(getJWTConfiguration());
            extensionHook.getHookView().addOptionPanel(new JWTOptionsPanel());
            ZapMenuItem jwtActiveEditorMenu = new ZapMenuItem("jwt.toolmenu.settings");
            jwtActiveEditorMenu.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            LOGGER.info("JWT Settings item");
                            JWTSettingsUI jwtSettingsUI = new JWTSettingsUI();
                            jwtSettingsUI.setVisible(true);
                        }
                    });
            extensionHook.getHookMenu().addToolsMenuItem(jwtActiveEditorMenu);
            LOGGER.info("JWT Extension loaded successfully");
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

    @Override
    public void stop() {
        this.getJWTConfiguration().shutdownExecutorService();
    }
}
