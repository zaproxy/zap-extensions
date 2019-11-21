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

import java.net.MalformedURLException;
import java.net.URL;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

/** @author KSASAN preetkaran20@gmail.com */
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

        try {
            LOGGER.error("SASAN");
            //			SAMLConfiguration conf = SAMLConfiguration.getInstance();
            //			SamlI18n.init();
            //			if (conf != null) {
            //				conf.initialize();
            //			} else {
            //				log.error("SAML Configuration can't be loaded. Extention will not be loaded...");
            //			}
            //			if (getView() != null && conf != null) {
            //				final SAMLProxyListener proxyListener = new SAMLProxyListener();
            //				extensionHook.addProxyListener(proxyListener);
            //
            //				ExtensionPopupMenu samlMenu = new ExtensionPopupMenuMessageContainer(
            //						SamlI18n.getMessage("saml.popup.mainmenu"));
            //				ExtensionPopupMenuItem samlResendMenuItem = new SAMLResendMenuItem(
            //						SamlI18n.getMessage("saml.popup.view_resend"));
            //
            //				samlMenu.add(samlResendMenuItem);
            //				extensionHook.getHookMenu().addPopupMenuItem(samlMenu);
            //
            //				JMenuItem samlActiveEditorMenu = new
            // JMenuItem(SamlI18n.getMessage("saml.toolmenu.settings"));
            //				samlActiveEditorMenu.addActionListener(new ActionListener() {
            //					@Override
            //					public void actionPerformed(ActionEvent e) {
            //						SamlExtentionSettingsUI settingUI = new SamlExtentionSettingsUI();
            //						settingUI.setVisible(true);
            //					}
            //				});
            //				extensionHook.getHookMenu().addToolsMenuItem(samlActiveEditorMenu);
            //			}
        } catch (Exception e) {
            LOGGER.error("JWT Extension can't be loaded. Configuration not found or invalid", e);
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }
}
