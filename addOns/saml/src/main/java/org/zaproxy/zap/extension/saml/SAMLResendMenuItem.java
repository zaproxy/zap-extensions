/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.saml;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.saml.ui.SamlManualEditor;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

public class SAMLResendMenuItem extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LogManager.getLogger(SAMLResendMenuItem.class);

    public SAMLResendMenuItem(String label) {
        super(label);
    }

    @Override
    public void performAction(HttpMessage httpMessage) {
        if (!SAMLUtils.hasSAMLMessage(httpMessage)) {
            View.getSingleton().showWarningDialog("Not a valid SAML request");
            return;
        }
        try {
            SamlManualEditor editor = new SamlManualEditor(new SAMLMessage(httpMessage));
            editor.setVisible(true);
        } catch (SAMLException e) {
            LOGGER.error("Failed to show SAML manual editor: {}", e.getMessage(), e);
        }
    }

    @Override
    public boolean isEnableForInvoker(Invoker invoker, HttpMessageContainer httpMessageContainer) {
        // TODO filter out the unnecessary invokers
        return true;
    }
}
