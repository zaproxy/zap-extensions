/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi;

import javax.swing.JFrame;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.openapi.converter.swagger.InvalidUrlException;

public class ImportFromUrlDialog extends ImportFromAbstractDialog {

    private static final long serialVersionUID = -7074394202143400215L;
    private static final String MESSAGE_PREFIX = "openapi.importfromurldialog.";

    public ImportFromUrlDialog(JFrame parent, ExtensionOpenApi caller) {
        super(
                parent,
                caller,
                Constant.messages.getString(MESSAGE_PREFIX + "title"),
                Constant.messages.getString(MESSAGE_PREFIX + "labelurl"));
    }

    @Override
    protected boolean importDefinition() {
        String url = getFromField().getText();
        if (url.isEmpty()) {
            showWarningDialog(Constant.messages.getString(MESSAGE_PREFIX + "urlerror.empty"));
            getFromField().requestFocusInWindow();
            return false;
        }

        URI uri;
        try {
            uri = new URI(url, false);
        } catch (URIException e) {
            showWarningDialog(
                    Constant.messages.getString(
                            MESSAGE_PREFIX + "urlerror.invalid", e.getLocalizedMessage()));
            getFromField().requestFocusInWindow();
            return false;
        }

        if (!isSupportedScheme(uri.getScheme())) {
            showWarningDialog(Constant.messages.getString("openapi.unsupportedscheme", url));
            getFromField().requestFocusInWindow();
            return false;
        }

        try {
            caller.importOpenApiDefinition(uri, getTargetField().getText(), true);
        } catch (InvalidUrlException e) {
            showWarningInvalidUrl(e.getUrl());
            return false;
        }

        return true;
    }

    private static boolean isSupportedScheme(String scheme) {
        return "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
    }
}
