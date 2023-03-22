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
package org.zaproxy.zap.extension.selenium;

import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.api.API;

@SuppressWarnings("serial")
public class PopupMenuItemOpenCustomRequestInBrowser extends PopupMenuItemOpenInBrowser {

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER =
            LogManager.getLogger(PopupMenuItemOpenCustomRequestInBrowser.class);

    private ExtensionSelenium ext;

    private ProvidedBrowser browser;

    public PopupMenuItemOpenCustomRequestInBrowser(
            String name, ExtensionSelenium ext, ProvidedBrowser browser) {
        super(name, ext, browser);
        this.ext = ext;
        this.browser = browser;
    }

    @Override
    public void performAction(HttpMessage msg) {
        new Thread(
                        () -> {
                            this.openInBrowser(msg);
                        })
                .start();
    }

    void openInBrowser(HttpMessage msg) {
        try {
            int id = msg.getHistoryRef().getHistoryId();
            
            String url =
                    API.getInstance()
                            .getCallBackUrl(this.ext.getApiImplementor(), this.getSite(msg));
            url = url + "?hist=" + id;
            String queryString = msg.getRequestHeader().getURI().getQuery();
            if (queryString != null && !queryString.isEmpty()) {
                url = url + "&" + queryString;
            }
            ext.getProxiedBrowser(browser.getId(), url);
        } catch (Exception e) {
            View.getSingleton().showWarningDialog(e.getMessage());
            LOGGER.error(e.getMessage(), e);
        }
    }

    private String getSite(HttpMessage msg) throws URIException {
        StringBuilder site = new StringBuilder();
        // Always force to https - we fake this for http sites
        site.append("https://");
        site.append(msg.getRequestHeader().getURI().getHost());
        if (msg.getRequestHeader().getURI().getPort() > 0) {
            site.append(":");
            site.append(msg.getRequestHeader().getURI().getPort());
        }
        return site.toString();
    }
}
