/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.dev;

import java.util.HashMap;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.network.HttpSenderListener;

public class AltDomainListener implements HttpSenderListener {

    private Map<String, HttpSenderListener> domainMap = new HashMap<>();

    private static final String ZAP_SSO_HEADER = "zap-dev-sso";

    private static final Logger LOGGER = LogManager.getLogger(AltDomainListener.class);

    public void addDomainListener(String domain, HttpSenderListener listener) {
        this.domainMap.put(domain, listener);
    }

    @Override
    public void onHttpRequestSend(HttpMessage msg, int initiator, HttpSender sender) {
        try {
            String host = SessionStructure.getHostName(msg);
            HttpSenderListener listener = domainMap.get(host);
            if (listener != null) {
                msg.getRequestHeader()
                        .addHeader(ZAP_SSO_HEADER, msg.getRequestHeader().getURI().toString());
                listener.onHttpRequestSend(msg, initiator, sender);
            }
        } catch (URIException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    @Override
    public void onHttpResponseReceive(HttpMessage msg, int initiator, HttpSender sender) {
        try {
            String url = msg.getRequestHeader().getHeader(ZAP_SSO_HEADER);
            if (url != null) {
                URI uri = new URI(url, false);
                String host = SessionStructure.getHostName(uri);
                HttpSenderListener listener = domainMap.get(host);
                if (listener != null) {
                    listener.onHttpResponseReceive(msg, initiator, sender);
                }
                // https:// - the 8 chrs we're stripping off
                msg.getRequestHeader().setURI(uri);
                msg.getRequestHeader().setHeader("host", host.substring(8));

                msg.getRequestHeader().setHeader(ZAP_SSO_HEADER, null);
            }
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    @Override
    public int getListenerOrder() {
        return 0;
    }
}
