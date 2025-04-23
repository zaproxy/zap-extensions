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

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.network.HttpSenderListener;

public abstract class DevHttpSenderListener implements HttpSenderListener {

    private TestProxyServer server;

    private static final Logger LOGGER = LogManager.getLogger(DevHttpSenderListener.class);

    public DevHttpSenderListener(TestProxyServer server) {
        this.server = server;
    }

    @Override
    public int getListenerOrder() {
        return 0;
    }

    public static URI changeTarget(URI uri, String host, int port) throws URIException {
        return new URI(
                uri.getScheme(), uri.getUserinfo(), host, port, uri.getPath(), uri.getQuery());
    }

    @Override
    public void onHttpRequestSend(HttpMessage msg, int initiator, HttpSender sender) {
        // Always redirect to the test server.
        try {
            msg.getRequestHeader()
                    .setURI(
                            changeTarget(
                                    msg.getRequestHeader().getURI(),
                                    server.getHost(),
                                    server.getPort()));
            msg.getRequestHeader().setHeader("host", server.getHost() + ":" + server.getPort());

        } catch (URIException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }
}
