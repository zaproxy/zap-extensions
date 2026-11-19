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
package org.zaproxy.addon.zesttest.shadowdom;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestDirectory;
import org.zaproxy.addon.dev.TestProxyServer;

/** The directory of a {@link ShadowDomCase}, with the page and the targets of its elements. */
public class ShadowDomDir extends TestDirectory {

    private static final Logger LOGGER = LogManager.getLogger(ShadowDomDir.class);

    private final ShadowDomCase shadowDomCase;

    public ShadowDomDir(TestProxyServer server, ShadowDomCase shadowDomCase) {
        super(server, shadowDomCase.getDirName());
        this.shadowDomCase = shadowDomCase;
        addPage(new ShadowDomPage(server));
        for (ShadowDomAction action : ShadowDomAction.values()) {
            addPage(new ShadowDomActionPage(server, action));
        }
    }

    public ShadowDomCase getShadowDomCase() {
        return shadowDomCase;
    }

    static void setHtmlResponse(HttpMessage msg, String body) {
        msg.setResponseBody(body);
        try {
            msg.setResponseHeader(
                    TestProxyServer.getDefaultResponseHeader(
                            "text/html", msg.getResponseBody().length()));
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }
}
