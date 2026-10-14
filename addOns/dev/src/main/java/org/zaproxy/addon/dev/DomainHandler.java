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
package org.zaproxy.addon.dev;

import org.parosproxy.paros.network.HttpMessage;

/**
 * Serves the requests for a fake domain, like {@code api.oauth2.zap}, from the test server.
 *
 * <p>The responses are real responses from the server, so ZAP sees them as it would those of any
 * other server, for example when checking if a user is still authenticated. This is unlike a
 * response listener that replaces the response, which is only done after ZAP has seen the server's
 * response.
 *
 * @see TestProxyServer#addDomainHandler(String, DomainHandler)
 */
@FunctionalInterface
public interface DomainHandler {

    /**
     * Handles the request, setting the response.
     *
     * @param msg the message with the request, as it was sent to the original domain.
     * @throws Exception if an error occurred, the response will be a server error.
     */
    void handle(HttpMessage msg) throws Exception;
}
