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
package org.zaproxy.addon.openapitest.simpletoken;

import org.zaproxy.addon.dev.TestDirectory;
import org.zaproxy.addon.dev.TestProxyServer;

/**
 * A directory which contains an OpenAPI spec. The spec is available unauthenticated but the
 * endpoint it describes can only be accessed when the request has the fixed security token in a
 * header.
 */
public class OpenApiSimpleTokenDir extends TestDirectory {

    public static final String TOKEN_HEADER = "X-Security-Token";

    // This is a test token, so hardcoding it is fine ;)
    public static final String TOKEN = "zap-test-security-token";

    public OpenApiSimpleTokenDir(TestProxyServer server, String name) {
        super(server, name);
        this.addPage(new OpenApiTokenTestApiPage(server));
    }
}
