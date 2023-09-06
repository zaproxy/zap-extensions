/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.dev.api.openapi.simpleAuth;

import org.zaproxy.addon.dev.TestAuthDirectory;
import org.zaproxy.addon.dev.TestProxyServer;

/**
 * A directory which contains an OpenAPI spec. The spec is available unauthenticated but the
 * endpoint it describes can only be accessed when a valid Authentication header is supplied. The
 * login page uses one JSON request to login endpoint. The token is returned in a standard field.
 */
public class OpenApiSimpleAuthDir extends TestAuthDirectory {

    public OpenApiSimpleAuthDir(TestProxyServer server, String name) {
        super(server, name);
        this.addPage(new OpenApiLoginPage(server));
        this.addPage(new OpenApiVerificationPage(server));
        this.addPage(new OpenApiTestApiPage(server));
    }
}
