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
package org.zaproxy.addon.openapitest.simpleoauth2;

import org.zaproxy.addon.dev.TestAuthDirectory;
import org.zaproxy.addon.dev.TestProxyServer;

/**
 * A directory which contains an OpenAPI spec. The spec is available unauthenticated but the
 * endpoint it describes can only be accessed with a bearer token from the token endpoint, which
 * supports the OAuth2 password grant for a confidential client.
 */
public class OpenApiSimpleOAuth2Dir extends TestAuthDirectory {

    // These are test credentials, so hardcoding them is fine ;)
    public static final String CLIENT_ID = "test-client";
    public static final String CLIENT_SECRET = "test-secret";

    static final String STATUS_UNAUTHORIZED = "401 Unauthorized";

    public OpenApiSimpleOAuth2Dir(TestProxyServer server, String name) {
        super(server, name);
        this.addPage(new OpenApiOAuth2TokenPage(server));
        this.addPage(new OpenApiOAuth2TestApiPage(server));
    }

    /**
     * Tells whether the client credentials are valid.
     *
     * @param clientId the client ID, might be {@code null}.
     * @param clientSecret the client secret, might be {@code null}.
     * @return {@code true} if the credentials are valid.
     */
    public boolean isValidClient(String clientId, String clientSecret) {
        return CLIENT_ID.equals(clientId) && CLIENT_SECRET.equals(clientSecret);
    }
}
