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
package org.zaproxy.addon.network.internal.client.apachev5;

import java.net.PasswordAuthentication;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.Credentials;
import org.apache.hc.client5.http.auth.CredentialsProvider;
import org.apache.hc.client5.http.auth.NTCredentials;
import org.apache.hc.client5.http.auth.StandardAuthScheme;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.zaproxy.addon.network.ConnectionOptions;
import org.zaproxy.addon.network.internal.client.HttpProxy;

/** A {@link CredentialsProvider} that provides the credentials for the configured HTTP proxy. */
public class ProxyCredentialsProvider implements CredentialsProvider {

    private final ConnectionOptions options;

    public ProxyCredentialsProvider(ConnectionOptions options) {
        this.options = options;
    }

    @Override
    public Credentials getCredentials(AuthScope authScope, HttpContext context) {
        HttpProxy proxy = options.getHttpProxy();
        if (!options.isHttpProxyEnabled() || !options.isHttpProxyAuthEnabled()) {
            return null;
        }

        String realm = proxy.getRealm();
        int result =
                authScope.match(
                        new AuthScope(
                                null,
                                proxy.getHost(),
                                proxy.getPort(),
                                realm.isEmpty() ? null : realm,
                                null));
        if (result <= 0) {
            return null;
        }

        PasswordAuthentication credentials = proxy.getPasswordAuthentication();

        if ((StandardAuthScheme.BASIC.equalsIgnoreCase(authScope.getSchemeName())
                || StandardAuthScheme.DIGEST.equalsIgnoreCase(authScope.getSchemeName()))) {
            return new UsernamePasswordCredentials(
                    credentials.getUserName(), credentials.getPassword());
        }

        return new NTCredentials(
                credentials.getUserName(), credentials.getPassword(), "", proxy.getRealm());
    }
}
