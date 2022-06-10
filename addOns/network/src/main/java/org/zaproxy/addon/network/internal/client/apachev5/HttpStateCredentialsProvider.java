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

import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.Credentials;
import org.apache.hc.client5.http.auth.CredentialsProvider;
import org.apache.hc.client5.http.auth.NTCredentials;
import org.apache.hc.client5.http.auth.StandardAuthScheme;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.core5.http.protocol.HttpContext;

/**
 * A {@link CredentialsProvider} that provides the credentials contained in a {@link
 * org.apache.commons.httpclient.HttpState HttpState}.
 */
public class HttpStateCredentialsProvider implements CredentialsProvider {

    private final org.apache.commons.httpclient.HttpState state;

    public HttpStateCredentialsProvider(org.apache.commons.httpclient.HttpState state) {
        this.state = state;
    }

    @Override
    public Credentials getCredentials(AuthScope authScope, HttpContext context) {
        return convertCredentials(authScope, state.getCredentials(convertAuthScope(authScope)));
    }

    private static org.apache.commons.httpclient.auth.AuthScope convertAuthScope(
            AuthScope authScope) {
        return new org.apache.commons.httpclient.auth.AuthScope(
                authScope.getHost(),
                authScope.getPort(),
                authScope.getRealm(),
                authScope.getSchemeName());
    }

    private static Credentials convertCredentials(
            AuthScope authScope, org.apache.commons.httpclient.Credentials credentials) {
        if ((StandardAuthScheme.BASIC.equals(authScope.getSchemeName())
                        || StandardAuthScheme.DIGEST.equals(authScope.getSchemeName()))
                && credentials
                        instanceof org.apache.commons.httpclient.UsernamePasswordCredentials) {
            org.apache.commons.httpclient.UsernamePasswordCredentials upCredentials =
                    (org.apache.commons.httpclient.UsernamePasswordCredentials) credentials;
            return new UsernamePasswordCredentials(
                    upCredentials.getUserName(), upCredentials.getPassword().toCharArray());
        }

        if (credentials instanceof org.apache.commons.httpclient.NTCredentials) {
            org.apache.commons.httpclient.NTCredentials ntCredentials =
                    (org.apache.commons.httpclient.NTCredentials) credentials;
            return new NTCredentials(
                    ntCredentials.getUserName(),
                    ntCredentials.getPassword().toCharArray(),
                    ntCredentials.getHost(),
                    ntCredentials.getDomain(),
                    null);
        }

        if (credentials instanceof org.apache.commons.httpclient.UsernamePasswordCredentials) {
            org.apache.commons.httpclient.UsernamePasswordCredentials upCredentials =
                    (org.apache.commons.httpclient.UsernamePasswordCredentials) credentials;
            return new UsernamePasswordCredentials(
                    upCredentials.getUserName(), upCredentials.getPassword().toCharArray());
        }
        return null;
    }
}
