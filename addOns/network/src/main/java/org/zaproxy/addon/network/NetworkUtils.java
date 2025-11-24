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
package org.zaproxy.addon.network;

import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.List;
import org.apache.commons.lang3.Strings;
import org.apache.hc.client5.http.auth.AuthChallenge;
import org.apache.hc.client5.http.auth.ChallengeType;
import org.apache.hc.client5.http.auth.Credentials;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.impl.auth.AuthChallengeParser;
import org.apache.hc.client5.http.impl.auth.DigestScheme;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.message.BasicHttpRequest;
import org.apache.hc.core5.http.message.ParserCursor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;

/**
 * @since 0.23.0
 */
public final class NetworkUtils {

    private static final Logger LOGGER = LogManager.getLogger(NetworkUtils.class);

    private NetworkUtils() {}

    /**
     * Returns true if the HTTP response indicates the site requires HTTP Basic authentication.
     *
     * @param msg the message to check
     * @return true if the site requires HTTP Basic authentication.
     */
    public static boolean isHttpBasicAuth(HttpMessage msg) {
        return Strings.CI.startsWith(
                msg.getResponseHeader().getHeader(HttpHeader.WWW_AUTHENTICATE), "Basic");
    }

    /**
     * Returns true if the HTTP response indicates the site requires HTTP Digest authentication.
     *
     * @param msg the message to check
     * @return true if the site requires HTTP Digest authentication.
     */
    public static boolean isHttpDigestAuth(HttpMessage msg) {
        return Strings.CI.startsWith(
                msg.getResponseHeader().getHeader(HttpHeader.WWW_AUTHENTICATE), "Digest");
    }

    /**
     * Returns the HTTP Basic Authorization header to use in a response for the credentials.
     *
     * @param credentials the users credentials.
     * @return the HTTP Basic Authorization header.
     */
    public static String getHttpBasicAuthorization(
            UsernamePasswordAuthenticationCredentials credentials) {
        return "Basic " + encodeCreds(credentials);
    }

    private static String encodeCreds(UsernamePasswordAuthenticationCredentials creds) {
        try {
            return Base64.getEncoder()
                    .encodeToString(
                            (creds.getUsername() + ":" + creds.getPassword()).getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            // Should never happen
            return "";
        }
    }

    /**
     * Returns the HTTP Digest Authorization header to use in a response for the credentials. This
     * is not sufficient to maintain an HTTP Digest session on its own and so may well change in the
     * future.
     *
     * @param credentials the users credentials.
     * @return the HTTP Digest Authorization header, or null if there has been a problem.
     */
    public static String getHttpDigestAuthorization(
            HttpMessage msg, UsernamePasswordAuthenticationCredentials credentials) {
        String authHeader = msg.getResponseHeader().getHeader(HttpHeader.WWW_AUTHENTICATE);
        if (authHeader == null) {
            LOGGER.error("Null auth header for request to {}", msg.getRequestHeader().getURI());
            return null;
        }
        if (credentials.getPassword() == null) {
            LOGGER.error("Null password for user {}", credentials.getUsername());
            return null;
        }
        AuthChallengeParser acp = new AuthChallengeParser();
        try {
            List<AuthChallenge> acs =
                    acp.parse(
                            ChallengeType.TARGET,
                            authHeader,
                            new ParserCursor(0, authHeader.length()));
            if (!acs.isEmpty()) {
                // Just handle 1 for now, this works on a test site
                DigestScheme ds = new DigestScheme();
                Credentials creds =
                        new UsernamePasswordCredentials(
                                credentials.getUsername(), credentials.getPassword().toCharArray());
                ds.initPreemptive(creds, "", "");
                ds.processChallenge(acs.get(0), null);
                return ds.generateAuthResponse(
                        new HttpHost(
                                msg.getRequestHeader().getHostName(),
                                msg.getRequestHeader().getHostPort()),
                        new BasicHttpRequest(
                                msg.getRequestHeader().getMethod(),
                                msg.getRequestHeader().getURI().toString()),
                        null);
            }
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }
}
