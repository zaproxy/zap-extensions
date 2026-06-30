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
package org.zaproxy.addon.commonlib;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class UriUtils {

    /**
     * Validates that the given string is a well-formed, absolute URL suitable for use in HTTP
     * requests.
     *
     * <p>Two conditions must both hold:
     *
     * <ol>
     *   <li><b>Valid URI syntax</b> — the string must conform to RFC 3986. This means all
     *       characters that are not allowed in a URI (such as unencoded spaces, tabs, or square
     *       brackets outside an IPv6 literal) must be percent-encoded, port numbers must be
     *       numeric, and IPv6 addresses must be properly bracketed.
     *   <li><b>Absolute URL with a supported scheme</b> — the string must include a scheme (e.g.
     *       {@code http}, {@code https}, {@code ftp}, {@code file}) and that scheme must be one the
     *       runtime knows how to handle. Protocol-relative strings (e.g. {@code //example.com}),
     *       relative paths, scheme-only strings (e.g. {@code https:}), and schemes without a
     *       registered handler (e.g. {@code javascript:}, {@code ldap://}, {@code ws://}) are all
     *       rejected.
     * </ol>
     *
     * @param uri the string to validate
     * @throws ZapUriException if either condition is not met, carrying the original input and the
     *     reason for rejection
     * @since 1.43.0
     */
    /**
     * Builds a {@link URL} from its component parts.
     *
     * @param scheme the protocol (e.g. {@code http}, {@code https})
     * @param host the hostname or IP address
     * @param port the port number, or {@code -1} to use the scheme's default
     * @param file the path and optional query string
     * @return the constructed URL
     * @throws MalformedURLException if the components do not form a valid URL
     */
    // FIXME
    @SuppressWarnings("deprecation")
    public static URL buildUrl(String scheme, String host, int port, String file)
            throws MalformedURLException {
        return new URL(scheme, host, port, file);
    }

    // FIXME
    @SuppressWarnings("deprecation")
    public static void isValid(String uri) throws ZapUriException {
        if (uri == null) {
            throw new ZapUriException(null, new MalformedURLException("URI must not be null"));
        }
        try {
            new URI(uri);
        } catch (URISyntaxException e) {
            throw new ZapUriException(uri, e);
        }
        try {
            new URL(uri);
        } catch (MalformedURLException e) {
            throw new ZapUriException(uri, e);
        }
    }
}
