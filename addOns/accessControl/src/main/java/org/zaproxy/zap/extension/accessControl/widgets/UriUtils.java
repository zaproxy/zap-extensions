/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.accessControl.widgets;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;

/** An utility class with various methods related to URIs and URLs used throughout ZAP. */
public final class UriUtils {

    /**
     * Returns a representation of the host name as used throughout ZAP. The representation contains
     * the scheme, the host and, if needed, the port. Method should be used to keep consistency
     * whenever displaying a node's hostname.
     *
     * <p>Example outputs:
     *
     * <ul>
     *   <li><i>http://example.org</i>
     *   <li><i>http://example.org:8080</i>
     *   <li><i>https://example.org</i>
     * </ul>
     *
     * @throws URIException
     */
    public static String getHostName(URI uri) throws URIException {
        StringBuilder host = new StringBuilder();

        String scheme = uri.getScheme().toLowerCase();
        host.append(scheme).append("://").append(uri.getHost());
        int port = uri.getPort();
        if ((port != -1)
                && ((port == 80 && !"http".equals(scheme))
                        || (port == 443 && !"https".equals(scheme))
                        || (port != 80 && port != 443))) {
            host.append(":").append(port);
        }

        return host.toString();
    }

    private UriUtils() {
        // Utility class
    }
}
