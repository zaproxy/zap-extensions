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

import java.util.Collection;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.network.HttpRequestHeader;

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

    /**
     * Gets the query parameters representation for being displayed in a node throughout ZAP. Method
     * should be used to keep consistency whenever displaying a node with parameters.
     *
     * <p>If the parameter name is longer than 40 characters, it gets truncated.
     *
     * <p>Example output: "<i>(param1,param2)</i>"
     *
     * @see #getLeafNodeRepresentation(String, String, Collection, Collection, String)
     * @param params the collection of parameters. Can be null or empty, in which case this method
     *     will return an empty String
     * @return the query params node representation
     */
    public static String getQueryParamsNodeRepresentation(Collection<String> params) {
        if (params == null || params.isEmpty()) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (String name : params) {
            if (name == null) {
                continue;
            }
            if (name.length() > 40) {
                // Truncate
                name = name.substring(0, 40);
            }
            sb.append(name).append(',');
        }

        String result = "";
        if (sb.length() > 0) {
            result = sb.deleteCharAt(sb.length() - 1).insert(0, '(').append(')').toString();
        }

        return result;
    }

    /**
     * Gets the node representation of a leaf node (a web resource page) for being displayed
     * throughout ZAP. The representation contains the HTTP method, node name and, if present, any
     * url or form parameters. Method should be used to keep consistency whenever displaying a
     * node's hostname.
     *
     * <p>Example outputs:
     *
     * <ul>
     *   <li><i>example.jsp</i>
     *   <li><i>POST:login.php(pass,username)</i>
     *   <li><i>GET:index.html</i>
     *   <li><i>POST:upload.jsp(page)(filename)</i>
     *   <li><i>PUT:example.php(multipart/form-data)</i>
     * </ul>
     *
     * @param nodeName the resource name
     * @param method the HTTP method used to fetch the resource
     * @param urlParameters the collection of parsed url parameters, if any, or {@code null}
     *     otherwise
     * @param formParameters the collection of parsed request body parameters, if any, or {@code
     *     null} otherwise. Will be used only if the method is PUT or POST
     * @param contentType the content type, if any. Will be used to check for multipart form data
     * @return a string representing the site node
     */
    public static String getLeafNodeRepresentation(
            String nodeName,
            String method,
            Collection<String> urlParameters,
            Collection<String> formParameters,
            String contentType) {

        StringBuilder leafName = new StringBuilder();
        if (method != null) {
            leafName.append(method).append(':');
        }
        leafName.append(nodeName);

        if (urlParameters != null) {
            leafName.append(getQueryParamsNodeRepresentation(urlParameters));
        }

        if (method != null
                && (method.equalsIgnoreCase(HttpRequestHeader.POST)
                        || method.equalsIgnoreCase(HttpRequestHeader.PUT))) {
            if (contentType != null && contentType.startsWith("multipart/form-data")) {
                leafName.append("(multipart/form-data)");
            } else if (formParameters != null) {
                leafName.append(getQueryParamsNodeRepresentation(formParameters));
            }
        }
        return leafName.toString();
    }

    private UriUtils() {
        // Utility class
    }
}
