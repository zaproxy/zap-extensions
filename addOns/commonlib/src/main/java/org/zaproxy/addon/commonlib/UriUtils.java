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

/**
 * @since 1.43.0
 */
public class UriUtils {

    /**
     * Validates that the given string is a well-formed, absolute URL suitable for use in HTTP
     * requests.
     *
     * @param uri the string to validate
     * @throws ZapUriException if either condition is not met, carrying the original input and the
     *     reason for rejection
     * @since 1.43.0
     */
    // FIXME
    @SuppressWarnings("deprecation")
    public static void isValid(String uri) throws ZapUriException {
        if (uri == null) {
            throw new ZapUriException("URI must not be null");
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

    /**
     * Builds a {@link URL} from its component parts.
     *
     * @param scheme the protocol (e.g. {@code http}, {@code https})
     * @param host the hostname or IP address
     * @param port the port number, or {@code -1} to use the scheme's default
     * @param file the path and optional query string
     * @return the constructed URL
     * @throws ZapUriException if the components do not form a valid URL
     */
    // FIXME
    @SuppressWarnings("deprecation")
    public static URL buildUrl(String scheme, String host, int port, String file)
            throws ZapUriException {
        try {
            return new URL(scheme, host, port, file);
        } catch (MalformedURLException e) {
            throw new ZapUriException(scheme + "://" + host + ":" + port + "/" + file, e);
        }
    }
}
