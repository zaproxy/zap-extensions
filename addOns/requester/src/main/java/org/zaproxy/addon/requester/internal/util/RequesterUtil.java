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
package org.zaproxy.addon.requester.internal.util;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.requester.internal.exception.RequesterException;

/** Requester utilities */
public class RequesterUtil {

    public static final String DEFAULT_URL = "https://example.com/";

    /**
     * Creates default HTTP message
     *
     * @return New {@link HttpMessage}
     */
    public static HttpMessage createDefaultHttpMessage() {
        HttpMessage message = new HttpMessage();
        try {
            URI uri = new URI(DEFAULT_URL, true);
            message.setRequestHeader(
                    new HttpRequestHeader(HttpRequestHeader.GET, uri, HttpHeader.HTTP11));
            return message;
        } catch (HttpMalformedHeaderException | URIException e) {
            throw new RequesterException(e);
        }
    }

    private RequesterUtil() {}
}
