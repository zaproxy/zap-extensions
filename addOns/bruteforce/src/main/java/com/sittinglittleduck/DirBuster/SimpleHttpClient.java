/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package com.sittinglittleduck.DirBuster;

import java.io.IOException;

/** A simple HTTP client. */
public interface SimpleHttpClient {

    /** The HTTP methods required by the client. */
    enum HttpMethod {
        HEAD,
        GET
    }

    /**
     * Sends an HTTP request with the given method and URL.
     *
     * @param method the method of the request.
     * @param url the URL of the request.
     * @return the response, never {@code null}.
     * @throws IOException if an error occurred while sending the request.
     */
    HttpResponse send(HttpMethod method, String url) throws IOException;
}
