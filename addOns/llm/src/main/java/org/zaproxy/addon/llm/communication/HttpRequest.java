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
package org.zaproxy.addon.llm.communication;

import dev.langchain4j.model.output.structured.Description;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;

public class HttpRequest {

    @Description("HTTP method such as GET, POST, PUT, DELETE, etc.")
    @Getter
    @Setter
    private String method;

    @Description("hostname of the request")
    @Getter
    @Setter
    private String hostname;

    @Description("Full URL of the request based on the hostname and base URL fields")
    @Getter
    @Setter
    private String url;

    @Description("Query parameters in key-value pairs")
    @Getter
    @Setter
    private Map<String, String> queryParams;

    @Description("HTTP headers in key-value pairs")
    @Getter
    @Setter
    private Map<String, String> headers;

    @Description("Body of the request, typically used with POST or PUT methods")
    @Getter
    @Setter
    private String body;

    public HttpRequest(
            String method,
            String hostname,
            String url,
            Map<String, String> queryParams,
            Map<String, String> headers,
            String body) {
        this.method = method;
        this.hostname = hostname;
        this.url = url;
        this.queryParams = queryParams;
        this.headers = headers;
        this.body = body;
    }

    @Override
    public String toString() {
        return "url = {}" + this.url;
    }
}
