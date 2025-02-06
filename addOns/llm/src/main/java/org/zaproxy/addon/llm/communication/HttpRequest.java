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

public class HttpRequest {

    @Description("HTTP method such as GET, POST, PUT, DELETE, etc.")
    private String method;

    @Description("hostname of the request")
    private String hostname;

    @Description("Full URL of the request based on the hostname and base URL fields")
    private String url;

    @Description("Query parameters in key-value pairs")
    private Map<String, String> queryParams;

    @Description("HTTP headers in key-value pairs")
    private Map<String, String> headers;

    @Description("Body of the request, typically used with POST or PUT methods")
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

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public Map<String, String> getQueryParams() {
        return queryParams;
    }

    public void setQueryParams(Map<String, String> queryParams) {
        this.queryParams = queryParams;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    @Override
    public String toString() {
        return "url = " + this.url;
    }
}
