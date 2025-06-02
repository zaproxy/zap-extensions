/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.postman.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import java.util.List;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.postman.deserializers.ListDeserializer;
import org.zaproxy.addon.postman.deserializers.ObjectDeserializer;

/**
 * Represents the request in the Postman format which is contained by the items.
 *
 * @see https://learning.postman.com/collection-format/reference/request/
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Request {

    @JsonDeserialize(using = ObjectDeserializer.class)
    private Url url;

    @JsonDeserialize(using = ObjectDeserializer.class)
    private String method = HttpRequestHeader.GET;

    @JsonDeserialize(using = ListDeserializer.class)
    private List<KeyValueData> header;

    @JsonDeserialize(using = ObjectDeserializer.class)
    private Body body;

    public Request() {}

    public Request(String url) {
        this.url = new Url(url);
    }

    public Url getUrl() {
        return url;
    }

    public void setUrl(Url url) {
        this.url = url;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public List<KeyValueData> getHeader() {
        return header;
    }

    public void setHeader(List<KeyValueData> header) {
        this.header = header;
    }

    public Body getBody() {
        return body;
    }

    public void setBody(Body body) {
        this.body = body;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Url {

        @JsonDeserialize(using = ObjectDeserializer.class)
        private String raw;

        @JsonDeserialize(using = ListDeserializer.class)
        private List<KeyValueData> variable;

        public Url() {}

        public Url(String raw) {
            this.raw = raw;
        }

        public String getRaw() {
            return raw;
        }

        public void setRaw(String raw) {
            this.raw = raw;
        }

        public List<KeyValueData> getVariable() {
            return variable;
        }

        public void setVariable(List<KeyValueData> variable) {
            this.variable = variable;
        }
    }
}
