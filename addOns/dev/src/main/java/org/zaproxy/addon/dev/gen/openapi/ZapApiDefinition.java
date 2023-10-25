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
package org.zaproxy.addon.dev.gen.openapi;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.api.API.Format;
import org.zaproxy.zap.extension.api.API.RequestType;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiDynamicActionImplementor;
import org.zaproxy.zap.extension.api.ApiElement;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiOther;
import org.zaproxy.zap.extension.api.ApiParameter;
import org.zaproxy.zap.extension.api.ApiPersistentConnection;
import org.zaproxy.zap.extension.api.ApiView;

/** The OpenAPI definition for the ZAP API. */
public class ZapApiDefinition {

    private String openapi;
    private Info info;
    private List<Server> servers;
    private Map<String, Object> components;
    private List<Map<String, List<String>>> security;
    private Map<String, Path> paths;

    /**
     * The API API implementors.
     *
     * @param implementors the implementors, must not be {@code null}.
     */
    public ZapApiDefinition(Collection<ApiImplementor> implementors) {
        openapi = "3.0.3";
        info = new Info();
        servers = new ArrayList<>();
        servers.add(new Server("http://zap", "The URL while proxying through ZAP."));
        var mainProxy = new Server("http://{address}:{port}", "The URL of a Local Proxy of ZAP.");
        mainProxy
                .getVariables()
                .put("address", new Variable("127.0.0.1", "The address ZAP is listening on."));
        mainProxy.getVariables().put("port", new Variable("8080", "The port ZAP is bound to."));
        servers.add(mainProxy);

        components = new LinkedHashMap<>();
        components.put(
                "securitySchemes",
                Map.of(
                        "apiKeyHeader",
                        new SecurityScheme("apiKey", "X-ZAP-API-Key", "header"),
                        "apiKeyQuery",
                        new SecurityScheme("apiKey", "apikey", "query")));

        components.put(
                "responses",
                Map.of(
                        "ErrorJson",
                        createErrorResponse(
                                "Error of JSON endpoints.",
                                createRefSchema("#/components/schemas/ErrorJson"),
                                "application/json"),
                        "ErrorOther",
                        createErrorResponse("Error of OTHER endpoints.", null, "*/*")));

        components.put("schemas", Map.of("ErrorJson", createErrorJsonSchema()));

        security = new ArrayList<>();
        security.add(Map.of());
        security.add(Map.of("apiKeyHeader", List.of()));
        security.add(Map.of("apiKeyQuery", List.of()));

        paths = new LinkedHashMap<>();
        implementors.stream()
                .sorted((a, b) -> a.getPrefix().compareTo(b.getPrefix()))
                .forEach(e -> addPaths(paths, e));
    }

    private static Response createErrorResponse(
            String description, Schema schema, String mediaType) {
        var errorResponse = new Response(description);
        errorResponse.getContent().put(mediaType, new Response.MediaType(schema));
        return errorResponse;
    }

    private static Schema createRefSchema(String ref) {
        var schema = new Schema();
        schema.ref = ref;
        return schema;
    }

    private static Schema createErrorJsonSchema() {
        var schema = new Schema("object");
        schema.required = List.of("code", "message");
        schema.properties = new LinkedHashMap<>();
        var stringSchema = new Schema("string");
        schema.properties.put("code", stringSchema);
        schema.properties.put("message", stringSchema);
        schema.properties.put("detail", stringSchema);
        return schema;
    }

    private static void addPaths(Map<String, Path> paths, ApiImplementor implementor) {
        List<ApiElement> endpoints = new ArrayList<>();
        endpoints.addAll(implementor.getApiViews());
        endpoints.addAll(implementor.getApiActions());
        endpoints.addAll(implementor.getApiOthers());
        Collections.sort(
                endpoints,
                (a, b) -> {
                    var typeA = getType(a);
                    var typeB = getType(b);
                    if (typeA != typeB) {
                        return typeA.name().compareTo(typeB.name());
                    }
                    return a.getName().compareTo(b.getName());
                });

        for (ApiElement endpoint : endpoints) {
            paths.put(getPath(implementor, endpoint), new Path(implementor, endpoint));
        }
    }

    public String getOpenapi() {
        return openapi;
    }

    public Info getInfo() {
        return info;
    }

    public List<Server> getServers() {
        return servers;
    }

    public Map<String, Object> getComponents() {
        return components;
    }

    public List<Map<String, List<String>>> getSecurity() {
        return security;
    }

    public Map<String, Path> getPaths() {
        return paths;
    }

    static class Info {

        private String title = "ZAP API";
        private String description = "The HTTP API for controlling and accessing ZAP.";
        private Contact contact = new Contact();
        private License license = new License();
        private String version = Constant.PROGRAM_VERSION;

        public String getTitle() {
            return title;
        }

        public String getDescription() {
            return description;
        }

        public Contact getContact() {
            return contact;
        }

        public License getLicense() {
            return license;
        }

        public String getVersion() {
            return version;
        }

        static class Contact {

            private String name = "ZAP User Group";
            private String url = "https://groups.google.com/group/zaproxy-users";
            private String email = "zaproxy-users@googlegroups.com";

            public String getName() {
                return name;
            }

            public String getUrl() {
                return url;
            }

            public String getEmail() {
                return email;
            }
        }

        static class License {

            private String name = "Apache 2.0";
            private String url = "https://www.apache.org/licenses/LICENSE-2.0.html";

            public String getName() {
                return name;
            }

            public String getUrl() {
                return url;
            }
        }
    }

    static class Server {

        private String url;
        private String description;

        @JsonInclude(value = JsonInclude.Include.NON_EMPTY)
        private Map<String, Variable> variables;

        Server(String url, String description) {
            this.url = url;
            this.description = description;
            this.variables = new LinkedHashMap<>();
        }

        public String getUrl() {
            return url;
        }

        public String getDescription() {
            return description;
        }

        public Map<String, Variable> getVariables() {
            return variables;
        }
    }

    static class Variable {

        @JsonProperty("default")
        private String defaultValue;

        private String description;

        public Variable(String defaultValue, String description) {
            this.defaultValue = defaultValue;
            this.description = description;
        }

        public String getDefaultValue() {
            return defaultValue;
        }

        public String getDescription() {
            return description;
        }
    }

    static class SecurityScheme {

        private String type;
        private String name;
        private String in;

        public SecurityScheme(String type, String name, String in) {

            this.type = type;
            this.name = name;
            this.in = in;
        }

        public String getType() {
            return type;
        }

        public String getName() {
            return name;
        }

        public String getIn() {
            return in;
        }
    }

    static class Path {

        private Method get;

        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        private List<Parameter> parameters;

        public Path(ApiImplementor parent, ApiElement endpoint) {
            parameters = new ArrayList<>();
            endpoint.getParameters().forEach(e -> parameters.add(new Parameter(e)));

            get = new Method(parent, endpoint);
        }

        public Method getGet() {
            return get;
        }

        public List<Parameter> getParameters() {
            return parameters;
        }

        static class Method {

            private String description;

            @JsonInclude(JsonInclude.Include.NON_NULL)
            private Boolean deprecated;

            private String operationId;
            private List<String> tags;

            private Map<String, Response> responses;

            public Method(ApiImplementor parent, ApiElement endpoint) {
                description = getDescription(endpoint);
                operationId = getOperationId(parent.getPrefix(), endpoint);
                tags = List.of(parent.getPrefix());

                if (endpoint.isDeprecated()) {
                    deprecated = true;
                }

                responses = new LinkedHashMap<>();
                responses.put(
                        "default",
                        getType(endpoint) != RequestType.other
                                ? new Response("#/components/responses/ErrorJson")
                                : new Response("#/components/responses/ErrorOther"));
            }

            public String getDescription() {
                return description;
            }

            public Boolean getDeprecated() {
                return deprecated;
            }

            public String getOperationId() {
                return operationId;
            }

            public List<String> getTags() {
                return tags;
            }

            public Map<String, Response> getResponses() {
                return responses;
            }

            private static String getOperationId(String component, ApiElement endpoint) {
                return component
                        + StringUtils.capitalize(getType(endpoint).name())
                        + StringUtils.capitalize(endpoint.getName());
            }

            private static String getDescription(ApiElement apiElement) {
                String descTag = apiElement.getDescriptionTag();
                if (apiElement.isDeprecated()) {
                    String deprecated = apiElement.getDeprecatedDescription();
                    if (StringUtils.isNotEmpty(deprecated)) {
                        return deprecated;
                    }
                }
                return getI18nString(descTag);
            }
        }

        static class Parameter {

            private String name;
            private String in;

            @JsonInclude(JsonInclude.Include.NON_NULL)
            private Boolean required;

            private String description;
            private Schema schema;

            public Parameter(ApiParameter parameter) {
                name = parameter.getName();
                in = "query";
                if (parameter.isRequired()) {
                    required = true;
                }
                description = getI18nString(parameter.getDescriptionKey());

                schema = new Schema(getType(parameter));
            }

            public String getName() {
                return name;
            }

            public String getIn() {
                return in;
            }

            public Boolean getRequired() {
                return required;
            }

            public String getDescription() {
                return description;
            }

            public Schema getSchema() {
                return schema;
            }

            private static String getType(ApiParameter parameter) {
                switch (parameter.getName()) {
                    case "Boolean":
                        return "boolean";

                    case "Integer":
                        return "integer";

                    default:
                        return "string";
                }
            }
        }

        static class Response {

            @JsonProperty("$ref")
            private String ref;

            public Response(String ref) {
                this.ref = ref;
            }

            public String getRef() {
                return ref;
            }
        }

        private static String getI18nString(String key) {
            if (Constant.messages.containsKey(key)) {
                return Constant.messages.getString(key);
            }
            return "";
        }
    }

    static class Schema {

        @JsonProperty("$ref")
        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        private String ref;

        @JsonInclude(JsonInclude.Include.NON_NULL)
        private String type;

        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        private List<String> required;

        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        private Map<String, Schema> properties;

        @JsonInclude(JsonInclude.Include.NON_NULL)
        private Integer minimum;

        @JsonInclude(JsonInclude.Include.NON_NULL)
        private Integer maximum;

        public Schema() {}

        public Schema(String type) {

            this.type = type;
        }

        public String getType() {
            return type;
        }

        public List<String> getRequired() {
            return required;
        }

        public Map<String, Schema> getProperties() {
            return properties;
        }

        public Integer getMinimum() {
            return minimum;
        }

        public Integer getMaximum() {
            return maximum;
        }
    }

    static class Response {

        private String description;

        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        private Map<String, MediaType> content = new LinkedHashMap<>();

        public Response(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }

        public Map<String, MediaType> getContent() {
            return content;
        }

        static class MediaType {

            @JsonInclude(JsonInclude.Include.NON_NULL)
            private Schema schema;

            public MediaType(Schema schema) {
                this.schema = schema;
            }

            public Schema getSchema() {
                return schema;
            }
        }
    }

    private static String getPath(ApiImplementor implementor, ApiElement endpoint) {
        RequestType type = getType(endpoint);
        Format format = type == RequestType.other ? Format.OTHER : Format.JSON;
        return "/"
                + format.name()
                + "/"
                + implementor.getPrefix()
                + "/"
                + type.name()
                + "/"
                + endpoint.getName()
                + "/";
    }

    private static RequestType getType(ApiElement endpoint) {
        if (endpoint instanceof ApiAction || endpoint instanceof ApiDynamicActionImplementor) {
            return RequestType.action;
        }
        if (endpoint instanceof ApiView) {
            return RequestType.view;
        }
        if (endpoint instanceof ApiOther) {
            return RequestType.other;
        }
        if (endpoint instanceof ApiPersistentConnection) {
            return RequestType.pconn;
        }
        return RequestType.action;
    }
}
