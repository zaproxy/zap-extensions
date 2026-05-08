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
package org.zaproxy.addon.mcp.importer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.core.scanner.Variant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

/**
 * A ZAP {@link Variant} that recognises JSON-RPC 2.0 MCP requests and organises them in the sites
 * tree using the {@code method} field as the path (e.g. {@code tools/call}) with a per-method
 * qualifier as an additional node.
 *
 * <p>For {@code resources/read}, the {@code uri} value is used to build the sites-tree path
 * directly (scheme → authority → path segments), matching the structure of the resource URI rather
 * than the JSON-RPC method. Template variables and query-string parameters within the URI are
 * exposed as fuzz parameters.
 */
public class VariantMcpJsonRpc implements Variant {

    private static final Logger LOGGER = LogManager.getLogger(VariantMcpJsonRpc.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern TEMPLATE_VAR = Pattern.compile("\\{([^}]+)\\}");

    private final List<NameValuePair> params = new ArrayList<>();

    @Override
    public void setMessage(HttpMessage msg) {
        params.clear();

        JsonNode body = parseJsonRpcBody(msg);
        if (body == null) {
            return;
        }
        params.addAll(buildParams(body));
    }

    private static List<NameValuePair> buildParams(JsonNode body) {
        List<NameValuePair> result = new ArrayList<>();
        JsonNode paramsNode = body.get("params");
        if (paramsNode == null || !paramsNode.isObject()) {
            return result;
        }

        String method = body.get("method").asText();

        paramsNode
                .properties()
                .forEach(
                        entry -> {
                            String key = entry.getKey();
                            JsonNode value = entry.getValue();

                            // Skip routing/selector fields — they identify which tool/prompt to
                            // call and are used for tree-path organisation, not for fuzzing.
                            if (isRoutingField(method, key)) {
                                return;
                            }

                            // For resources/read the uri field defines the tree path structure.
                            // Only template variables and query-string params are fuzz targets.
                            if ("resources/read".equals(method) && "uri".equals(key)) {
                                extractUriParams(value.asText(), result);
                                return;
                            }

                            if (value.isObject()) {
                                // Flatten one level: "arguments": {"target": "..."} → "target"
                                value.properties()
                                        .forEach(
                                                inner ->
                                                        addParamOrTemplateVars(
                                                                inner.getKey(),
                                                                nodeText(inner.getValue()),
                                                                result));
                            } else {
                                addParamOrTemplateVars(key, nodeText(value), result);
                            }
                        });
        return result;
    }

    /**
     * Extracts fuzz parameters from a resource URI: template variables from the path (e.g. {@code
     * {alertRef}}) and key=value pairs from the query string.
     */
    private static void extractUriParams(String uriValue, List<NameValuePair> result) {
        int queryStart = uriValue.indexOf('?');
        String pathPart = queryStart >= 0 ? uriValue.substring(0, queryStart) : uriValue;
        String queryPart = queryStart >= 0 ? uriValue.substring(queryStart + 1) : null;

        for (String var : templateVarsIn(pathPart)) {
            result.add(new NameValuePair(NameValuePair.TYPE_JSON, var, "", result.size()));
        }

        if (queryPart != null && !queryPart.isEmpty()) {
            for (String pair : queryPart.split("&")) {
                int eq = pair.indexOf('=');
                if (eq < 0) {
                    continue;
                }
                String name = pair.substring(0, eq);
                String val = pair.substring(eq + 1);
                if (!name.isEmpty()) {
                    result.add(
                            new NameValuePair(NameValuePair.TYPE_JSON, name, val, result.size()));
                }
            }
        }
    }

    /**
     * Adds the parameter — or, if the value contains {@code {var}} placeholders, adds one parameter
     * per placeholder instead of the raw value.
     */
    private static void addParamOrTemplateVars(
            String name, String value, List<NameValuePair> result) {
        List<String> vars = templateVarsIn(value);
        if (!vars.isEmpty()) {
            for (String var : vars) {
                result.add(new NameValuePair(NameValuePair.TYPE_JSON, var, "", result.size()));
            }
        } else {
            result.add(new NameValuePair(NameValuePair.TYPE_JSON, name, value, result.size()));
        }
    }

    /** Returns {@code true} when {@code key} is a method-selector rather than a data field. */
    private static boolean isRoutingField(String method, String key) {
        return "name".equals(key) && ("tools/call".equals(method) || "prompts/get".equals(method));
    }

    /**
     * Returns the string representation of a {@link JsonNode} value: for scalar nodes (string,
     * number, boolean, null) this is the natural text form (e.g. {@code "42"}, {@code "true"},
     * {@code "hello"}); for array and object nodes it is the compact JSON serialisation (e.g.
     * {@code "[1,2]"}) so that the value is not silently lost as an empty string.
     */
    private static String nodeText(JsonNode node) {
        return node.isValueNode() ? node.asText() : node.toString();
    }

    /** Extracts all {@code {varName}} placeholders from {@code text}. */
    private static List<String> templateVarsIn(String text) {
        List<String> vars = new ArrayList<>();
        Matcher m = TEMPLATE_VAR.matcher(text);
        while (m.find()) {
            vars.add(m.group(1));
        }
        return vars;
    }

    @Override
    public List<NameValuePair> getParamList() {
        return Collections.emptyList();
    }

    @Override
    public String setEscapedParameter(
            HttpMessage msg, NameValuePair originalPair, String param, String value) {
        return null;
    }

    @Override
    public String setParameter(
            HttpMessage msg, NameValuePair originalPair, String param, String value) {
        return null;
    }

    @Override
    public String getLeafName(String nodeName, HttpMessage msg) {
        JsonNode body = parseJsonRpcBody(msg);
        if (body == null) {
            return null;
        }
        List<String> treePath = buildTreePath(msg, body);
        List<NameValuePair> localParams = buildParams(body);
        LOGGER.debug(
                "getLeafName: nodeName={}, treePath={}, params={}",
                nodeName,
                treePath,
                localParams.stream().map(NameValuePair::getName).toList());
        String effectiveNodeName =
                (treePath != null && !treePath.isEmpty())
                        ? treePath.get(treePath.size() - 1)
                        : nodeName;
        StringBuilder sb = new StringBuilder(msg.getRequestHeader().getMethod());
        sb.append(": ");
        sb.append(effectiveNodeName);
        sb.append("(");
        boolean first = true;
        for (NameValuePair nvp : localParams) {
            if (!first) {
                sb.append(",");
            }
            sb.append(nvp.getName());
            first = false;
        }
        sb.append(")");
        LOGGER.debug("getLeafName result: {}", sb);
        return sb.toString();
    }

    @Override
    public List<String> getTreePath(HttpMessage msg) {
        JsonNode body = parseJsonRpcBody(msg);
        if (body == null) {
            LOGGER.debug("getTreePath: body is null for URI={}", msg.getRequestHeader().getURI());
            return null;
        }
        return buildTreePath(msg, body);
    }

    private List<String> buildTreePath(HttpMessage msg, JsonNode body) {
        JsonNode methodNode = body.get("method");
        if (methodNode == null || !methodNode.isTextual()) {
            return null;
        }
        String method = methodNode.asText();

        if ("resources/read".equals(method)) {
            JsonNode paramsNode = body.get("params");
            if (paramsNode != null && paramsNode.isObject()) {
                JsonNode uriNode = paramsNode.get("uri");
                if (uriNode != null) {
                    List<String> uriPath = buildUriTreePath(uriNode.asText());
                    if (uriPath != null) {
                        List<String> fullPath = new ArrayList<>();
                        fullPath.add("resources");
                        fullPath.addAll(uriPath);
                        return fullPath;
                    }
                }
            }
            return null;
        }

        List<String> treePath = new ArrayList<>();
        try {
            URI uri = msg.getRequestHeader().getURI();
            String path = uri.getPath();
            LOGGER.debug("getTreePath: URI={}, path={}", uri, path);
            if (path != null) {
                for (String seg : path.split("/")) {
                    if (!seg.isEmpty()) {
                        treePath.add(seg);
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.debug("getTreePath: URI parse failed: {}", e.getMessage());
        }

        Collections.addAll(treePath, method.split("/"));
        LOGGER.debug("getTreePath: after URI+method segments: {}", treePath);

        JsonNode paramsNode = body.get("params");
        if (paramsNode != null && paramsNode.isObject()) {
            String qualifier = getQualifier(method, paramsNode);
            if (qualifier != null && !qualifier.isEmpty()) {
                treePath.add(qualifier);
            }
        }
        return treePath;
    }

    private static List<String> buildUriTreePath(String uriValue) {
        int q = uriValue.indexOf('?');
        String noQuery = q >= 0 ? uriValue.substring(0, q) : uriValue;

        int schemeEnd = noQuery.indexOf("://");
        if (schemeEnd < 0) {
            return null;
        }
        String scheme = noQuery.substring(0, schemeEnd);
        String rest = noQuery.substring(schemeEnd + 3);

        int slash = rest.indexOf('/');
        String authority = slash >= 0 ? rest.substring(0, slash) : rest;
        String pathStr = slash >= 0 ? rest.substring(slash + 1) : "";

        List<String> treePath = new ArrayList<>();
        treePath.add(scheme);
        if (!authority.isEmpty()) {
            treePath.add(authority);
        }

        if (!pathStr.isEmpty()) {
            for (String seg : pathStr.split("/", -1)) {
                if (!seg.isEmpty() && !isTemplateSegment(seg)) {
                    treePath.add(seg);
                }
            }
        }

        return treePath;
    }

    private static boolean isTemplateSegment(String segment) {
        return segment.startsWith("{") && segment.endsWith("}");
    }

    private static String getQualifier(String method, JsonNode paramsNode) {
        return switch (method) {
            case "tools/call", "prompts/get" -> {
                JsonNode name = paramsNode.get("name");
                yield name != null ? name.asText() : null;
            }
            default -> null;
        };
    }

    private static JsonNode parseJsonRpcBody(HttpMessage msg) {
        if (!HttpRequestHeader.POST.equals(msg.getRequestHeader().getMethod())) {
            return null;
        }
        String body = msg.getRequestBody().toString();
        if (body.isEmpty() || !body.contains("\"jsonrpc\"")) {
            return null;
        }
        try {
            JsonNode node = MAPPER.readTree(body);
            if (node.isObject() && node.has("method") && node.has("jsonrpc")) {
                return node;
            }
        } catch (Exception e) {
            // Not valid JSON-RPC
        }
        return null;
    }
}
