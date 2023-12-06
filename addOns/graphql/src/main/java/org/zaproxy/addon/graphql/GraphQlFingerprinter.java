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
package org.zaproxy.addon.graphql;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.BooleanSupplier;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

public class GraphQlFingerprinter {

    private static final String FINGERPRINTING_ALERT_REF = ExtensionGraphQl.TOOL_ALERT_ID + "-2";
    private static final Map<String, String> FINGERPRINTING_ALERT_TAGS =
            CommonAlertTag.toMap(CommonAlertTag.WSTG_V42_INFO_02_FINGERPRINT_WEB_SERVER);
    private static final Logger LOGGER = LogManager.getLogger(GraphQlFingerprinter.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final Requestor requestor;
    private final Map<String, HttpMessage> queryCache;

    private HttpMessage lastQueryMsg;
    private String matchedString;

    public GraphQlFingerprinter(URI endpointUrl) {
        requestor = new Requestor(endpointUrl, HttpSender.MANUAL_REQUEST_INITIATOR);
        queryCache = new HashMap<>();
    }

    public void fingerprint() {
        Map<String, BooleanSupplier> fingerprinters = new LinkedHashMap<>(29);
        // TODO: Check whether the order of the fingerprint checks matters.
        fingerprinters.put("lighthouse", this::checkLighthouseEngine);
        fingerprinters.put("caliban", this::checkCalibanEngine);
        fingerprinters.put("lacinia", this::checkLaciniaEngine);
        fingerprinters.put("jaal", this::checkJaalEngine);
        fingerprinters.put("morpheus", this::checkMorpheusEngine);
        fingerprinters.put("mercurius", this::checkMercuriusEngine);
        fingerprinters.put("graphql-yoga", this::checkGraphQlYogaEngine);
        fingerprinters.put("agoo", this::checkAgooEngine);
        fingerprinters.put("dgraph", this::checkDgraphEngine);
        fingerprinters.put("graphene", this::checkGrapheneEngine);
        fingerprinters.put("ariadne", this::checkAriadneEngine);
        fingerprinters.put("apollo", this::checkApolloEngine);
        fingerprinters.put("aws-appsync", this::checkAwsAppSyncEngine);
        fingerprinters.put("hasura", this::checkHasuraEngine);
        fingerprinters.put("wpgraphql", this::checkWpGraphQlEngine);
        fingerprinters.put("graphql-by-pop", this::checkGraphQlByPopEngine);
        fingerprinters.put("graphql-java", this::checkGraphQlJavaEngine);
        fingerprinters.put("hypergraphql", this::checkHyperGraphQlEngine);
        fingerprinters.put("graphql-ruby", this::checkGraphQlRubyEngine);
        fingerprinters.put("graphql-php", this::checkGraphQlPhpEngine);
        fingerprinters.put("gqlgen", this::checkGqlGenEngine);
        fingerprinters.put("graphql-go", this::checkGraphQlGoEngine);
        fingerprinters.put("juniper", this::checkJuniperEngine);
        fingerprinters.put("sangria", this::checkSangriaEngine);
        fingerprinters.put("graphql-flutter", this::checkFlutterEngine);
        fingerprinters.put("dianajl", this::checkDianajlEngine);
        fingerprinters.put("strawberry", this::checkStrawberryEngine);
        fingerprinters.put("tartiflette", this::checkTartifletteEngine);
        fingerprinters.put("directus", this::checkDirectusEngine);
        fingerprinters.put("absinthe", this::checkAbsintheEngine);
        fingerprinters.put("graphql-dotnet", this::checkGraphqlDotNetEngine);

        for (var fingerprinter : fingerprinters.entrySet()) {
            try {
                if (fingerprinter.getValue().getAsBoolean()) {
                    raiseFingerprintingAlert(fingerprinter.getKey());
                    break;
                }
            } catch (Exception e) {
                LOGGER.warn("Failed to fingerprint GraphQL engine: {}", fingerprinter.getKey(), e);
            }
        }
        queryCache.clear();
    }

    void sendQuery(String query) {
        lastQueryMsg =
                queryCache.computeIfAbsent(
                        query,
                        k -> requestor.sendQuery(k, GraphQlParam.RequestMethodOption.POST_JSON));
    }

    boolean errorContains(String substring) {
        return errorContains(substring, "message");
    }

    boolean errorContains(String substring, String errorField) {
        if (lastQueryMsg == null) {
            return false;
        }
        if (!lastQueryMsg.getResponseHeader().isJson()) {
            return false;
        }
        try {
            String response = lastQueryMsg.getResponseBody().toString();
            JsonNode errors = OBJECT_MAPPER.readValue(response, JsonNode.class).get("errors");
            if (errors == null || !errors.isArray()) {
                return false;
            }
            for (var error : errors) {
                if (!error.isObject()) {
                    continue;
                }
                var errorFieldValue = error.get(errorField);
                if (errorFieldValue == null) {
                    continue;
                }
                if (errorFieldValue.asText().contains(substring)) {
                    matchedString = substring;
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    static Alert.Builder createFingerprintingAlert(String engineId) {
        final String enginePrefix = "graphql.engine." + engineId + ".";
        return Alert.builder()
                .setPluginId(ExtensionGraphQl.TOOL_ALERT_ID)
                .setAlertRef(FINGERPRINTING_ALERT_REF)
                .setName(Constant.messages.getString("graphql.fingerprinting.alert.name"))
                .setDescription(
                        Constant.messages.getString(
                                "graphql.fingerprinting.alert.desc",
                                Constant.messages.getString(enginePrefix + "name"),
                                Constant.messages.getString(enginePrefix + "technologies")))
                .setReference(Constant.messages.getString(enginePrefix + "docsUrl"))
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setRisk(Alert.RISK_INFO)
                .setCweId(205)
                .setWascId(45)
                .setSource(Alert.Source.TOOL)
                .setTags(FINGERPRINTING_ALERT_TAGS);
    }

    private void raiseFingerprintingAlert(String engineId) {
        var extAlert =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
        if (extAlert == null) {
            return;
        }
        Alert alert =
                createFingerprintingAlert(engineId)
                        .setEvidence(matchedString)
                        .setMessage(lastQueryMsg)
                        .setUri(requestor.getEndpointUrl().toString())
                        .build();
        extAlert.alertFound(alert, null);
    }

    private boolean checkAbsintheEngine() {
        sendQuery("{zaproxy}");
        return errorContains("Cannot query field \"zaproxy\" on type \"RootQueryType\".");
    }

    private boolean checkAgooEngine() {
        sendQuery("{zaproxy}");
        return errorContains("eval error", "code");
    }

    private boolean checkApolloEngine() {
        sendQuery("query @skip {__typename}");
        if (errorContains(
                "Directive \"@skip\" argument \"if\" of type \"Boolean!\" is required, but it was not provided.")) {
            return true;
        }
        sendQuery("query @deprecated {__typename}");
        return errorContains("Directive \"@deprecated\" may not be used on QUERY.");
    }

    private boolean checkAriadneEngine() {
        sendQuery("{__typename @abc}");
        if (errorContains("Unknown directive '@abc'.")) {
            try {
                String response = lastQueryMsg.getResponseBody().toString();
                JsonNode data = OBJECT_MAPPER.readValue(response, JsonNode.class).get("data");
                if (data == null) {
                    matchedString = null;
                    return true;
                }
            } catch (Exception ignored) {
            }
        }
        sendQuery("");
        return errorContains("The query must be a string.");
    }

    private boolean checkAwsAppSyncEngine() {
        sendQuery("query @skip {__typename}");
        return errorContains("MisplacedDirective");
    }

    private boolean checkCalibanEngine() {
        sendQuery("{__typename} fragment zap on __Schema {directives {name}}");
        return errorContains("Fragment 'zap' is not used in any spread");
    }

    private boolean checkDgraphEngine() {
        sendQuery("{__typename @cascade}");
        if (lastQueryMsg != null && lastQueryMsg.getResponseHeader().isJson()) {
            try {
                String response = lastQueryMsg.getResponseBody().toString();
                JsonNode data = OBJECT_MAPPER.readValue(response, JsonNode.class).get("data");
                if (data != null && data.isObject()) {
                    if (data.has("__typename") && "Query".equals(data.get("__typename").asText())) {
                        matchedString = "Query";
                        return true;
                    }
                }
            } catch (Exception ignored) {
            }
        }
        sendQuery("{__typename}");
        return errorContains(
                "Not resolving __typename. There's no GraphQL schema in Dgraph. Use the /admin API to add a GraphQL schema");
    }

    private boolean checkDianajlEngine() {
        sendQuery("queryy {__typename}");
        return errorContains("Syntax Error GraphQL request (1:1) Unexpected Name \"queryy\"");
    }

    private boolean checkDirectusEngine() {
        try {
            sendQuery("");
            if (lastQueryMsg == null || !lastQueryMsg.getResponseHeader().isJson()) {
                return false;
            }
            String response = lastQueryMsg.getResponseBody().toString();
            JsonNode errors = OBJECT_MAPPER.readValue(response, JsonNode.class).get("errors");
            if (errors == null || !errors.isArray()) {
                return false;
            }
            if (errors.size() == 0) {
                return false;
            }
            var error = errors.get(0);
            if (error == null || !error.isObject()) {
                return false;
            }
            JsonNode extensions = error.get("extensions");
            if (extensions == null || !extensions.isObject()) {
                return false;
            }
            if (extensions.has("code")
                    && "INVALID_PAYLOAD".equals(extensions.get("code").asText())) {
                matchedString = "INVALID_PAYLOAD";
                return true;
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private boolean checkFlutterEngine() {
        sendQuery("{__typename @deprecated}");
        return errorContains("Directive \"deprecated\" may not be used on FIELD.");
    }

    private boolean checkGqlGenEngine() {
        sendQuery("{__typename{}");
        if (errorContains("expected at least one definition")) {
            return true;
        }
        sendQuery("{alias^_:__typename {}");
        return errorContains("Expected Name, found <Invalid>");
    }

    private boolean checkGrapheneEngine() {
        sendQuery("aaa");
        return errorContains("Syntax Error GraphQL (1:1)");
    }

    private boolean checkGraphQlByPopEngine() {
        sendQuery("{alias1$1:__typename}");
        if (lastQueryMsg != null && lastQueryMsg.getResponseHeader().isJson()) {
            try {
                String response = lastQueryMsg.getResponseBody().toString();
                JsonNode data = OBJECT_MAPPER.readValue(response, JsonNode.class).get("data");
                if (data != null && data.isObject()) {
                    if (data.has("alias1$1") && "QueryRoot".equals(data.get("alias1$1").asText())) {
                        matchedString = "QueryRoot";
                        return true;
                    }
                }
            } catch (Exception ignored) {
            }
        }
        sendQuery("query aa#aa {__typename}");
        if (errorContains("Unexpected token \"END\"")) {
            return true;
        }
        sendQuery("query @skip {__typename}");
        if (errorContains("Argument 'if' cannot be empty, so directive 'skip' has been ignored")) {
            return true;
        }
        sendQuery("query @doesnotexist {__typename}");
        if (errorContains("No DirectiveResolver resolves directive with name 'doesnotexist'")) {
            return true;
        }
        sendQuery("");
        return errorContains("The query in the body is empty");
    }

    private boolean checkGraphqlDotNetEngine() {
        sendQuery("query @skip {__typename}");
        return errorContains("Directive 'skip' may not be used on Query.");
    }

    private boolean checkGraphQlGoEngine() {
        sendQuery("{__typename{}");
        if (errorContains("Unexpected empty IN")) {
            return true;
        }
        sendQuery("");
        if (errorContains("Must provide an operation.")) {
            return true;
        }
        sendQuery("{__typename}");
        try {
            String response = lastQueryMsg.getResponseBody().toString();
            JsonNode data = OBJECT_MAPPER.readValue(response, JsonNode.class).get("data");
            if (data != null && data.isObject()) {
                if (data.has("__typename") && "RootQuery".equals(data.get("__typename").asText())) {
                    matchedString = "RootQuery";
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private boolean checkGraphQlJavaEngine() {
        sendQuery("queryy {__typename}");
        if (errorContains("Invalid Syntax : offending token 'queryy'")) {
            return true;
        }
        sendQuery("query @aaa@aaa {__typename}");
        if (errorContains(
                "Validation error of type DuplicateDirectiveName: Directives must be uniquely named within a location.")) {
            return true;
        }
        sendQuery("");
        return errorContains("Invalid Syntax : offending token '<EOF>'");
    }

    private boolean checkGraphQlPhpEngine() {
        sendQuery("query @deprecated {__typename}");
        return errorContains("Directive \"deprecated\" may not be used on \"QUERY\".");
    }

    private boolean checkGraphQlRubyEngine() {
        sendQuery("query @skip {__typename}");
        if (errorContains(
                        "'@skip' can't be applied to queries (allowed: fields, fragment spreads, inline fragments)")
                || errorContains("Directive 'skip' is missing required arguments: if")) {
            return true;
        }
        sendQuery("query @deprecated {__typename}");
        if (errorContains("'@deprecated' can't be applied to queries")) {
            return true;
        }
        sendQuery("{__typename{}");
        if (errorContains("Parse error on \"}\" (RCURLY)")) {
            return true;
        }
        sendQuery("{__typename @skip}");
        return errorContains("Directive 'skip' is missing required arguments: if");
    }

    private boolean checkGraphQlYogaEngine() {
        sendQuery("subscription {__typename}");
        return errorContains("asyncExecutionResult[Symbol.asyncIterator] is not a function")
                || errorContains("Unexpected error.");
    }

    private boolean checkHasuraEngine() {
        sendQuery("query @cached {__typename}");
        if (lastQueryMsg != null && lastQueryMsg.getResponseHeader().isJson()) {
            try {
                String response = lastQueryMsg.getResponseBody().toString();
                JsonNode data = OBJECT_MAPPER.readValue(response, JsonNode.class).get("data");
                if (data != null && data.isObject()) {
                    if (data.has("__typename")
                            && "query_root".equals(data.get("__typename").asText())) {
                        matchedString = "query_root";
                        return true;
                    }
                }
            } catch (Exception ignored) {
            }
        }
        sendQuery("{zaproxy}");
        if (errorContains("field \"zaproxy\" not found in type: 'query_root'")) {
            return true;
        }
        sendQuery("query @skip {__typename}");
        if (errorContains("directive \"skip\" is not allowed on a query")) {
            return true;
        }
        sendQuery("{__schema}");
        return errorContains("missing selection set for \"__Schema\"");
    }

    private boolean checkHyperGraphQlEngine() {
        sendQuery("queryy {__typename}");
        if (errorContains("Validation error of type InvalidSyntax: Invalid query syntax.")) {
            return true;
        }
        sendQuery("query {alias1:__typename @deprecated}");
        return errorContains(
                "Validation error of type UnknownDirective: Unknown directive deprecated @ '__typename'");
    }

    private boolean checkJaalEngine() {
        sendQuery("");
        return errorContains("must have a single query");
    }

    private boolean checkJuniperEngine() {
        sendQuery("queryy {__typename}");
        if (errorContains("Unexpected \"queryy\"")) {
            return true;
        }
        sendQuery("");
        return errorContains("Unexpected end of input");
    }

    private boolean checkLaciniaEngine() {
        sendQuery("{zaproxy}");
        return errorContains("Cannot query field `zaproxy' on type `QueryRoot'.");
    }

    private boolean checkLighthouseEngine() {
        sendQuery("{__typename @include(if: falsee)}");
        return errorContains("Internal server error") || errorContains("internal", "category");
    }

    private boolean checkMercuriusEngine() {
        sendQuery("");
        return errorContains("Unknown query");
    }

    private boolean checkMorpheusEngine() {
        sendQuery("queryy {__typename}");
        return errorContains("expecting white space") || errorContains("offset");
    }

    private boolean checkSangriaEngine() {
        try {
            sendQuery("queryy {__typename}");
            if (lastQueryMsg == null || !lastQueryMsg.getResponseHeader().isJson()) {
                return false;
            }
            String response = lastQueryMsg.getResponseBody().toString();
            JsonNode syntaxError =
                    OBJECT_MAPPER.readValue(response, JsonNode.class).get("syntaxError");
            if (syntaxError == null || !syntaxError.isValueNode()) {
                return false;
            }
            String expectedError =
                    "Syntax error while parsing GraphQL query. Invalid input \"queryy\", expected ExecutableDefinition or TypeSystemDefinition";
            if (syntaxError.asText().contains(expectedError)) {
                matchedString = expectedError;
                return true;
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private boolean checkStrawberryEngine() {
        sendQuery("query @deprecated {__typename}");
        String response = lastQueryMsg.getResponseBody().toString();
        try {
            return errorContains("Directive '@deprecated' may not be used on query.")
                    && OBJECT_MAPPER.readValue(response, JsonNode.class).has("data");
        } catch (JsonProcessingException ignore) {
        }
        return false;
    }

    private boolean checkTartifletteEngine() {
        sendQuery("query @doesnotexist {__typename}");
        // https://github.com/tartiflette/tartiflette/blob/421c1e937f553d6a5bf2f30154022c0d77053cfb/tartiflette/language/validators/query/directives_are_defined.py#L22
        if (errorContains("Unknow Directive < @doesnotexist >.")) {
            return true;
        }
        sendQuery("query @skip {__typename}");
        if (errorContains("Missing mandatory argument < if > in directive < @skip >.")) {
            return true;
        }
        sendQuery("{zaproxy}");
        if (errorContains("Field zaproxy doesn't exist on Query")) {
            return true;
        }
        sendQuery("{__typename @deprecated}");
        if (errorContains("Directive < @deprecated > is not used in a valid location.")) {
            return true;
        }
        sendQuery("queryy {__typename}");
        return errorContains("syntax error, unexpected IDENTIFIER");
    }

    private boolean checkWpGraphQlEngine() {
        sendQuery("");
        if (errorContains(
                "GraphQL Request must include at least one of those two parameters: \"query\" or \"queryId\"")) {
            return true;
        }
        sendQuery("{alias1$1:__typename}");
        if (!errorContains("Syntax Error: Expected Name, found $")) {
            return false;
        }
        try {
            String response = lastQueryMsg.getResponseBody().toString();
            JsonNode extensions =
                    OBJECT_MAPPER.readValue(response, JsonNode.class).get("extensions");
            if (extensions != null && extensions.isObject()) {
                JsonNode debug = extensions.get("debug");
                if (debug != null && debug.isArray()) {
                    if (!debug.isEmpty()) {
                        var debugObject = debug.get(0);
                        String expectedDebugType = "DEBUG_LOGS_INACTIVE";
                        if (debugObject.has("type")
                                && expectedDebugType.equals(debugObject.get("type").asText())) {
                            matchedString = expectedDebugType;
                            return true;
                        }
                        String expectedDebugMessage =
                                "GraphQL Debug logging is not active. To see debug logs, GRAPHQL_DEBUG must be enabled.";
                        if (debugObject.has("message")
                                && expectedDebugMessage.equals(
                                        debugObject.get("message").asText())) {
                            matchedString = expectedDebugMessage;
                            return true;
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }
}
