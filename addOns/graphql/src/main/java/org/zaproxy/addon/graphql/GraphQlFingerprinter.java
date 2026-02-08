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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

public class GraphQlFingerprinter {

    /**
     * A fingerprint check with its reliability score (0-100, higher = more specific).
     *
     * @param check The fingerprinting function that returns true if framework matches
     * @param specificityScore Reliability score: 90-95 highly specific, 60-69 generic
     */
    private record FingerprintCheck(BooleanSupplier check, int specificityScore) {

        private static final int MIN_SCORE = 0;
        private static final int MAX_SCORE = 100;

        /**
         * Creates a fingerprint check with score validation.
         *
         * @throws IllegalArgumentException if specificityScore is not in range [0, 100]
         */
        public FingerprintCheck {
            if (specificityScore < MIN_SCORE || specificityScore > MAX_SCORE) {
                throw new IllegalArgumentException(
                        "Specificity score must be in range [0, 100], got: " + specificityScore);
            }
        }
    }

    private static final String FINGERPRINTING_ALERT_REF = ExtensionGraphQl.TOOL_ALERT_ID + "-2";
    private static final Map<String, String> FINGERPRINTING_ALERT_TAGS =
            CommonAlertTag.toMap(CommonAlertTag.WSTG_V42_INFO_02_FINGERPRINT_WEB_SERVER);
    private static final Logger LOGGER = LogManager.getLogger(GraphQlFingerprinter.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static List<DiscoveredGraphQlEngineHandler> handlers;

    private final URI endpointUrl;
    private final Requestor requestor;
    private final Map<String, HttpMessage> queryCache;

    private HttpMessage lastQueryMsg;
    private String matchedString;

    public GraphQlFingerprinter(URI endpointUrl, Requestor requestor) {
        resetHandlers();
        this.endpointUrl = endpointUrl;
        this.requestor = requestor;
        queryCache = new HashMap<>();
    }

    /**
     * Performs GraphQL framework fingerprinting using pattern-based detection.
     *
     * <p>Sends malformed queries and analyzes error responses to identify framework-specific
     * patterns. Framework checks are ordered by specificity score, and the first successful match
     * is used.
     *
     * @see #performPatternBasedDetection()
     */
    public void fingerprint() {
        String detectedFramework = performPatternBasedDetection();

        if (detectedFramework != null) {
            raiseAlertForFramework(detectedFramework);
        }

        matchedString = null;
        queryCache.clear();
    }

    /**
     * Performs pattern-based detection using error message analysis.
     *
     * <p>Sends malformed queries and analyzes error responses to identify framework-specific
     * patterns. Frameworks are checked in descending specificity order based on their specificity
     * scores, and the first framework whose check succeeds is returned. The specificity scores are
     * used only to determine the order of evaluation; any successful check is treated as a match.
     *
     * @return The detected framework name, or {@code null} if no framework matches
     */
    private String performPatternBasedDetection() {
        Map<String, FingerprintCheck> fingerprinters = new LinkedHashMap<>();

        // Register checks with specificity scores (higher = more specific/reliable)
        // Scores range from 50 (generic errors) to 95 (highly unique patterns)

        // Tier A: Highly specific patterns (90-95)
        fingerprinters.put("tartiflette", new FingerprintCheck(this::checkTartifletteEngine, 95));
        fingerprinters.put("hasura", new FingerprintCheck(this::checkHasuraEngine, 90));
        fingerprinters.put("dgraph", new FingerprintCheck(this::checkDgraphEngine, 90));
        fingerprinters.put("directus", new FingerprintCheck(this::checkDirectusEngine, 90));
        fingerprinters.put("inigo", new FingerprintCheck(this::checkInigoEngine, 90));

        // Tier B: Very specific patterns (80-89)
        fingerprinters.put(
                "graphql-by-pop", new FingerprintCheck(this::checkGraphQlByPopEngine, 85));
        fingerprinters.put("wpgraphql", new FingerprintCheck(this::checkWpGraphQlEngine, 85));
        fingerprinters.put("absinthe", new FingerprintCheck(this::checkAbsintheEngine, 80));
        fingerprinters.put("lacinia", new FingerprintCheck(this::checkLaciniaEngine, 80));
        fingerprinters.put("sangria", new FingerprintCheck(this::checkSangriaEngine, 80));

        // Tier C: Moderately specific patterns (70-79)
        fingerprinters.put("caliban", new FingerprintCheck(this::checkCalibanEngine, 75));
        fingerprinters.put("strawberry", new FingerprintCheck(this::checkStrawberryEngine, 75));
        fingerprinters.put("ariadne", new FingerprintCheck(this::checkAriadneEngine, 75));
        fingerprinters.put("graphql-java", new FingerprintCheck(this::checkGraphQlJavaEngine, 70));
        fingerprinters.put(
                "graphql-dotnet", new FingerprintCheck(this::checkGraphqlDotNetEngine, 70));
        fingerprinters.put("graphql-ruby", new FingerprintCheck(this::checkGraphQlRubyEngine, 70));
        fingerprinters.put("graphql-php", new FingerprintCheck(this::checkGraphQlPhpEngine, 70));
        fingerprinters.put("gqlgen", new FingerprintCheck(this::checkGqlGenEngine, 70));
        fingerprinters.put("graphql-go", new FingerprintCheck(this::checkGraphQlGoEngine, 70));
        fingerprinters.put("juniper", new FingerprintCheck(this::checkJuniperEngine, 70));
        fingerprinters.put("hotchocolate", new FingerprintCheck(this::checkHotchocolateEngine, 70));
        fingerprinters.put("pg_graphql", new FingerprintCheck(this::checkPgGraphqlEngine, 70));
        fingerprinters.put("tailcall", new FingerprintCheck(this::checkTailcallEngine, 70));

        // Tier D: Generic patterns (60-69)
        fingerprinters.put("graphene", new FingerprintCheck(this::checkGrapheneEngine, 65));
        fingerprinters.put("graphql-yoga", new FingerprintCheck(this::checkGraphQlYogaEngine, 65));
        fingerprinters.put("aws-appsync", new FingerprintCheck(this::checkAwsAppSyncEngine, 65));
        fingerprinters.put("hypergraphql", new FingerprintCheck(this::checkHyperGraphQlEngine, 65));
        fingerprinters.put("graphql-flutter", new FingerprintCheck(this::checkFlutterEngine, 65));
        fingerprinters.put("dianajl", new FingerprintCheck(this::checkDianajlEngine, 65));
        fingerprinters.put("morpheus", new FingerprintCheck(this::checkMorpheusEngine, 65));
        fingerprinters.put("apollo", new FingerprintCheck(this::checkApolloEngine, 60));
        fingerprinters.put("mercurius", new FingerprintCheck(this::checkMercuriusEngine, 60));
        fingerprinters.put("jaal", new FingerprintCheck(this::checkJaalEngine, 60));
        fingerprinters.put("agoo", new FingerprintCheck(this::checkAgooEngine, 65));

        // Tier E: Very generic patterns (50-59) - prone to false positives
        fingerprinters.put("lighthouse", new FingerprintCheck(this::checkLighthouseEngine, 50));

        // Iterate checks in descending score order and return on first match
        // This ensures we check high-confidence patterns first and can early-exit
        var sortedFingerprinters =
                fingerprinters.entrySet().stream()
                        .sorted(
                                Map.Entry.comparingByValue(
                                        Comparator.comparingInt(FingerprintCheck::specificityScore)
                                                .reversed()))
                        .toList();

        for (var fingerprinter : sortedFingerprinters) {
            try {
                if (fingerprinter.getValue().check().getAsBoolean()) {
                    String framework = fingerprinter.getKey();
                    LOGGER.debug(
                            "Detected GraphQL engine: {} (specificity score: {})",
                            framework,
                            fingerprinter.getValue().specificityScore());
                    return framework;
                }
            } catch (Exception e) {
                LOGGER.warn("Failed to fingerprint GraphQL engine: {}", fingerprinter.getKey(), e);
            }
        }

        LOGGER.debug("No framework match found");
        return null;
    }

    /**
     * Helper method to raise fingerprinting alert for detected framework.
     *
     * @param framework The detected framework name
     */
    private void raiseAlertForFramework(String framework) {
        DiscoveredGraphQlEngine discoveredGraphQlEngine =
                new DiscoveredGraphQlEngine(framework, lastQueryMsg.getRequestHeader().getURI());
        handleDetectedEngine(discoveredGraphQlEngine);
        raiseFingerprintingAlert(discoveredGraphQlEngine);
    }

    private static void handleDetectedEngine(DiscoveredGraphQlEngine discoveredGraphQlEngine) {
        for (DiscoveredGraphQlEngineHandler handler : handlers) {
            try {
                handler.process(discoveredGraphQlEngine);
            } catch (Exception ex) {
                LOGGER.error("Unable to handle: {}", discoveredGraphQlEngine.getName(), ex);
            }
        }
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

    static Alert.Builder createFingerprintingAlert(
            DiscoveredGraphQlEngine discoveredGraphQlEngine) {
        return Alert.builder()
                .setPluginId(ExtensionGraphQl.TOOL_ALERT_ID)
                .setAlertRef(FINGERPRINTING_ALERT_REF)
                .setName(Constant.messages.getString("graphql.fingerprinting.alert.name"))
                .setDescription(
                        Constant.messages.getString(
                                "graphql.fingerprinting.alert.desc",
                                discoveredGraphQlEngine.getName(),
                                discoveredGraphQlEngine.getTechnologies()))
                .setReference(discoveredGraphQlEngine.getDocsUrl())
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setRisk(Alert.RISK_INFO)
                .setCweId(205)
                .setWascId(45)
                .setSource(Alert.Source.TOOL)
                .setTags(FINGERPRINTING_ALERT_TAGS);
    }

    void raiseFingerprintingAlert(DiscoveredGraphQlEngine discoveredGraphQlEngine) {
        var extAlert =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
        if (extAlert == null) {
            return;
        }

        Alert alert =
                createFingerprintingAlert(discoveredGraphQlEngine)
                        .setEvidence(matchedString)
                        .setMessage(lastQueryMsg)
                        .setUri(endpointUrl.toString())
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

    private boolean checkHotchocolateEngine() {
        sendQuery("queryy  {__typename}");
        if (errorContains("Unexpected token: Name.")) {
            return true;
        }
        sendQuery("query @aaa@aaa {__typename}");
        return errorContains(
                "The specified directive `aaa` is not supported by the current schema.");
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

    private boolean checkInigoEngine() {
        // https://github.com/dolevf/graphw00f/commit/52e25d376f5fd4dcad062ba79a1b6c3e5e1c68dc
        sendQuery("query {__typename}");
        if (lastQueryMsg != null && lastQueryMsg.getResponseHeader().isJson()) {
            try {
                String response = lastQueryMsg.getResponseBody().toString();
                JsonNode exts = OBJECT_MAPPER.readValue(response, JsonNode.class).get("extensions");
                if (exts != null && exts.isObject() && exts.has("inigo")) {
                    matchedString = "inigo";
                    return true;
                }
            } catch (Exception ignored) {
            }
        }
        return false;
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

    private boolean checkPgGraphqlEngine() {
        sendQuery("query { __typename @skip(aa:tr");
        // https://github.com/supabase/pg_graphql/blob/5f9c62b85293b753676b07c9b309670a77e6310e/src/parser_util.rs#L65
        return (errorContains("Unknown argument to @skip: aa"));
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
        if (lastQueryMsg == null || !lastQueryMsg.getResponseHeader().isJson()) {
            return false;
        }
        String response = lastQueryMsg.getResponseBody().toString();
        try {
            return errorContains("Directive '@deprecated' may not be used on query.")
                    && OBJECT_MAPPER.readValue(response, JsonNode.class).has("data");
        } catch (JsonProcessingException ignore) {
        }
        return false;
    }

    private boolean checkTailcallEngine() {
        sendQuery("aa {__typename}");
        return errorContains("expected executable_definition");
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

    public static void addEngineHandler(DiscoveredGraphQlEngineHandler handler) {
        if (handlers == null) {
            resetHandlers();
        }
        handlers.add(handler);
    }

    public static void resetHandlers() {
        handlers = new ArrayList<>(2);
    }

    public static class DiscoveredGraphQlEngine {
        private static final String PREFIX = "graphql.engine.";
        private String enginePrefix;
        private String name;
        private String docsUrl;
        private String technologies;
        private URI uri;

        public DiscoveredGraphQlEngine(String engineId, URI uri) {
            this.enginePrefix = PREFIX + engineId + ".";

            this.name = Constant.messages.getString(enginePrefix + "name");
            this.docsUrl = Constant.messages.getString(enginePrefix + "docsUrl");
            this.technologies = Constant.messages.getString(enginePrefix + "technologies");
            this.uri = uri;
        }

        public String getName() {
            return name;
        }

        public String getDocsUrl() {
            return docsUrl;
        }

        public String getTechnologies() {
            return technologies;
        }

        public URI getUri() {
            return uri;
        }
    }
}
