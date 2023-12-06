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

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.withSettings;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.StaticContentServerHandler;
import org.zaproxy.zap.testutils.TestUtils;

class GraphQlFingerprinterUnitTest extends TestUtils {

    String endpointUrl;

    @BeforeEach
    void setup() throws Exception {
        setUpZap();
        startServer();
        endpointUrl = "http://localhost:" + nano.getListeningPort() + "/graphql";
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionGraphQl());
    }

    @AfterEach
    void teardown() {
        stopServer();

        Constant.messages = null;
    }

    @Test
    void shouldFindSubstringInErrorResponse() throws Exception {
        // Given
        nano.addHandler(
                new NanoServerHandler("/graphql") {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(
                                NanoHTTPD.Response.Status.OK,
                                "application/json",
                                "{\"errors\": [{\"code\":\"Oh no! Something went wrong.\"}]}");
                    }
                });
        var fp = new GraphQlFingerprinter(UrlBuilder.build(endpointUrl));
        // When
        fp.sendQuery("{zaproxy}");
        // Then
        assertThat(fp.errorContains("Something", "code"), is(true));
    }

    @Test
    void shouldNotSendTheSameQueryMultipleTimes() throws Exception {
        // Given
        var handler =
                new NanoServerHandler("/graphql") {
                    private int requestCount = 0;

                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        consumeBody(session);
                        return newFixedLengthResponse(
                                NanoHTTPD.Response.Status.OK,
                                "application/json",
                                "{\"data\": {\"count\": " + ++requestCount + "}}");
                    }

                    int getRequestCount() {
                        return requestCount;
                    }
                };
        nano.addHandler(handler);
        var fp = new GraphQlFingerprinter(UrlBuilder.build(endpointUrl));
        // When
        fp.sendQuery("{count}");
        fp.sendQuery("{count}");
        fp.sendQuery("{count}");
        // Then
        assertThat(handler.getRequestCount(), is(equalTo(1)));
    }

    @Test
    void shouldSendQuery() throws Exception {
        // Given
        nano.addHandler(
                new StaticContentServerHandler(
                        "/graphql", "{\"data\": {\"__typename\": \"Query\"}}"));
        var fp = new GraphQlFingerprinter(UrlBuilder.build(endpointUrl));
        // When
        fp.sendQuery("{__typename}");
        // Then
        assertThat(nano.getRequestedUris(), hasSize(1));
    }

    @Test
    void shouldFingerprintWithInvalidData() throws Exception {
        // Given
        ExtensionAlert extensionAlert = mockExtensionAlert();
        nano.addHandler(new GraphQlResponseHandler("{ not actual json… }"));
        var fp = new GraphQlFingerprinter(UrlBuilder.build(endpointUrl));
        // When
        fp.fingerprint();
        // Then
        assertThat(nano.getRequestedUris(), hasSize(23));
        verifyNoInteractions(extensionAlert);
    }

    static Stream<Arguments> fingerprintData() {
        return Stream.of(
                arguments("Lighthouse", errorResponse("Internal server error")),
                arguments("Lighthouse", errorResponse("internal", "category")),
                arguments("caliban", errorResponse("Fragment 'zap' is not used in any spread")),
                arguments(
                        "lacinia",
                        errorResponse("Cannot query field `zaproxy' on type `QueryRoot'.")),
                arguments("jaal", errorResponse("must have a single query")),
                arguments("morpheus-graphql", errorResponse("expecting white space")),
                arguments("morpheus-graphql", errorResponse("offset")),
                arguments("mercurius", errorResponse("Unknown query")),
                arguments(
                        "GraphQL Yoga",
                        errorResponse(
                                "asyncExecutionResult[Symbol.asyncIterator] is not a function")),
                arguments("GraphQL Yoga", errorResponse("Unexpected error.")),
                arguments("Agoo", errorResponse("eval error", "code")),
                arguments("Dgraph", "{ \"data\": { \"__typename\":\"Query\" } }"),
                arguments("gqlgen", errorResponse("expected at least one definition")),
                arguments("gqlgen", errorResponse("Expected Name, found <Invalid>")),
                arguments("Ariadne", errorResponse("Unknown directive '@abc'.", "message", false)),
                arguments("Ariadne", errorResponse("The query must be a string.")),
                arguments(
                        "Apollo",
                        errorResponse(
                                "Directive \\\"@skip\\\" argument \\\"if\\\" of type \\\"Boolean!\\\" is required, but it was not provided.")),
                arguments(
                        "Apollo",
                        errorResponse("Directive \\\"@deprecated\\\" may not be used on QUERY.")),
                arguments("AWS", errorResponse("MisplacedDirective")),
                arguments("Hasura", "{ \"data\": { \"__typename\":\"query_root\" } }"),
                arguments(
                        "Hasura",
                        errorResponse("field \\\"zaproxy\\\" not found in type: 'query_root'")),
                arguments(
                        "Hasura",
                        errorResponse("directive \\\"skip\\\" is not allowed on a query")),
                arguments("Hasura", errorResponse("missing selection set for \\\"__Schema\\\"")),
                arguments(
                        "WPGraphQL WordPress Plugin",
                        errorResponse(
                                "GraphQL Request must include at least one of those two parameters: \\\"query\\\" or \\\"queryId\\\"")),
                arguments(
                        "WPGraphQL WordPress Plugin",
                        "{ \"errors\" : [ { \"message\" : \"Syntax Error: Expected Name, found $\" } ], \"data\" : { }, \"extensions\" : { \"debug\" : [ { \"type\" : \"DEBUG_LOGS_INACTIVE\" } ] } }"),
                arguments(
                        "WPGraphQL WordPress Plugin",
                        "{ \"errors\" : [ { \"message\" : \"Syntax Error: Expected Name, found $\" } ], \"data\" : { },  \"extensions\" : { \"debug\" : [ { \"message\" : \"GraphQL Debug logging is not active. To see debug logs, GRAPHQL_DEBUG must be enabled.\" } ] } }"),
                arguments("GraphQL by PoP", "{ \"data\" : { \"alias1$1\" : \"QueryRoot\" } }"),
                arguments("GraphQL by PoP", errorResponse("Unexpected token \\\"END\\\"")),
                arguments(
                        "GraphQL by PoP",
                        errorResponse(
                                "Argument 'if' cannot be empty, so directive 'skip' has been ignored")),
                arguments(
                        "GraphQL by PoP",
                        errorResponse(
                                "No DirectiveResolver resolves directive with name 'doesnotexist'")),
                arguments("GraphQL by PoP", errorResponse("The query in the body is empty")),
                arguments(
                        "graphql-java", errorResponse("Invalid Syntax : offending token 'queryy'")),
                arguments(
                        "graphql-java",
                        errorResponse(
                                "Validation error of type DuplicateDirectiveName: Directives must be uniquely named within a location.")),
                arguments(
                        "graphql-java", errorResponse("Invalid Syntax : offending token '<EOF>'")),
                arguments(
                        "HyperGraphQL",
                        errorResponse(
                                "Validation error of type InvalidSyntax: Invalid query syntax.")),
                arguments(
                        "HyperGraphQL",
                        errorResponse(
                                "Validation error of type UnknownDirective: Unknown directive deprecated @ '__typename'")),
                arguments(
                        "ruby",
                        errorResponse(
                                "'@skip' can't be applied to queries (allowed: fields, fragment spreads, inline fragments)")),
                arguments(
                        "ruby",
                        errorResponse("Directive 'skip' is missing required arguments: if")),
                arguments("ruby", errorResponse("'@deprecated' can't be applied to queries")),
                arguments("ruby", errorResponse("Parse error on \\\"}\\\" (RCURLY)")),
                arguments(
                        "ruby",
                        errorResponse("Directive 'skip' is missing required arguments: if")),
                arguments(
                        "PHP",
                        errorResponse(
                                "Directive \\\"deprecated\\\" may not be used on \\\"QUERY\\\".")),
                arguments("gqlgen", errorResponse("expected at least one definition")),
                arguments("gqlgen", errorResponse("Expected Name, found <Invalid>")),
                arguments("Go", errorResponse("Unexpected empty IN")),
                arguments("Go", errorResponse("Must provide an operation.")),
                arguments("Go", "{ \"data\": { \"__typename\":\"RootQuery\" } }"),
                arguments("Juniper", errorResponse("Unexpected \\\"queryy\\\"")),
                arguments("Juniper", errorResponse("Unexpected end of input")),
                arguments(
                        "Sangria",
                        "{ \"syntaxError\" : \"Syntax error while parsing GraphQL query. Invalid input \\\"queryy\\\", expected ExecutableDefinition or TypeSystemDefinition\" }"),
                arguments(
                        "Flutter",
                        errorResponse("Directive \\\"deprecated\\\" may not be used on FIELD.")),
                arguments(
                        "Diana.jl",
                        errorResponse(
                                "Syntax Error GraphQL request (1:1) Unexpected Name \\\"queryy\\\"")),
                arguments(
                        "Strawberry",
                        errorResponse("Directive '@deprecated' may not be used on query.")),
                arguments("tartiflette", errorResponse("Unknow Directive < @doesnotexist >.")),
                arguments(
                        "tartiflette",
                        errorResponse("Missing mandatory argument < if > in directive < @skip >.")),
                arguments("tartiflette", errorResponse("Field zaproxy doesn't exist on Query")),
                arguments(
                        "tartiflette",
                        errorResponse(
                                "Directive < @deprecated > is not used in a valid location.")),
                arguments("tartiflette", errorResponse("syntax error, unexpected IDENTIFIER")),
                arguments(
                        "Directus",
                        "{ \"errors\" : [ { \"extensions\" : { \"code\" : \"INVALID_PAYLOAD\" } } ] }"),
                arguments(
                        "Absinthe",
                        errorResponse(
                                "Cannot query field \\\"zaproxy\\\" on type \\\"RootQueryType\\\".")),
                arguments(
                        "GraphQL.NET",
                        errorResponse("Directive 'skip' may not be used on Query.")));
    }

    private static String errorResponse(String error) {
        return errorResponse(error, "message");
    }

    private static String errorResponse(String error, String field) {
        return errorResponse(error, field, true);
    }

    private static String errorResponse(String error, String field, boolean data) {
        return "{ \"errors\" : [ { \""
                + field
                + "\" : \""
                + error
                + "\" } ]"
                + (data ? ", \"data\" : { }" : "")
                + " }";
    }

    @ParameterizedTest
    @MethodSource("fingerprintData")
    void shouldFingerprintValidData(String graphqlImpl, String response) throws Exception {
        // Given
        ExtensionAlert extensionAlert = mockExtensionAlert();
        nano.addHandler(new GraphQlResponseHandler(response));
        var fp = new GraphQlFingerprinter(UrlBuilder.build(endpointUrl));
        // When
        fp.fingerprint();
        // Then
        ArgumentCaptor<Alert> alertArgCaptor = ArgumentCaptor.forClass(Alert.class);
        verify(extensionAlert).alertFound(alertArgCaptor.capture(), any());
        Alert alert = alertArgCaptor.getValue();
        assertThat(alert, is(notNullValue()));
        assertThat(alert.getDescription(), containsString(graphqlImpl));
    }

    private static ExtensionAlert mockExtensionAlert() {
        var lenientSettings = withSettings().strictness(Strictness.LENIENT);
        var extensionLoader = mock(ExtensionLoader.class, lenientSettings);
        var extensionAlert = mock(ExtensionAlert.class, lenientSettings);
        given(extensionLoader.getExtension(ExtensionAlert.class)).willReturn(extensionAlert);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        return extensionAlert;
    }

    private static class GraphQlResponseHandler extends NanoServerHandler {

        private final String response;

        public GraphQlResponseHandler(String response) {
            super("/graphql");
            this.response = response;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            consumeBody(session);
            return newFixedLengthResponse(
                    NanoHTTPD.Response.Status.OK, "application/json", response);
        }
    }
}
