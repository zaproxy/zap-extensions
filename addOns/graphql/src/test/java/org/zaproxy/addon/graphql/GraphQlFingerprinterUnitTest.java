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
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.withSettings;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.WriterAppender;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.graphql.GraphQlFingerprinter.DiscoveredGraphQlEngine;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.StaticContentServerHandler;
import org.zaproxy.zap.testutils.TestUtils;

@TestMethodOrder(OrderAnnotation.class)
class GraphQlFingerprinterUnitTest extends TestUtils {

    private Logger logger;
    private StringWriter writer;
    private WriterAppender appender;
    String endpointUrl;

    @BeforeEach
    void setup() throws Exception {
        setUpZap();
        startServer();
        endpointUrl = "http://localhost:" + nano.getListeningPort() + "/graphql";
        logger = (Logger) LogManager.getLogger(GraphQlFingerprinter.class);
        writer = new StringWriter();
        appender =
                WriterAppender.newBuilder()
                        .setName("TestAppender")
                        .setLayout(
                                PatternLayout.newBuilder()
                                        .withPattern(PatternLayout.TTCC_CONVERSION_PATTERN)
                                        .build())
                        .setTarget(writer)
                        .build();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.ALL);
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionGraphQl());
    }

    @AfterEach
    void teardown() {
        stopServer();
        GraphQlFingerprinter.resetHandlers();
        logger.removeAppender(appender);
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
        var fp = buildFingerprinter(endpointUrl);
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
        var fp = buildFingerprinter(endpointUrl);
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
        var fp = buildFingerprinter(endpointUrl);
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
        var fp = buildFingerprinter(endpointUrl);
        // When
        fp.fingerprint();
        // Then
        assertThat(nano.getRequestedUris(), hasSize(27));
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
                arguments("AWS AppSync", errorResponse("MisplacedDirective")),
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
                        "graphql-ruby",
                        errorResponse(
                                "'@skip' can't be applied to queries (allowed: fields, fragment spreads, inline fragments)")),
                arguments(
                        "graphql-ruby",
                        errorResponse("Directive 'skip' is missing required arguments: if")),
                arguments(
                        "graphql-ruby", errorResponse("'@deprecated' can't be applied to queries")),
                arguments("graphql-ruby", errorResponse("Parse error on \\\"}\\\" (RCURLY)")),
                arguments(
                        "graphql-ruby",
                        errorResponse("Directive 'skip' is missing required arguments: if")),
                arguments(
                        "graphql-php",
                        errorResponse(
                                "Directive \\\"deprecated\\\" may not be used on \\\"QUERY\\\".")),
                arguments("gqlgen", errorResponse("expected at least one definition")),
                arguments("gqlgen", errorResponse("Expected Name, found <Invalid>")),
                arguments("graphql-go", errorResponse("Unexpected empty IN")),
                arguments("graphql-go", errorResponse("Must provide an operation.")),
                arguments("graphql-go", "{ \"data\": { \"__typename\":\"RootQuery\" } }"),
                arguments("Juniper", errorResponse("Unexpected \\\"queryy\\\"")),
                arguments("Juniper", errorResponse("Unexpected end of input")),
                arguments(
                        "Sangria",
                        "{ \"syntaxError\" : \"Syntax error while parsing GraphQL query. Invalid input \\\"queryy\\\", expected ExecutableDefinition or TypeSystemDefinition\" }"),
                arguments(
                        "graphql-flutter",
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
                        "GraphQL.NET", errorResponse("Directive 'skip' may not be used on Query.")),
                arguments("pg_graphql", errorResponse("Unknown argument to @skip: aaQuery.")),
                arguments("tailcall", errorResponse("expected executable_definition")),
                arguments("Hot Chocolate", errorResponse("Unexpected token: Name.")),
                arguments("Inigo", "{\"extensions\": {\"inigo\": []}}"));
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

    @SuppressWarnings("null")
    @ParameterizedTest
    @MethodSource("fingerprintData")
    void shouldFingerprintValidData(String graphqlImpl, String response) throws Exception {
        // Given
        nano.addHandler(new GraphQlResponseHandler(response));
        var fp = buildFingerprinter(endpointUrl);
        List<DiscoveredGraphQlEngine> discoveredEngine = new ArrayList<>(1);
        GraphQlFingerprinter.addEngineHandler(discoveredEngine::add);
        // When
        fp.fingerprint();
        // Then
        Alert alert =
                GraphQlFingerprinter.createFingerprintingAlert(discoveredEngine.get(0)).build();
        assertThat(alert, is(notNullValue()));
        assertThat(alert.getDescription(), containsString(graphqlImpl));
        // Check "handled" values
        assertThat(discoveredEngine.get(0).getUri().toString(), is(equalTo(endpointUrl)));
        assertThat(discoveredEngine.get(0).getName(), is(equalTo(graphqlImpl)));
    }

    @Test
    void shouldFingerprintWithoutAddedHandler() throws Exception {
        // Given
        ExtensionAlert extensionAlert = mockExtensionAlert();
        nano.addHandler(new GraphQlResponseHandler(errorResponse("The query must be a string.")));
        var fp = buildFingerprinter(endpointUrl);
        // When
        fp.fingerprint();
        // Then
        assertNoErrors(extensionAlert, writer.toString());
    }

    @Test
    void shouldFingerprintAfterHandlerReset() throws Exception {
        // Given
        ExtensionAlert extensionAlert = mockExtensionAlert();
        nano.addHandler(new GraphQlResponseHandler(errorResponse("The query must be a string.")));
        var fp = buildFingerprinter(endpointUrl);
        // When
        GraphQlFingerprinter.resetHandlers();
        fp.fingerprint();
        // Then
        assertNoErrors(extensionAlert, writer.toString());
    }

    @Test
    @Order(1)
    void shouldStaticallyAddHandlerWithoutException() throws Exception {
        // Given
        List<DiscoveredGraphQlEngine> handler = new ArrayList<>();
        // When / Then
        assertDoesNotThrow(() -> GraphQlFingerprinter.addEngineHandler(handler::add));
    }

    private static void assertNoErrors(ExtensionAlert extMock, String loggerOutput) {
        assertThat(loggerOutput, not(containsString("WARN")));
        assertThat(loggerOutput, not(containsString("Null")));
        verify(extMock, times(1)).alertFound(any(), any());
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

    private static GraphQlFingerprinter buildFingerprinter(String endpointUrlStr)
            throws URIException {
        URI endpointUri = UrlBuilder.build(endpointUrlStr);
        Requestor requestor =
                new Requestor(
                        new GraphQlQueryMessageBuilder(endpointUri),
                        HttpSender.MANUAL_REQUEST_INITIATOR);
        return new GraphQlFingerprinter(endpointUri, requestor);
    }
}
