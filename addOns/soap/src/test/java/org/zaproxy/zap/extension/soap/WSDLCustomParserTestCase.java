/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.soap;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import fi.iki.elonen.NanoHTTPD.Response.Status;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.option.OptionsParamView;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;

class WSDLCustomParserTestCase extends TestUtils {

    private static final String MOCK_FILL_VALUE = "mock-fill-value";
    private static final String FILL_PARAMETERS_WSDL = "fill-parameters.wsdl";
    private static final String DEGRADED_PARAMETERS_WSDL = "degraded-parameters.wsdl";

    private static ExtensionLoader extensionLoader;
    private static Session session;

    private ValueProvider valueProvider;
    private Supplier<Date> dateSupplier;
    private String wsdlContent;
    private WSDLCustomParser parser;

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();
        startServer();

        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        Model.setSingletonForTesting(model);

        session = mock(Session.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getSession()).willReturn(session);

        OptionsParam optionsParam =
                mock(OptionsParam.class, withSettings().strictness(Strictness.LENIENT));
        OptionsParamView viewParam =
                mock(OptionsParamView.class, withSettings().strictness(Strictness.LENIENT));

        given(model.getOptionsParam()).willReturn(optionsParam);
        given(optionsParam.getViewParam()).willReturn(viewParam);
        given(viewParam.getMode()).willReturn(Mode.standard.name());

        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        /* Gets test wsdl file and retrieves its content as String. */
        Path wsdlPath = getResourcePath("resources/test.wsdl");
        wsdlContent = new String(Files.readAllBytes(wsdlPath), StandardCharsets.UTF_8);

        valueProvider = mock(ValueProvider.class);
        lenient()
                .when(valueProvider.getValue(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(MOCK_FILL_VALUE);
        dateSupplier = mockLenientDateSupplier();
        parser = new WSDLCustomParser(() -> valueProvider, null, dateSupplier);
    }

    @AfterEach
    void tearDown() {
        stopServer();
        Control.getSingleton().setMode(Mode.standard);
    }

    @Test
    void parseWSDLContentTest() {
        /* Positive case. Checks the method's return value. */
        boolean result = parser.extContentWSDLImport(wsdlContent, false);
        assertTrue(result);

        /* Negative cases. */
        result = parser.extContentWSDLImport("", false); // Empty content.
        assertFalse(result);

        result = parser.extContentWSDLImport("asdf", false); // Non-empty invalid content.
        assertFalse(result);
    }

    @Test
    void canBeWSDLparsedTest() {
        /* Positive case. */
        boolean result = parser.canBeWSDLparsed(wsdlContent);
        assertTrue(result);
        /* Negative cases. */
        result = parser.canBeWSDLparsed(""); // Empty content.
        assertFalse(result);
        result = parser.canBeWSDLparsed("asdf"); // Non-empty invalid content.
        assertFalse(result);
    }

    @Test
    void createSoapRequestTest() {
        parser.extContentWSDLImport(wsdlContent, false);
        /* Positive case. */
        HttpMessage result = parser.createSoapRequest(parser.getLastConfig());
        assertNotNull(result);
        /* Negative case. */
        result = parser.createSoapRequest(new SOAPMsgConfig());
        assertNull(result);
    }

    @Test
    void shouldLimitMessagesWhenMaxMessagesSet() throws Exception {
        Path wsdl = Files.createTempFile("soap-max-messages", ".wsdl");
        Files.writeString(wsdl, wsdlContent);

        parser.syncImportWsdlFile(wsdl.toFile(), 1);

        assertThat(parser.getLastConfig().getBindOp().getName(), is(equalTo("sayByeWorld")));
    }

    @Test
    void shouldNotFetchWsdlInSafeMode() throws Exception {
        // Given
        Control.getSingleton().setMode(Mode.safe);
        // When
        parser.syncImportWsdlUrl(serverUrl("/service.wsdl"), 0);
        // Then
        assertThat(nano.getRequestedUris().isEmpty(), is(true));
    }

    @Test
    void shouldNotFetchOutOfScopeWsdlInScopedMode() throws Exception {
        // Given
        Control.getSingleton().setMode(Mode.protect);
        // When
        parser.syncImportWsdlUrl(serverUrl("/service.wsdl"), 0);
        // Then
        assertThat(nano.getRequestedUris().isEmpty(), is(true));
    }

    @Test
    void shouldFetchInScopeWsdlInScopedMode() throws Exception {
        // Given
        addWsdlHandler("/service.wsdl", simpleWsdl());
        Control.getSingleton().setMode(Mode.protect);
        given(session.isInScope(anyString())).willReturn(true);
        // When
        parser.syncImportWsdlUrl(serverUrl("/service.wsdl"), 0);
        // Then
        assertThat(nano.getRequestedUris(), is(List.of("/service.wsdl")));
    }

    @Test
    void shouldFetchRelativeSchemaImportThroughZapHttpSender() throws Exception {
        // Given
        addWsdlHandler("/service.wsdl", wsdlWithSchemaImport("schema/types.xsd"));
        addWsdlHandler("/schema/types.xsd", simpleSchema());
        // When
        parser.syncImportWsdlUrl(serverUrl("/service.wsdl"), 0);
        // Then
        assertThat(nano.getRequestedUris(), is(List.of("/service.wsdl", "/schema/types.xsd")));
    }

    @Test
    void shouldNotFetchImportedSchemaInSafeMode() throws Exception {
        // Given
        addWsdlHandler("/service.wsdl", wsdlWithSchemaImport("schema/types.xsd"));
        addWsdlHandler("/schema/types.xsd", simpleSchema());

        // Safe mode should block the initial WSDL request, so no imported resources are fetched
        // either.
        Control.getSingleton().setMode(Mode.safe);
        // When
        parser.syncImportWsdlUrl(serverUrl("/service.wsdl"), 0);
        // Then
        assertThat(nano.getRequestedUris().isEmpty(), is(true));
    }

    @Test
    void shouldNotFetchOutOfScopeImportedSchemaInScopedMode() throws Exception {
        // Given
        addWsdlHandler("/service.wsdl", wsdlWithSchemaImport("schema/types.xsd"));
        addWsdlHandler("/schema/types.xsd", simpleSchema());
        Control.getSingleton().setMode(Mode.protect);
        String wsdlUrl = serverUrl("/service.wsdl");
        // Everything out of scope unless explicitly allowed.
        given(session.isInScope(anyString())).willReturn(false);
        given(session.isInScope(wsdlUrl)).willReturn(true);
        // When
        parser.syncImportWsdlUrl(wsdlUrl, 0);
        // Then
        assertThat(nano.getRequestedUris(), is(List.of("/service.wsdl")));
    }

    @Test
    void shouldRejectFileSchemaImport() throws Exception {
        // Given
        Path schema = Files.createTempFile("soap-local-schema", ".xsd");
        Files.writeString(
                schema,
                "<xsd:schema xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><xsd:include schemaLocation=\""
                        + serverUrl("/unexpected.xsd")
                        + "\"/></xsd:schema>");
        addWsdlHandler("/service.wsdl", wsdlWithSchemaImport(schema.toUri().toString()));
        // When
        parser.syncImportWsdlUrl(serverUrl("/service.wsdl"), 0);
        // Then
        assertThat(nano.getRequestedUris(), is(List.of("/service.wsdl")));
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"generated"})
    void addParameterShouldUseValueProviderWhenAvailable(String genValue) {
        // Given
        String path = "CelsiusToFahrenheit/Celsius";
        String paramType = "s:string";
        String name = "Celsius";
        Map<String, String> fieldAttributes = new HashMap<>();
        fieldAttributes.put("Control Type", "TEXT");
        fieldAttributes.put("type", name);

        when(valueProvider.getValue(
                        eq(null),
                        eq(null),
                        eq(name),
                        anyString(),
                        eq(List.of()),
                        eq(Map.of()),
                        eq(fieldAttributes)))
                .thenReturn(genValue);

        // Then
        Map<String, String> expectedParams = new HashMap<>();
        expectedParams.put("xpath:/" + path, genValue);
        assertEquals(expectedParams, parser.addParameter(path, paramType, name, null));
    }

    @ParameterizedTest
    @CsvSource(
            value = {
                "string, paramValue",
                "int, 0",
                "integer, 0",
                "decimal, 0",
                "float, 0",
                "double, 0",
                "long, 0",
                "short, 0",
                "byte, 0",
                "unsignedLong, 0",
                "unsignedInt, 0",
                "unsignedShort, 0",
                "unsignedByte, 0",
                "positiveInteger, 1",
                "negativeInteger, -1",
                "nonNegativeInteger, 0",
                "nonPositiveInteger, 0",
                "boolean, true",
                "token, paramValue",
                "normalizedString, paramValue",
                "anyURI, paramValue",
                "date, 2023-11-21",
                "dateTime, 2023-11-21T05:16:40+0000",
                "something, paramValue"
            })
    void shouldGenerateAppropriateDefaultValueForValueProvider(
            String paramType, String expectedDefaultValue) {
        // Given
        ArgumentCaptor<String> defaultValueArgCaptor = ArgumentCaptor.forClass(String.class);
        given(dateSupplier.get()).willReturn(new Date(1700587000000L));
        // When
        parser.addParameter("", paramType, "", null);

        // Then
        verify(valueProvider)
                .getValue(
                        any(), any(), any(), defaultValueArgCaptor.capture(), any(), any(), any());
        assertThat(defaultValueArgCaptor.getValue(), is(equalTo(expectedDefaultValue)));
    }

    @Test
    void shouldPopulateFieldsViaRefElement() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/refOuter/refBlock/leafField", MOCK_FILL_VALUE));
    }

    @Test
    void shouldPickFirstChoiceOption() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/branchBox/optA", MOCK_FILL_VALUE));
        assertThat(params, not(hasKey("xpath:/Request/branchBox/optB")));
    }

    @Test
    void shouldUseFixedValueForAttribute() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/attrBox/@fixedKey", "FIXED-VAL"));
    }

    @Test
    void shouldUseEnumerationValueForElement() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/enumField", "EL-1"));
    }

    @Test
    void shouldPopulateAttributeFields() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/attrBox/@keyA", MOCK_FILL_VALUE));
        assertThat(params, hasEntry("xpath:/Request/attrBox/@keyB", MOCK_FILL_VALUE));
    }

    @Test
    void shouldUseEnumerationValueForAttribute() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/enumBox/@enumKey", "EV-1"));
    }

    @Test
    void shouldUseUnicodeEnumerationValue() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/unicodeBox/@codeKey", "val-ää"));
    }

    @Test
    void shouldEmitParamForBoundedSimpleType() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/boundedInt", MOCK_FILL_VALUE));
        verify(valueProvider)
                .getValue(any(), any(), eq("boundedInt"), eq("0"), any(), any(), any());
    }

    @Test
    void shouldPassIntegerDefaultsToValueProviderViaWsdlImport() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();

        // Then
        assertThat(params, hasEntry("xpath:/Request/positiveIntField", MOCK_FILL_VALUE));
        assertThat(params, hasEntry("xpath:/Request/negativeIntField", MOCK_FILL_VALUE));
        assertThat(params, hasEntry("xpath:/Request/nonNegativeIntField", MOCK_FILL_VALUE));
        assertThat(params, hasEntry("xpath:/Request/nonPositiveIntField", MOCK_FILL_VALUE));
        verify(valueProvider)
                .getValue(any(), any(), eq("positiveIntField"), eq("1"), any(), any(), any());
        verify(valueProvider)
                .getValue(any(), any(), eq("negativeIntField"), eq("-1"), any(), any(), any());
        verify(valueProvider)
                .getValue(any(), any(), eq("nonNegativeIntField"), eq("0"), any(), any(), any());
        verify(valueProvider)
                .getValue(any(), any(), eq("nonPositiveIntField"), eq("0"), any(), any(), any());
    }

    @Test
    void shouldFallbackToStringForPlainElementWithNoType() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();

        // Then
        assertThat(params, hasEntry("xpath:/Request/plainField", MOCK_FILL_VALUE));
        verify(valueProvider)
                .getValue(any(), any(), eq("plainField"), eq("paramValue"), any(), any(), any());
    }

    @Test
    void shouldEmitParamForTokenTypedElement() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/tokenField", MOCK_FILL_VALUE));
        verify(valueProvider)
                .getValue(any(), any(), eq("tokenField"), eq("paramValue"), any(), any(), any());
    }

    @Test
    void shouldPopulateFieldsFromNamedComplexTypeReference() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/namedBox/inner", MOCK_FILL_VALUE));
    }

    @Test
    void shouldPopulateExtendedTypeFields() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/block/inherited", MOCK_FILL_VALUE));
        assertThat(params, hasEntry("xpath:/Request/block/added", MOCK_FILL_VALUE));
    }

    @Test
    void shouldSkipAttrOnlyTypeAndProcessSibling() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/groupOuter/group/leafField", MOCK_FILL_VALUE));
        assertThat(
                params,
                hasEntry("xpath:/Request/groupOuter/group/metaBlock/@idKey", MOCK_FILL_VALUE));
        assertThat(
                params,
                hasEntry("xpath:/Request/groupOuter/group/metaBlock/@nameKey", MOCK_FILL_VALUE));
    }

    @Test
    void shouldAcceptUnicodeAttributeNames() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/attrWrapper/@plainKey", MOCK_FILL_VALUE));
        assertThat(params, hasEntry("xpath:/Request/attrWrapper/@äKey", MOCK_FILL_VALUE));
    }

    @Test
    void shouldContinueWhenRefElementCannotBeResolved() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams(DEGRADED_PARAMETERS_WSDL);
        // Then
        assertThat(params, hasEntry("xpath:/Request/controlField", MOCK_FILL_VALUE));
        assertThat(params, hasEntry("xpath:/Request/badRefOuter/siblingField", MOCK_FILL_VALUE));
        assertThat(params, not(hasKey("xpath:/Request/badRefOuter/missingBlock")));
    }

    @Test
    void shouldContinueWhenExtensionBaseTypeCannotBeResolved() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams(DEGRADED_PARAMETERS_WSDL);
        // Then – import continues; predic8 omits the extension sequence when the base
        // type is unresolvable, so neither inherited nor localField params are emitted
        assertThat(params, hasEntry("xpath:/Request/controlField", MOCK_FILL_VALUE));
        assertThat(params, not(hasKey("xpath:/Request/brokenBlock/localField")));
        assertThat(params, not(hasKey("xpath:/Request/brokenBlock/inherited")));
    }

    @Test
    void shouldContinueWhenExtensionBaseIsNotComplexType() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams(DEGRADED_PARAMETERS_WSDL);
        // Then
        assertThat(
                params, hasEntry("xpath:/Request/simpleBaseBlock/derivedField", MOCK_FILL_VALUE));
        assertThat(params, not(hasKey("xpath:/Request/simpleBaseBlock/value")));
    }

    @Test
    void shouldContinueWhenElementTypeLookupFails() throws Exception {
        // Given / When – type="tns:MissingNamedType" makes resolveComplexType throw
        // ModelAccessException; fillParameters catches per-element and returns an empty map
        // for badTypeField only, while siblings continue to be processed
        Map<String, String> params = parseWsdlParams(DEGRADED_PARAMETERS_WSDL);
        // Then
        assertThat(params, hasEntry("xpath:/Request/controlField", MOCK_FILL_VALUE));
        assertThat(
                params, hasEntry("xpath:/Request/badTypeOuter/typeSiblingField", MOCK_FILL_VALUE));
        assertThat(params, not(hasKey("xpath:/Request/badTypeOuter/badTypeField")));
    }

    @Test
    void shouldSkipAttributeDeclaredByRefWithNullName() throws Exception {
        // Given / When – valid XSD uses <xs:attribute ref="tns:globalRefKey"/>; predic8 leaves
        // Attribute.getName() null until resolved, and fillFromComplexType skips it
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/attrRefWrapper/@inlineKey", MOCK_FILL_VALUE));
        assertThat(params, not(hasKey("xpath:/Request/attrRefWrapper/@globalRefKey")));
    }

    @Test
    void shouldFollowInScopeRedirectInScopedMode() throws Exception {
        // Given
        addRedirectHandler("/redirect.wsdl", serverUrl("/service.wsdl"));
        addWsdlHandler("/service.wsdl", simpleWsdl());
        Control.getSingleton().setMode(Mode.protect);
        given(session.isInScope(anyString())).willReturn(true);
        // When
        parser.syncImportWsdlUrl(serverUrl("/redirect.wsdl"), 0);
        // Then
        assertThat(nano.getRequestedUris(), is(List.of("/redirect.wsdl", "/service.wsdl")));
    }

    @Test
    void shouldNotFollowOutOfScopeRedirectInScopedMode() throws Exception {
        // Given
        String wsdlUrl = serverUrl("/redirect.wsdl");
        addRedirectHandler("/redirect.wsdl", serverUrl("/out.wsdl"));
        addWsdlHandler("/out.wsdl", simpleWsdl());
        Control.getSingleton().setMode(Mode.protect);
        given(session.isInScope(anyString())).willReturn(false);
        given(session.isInScope(wsdlUrl)).willReturn(true);
        // When
        parser.syncImportWsdlUrl(wsdlUrl, 0);
        // Then
        assertThat(nano.getRequestedUris(), is(List.of("/redirect.wsdl")));
    }

    @Test
    void shouldResolveRelativeImportAgainstRedirectedWsdlUrl() throws Exception {
        // Given
        String initialWsdlUrl = serverUrl("/redirect.wsdl");
        String redirectedWsdlUrl = serverUrl("/foo/bar/service.wsdl");
        // When
        addRedirectHandler("/redirect.wsdl", redirectedWsdlUrl);
        addWsdlHandler("/foo/bar/service.wsdl", wsdlWithSchemaImport("schema.xsd"));
        addWsdlHandler("/foo/bar/schema.xsd", simpleSchema());
        Control.getSingleton().setMode(Mode.standard);
        parser.syncImportWsdlUrl(initialWsdlUrl, 0);
        // Then
        assertThat(
                nano.getRequestedUris(),
                is(List.of("/redirect.wsdl", "/foo/bar/service.wsdl", "/foo/bar/schema.xsd")));
    }

    private String serverUrl(String path) {
        return "http://localhost:" + nano.getListeningPort() + path;
    }

    private void addWsdlHandler(String path, String body) {
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        return NanoHTTPD.newFixedLengthResponse(Status.OK, "text/xml", body);
                    }
                });
    }

    private void addRedirectHandler(String path, String location) {
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        Response response =
                                NanoHTTPD.newFixedLengthResponse(
                                        Status.REDIRECT, NanoHTTPD.MIME_PLAINTEXT, "");
                        response.addHeader(HttpHeader.LOCATION, location);
                        return response;
                    }
                });
    }

    private static String simpleWsdl() {
        return """
                <?xml version="1.0"?>
                <wsdl:definitions
                    xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
                    targetNamespace="http://example.com/test">
                </wsdl:definitions>
                """;
    }

    private static String wsdlWithSchemaImport(String schemaLocation) {
        return """
                <?xml version="1.0"?>
                <wsdl:definitions
                    xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
                    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                    targetNamespace="http://example.com/test">
                  <wsdl:types>
                    <xsd:schema targetNamespace="http://example.com/test">
                      <xsd:import
                          namespace="http://example.com/types"
                          schemaLocation="%s"/>
                    </xsd:schema>
                  </wsdl:types>
                </wsdl:definitions>
                """
                .formatted(schemaLocation);
    }

    private static String simpleSchema() {
        return """
                <?xml version="1.0"?>
                <xsd:schema
                    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                    targetNamespace="http://example.com/types">
                  <xsd:element name="value" type="xsd:string"/>
                </xsd:schema>
                """;
    }

    private Map<String, String> parseWsdlParams() throws Exception {
        return parseWsdlParams(FILL_PARAMETERS_WSDL);
    }

    private Map<String, String> parseWsdlParams(String resourceName) throws Exception {
        importWsdl(resourceName);
        return parser.getLastConfig().getParams();
    }

    private void importWsdl(String resourceName) throws Exception {
        String content =
                new String(
                        Files.readAllBytes(getResourcePath("resources/" + resourceName)),
                        StandardCharsets.UTF_8);
        parser.extContentWSDLImport(content, false);
    }

    @SuppressWarnings("unchecked")
    private Supplier<Date> mockLenientDateSupplier() {
        return mock(Supplier.class, withSettings().strictness(Strictness.LENIENT));
    }
}
