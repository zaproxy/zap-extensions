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
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.zap.testutils.TestUtils;

class WSDLCustomParserTestCase extends TestUtils {

    private static final String MOCK_FILL_VALUE = "mock-fill-value";
    private static final String FILL_PARAMETERS_WSDL = "fill-parameters.wsdl";

    private ValueProvider valueProvider;
    private Supplier<Date> dateSupplier;
    private String wsdlContent;
    private WSDLCustomParser parser;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() throws Exception {
        /* Gets test wsdl file and retrieves its content as String. */
        Path wsdlPath = getResourcePath("resources/test.wsdl");
        wsdlContent = new String(Files.readAllBytes(wsdlPath), StandardCharsets.UTF_8);

        valueProvider = mock(ValueProvider.class);
        dateSupplier = mock(Supplier.class, withSettings().strictness(Strictness.LENIENT));
        parser = new WSDLCustomParser(() -> valueProvider, null, dateSupplier);
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
        assertThat(params, hasKey("xpath:/Request/refOuter/refBlock/leafField"));
    }

    @Test
    void shouldPickFirstChoiceOption() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasKey("xpath:/Request/branchBox/optA"));
        assertThat(params, not(hasKey("xpath:/Request/branchBox/optB")));
    }

    @Test
    void shouldUseFixedValueForAttribute() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/attrBox/@fixedKey", "FIXED-VAL"));
        assertThat(params.get("xpath:/Request/attrBox/@fixedKey"), is(not(MOCK_FILL_VALUE)));
    }

    @Test
    void shouldUseEnumerationValueForElement() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/enumField", "EL-1"));
        assertThat(params.get("xpath:/Request/enumField"), is(not(MOCK_FILL_VALUE)));
    }

    @Test
    void shouldPopulateAttributeFields() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasKey("xpath:/Request/attrBox/@keyA"));
        assertThat(params, hasKey("xpath:/Request/attrBox/@keyB"));
    }

    @Test
    void shouldUseEnumerationValueForAttribute() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/enumBox/@enumKey", "EV-1"));
        assertThat(params.get("xpath:/Request/enumBox/@enumKey"), is(not(MOCK_FILL_VALUE)));
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
        assertThat(params, hasKey("xpath:/Request/boundedInt"));
    }

    @Test
    void shouldEmitParamForTokenTypedElement() throws Exception {
        // Given – 'tokenField' has type xs:token; must not be dropped and VP must receive a
        // non-empty default so it can generate a value
        // When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasEntry("xpath:/Request/tokenField", MOCK_FILL_VALUE));
    }

    @Test
    void shouldPopulateExtendedTypeFields() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasKey("xpath:/Request/block/inherited"));
        assertThat(params, hasKey("xpath:/Request/block/added"));
    }

    @Test
    void shouldSkipAttrOnlyTypeAndProcessSibling() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasKey("xpath:/Request/groupOuter/group/leafField"));
        assertThat(params, hasKey("xpath:/Request/groupOuter/group/metaBlock/@idKey"));
        assertThat(params, hasKey("xpath:/Request/groupOuter/group/metaBlock/@nameKey"));
    }

    @Test
    void shouldAcceptUnicodeAttributeNames() throws Exception {
        // Given / When
        Map<String, String> params = parseWsdlParams();
        // Then
        assertThat(params, hasKey("xpath:/Request/attrWrapper/@plainKey"));
        assertThat(params, hasKey("xpath:/Request/attrWrapper/@äKey"));
    }

    private Map<String, String> parseWsdlParams() throws Exception {
        return parseWsdlParams(FILL_PARAMETERS_WSDL);
    }

    private Map<String, String> parseWsdlParams(String resourceName) throws Exception {
        WSDLCustomParser p = createParserForWsdl(resourceName);
        return p.getLastConfig().getParams();
    }

    private WSDLCustomParser createParserForWsdl(String resourceName) throws Exception {
        Supplier<Date> dateSupplier = mock(withSettings().strictness(Strictness.LENIENT));
        ValueProvider vp = mock(ValueProvider.class);
        when(vp.getValue(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(MOCK_FILL_VALUE);
        WSDLCustomParser p = new WSDLCustomParser(() -> vp, null, dateSupplier);
        String content =
                new String(
                        Files.readAllBytes(getResourcePath("resources/" + resourceName)),
                        StandardCharsets.UTF_8);
        p.extContentWSDLImport(content, false);
        return p;
    }
}
