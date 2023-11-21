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
import static org.hamcrest.Matchers.is;
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
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.testutils.TestUtils;

class WSDLCustomParserTestCase extends TestUtils {

    private ValueGenerator valueGenerator;
    private Supplier<Date> dateSupplier;
    private String wsdlContent;
    private WSDLCustomParser parser;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() throws Exception {
        /* Gets test wsdl file and retrieves its content as String. */
        Path wsdlPath = getResourcePath("resources/test.wsdl");
        wsdlContent = new String(Files.readAllBytes(wsdlPath), StandardCharsets.UTF_8);

        valueGenerator = mock(ValueGenerator.class);
        dateSupplier = mock(Supplier.class, withSettings().strictness(Strictness.LENIENT));
        parser = new WSDLCustomParser(() -> valueGenerator, null, dateSupplier);
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
    void addParameterShouldUseValueGeneratorWhenAvailable(String genValue) {
        // Given
        String path = "CelsiusToFahrenheit/Celsius";
        String paramType = "s:string";
        String name = "Celsius";
        Map<String, String> fieldAttributes = new HashMap<>();
        fieldAttributes.put("Control Type", "TEXT");
        fieldAttributes.put("type", name);

        when(valueGenerator.getValue(
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
                "double, 0",
                "long, 0",
                "date, 2023-11-21",
                "dateTime, 2023-11-21T05:16:40+0000",
                "something, ''"
            })
    void shouldGenerateAppropriateDefaultValueForValueGenerator(
            String paramType, String expectedDefaultValue) {
        // Given
        ArgumentCaptor<String> defaultValueArgCaptor = ArgumentCaptor.forClass(String.class);
        given(dateSupplier.get()).willReturn(new Date(1700587000000L));
        // When
        parser.addParameter("", paramType, "", null);

        // Then
        verify(valueGenerator)
                .getValue(
                        any(), any(), any(), defaultValueArgCaptor.capture(), any(), any(), any());
        assertThat(defaultValueArgCaptor.getValue(), is(equalTo(expectedDefaultValue)));
    }
}
