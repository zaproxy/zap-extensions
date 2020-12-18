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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.testutils.TestUtils;

public class WSDLCustomParserTestCase extends TestUtils {

    private String wsdlContent;
    private WSDLCustomParser parser;

    @BeforeEach
    public void setUp() throws Exception {
        /* Simple log configuration to prevent Log4j malfunction. */
        BasicConfigurator.configure();
        Logger rootLogger = Logger.getRootLogger();
        rootLogger.setLevel(Level.OFF);

        /* Gets test wsdl file and retrieves its content as String. */
        Path wsdlPath = getResourcePath("resources/test.wsdl");
        wsdlContent = new String(Files.readAllBytes(wsdlPath), StandardCharsets.UTF_8);

        parser = new WSDLCustomParser(null);
    }

    @Test
    public void parseWSDLContentTest() {
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
    public void canBeWSDLparsedTest() {
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
    public void createSoapRequestTest() {
        parser.extContentWSDLImport(wsdlContent, false);
        /* Positive case. */
        HttpMessage result = parser.createSoapRequest(parser.getLastConfig());
        assertNotNull(result);
        /* Negative case. */
        result = parser.createSoapRequest(new SOAPMsgConfig());
        assertNull(result);
    }

    @Test
    public void addParameterShouldUseValueGeneratorWhenAvailable() {
        // Given
        String path = "CelsiusToFahrenheit/Celsius";
        String paramType = "s:string";
        String name = "Celsius";
        Map<String, String> fieldAttributes = new HashMap<>();
        fieldAttributes.put("Control Type", "TEXT");
        fieldAttributes.put("type", name);

        ValueGenerator valueGenerator = mock(ValueGenerator.class);
        when(valueGenerator.getValue(
                        null,
                        null,
                        name,
                        "",
                        Collections.emptyList(),
                        Collections.emptyMap(),
                        fieldAttributes))
                .thenReturn("TEST_VALUE");
        parser.setValueGenerator(valueGenerator);

        // Then
        Map<String, String> expectedParams = new HashMap<>();
        expectedParams.put("xpath:/" + path, "TEST_VALUE");
        assertEquals(expectedParams, parser.addParameter(path, paramType, name, null));
    }

    @Test
    public void addParameterShouldUseDefaultValuesWhenValueIsNotSpecified() {
        // Given
        String path = "CelsiusToFahrenheit/Celsius";
        String paramType = "s:string";
        String name = "Celsius";
        Map<String, String> fieldAttributes = new HashMap<>();
        fieldAttributes.put("Control Type", "TEXT");
        fieldAttributes.put("type", name);

        ValueGenerator valueGenerator = mock(ValueGenerator.class);
        when(valueGenerator.getValue(
                        null,
                        null,
                        name,
                        "",
                        Collections.emptyList(),
                        Collections.emptyMap(),
                        fieldAttributes))
                .thenReturn("");
        parser.setValueGenerator(valueGenerator);

        // Then
        Map<String, String> expectedParams = new HashMap<>();
        expectedParams.put("xpath:/" + path, "paramValue");
        assertEquals(expectedParams, parser.addParameter(path, paramType, name, null));
    }
}
