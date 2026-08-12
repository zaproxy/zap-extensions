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
package org.zaproxy.zap.extension.soap;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.File;
import java.nio.file.Files;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link SoapAPI}. */
class SoapAPIUnitTest extends TestUtils {

    private ExtensionImportWSDL extension;
    private SoapAPI soapAPI;

    @BeforeEach
    void prepare() {
        mockMessages(new ExtensionImportWSDL());
        extension = mock(ExtensionImportWSDL.class);
        soapAPI = new SoapAPI(extension);
    }

    @Test
    void shouldThrowApiExceptionIfMaxMessagesNegativeForUrl() {
        // Given
        JSONObject params = new JSONObject();
        params.put("url", "http://example.com");
        params.put("maxMessages", "-1");
        // When / Then
        ApiException exception =
                assertThrows(
                        ApiException.class, () -> soapAPI.handleApiAction("importUrl", params));
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        assertThat(exception.toString(), containsString("(illegal_parameter): maxMessages"));
    }

    @Test
    void shouldThrowApiExceptionIfMaxMessagesNegativeForFile() throws Exception {
        // Given
        File importFile = Files.createTempFile("soap", ".wsdl").toFile();
        JSONObject params = new JSONObject();
        params.put("file", importFile.getAbsolutePath());
        params.put("maxMessages", "-1");
        // When / Then
        ApiException exception =
                assertThrows(
                        ApiException.class, () -> soapAPI.handleApiAction("importFile", params));
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        assertThat(exception.toString(), containsString("(illegal_parameter): maxMessages"));
    }

    @Test
    void shouldPassMaxMessagesForUrl() throws Exception {
        // Given
        JSONObject params = new JSONObject();
        params.put("url", "http://example.com");
        params.put("maxMessages", "2");
        // When
        soapAPI.handleApiAction("importUrl", params);
        // Then
        verify(extension).syncImportWsdlUrl("http://example.com", 2);
    }

    @Test
    void shouldPassMaxMessagesForFile() throws Exception {
        // Given
        File importFile = Files.createTempFile("soap", ".wsdl").toFile();
        JSONObject params = new JSONObject();
        params.put("file", importFile.getAbsolutePath());
        params.put("maxMessages", "1");
        // When
        soapAPI.handleApiAction("importFile", params);
        // Then
        verify(extension).syncImportWsdlFile(importFile, 1);
    }
}
