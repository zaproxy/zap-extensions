/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.reports.sarif;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.parosproxy.paros.network.HttpHeader;

class SarifBinaryContentDetectorUnitTest {

    private SarifBinaryContentDetector toTest;
    private HttpHeader header;

    @BeforeEach
    void beforeEach() {
        toTest = new SarifBinaryContentDetector();
        header = mock(HttpHeader.class);
    }

    @CsvSource({
        "text/html,false",
        "text/plain,false",
        "application/json,false",
        "application/json-patch+json,false",
        "application/json-seq,false",
        "application/xml,false",
        "application/xml-dtd,false",
        "image/png,true",
        "application/pdf,true",
        "application/zip,true",
        "audio/mp4,true",
        ",true",

        /* obsolete javascript definitions - but maybe still used:*/
        "text/javascript,false",
        "text/javascript1.0,false",
        "text/jscript,false",
        "text/livescript,false",
        "text/x-javascript,false",
        "text/ecmascript,false",
        "text/x-ecmascript,false",
        "application/x-javascript,false",
        "application/javascript,false",
        "application/javascript,false",
        "application/x-ecmascript,false",

        /* official javascript setup - see https://www.rfc-editor.org/rfc/rfc4329.txt */
        "application/javascript,false",
        "application/ecmascript,false",

        /* some additions in combination with charset defined */
        "text/html; charset=utf-8, false",
        "text/html; charset=utf-8   , false",
        "text/html;    charset=utf-8   , false",
        "application/zip; charset=utf-8, true",
        "; charset=utf-16,true",

        /* some additions found "in the wild" */
        "aplication/health+json,false",
        "aplication/octet-stream,true",
        "aplication/problem+json,false",
        "aplication/problem+xml,false",
        "aplication/soap+xml,false",
        "aplication/vnd.api+json,false",
        "aplication/xml,false",
        "aplication/x-ndjson,false",
        "aplication/x-yaml,false",
        "txt/x-json,false",
        "txt/json,false",
        "txt/yaml,false",
        "txt/plain,false"
    })
    @ParameterizedTest(name = "content type:{0} is binary:{1}")
    void normalizedHeaderContenTypeNotNulltHandledAsExpected(
            String normalizedContentValue, String expectedAsBinary) {
        /* prepare */
        when(header.getNormalisedContentTypeValue()).thenReturn(normalizedContentValue);

        /* execute */
        boolean isBinary = toTest.isBinaryContent(header);

        /* test */
        assertEquals(expectedAsBinary, "" + isBinary);
    }

    @DisplayName("When normalized content type value is null, it is treated as binary")
    @Test()
    void whenNormalizedContentTypeValueIsNullItIsTreatedAsBinary() {
        /* prepare */
        when(header.getNormalisedContentTypeValue()).thenReturn(null);

        /* execute */
        boolean isBinary = toTest.isBinaryContent(header);

        /* test */
        assertTrue(isBinary);
    }
}
