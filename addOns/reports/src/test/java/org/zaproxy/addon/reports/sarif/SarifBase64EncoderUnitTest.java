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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SarifBase64EncoderUnitTest {

    private SarifBase64Encoder toTest;

    @BeforeEach
    void beforeEach() {
        toTest = new SarifBase64Encoder();
    }

    @Test
    void testdataCanBeEncodedToBase64() {
        /* prepare */
        String content = "testdata";

        /* execute */
        String encoded = toTest.encodeBytesToBase64(content.getBytes());

        /* test */
        assertEquals("dGVzdGRhdGE=", encoded);
        byte[] backwardCheck = Base64.getDecoder().decode(encoded);
        assertEquals(content, new String(backwardCheck));
    }

    @Test
    void emojThinkingFaceCanBeEncodedToBase64() {
        /* prepare */
        Charset charset = StandardCharsets.UTF_8;
        String content = "🤔 Thinking Face";

        /* execute */
        String encoded = toTest.encodeBytesToBase64(content.getBytes(charset));

        /* test */
        byte[] backwardCheck = Base64.getDecoder().decode(encoded);
        assertEquals(content, new String(backwardCheck, charset));
        assertEquals("8J+klCBUaGlua2luZyBGYWNl", encoded);
    }

    @Test
    void nullBytesArgumentDoesReturnNull() {
        /* prepare */
        byte[] content = null;

        /* execute */
        String encoded = toTest.encodeBytesToBase64(content);

        /* test */
        assertEquals(null, encoded);
    }
}
