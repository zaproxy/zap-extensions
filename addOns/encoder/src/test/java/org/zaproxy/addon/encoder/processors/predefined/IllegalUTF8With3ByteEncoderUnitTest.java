/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.encoder.processors.predefined;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;
import org.zaproxy.addon.encoder.processors.EncodeDecodeResult;

class IllegalUTF8With3ByteEncoderUnitTest extends ProcessorTests<IllegalUTF8With3ByteEncoder> {

    @Override
    protected IllegalUTF8With3ByteEncoder createProcessor() {
        return IllegalUTF8With3ByteEncoder.getSingleton();
    }

    @Test
    void shouldEncodeWithoutError() throws Exception {
        // Given / When
        EncodeDecodeResult result = processor.process("<script>alert('✅')</script>");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(
                result.getResult(),
                is(
                        equalTo(
                                "%e0%80%bc%e0%81%b3%e0%81%a3%e0%81%b2%e0%81%a9%e0%81%b0%e0%81%b4%e0%80%be%e0%81%a1%e0%81%ac%e0%81%a5%e0%81%b2%e0%81%b4%e0%80%a8%e0%80%a7%e0%80%85%e0%80%a7%e0%80%a9%e0%80%bc%e0%80%af%e0%81%b3%e0%81%a3%e0%81%b2%e0%81%a9%e0%81%b0%e0%81%b4%e0%80%be")));
    }

    @Test
    void shouldEncodeMultilineInput() throws Exception {
        // Given / When
        EncodeDecodeResult result = processor.process("some multiline\ncontent");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(
                result.getResult(),
                is(
                        equalTo(
                                "%e0%81%b3%e0%81%af%e0%81%ad%e0%81%a5%e0%80%a0%e0%81%ad%e0%81%b5%e0%81%ac%e0%81%b4%e0%81%a9%e0%81%ac%e0%81%a9%e0%81%ae%e0%81%a5%e0%80%8a%e0%81%a3%e0%81%af%e0%81%ae%e0%81%b4%e0%81%a5%e0%81%ae%e0%81%b4")));
    }
}
