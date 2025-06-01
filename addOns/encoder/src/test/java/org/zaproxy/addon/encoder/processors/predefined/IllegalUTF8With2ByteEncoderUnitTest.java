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

class IllegalUTF8With2ByteEncoderUnitTest extends ProcessorTests<IllegalUTF8With2ByteEncoder> {

    @Override
    protected IllegalUTF8With2ByteEncoder createProcessor() {
        return IllegalUTF8With2ByteEncoder.getSingleton();
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
                                "%c0%bc%c1%b3%c1%a3%c1%b2%c1%a9%c1%b0%c1%b4%c0%be%c1%a1%c1%ac%c1%a5%c1%b2%c1%b4%c0%a8%c0%a7%c0%85%c0%a7%c0%a9%c0%bc%c0%af%c1%b3%c1%a3%c1%b2%c1%a9%c1%b0%c1%b4%c0%be")));
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
                                "%c1%b3%c1%af%c1%ad%c1%a5%c0%a0%c1%ad%c1%b5%c1%ac%c1%b4%c1%a9%c1%ac%c1%a9%c1%ae%c1%a5%c0%8a%c1%a3%c1%af%c1%ae%c1%b4%c1%a5%c1%ae%c1%b4")));
    }
}
