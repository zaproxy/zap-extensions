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

class HexStringDecoderUnitTest extends ProcessorTests<HexStringDecoder> {

    @Override
    protected HexStringDecoder createProcessor() {
        return HexStringDecoder.getSingleton();
    }

    @Test
    void shouldDecodeWithoutError() throws Exception {
        // Given / When
        EncodeDecodeResult result =
                processor.process("3C7363726970743E616C6572742827E29C8527293C2F7363726970743E");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(result.getResult(), is(equalTo("<script>alert('✅')</script>")));
    }

    @Test
    void shouldDecodeMultilineInput() throws Exception {
        // Given / When
        EncodeDecodeResult result =
                processor.process("736F6D65206D756C74696C696E650A636F6E74656E74");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(result.getResult(), is(equalTo("some multiline\ncontent")));
    }
}
