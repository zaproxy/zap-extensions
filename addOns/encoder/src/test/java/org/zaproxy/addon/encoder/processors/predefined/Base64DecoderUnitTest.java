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

class Base64DecoderUnitTest extends ProcessorTests<Base64Decoder> {

    @Override
    protected Base64Decoder createProcessor() {
        return Base64Decoder.getSingleton();
    }

    private static final String EIGHTY_CHARS_LOREM =
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nullam tristique morbi.";

    @Test
    void shouldErrorOnInvalidStringInput() throws Exception {
        // Given / When
        EncodeDecodeResult result = processor.process("admin");
        // Then
        assertThat(result.hasError(), is(equalTo(true)));
        assertThat(
                result.getResult(),
                is(equalTo("IllegalArgumentException: Last unit does not have enough valid bits")));
    }

    @Test
    void shouldHandleEncodedInput() throws Exception {
        // Given / When
        EncodeDecodeResult result = processor.process("YWRtaW4=");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(result.getResult(), is(equalTo("admin")));
    }

    @Test
    void shouldNotFailToDecodeWhenInputIsWrapped() throws Exception {
        // Given / When
        EncodeDecodeResult result =
                processor.process(
                        "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4g\r\n"
                                + "TnVsbGFtIHRyaXN0aXF1ZSBtb3JiaS4=");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(result.getResult(), is(equalTo(EIGHTY_CHARS_LOREM)));
    }

    @Test
    void shouldDecodeStringOver76Char() throws Exception {
        // Given / When
        EncodeDecodeResult result =
                processor.process(
                        "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4gTnVsbGFtIHRyaXN0aXF1ZSBtb3JiaS4=");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(result.getResult(), is(equalTo(EIGHTY_CHARS_LOREM)));
    }
}
