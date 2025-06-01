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
import static org.mockito.BDDMockito.given;

import org.junit.jupiter.api.Test;
import org.zaproxy.addon.encoder.processors.EncodeDecodeResult;

class Base64EncoderUnitTest extends ProcessorTests<Base64Encoder> {

    @Override
    protected Base64Encoder createProcessor() {
        return Base64Encoder.getSingleton();
    }

    private static final String EIGHTY_CHARS_LOREM =
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nullam tristique morbi.";

    @Test
    void shouldEncodeSimpleString() throws Exception {
        // Given / When
        EncodeDecodeResult result = processor.process("admin");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(result.getResult(), is(equalTo("YWRtaW4=")));
    }

    @Test
    void shouldEncodeAndWrapWhenIndicatedByOptions() throws Exception {
        // Given
        given(options.isBase64DoBreakLines()).willReturn(true);
        // When
        EncodeDecodeResult result = processor.process(EIGHTY_CHARS_LOREM);
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(
                result.getResult(),
                is(
                        equalTo(
                                "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4g\r\n"
                                        + "TnVsbGFtIHRyaXN0aXF1ZSBtb3JiaS4=")));
    }

    @Test
    void shouldEncodeAndNotWrapWhenIndicatedByOptions() throws Exception {
        // Given
        given(options.isBase64DoBreakLines()).willReturn(false);
        // When
        EncodeDecodeResult result = processor.process(EIGHTY_CHARS_LOREM);
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(
                result.getResult(),
                is(
                        equalTo(
                                "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4gTnVsbGFtIHRyaXN0aXF1ZSBtb3JiaS4=")));
    }
}
