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

class UnicodeDecoderUnitTest extends ProcessorTests<UnicodeDecoder> {

    @Override
    protected UnicodeDecoder createProcessor() {
        return UnicodeDecoder.getSingleton();
    }

    @Test
    void shouldDecodeWithoutError() throws Exception {
        // Given / When
        EncodeDecodeResult result =
                processor.process(
                        "%u003c%u0073%u0063%u0072%u0069%u0070%u0074%u003e%u0061%u006c%u0065%u0072%u0074%u0028%u0027%u2705%u0027%u0029%u003c%u002f%u0073%u0063%u0072%u0069%u0070%u0074%u003e");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(result.getResult(), is(equalTo("<script>alert('✅')</script>")));
    }

    @Test
    void shouldDecodeMultilineInput() throws Exception {
        // Given / When
        EncodeDecodeResult result =
                processor.process(
                        "%u0073%u006f%u006d%u0065%u0020%u006d%u0075%u006c%u0074%u0069%u006c%u0069%u006e%u0065%u000a%u0063%u006f%u006e%u0074%u0065%u006e%u00745");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(result.getResult(), is(equalTo("some multiline\ncontent")));
    }
}
