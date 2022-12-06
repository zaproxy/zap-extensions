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

class FullHtmlStringEncoderUnitTest extends ProcessorTests<FullHtmlStringEncoder> {

    @Override
    protected FullHtmlStringEncoder createProcessor() {
        return FullHtmlStringEncoder.getSingleton();
    }

    @Test
    void shouldEncodeSimpleScriptTag() throws Exception {
        // Given / When
        EncodeDecodeResult result = processor.process("<script>");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(
                result.getResult(), is(equalTo("&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;")));
    }

    @Test
    void shouldEncodeStringWithEmoji() throws Exception {
        // Given / When
        EncodeDecodeResult result = processor.process("fred✅");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(result.getResult(), is(equalTo("&#102;&#114;&#101;&#100;&#9989;")));
    }
}
