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

class FullUrlEncoderUnitTest extends ProcessorTests<FullUrlEncoder> {

    @Override
    protected FullUrlEncoder createProcessor() {
        return FullUrlEncoder.getSingleton();
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
                                "%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%27%E2%9C%85%27%29%3C%2F%73%63%72%69%70%74%3E")));
    }

    @Test
    void shouldEncodeMultilineInput() throws Exception {
        // Given / When
        EncodeDecodeResult result = processor.process("some multiline\ncontent");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(
                result.getResult(),
                is(equalTo("%73%6F%6D%65%20%6D%75%6C%74%69%6C%69%6E%65%0A%63%6F%6E%74%65%6E%74")));
    }
}
