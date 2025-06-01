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

class Sha256HasherUnitTest extends ProcessorTests<Sha256Hasher> {

    @Override
    protected Sha256Hasher createProcessor() {
        return Sha256Hasher.getSingleton();
    }

    @Override
    void shouldHandleEmptyInput() throws Exception {
        // Given / When
        EncodeDecodeResult result = processor.process("");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(
                result.getResult(),
                is(equalTo("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")));
    }

    @Test
    void shouldEncodeSimpleString() throws Exception {
        // Given / When
        EncodeDecodeResult result = processor.process("admin");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(
                result.getResult(),
                is(equalTo("8C6976E5B5410415BDE908BD4DEE15DFB167A9C873FC4BB8A81F6F2AB448A918")));
    }
}
