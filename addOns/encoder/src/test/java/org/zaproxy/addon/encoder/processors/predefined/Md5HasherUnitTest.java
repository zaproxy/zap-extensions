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

class Md5HasherUnitTest extends ProcessorTests<Md5Hasher> {

    @Override
    protected Md5Hasher createProcessor() {
        return Md5Hasher.getSingleton();
    }

    @Override
    void shouldHandleEmptyInput() throws Exception {
        // Given / When
        EncodeDecodeResult result = processor.process("");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(result.getResult(), is(equalTo("D41D8CD98F00B204E9800998ECF8427E")));
    }

    @Test
    void shouldEncodeSimpleString() throws Exception {
        // Given / When
        EncodeDecodeResult result = processor.process("admin");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(result.getResult(), is(equalTo("21232F297A57A5A743894A0E4A801FC3")));
    }
}
