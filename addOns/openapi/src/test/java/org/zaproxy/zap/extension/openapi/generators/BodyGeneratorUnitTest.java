/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi.generators;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;

import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.ObjectSchema;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit test for {@link BodyGenerator}. */
class BodyGeneratorUnitTest {

    private Generators generators;
    private BodyGenerator bodyGenerator;

    @BeforeEach
    void setup() {
        generators = mock(Generators.class);
        bodyGenerator = new BodyGenerator(generators);
    }

    @Test
    void shouldHandleFormWithNoSchema() {
        // Given / When
        String result = bodyGenerator.generateForm(null);
        // Then
        assertThat(result, is(equalTo("")));
    }

    @Test
    void shouldHandleMultipartWithNoSchema() {
        // Given / When
        String result = bodyGenerator.generateMultiPart(null, null);
        // Then
        assertThat(result, is(equalTo("")));
    }

    @Test
    void shouldProperlyUseJsonExample() {
        // Given
        ObjectSchema schema = new ObjectSchema().example("{\"foo\":\"bar\"}");
        MediaType mediaType = new MediaType().schema(schema);
        // When
        String body = bodyGenerator.generate(mediaType);
        // Then
        assertThat(body, is(equalTo("{\"foo\":\"bar\"}")));
    }
}
