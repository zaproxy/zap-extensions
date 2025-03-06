/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.exim;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.Model;

/** Unit test for {@link ExtensionExim}. */
class ExtensionEximUnitTest {

    private ExtensionExim extension;

    @BeforeEach
    void setup() {
        extension = new ExtensionExim();
    }

    @Test
    void shouldNotHaveExporterBeforeInitModel() {
        // Given / When
        Exporter exporter = extension.getExporter();
        // Then
        assertThat(exporter, is(nullValue()));
    }

    @Test
    void shouldInitModelAndExporter() {
        // Given
        Model model = mock(Model.class);
        // When
        extension.initModel(model);
        // Then
        assertThat(extension.getModel(), is(notNullValue()));
        assertThat(extension.getExporter(), is(notNullValue()));
    }

    @Test
    void shouldNotHaveImporterBeforeInit() {
        // Given / When
        Importer importer = extension.getImporter();
        // Then
        assertThat(importer, is(nullValue()));
    }

    @Test
    void shouldInitImporter() {
        // Given / When
        extension.init();
        // Then
        assertThat(extension.getImporter(), is(notNullValue()));
    }
}
