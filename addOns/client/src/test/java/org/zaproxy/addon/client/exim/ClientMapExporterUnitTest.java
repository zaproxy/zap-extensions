/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.client.exim;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.exim.ExporterOptions;
import org.zaproxy.zap.model.Context;

/** Unit test for {@link ClientMapExporter}. */
class ClientMapExporterUnitTest {

    private ExtensionClientIntegration extensionClient;
    private ClientMapExporter exporter;

    @BeforeEach
    void setup() {
        extensionClient = mock(ExtensionClientIntegration.class);
        exporter = new ClientMapExporter(extensionClient);
    }

    @Test
    void shouldDelegateExportToExtensionWithNoContext() throws IOException {
        // Given
        Writer writer = new StringWriter();
        ExporterOptions options = mock(ExporterOptions.class);
        // When
        exporter.export(writer, options);
        // Then
        verify(extensionClient).exportClientMap(writer, null);
    }

    @Test
    void shouldDelegateExportToExtensionWithContext() throws IOException {
        // Given
        Writer writer = new StringWriter();
        ExporterOptions options = mock(ExporterOptions.class);
        Context context = mock(Context.class);
        org.mockito.BDDMockito.given(options.getContext()).willReturn(context);
        // When
        exporter.export(writer, options);
        // Then
        verify(extensionClient).exportClientMap(writer, context);
    }

    @Test
    void shouldPropagateIoExceptionFromExtension() throws IOException {
        // Given
        Writer writer = new StringWriter();
        ExporterOptions options = mock(ExporterOptions.class);
        doThrow(new IOException("write error"))
                .when(extensionClient)
                .exportClientMap(any(Writer.class), isNull());
        // When / Then
        Assertions.assertThrows(IOException.class, () -> exporter.export(writer, options));
    }
}
