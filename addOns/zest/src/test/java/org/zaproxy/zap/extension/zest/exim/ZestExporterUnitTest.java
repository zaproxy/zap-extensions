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
package org.zaproxy.zap.extension.zest.exim;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.IOException;
import java.io.StringWriter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestParam;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zest.core.v1.ZestElement;
import org.zaproxy.zest.core.v1.ZestJSON;

/** Unit test for {@link ZestExporter}. */
class ZestExporterUnitTest extends TestUtils {

    private static final String ZEST_SCRIPT_TITLE =
            "Exported from ZAP " + Constant.PROGRAM_VERSION + " History";

    private ExtensionZest extZest;
    private ZestExporter zestExporter;

    @BeforeAll
    static void setupMessages() {
        mockMessages(new ExtensionZest());
    }

    @BeforeEach
    void setup() {
        extZest = mock(ExtensionZest.class, withSettings().strictness(Strictness.LENIENT));
        ZestParam zestParam = mock(ZestParam.class);
        given(extZest.getParam()).willReturn(zestParam);
        given(extZest.convertElementToString(any()))
                .willAnswer(
                        invocation -> {
                            Object element = invocation.getArgument(0);
                            return element != null
                                    ? ZestJSON.toString((ZestElement) element)
                                    : "{}";
                        });

        zestExporter = new ZestExporter(extZest);
    }

    @Test
    void shouldExportEmptyZestScriptWhenNoMessages() throws IOException {
        // Given
        StringWriter writer = new StringWriter();
        zestExporter.begin(writer);

        // When
        zestExporter.end(writer);

        // Then
        String content = writer.toString();
        assertThat(content, containsString(ZEST_SCRIPT_TITLE));
    }

    @Test
    void shouldExportHistoryToZest() throws Exception {
        // Given
        HttpMessage msg = createHttpMessage("http://example.com/1");
        HistoryReference ref =
                mock(HistoryReference.class, withSettings().strictness(Strictness.LENIENT));
        given(ref.getHistoryType()).willReturn(HistoryReference.TYPE_PROXIED);
        given(ref.getHttpMessage()).willReturn(msg);

        StringWriter writer = new StringWriter();
        zestExporter.begin(writer);

        // When
        zestExporter.write(writer, ref);
        zestExporter.end(writer);

        // Then
        String content = writer.toString();
        assertThat(content, containsString(ZEST_SCRIPT_TITLE));
        assertThat(content, containsString("http://example.com/1"));
    }

    @Test
    void shouldSkipTemporaryHistoryReferences() throws Exception {
        // Given
        HttpMessage msg = createHttpMessage("http://example.com/1");
        HistoryReference ref =
                mock(HistoryReference.class, withSettings().strictness(Strictness.LENIENT));
        given(ref.getHistoryType()).willReturn(HistoryReference.TYPE_TEMPORARY);
        given(ref.getHttpMessage()).willReturn(msg);

        StringWriter writer = new StringWriter();
        zestExporter.begin(writer);

        // When
        zestExporter.write(writer, ref);
        zestExporter.end(writer);

        // Then - temporary refs are skipped, so no URL in output
        String content = writer.toString();
        assertThat(content, containsString(ZEST_SCRIPT_TITLE));
        assertThat(content, not(containsString("http://example.com/1")));
    }

    private static HttpMessage createHttpMessage(String url) throws HttpMalformedHeaderException {
        return new HttpMessage(
                new HttpRequestHeader("GET " + url + " HTTP/1.1\r\nHost: example.com"));
    }
}
