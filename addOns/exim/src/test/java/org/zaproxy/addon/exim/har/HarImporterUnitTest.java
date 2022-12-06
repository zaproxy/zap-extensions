/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.exim.har;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import edu.umass.cs.benchlab.har.HarEntries;
import edu.umass.cs.benchlab.har.HarLog;
import java.io.File;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.zap.utils.HarUtils;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link HarImporter}. */
class HarImporterUnitTest {

    private static final byte[] EMPTY_BODY = {};

    @BeforeAll
    static void setup() {
        Constant.messages = mock(I18N.class);
        given(Constant.messages.getString(any())).willReturn("");
    }

    @AfterAll
    static void cleanup() {
        Constant.messages = null;
    }

    @Test
    void serializedAndDeserializedShouldMatch() throws Exception {
        // Given
        byte[] requestBody = {0x01, 0x02};
        byte[] responseBody = {0x30, 0x31};
        HttpMessage httpMessage =
                new HttpMessage(
                        "POST /path HTTP/1.1\r\nContent-Type: application/octet-stream\r\n\r\n",
                        requestBody,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain;charset=US-ASCII\r\n\r\n",
                        responseBody);

        HarLog harLog = createHarLog(httpMessage);
        // When
        List<HttpMessage> deserialized = HarImporter.getHttpMessages(harLog);
        // Then
        assertThat(deserialized.size(), equalTo(1));
        assertThat(deserialized.get(0), equalTo(httpMessage));
    }

    @Test
    void shouldHaveValidResponseSetFromTargetHost() throws Exception {
        // Given
        HarLog harLog =
                createHarLog(
                        new HttpMessage(
                                "GET / HTTP/1.1", EMPTY_BODY, "HTTP/1.1 200 OK", EMPTY_BODY));
        // When
        List<HttpMessage> messages = HarImporter.getHttpMessages(harLog);
        // Then
        assertThat(messages, hasSize(1));
        assertThat(messages.get(0).isResponseFromTargetHost(), equalTo(true));
    }

    @Test
    void shouldHaveInvalidResponseNotSetFromTargetHost() throws Exception {
        // Given
        HarLog harLog = createHarLog(new HttpMessage(new HttpRequestHeader("GET / HTTP/1.1")));
        // When
        List<HttpMessage> messages = HarImporter.getHttpMessages(harLog);
        // Then
        assertThat(messages, hasSize(1));
        assertThat(messages.get(0).isResponseFromTargetHost(), equalTo(false));
    }

    @Test
    void shouldBeFailureIfFileNotFound(@TempDir Path dir) throws Exception {
        // Given
        File file = dir.resolve("missing.har").toFile();
        // When
        HarImporter importer = new HarImporter(file);
        // Then
        assertThat(importer.isSuccess(), equalTo(false));
    }

    @Test
    void shouldCompleteListenerIfFileNotFound(@TempDir Path dir) throws Exception {
        // Given
        File file = dir.resolve("missing.har").toFile();
        ProgressPaneListener listener = mock(ProgressPaneListener.class);
        // When
        HarImporter importer = new HarImporter(file, listener);
        // Then
        assertThat(importer.isSuccess(), equalTo(false));
        verify(listener).completed();
    }

    private static HarLog createHarLog(HttpMessage message) {
        HarLog harLog = HarUtils.createZapHarLog();
        HarEntries harEntries = new HarEntries();
        harEntries.addEntry(HarUtils.createHarEntry(message));
        harLog.setEntries(harEntries);
        return harLog;
    }
}
