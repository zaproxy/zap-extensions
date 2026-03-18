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
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ZestImporter}. */
class ZestImporterUnitTest extends TestUtils {

    private static TableHistory tableHistory;
    private static ExtensionLoader extensionLoader;
    private static ExtensionHistory extHistory;
    private static SiteMap siteMap;

    @BeforeAll
    static void setup() throws Exception {
        mockMessages(new ExtensionZest());

        tableHistory = mock(TableHistory.class, withSettings().strictness(Strictness.LENIENT));
        given(tableHistory.write(anyLong(), anyInt(), any())).willReturn(mock(RecordHistory.class));
        HistoryReference.setTableHistory(tableHistory);
        HistoryReference.setTableAlert(mock(TableAlert.class));

        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        Model.setSingletonForTesting(model);
        Session session = mock(Session.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getSession()).willReturn(session);

        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extHistory = mock(ExtensionHistory.class);
        given(extensionLoader.getExtension(ExtensionHistory.class)).willReturn(extHistory);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        siteMap = mock(SiteMap.class);
        given(session.getSiteTree()).willReturn(siteMap);
    }

    @AfterAll
    static void cleanup() {
        Constant.messages = null;
        HistoryReference.setTableHistory(null);
        HistoryReference.setTableAlert(null);
    }

    @Test
    void shouldBeFailureIfFileNotFound(@TempDir java.nio.file.Path dir) {
        // Given
        java.io.File file = dir.resolve("missing.zst").toFile();
        // When
        ZestImporter importer = new ZestImporter(file);
        // Then
        assertThat(importer.isSuccess(), equalTo(false));
    }

    @Test
    void shouldCompleteListenerIfFileNotFound(@TempDir java.nio.file.Path dir) {
        // Given
        java.io.File file = dir.resolve("missing.zst").toFile();
        ProgressPaneListener listener = mock(ProgressPaneListener.class);
        // When
        ZestImporter importer = new ZestImporter(file, listener);
        // Then
        assertThat(importer.isSuccess(), equalTo(false));
        verify(listener).completed();
    }

    @Test
    void shouldImportOneRequest() {
        // Given
        ProgressPaneListener listener = mock(ProgressPaneListener.class);
        // When
        ZestImporter importer =
                new ZestImporter(getResourcePath("oneRequest.zst").toFile(), listener);
        // Then
        assertThat(importer.isSuccess(), equalTo(true));
        verify(listener).setTotalTasks(1);
        verify(listener).setTasksDone(1);
        verify(listener).completed();
    }

    @Test
    void shouldImportEmptyScript() {
        // Given
        ProgressPaneListener listener = mock(ProgressPaneListener.class);
        // When
        ZestImporter importer =
                new ZestImporter(getResourcePath("emptyScript.zst").toFile(), listener);
        // Then
        assertThat(importer.isSuccess(), equalTo(true));
        verify(listener).setTotalTasks(0);
        verify(listener).completed();
    }

    @Test
    void shouldSkipCommentsAndImportRequests() {
        // Given
        ProgressPaneListener listener = mock(ProgressPaneListener.class);
        // When
        ZestImporter importer =
                new ZestImporter(getResourcePath("scriptWithComment.zst").toFile(), listener);
        // Then
        assertThat(importer.isSuccess(), equalTo(true));
        verify(listener).setTotalTasks(1);
        verify(listener).setTasksDone(1);
        verify(listener).completed();
    }
}
