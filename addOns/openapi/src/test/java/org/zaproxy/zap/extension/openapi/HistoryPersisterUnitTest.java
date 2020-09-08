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
package org.zaproxy.zap.extension.openapi;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.RETURNS_MOCKS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.io.StringWriter;
import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.WriterAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.platform.commons.support.HierarchyTraversalMode;
import org.junit.platform.commons.support.ReflectionSupport;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link HistoryPersister}. */
class HistoryPersisterUnitTest extends TestUtils {

    private long sessionId;
    private TableHistory tableHistory;
    private SiteMap siteMap;
    private ExtensionLoader extensionLoader;
    private ExtensionHistory extHistory;
    private HttpMessage message;

    private HistoryPersister historyPersister;

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();

        Control control = mock(Control.class, withSettings().lenient());
        setControlSingleton(control);

        extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        when(control.getExtensionLoader()).thenReturn(extensionLoader);

        Model model = mock(Model.class, withSettings().lenient());
        setModelSingleton(model);

        Session session = mock(Session.class, withSettings().lenient());
        given(session.getSessionId()).willReturn(1234L);

        siteMap = mock(SiteMap.class, withSettings().lenient());
        given(session.getSiteTree()).willReturn(siteMap);

        given(model.getSession()).willReturn(session);

        message = mock(HttpMessage.class, withSettings().defaultAnswer(RETURNS_MOCKS));

        tableHistory =
                mock(TableHistory.class, withSettings().defaultAnswer(RETURNS_MOCKS).lenient());
        HistoryReference.setTableHistory(tableHistory);
        HistoryReference.setTableAlert(
                mock(TableAlert.class, withSettings().defaultAnswer(RETURNS_MOCKS).lenient()));

        sessionId = Model.getSingleton().getSession().getSessionId();

        extHistory = mock(ExtensionHistory.class);
        given(extensionLoader.getExtension(ExtensionHistory.class)).willReturn(extHistory);

        historyPersister = new HistoryPersister();
    }

    private static void setControlSingleton(Control control) throws Exception {
        Field field =
                ReflectionSupport.findFields(
                                Control.class,
                                f -> "control".equals(f.getName()),
                                HierarchyTraversalMode.TOP_DOWN)
                        .get(0);
        field.setAccessible(true);
        field.set(Control.class, control);
    }

    private static void setModelSingleton(Model model) throws Exception {
        Field field =
                ReflectionSupport.findFields(
                                Model.class,
                                f -> "model".equals(f.getName()),
                                HierarchyTraversalMode.TOP_DOWN)
                        .get(0);
        field.setAccessible(true);
        field.set(Model.class, model);
    }

    @AfterEach
    void cleanUp() throws Exception {
        HistoryReference.setTableHistory(null);
        HistoryReference.setTableAlert(null);

        setControlSingleton(null);
        setModelSingleton(null);
    }

    @Test
    void shouldPersistMessageAndAddToSiteMapAndHistory() throws Exception {
        // Given / When
        historyPersister.handleMessage(message, 1);
        // Then
        verify(tableHistory).write(eq(sessionId), anyInt(), eq(message));
        verify(extHistory).addHistory(any(HistoryReference.class));
        verify(siteMap).addPath(any(HistoryReference.class), eq(message));
    }

    @Test
    void shouldPersistMessageAndAddToSiteMapButNotHistoryWhenDisabled() throws Exception {
        // Given
        given(extensionLoader.getExtension(ExtensionHistory.class)).willReturn(null);
        historyPersister = new HistoryPersister();
        // When
        assertDoesNotThrow(() -> historyPersister.handleMessage(message, 1));
        // Then
        verify(tableHistory).write(eq(sessionId), anyInt(), eq(message));
        verify(siteMap).addPath(any(HistoryReference.class), eq(message));
    }

    @Test
    void shouldPersistMessageAsSpiderIfSpiderInitiator() throws Exception {
        // Given
        int initiator = HttpSender.SPIDER_INITIATOR;
        // When
        historyPersister.handleMessage(message, initiator);
        // Then
        verify(tableHistory).write(sessionId, HistoryReference.TYPE_SPIDER, message);
    }

    @ParameterizedTest
    @ValueSource(ints = {HttpSender.SPIDER_INITIATOR - 1, HttpSender.SPIDER_INITIATOR + 1})
    void shouldPersistMessageAsZapUserIfNotSpiderInitiator(int initiator) throws Exception {
        // Given / When
        historyPersister.handleMessage(message, initiator);
        // Then
        verify(tableHistory).write(sessionId, HistoryReference.TYPE_ZAP_USER, message);
    }

    @Test
    void shouldLogWarnIfUnableToPersistMessage() throws Exception {
        // Given
        Logger logger = Logger.getLogger(HistoryPersister.class);
        StringAppender appender = new StringAppender();
        try {
            logger.addAppender(appender);
            given(tableHistory.write(anyLong(), anyInt(), any(HttpMessage.class)))
                    .willThrow(DatabaseException.class);
            // When
            historyPersister.handleMessage(message, 1);
            // Then
            assertThat(appender.toString(), containsString("WARN"));
        } finally {
            logger.removeAppender(appender);
        }
    }

    @Test
    void shouldNotAddToSiteMapNorHistoryIfUnableToPersistMessage() throws Exception {
        // Given
        given(tableHistory.write(anyLong(), anyInt(), any(HttpMessage.class)))
                .willThrow(DatabaseException.class);
        // When
        historyPersister.handleMessage(message, 1);
        // Then
        verifyNoInteractions(extHistory);
        verifyNoInteractions(siteMap);
    }

    @Test
    void shouldAddMessageToSiteMapSynchronously() {
        // Given
        AtomicBoolean synchronous = new AtomicBoolean();
        doAnswer(
                        invocation -> {
                            Thread.sleep(250);
                            synchronous.set(true);
                            return null;
                        })
                .when(extHistory)
                .addHistory(any(HistoryReference.class));
        // When
        historyPersister.handleMessage(message, 1);
        // Then
        assertThat(synchronous.get(), is(true));
    }

    private static class StringAppender extends WriterAppender {

        private final StringWriter writer;

        StringAppender() {
            super();
            writer = new StringWriter();
            setLayout(new PatternLayout(PatternLayout.TTCC_CONVERSION_PATTERN));
            setWriter(writer);
        }

        @Override
        public String toString() {
            return writer.toString();
        }
    }
}
