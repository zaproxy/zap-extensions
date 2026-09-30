/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.BDDMockito.when;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.commons.configuration.Configuration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordAlert;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.db.TableAlertTag;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.extension.alert.AlertEventPublisher;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link ExtensionAlertFilters}. */
class ExtensionAlertFiltersUnitTest extends TestUtils {

    private ExtensionAlertFilters extension;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionAlertFilters());
        extension = new ExtensionAlertFilters();
    }

    @Test
    void shouldLoadContextWithoutAlertFilters() throws Exception {
        // Given
        int ctxId = 1;
        Context ctx = new Context(null, ctxId);
        Session session = sessionWithAlertFilters();
        // When
        extension.loadContextData(session, ctx);
        // Then
        ContextAlertFilterManager m = extension.getContextAlertFilterManager(ctxId);
        assertThat(m.getAlertFilters(), is(empty()));
        verify(session).getContextDataStrings(ctxId, 500);
    }

    @Test
    void shouldLoadContextWithAlertFilters() throws Exception {
        // Given
        int ctxId = 1;
        Context ctx = new Context(null, ctxId);
        Session session = sessionWithAlertFilters("true;42;1;;;", "false;43;1;;;");
        // When
        extension.loadContextData(session, ctx);
        // Then
        ContextAlertFilterManager m = extension.getContextAlertFilterManager(ctxId);
        assertThat(
                m.getAlertFilters(),
                contains(
                        new AlertFilter(ctxId, "42", 1, "", false, "", true),
                        new AlertFilter(ctxId, "43", 1, "", false, "", false)));
        verify(session).getContextDataStrings(ctxId, 500);
    }

    @Test
    void shouldLoadContextWithAlertFiltersSkippingMalformed() throws Exception {
        // Given
        int ctxId = 1;
        Context ctx = new Context(null, ctxId);
        Session session = sessionWithAlertFilters("not alert filter", "false;43;1;;;");
        // When
        extension.loadContextData(session, ctx);
        // Then
        ContextAlertFilterManager m = extension.getContextAlertFilterManager(ctxId);
        assertThat(
                m.getAlertFilters(),
                contains(new AlertFilter(ctxId, "43", 1, "", false, "", false)));
        verify(session).getContextDataStrings(ctxId, 500);
    }

    @Test
    void shouldImportContextWithoutAlertFilters() {
        // Given
        int ctxId = 1;
        Context ctx = new Context(null, ctxId);
        Configuration config = configWithAlertFilters();
        // When
        extension.importContextData(ctx, config);
        // Then
        ContextAlertFilterManager m = extension.getContextAlertFilterManager(ctxId);
        assertThat(m.getAlertFilters(), is(empty()));
    }

    @Test
    void shouldImportContextWithAlertFilters() {
        // Given
        int ctxId = 1;
        Context ctx = new Context(null, ctxId);
        Configuration config = configWithAlertFilters("true;42;1;;;", "false;43;1;;;");
        // When
        extension.importContextData(ctx, config);
        // Then
        ContextAlertFilterManager m = extension.getContextAlertFilterManager(ctxId);
        assertThat(
                m.getAlertFilters(),
                contains(
                        new AlertFilter(ctxId, "42", 1, "", false, "", true),
                        new AlertFilter(ctxId, "43", 1, "", false, "", false)));
    }

    @Test
    void shouldImportContextWithAlertFiltersSkippingMalformed() {
        // Given
        int ctxId = 1;
        Context ctx = new Context(null, ctxId);
        Configuration config = configWithAlertFilters("not alert filter", "false;43;1;;;");
        // When
        extension.importContextData(ctx, config);
        // Then
        ContextAlertFilterManager m = extension.getContextAlertFilterManager(ctxId);
        assertThat(
                m.getAlertFilters(),
                contains(new AlertFilter(ctxId, "43", 1, "", false, "", false)));
    }

    private static final int ALERT_ID = 1;
    private static final int HISTORY_ID = 7;
    private static final int CONTEXT_ID = 1;
    private static final String ALERT_URI = "https://www.example.com/";

    private ExtensionAlert extAlert;
    private TableAlertTag tableAlertTag;

    @AfterEach
    void tearDown() {
        ZAP.getEventBus()
                .unregisterConsumer(
                        extension, AlertEventPublisher.getPublisher().getPublisherName());
    }

    @Test
    void shouldKeepStoredTagsWhenAlertFiltered() throws Exception {
        // Given
        setUpAlertFiltering(true);
        when(tableAlertTag.getTagsByAlertId(ALERT_ID)).thenReturn(Map.of("SYSTEMIC", "true"));

        // When
        extension.eventReceived(alertAddedEvent());

        // Then
        ArgumentCaptor<Alert> alertCaptor = ArgumentCaptor.forClass(Alert.class);
        InOrder inOrder = inOrder(tableAlertTag, extAlert);
        inOrder.verify(tableAlertTag).getTagsByAlertId(ALERT_ID);
        inOrder.verify(extAlert).updateAlert(alertCaptor.capture());
        assertEquals(Alert.CONFIDENCE_FALSE_POSITIVE, alertCaptor.getValue().getConfidence());
        assertEquals(Map.of("SYSTEMIC", "true"), alertCaptor.getValue().getTags());
    }

    @Test
    void shouldNotCallUpdateAlertInTreeWhenAlertFiltered() throws Exception {
        // Given
        setUpAlertFiltering(true);

        // When
        extension.eventReceived(alertAddedEvent());

        // Then
        verify(extAlert).updateAlert(any());
        verify(extAlert, never()).updateAlertInTree(any());
    }

    /**
     * Sets up a model and database (mocked), a passive alert stored in the database and a context
     * with an alert filter changing the alert to a false positive, so that a raised alert can be
     * passed to the extension with {@link #alertAddedEvent()}.
     *
     * @param withHistoryReference whether or not the history reference of the stored alert should
     *     be available.
     */
    private void setUpAlertFiltering(boolean withHistoryReference) throws Exception {
        Model model = mock(Model.class);
        Model.setSingletonForTesting(model);
        Session session = mock(Session.class);
        when(model.getSession()).thenReturn(session);
        Database database = mock(Database.class);
        when(model.getDb()).thenReturn(database);
        TableAlert tableAlert = mock(TableAlert.class);
        when(database.getTableAlert()).thenReturn(tableAlert);
        tableAlertTag = mock(TableAlertTag.class);
        when(database.getTableAlertTag()).thenReturn(tableAlertTag);

        RecordAlert recordAlert = mock(RecordAlert.class);
        when(recordAlert.getAlertId()).thenReturn(ALERT_ID);
        when(recordAlert.getHistoryId()).thenReturn(HISTORY_ID);
        when(recordAlert.getPluginId()).thenReturn(0);
        when(recordAlert.getUri()).thenReturn(ALERT_URI);
        when(recordAlert.getAlert()).thenReturn("Alert A");
        when(recordAlert.getRisk()).thenReturn(Alert.RISK_LOW);
        when(recordAlert.getConfidence()).thenReturn(Alert.CONFIDENCE_MEDIUM);
        when(tableAlert.read(ALERT_ID)).thenReturn(recordAlert);

        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(model, extensionLoader);
        extAlert = mock(ExtensionAlert.class);
        ExtensionHistory extHistory = mock(ExtensionHistory.class);
        when(extensionLoader.getExtension(ExtensionAlert.class)).thenReturn(extAlert);
        when(extensionLoader.getExtension(ExtensionHistory.class)).thenReturn(extHistory);

        if (withHistoryReference) {
            HistoryReference href = mock(HistoryReference.class);
            when(extHistory.getHistoryReference(HISTORY_ID)).thenReturn(href);
            when(href.getSiteNode()).thenReturn(mock(SiteNode.class));
        }

        Context context = mock(Context.class);
        when(context.isInContext(ALERT_URI)).thenReturn(true);
        when(session.getContext(CONTEXT_ID)).thenReturn(context);
        when(session.getContextDataStrings(anyInt(), anyInt())).thenReturn(List.of("true;0;-1;;;"));
        extension.loadContextData(session, new Context(null, CONTEXT_ID));

        extension.init();
        extension.getParam().load(new ZapXmlConfiguration());
        ZAP.getEventBus()
                .unregisterConsumer(
                        extension, AlertEventPublisher.getPublisher().getPublisherName());
    }

    private static Event alertAddedEvent() {
        Event event = mock(Event.class);
        when(event.getParameters()).thenReturn(Map.of(AlertEventPublisher.ALERT_ID, "1"));
        return event;
    }

    private static Session sessionWithAlertFilters(String... filters) {
        Session session = mock(Session.class);
        try {
            when(session.getContextDataStrings(anyInt(), anyInt())).thenReturn(List.of(filters));
        } catch (DatabaseException e) {
            throw new RuntimeException(e);
        }
        return session;
    }

    private static ZapXmlConfiguration configWithAlertFilters(String... filters) {
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        String contents =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
                        + "<configuration>\n"
                        + "  <context>\n"
                        + "    <alertFilters>\n"
                        + Stream.of(filters)
                                .map(e -> "      <filter>" + e + "</filter>")
                                .collect(Collectors.joining("\n"))
                        + "\n    </alertFilters>\n"
                        + "  </context>\n"
                        + "</configuration>";
        try {
            config.load(new ByteArrayInputStream(contents.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return config;
    }
}
