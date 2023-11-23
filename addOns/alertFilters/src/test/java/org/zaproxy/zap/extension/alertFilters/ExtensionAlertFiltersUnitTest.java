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
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.BDDMockito.when;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.commons.configuration.Configuration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link ExtensionAlertFilters}. */
class ExtensionAlertFiltersUnitTest {

    private ExtensionAlertFilters extension;

    @BeforeEach
    void setUp() {
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
