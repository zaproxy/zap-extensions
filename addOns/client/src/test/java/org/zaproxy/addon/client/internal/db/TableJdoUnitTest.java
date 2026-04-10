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
package org.zaproxy.addon.client.internal.db;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;

import javax.jdo.JDOHelper;
import javax.jdo.PersistenceManagerFactory;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.configuration.FluentConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.DatabaseServer;

/** Unit tests for {@link TableJdo}. */
class TableJdoUnitTest {

    @AfterEach
    void cleanUp() throws Exception {
        createTableJdo().closing(null);
    }

    @Test
    void shouldReturnNullPmfWhenNotInitialised() {
        assertThat(TableJdo.getPmf(), is(nullValue()));
    }

    @Test
    void shouldSetPmfOnDatabaseOpen() throws Exception {
        // Given
        try (MockedStatic<Flyway> flywayStatic = mockStatic(Flyway.class);
                MockedStatic<JDOHelper> jdoStatic = mockStatic(JDOHelper.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            setupStaticMocks(flywayStatic, jdoStatic, pmf);

            // When
            createTableJdo();

            // Then
            assertThat(TableJdo.getPmf(), is(equalTo(pmf)));
        }
    }

    @Test
    void shouldRegisterAsDatabaseListener() throws Exception {
        // Given
        try (MockedStatic<Flyway> flywayStatic = mockStatic(Flyway.class);
                MockedStatic<JDOHelper> jdoStatic = mockStatic(JDOHelper.class)) {
            setupStaticMocks(flywayStatic, jdoStatic);

            Database db = mock(Database.class);
            DatabaseServer dbServer = mockDatabaseServer();
            given(db.getDatabaseServer()).willReturn(dbServer);

            // When
            TableJdo tableJdo = new TableJdo(db);

            // Then
            verify(db).addDatabaseListener(tableJdo);
        }
    }

    @Test
    void shouldClosePmfOnClosing() throws Exception {
        // Given
        try (MockedStatic<Flyway> flywayStatic = mockStatic(Flyway.class);
                MockedStatic<JDOHelper> jdoStatic = mockStatic(JDOHelper.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            setupStaticMocks(flywayStatic, jdoStatic, pmf);
            TableJdo tableJdo = createTableJdo();

            // When
            tableJdo.closing(mock(DatabaseServer.class));

            // Then
            verify(pmf).close();
            assertThat(TableJdo.getPmf(), is(nullValue()));
        }
    }

    @Test
    void shouldNotThrowWhenClosingWithNullPmf() throws Exception {
        // Given
        try (MockedStatic<Flyway> flywayStatic = mockStatic(Flyway.class);
                MockedStatic<JDOHelper> jdoStatic = mockStatic(JDOHelper.class)) {
            setupStaticMocks(flywayStatic, jdoStatic);
            TableJdo tableJdo = createTableJdo();
            tableJdo.closing(mock(DatabaseServer.class));

            // When / Then
            assertDoesNotThrow(() -> tableJdo.closing(mock(DatabaseServer.class)));
            assertThat(TableJdo.getPmf(), is(nullValue()));
        }
    }

    @Test
    void shouldRemoveDatabaseListenerOnUnload() throws Exception {
        // Given
        try (MockedStatic<Flyway> flywayStatic = mockStatic(Flyway.class);
                MockedStatic<JDOHelper> jdoStatic = mockStatic(JDOHelper.class)) {
            setupStaticMocks(flywayStatic, jdoStatic);

            Database db = mock(Database.class);
            DatabaseServer dbServer = mockDatabaseServer();
            given(db.getDatabaseServer()).willReturn(dbServer);
            TableJdo tableJdo = new TableJdo(db);

            // When
            tableJdo.unload();

            // Then
            verify(db).removeDatabaseListener(tableJdo);
        }
    }

    @Test
    void shouldCreatePmfWithClientPersistenceUnit() throws Exception {
        // Given
        try (MockedStatic<Flyway> flywayStatic = mockStatic(Flyway.class);
                MockedStatic<JDOHelper> jdoStatic = mockStatic(JDOHelper.class)) {
            setupStaticMocks(flywayStatic, jdoStatic);

            // When
            createTableJdo();

            // Then
            jdoStatic.verify(
                    () ->
                            JDOHelper.getPersistenceManagerFactory(
                                    any(), eq("client"), any(ClassLoader.class)));
        }
    }

    private static TableJdo createTableJdo() throws Exception {
        Database db = mock(Database.class);
        DatabaseServer dbServer = mockDatabaseServer();
        given(db.getDatabaseServer()).willReturn(dbServer);
        return new TableJdo(db);
    }

    private static DatabaseServer mockDatabaseServer() {
        DatabaseServer dbServer = mock(DatabaseServer.class);
        given(dbServer.getUrl()).willReturn("jdbc:hsqldb:mem:test");
        given(dbServer.getUser()).willReturn("sa");
        given(dbServer.getPassword()).willReturn("");
        return dbServer;
    }

    private static void setupStaticMocks(
            MockedStatic<Flyway> flywayStatic, MockedStatic<JDOHelper> jdoStatic) {
        setupStaticMocks(flywayStatic, jdoStatic, mock(PersistenceManagerFactory.class));
    }

    private static void setupStaticMocks(
            MockedStatic<Flyway> flywayStatic,
            MockedStatic<JDOHelper> jdoStatic,
            PersistenceManagerFactory pmf) {
        FluentConfiguration config = mock(FluentConfiguration.class, RETURNS_DEEP_STUBS);
        flywayStatic.when(() -> Flyway.configure(any(ClassLoader.class))).thenReturn(config);
        jdoStatic
                .when(
                        () ->
                                JDOHelper.getPersistenceManagerFactory(
                                        any(), anyString(), any(ClassLoader.class)))
                .thenReturn(pmf);
    }
}
