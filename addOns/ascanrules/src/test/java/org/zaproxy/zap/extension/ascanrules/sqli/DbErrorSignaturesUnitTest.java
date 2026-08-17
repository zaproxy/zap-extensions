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
package org.zaproxy.zap.extension.ascanrules.sqli;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.ascanrules.sqli.DbErrorSignatures.Dbms;

/** Pure-logic unit test for {@link DbErrorSignatures} -- no HTTP server needed. */
class DbErrorSignaturesUnitTest {

    @Test
    void shouldIdentifyMySqlFromRealErrorText() {
        // Given
        String body = "<html>Warning: You have an error in your SQL syntax; check the manual";
        // When
        Optional<Dbms> result = DbErrorSignatures.identify(body);
        // Then
        assertThat(result.isPresent(), is(true));
        assertThat(result.get(), is(equalTo(Dbms.MYSQL)));
    }

    @Test
    void shouldIdentifyOracleFromRealErrorText() {
        // Given
        String body = "ORA-00933: SQL command not properly ended";
        // When
        Optional<Dbms> result = DbErrorSignatures.identify(body);
        // Then
        assertThat(result.isPresent(), is(true));
        assertThat(result.get(), is(equalTo(Dbms.ORACLE)));
    }

    @Test
    void shouldFallBackToGenericSignature() {
        // Given
        String body = "500 Internal Server Error: java.sql.SQLException: something broke";
        // When
        Optional<Dbms> result = DbErrorSignatures.identify(body);
        // Then
        assertThat(result.isPresent(), is(true));
        assertThat(result.get(), is(equalTo(Dbms.GENERIC)));
    }

    @Test
    void shouldNotMatchOrdinaryPageContent() {
        // Given
        String body = "<html><body>Welcome back, valued customer!</body></html>";
        // When
        Optional<Dbms> result = DbErrorSignatures.identify(body);
        // Then
        assertThat(result.isPresent(), is(false));
    }

    @Test
    void shouldNotMatchNullOrEmptyBody() {
        assertThat(DbErrorSignatures.identify(null).isPresent(), is(false));
        assertThat(DbErrorSignatures.identify("").isPresent(), is(false));
    }

    @Test
    void shouldBeCaseInsensitive() {
        // Given
        String body = "you HAVE AN error in your sql SYNTAX";
        // When
        Optional<Dbms> result = DbErrorSignatures.identify(body);
        // Then
        assertThat(result.isPresent(), is(true));
        assertThat(result.get(), is(equalTo(Dbms.MYSQL)));
    }
}
