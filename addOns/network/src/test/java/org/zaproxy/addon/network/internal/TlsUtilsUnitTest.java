/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

/* Unit test for {@link TlsUtils}. */
class TlsUtilsUnitTest {

    @Test
    void shouldHaveSupportedProtocols() {
        assertThat(TlsUtils.getSupportedProtocols(), is(not(empty())));
    }

    @Test
    void shoulFilterUnsupportedProtocols() {
        // Given
        List<String> protocols = Arrays.asList("Unknown A", TlsUtils.TLS_V1_2, "Unknown B");
        // When
        List<String> filteredProtocols = TlsUtils.filterUnsupportedProtocols(protocols);
        // Then
        assertThat(filteredProtocols, contains(TlsUtils.TLS_V1_2));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shoulThrowIfNoProtocols(List<String> protocols) {
        assertThrows(
                IllegalArgumentException.class,
                () -> TlsUtils.filterUnsupportedProtocols(protocols));
    }

    @Test
    void shoulThrowIfNoProtocolsAfterFilter() {
        // Given
        List<String> protocols = Arrays.asList("Unknown A");
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> TlsUtils.filterUnsupportedProtocols(protocols));
    }

    @Test
    void shoulThrowIfInvalidConfiguration() {
        // Given
        List<String> protocols = Arrays.asList(TlsUtils.SSL_V2_HELLO);
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> TlsUtils.filterUnsupportedProtocols(protocols));
    }
}
