/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.cert;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/** Unit test for {@link CertConfig}. */
class CertConfigUnitTest {

    @Test
    void shouldCreateConfigWithValidity() {
        // Given
        Duration validity = Duration.ofDays(1);
        // When
        CertConfig config = new CertConfig(validity);
        // Then
        assertThat(config.getValidity(), is(equalTo(validity)));
    }

    @Test
    void shouldThrowExceptionWhenCreatingConfigWithNullValidity() {
        // Given
        Duration validity = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> new CertConfig(validity));
    }
}
