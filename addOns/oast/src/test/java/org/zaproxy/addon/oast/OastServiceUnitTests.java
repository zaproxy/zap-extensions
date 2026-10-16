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
package org.zaproxy.addon.oast;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class OastServiceUnitTests {

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void shouldPreservePayloadsForServicesWithoutHttpsSpecificFormat(boolean secure)
            throws Exception {
        // Given
        OastService service = mock(OastService.class, CALLS_REAL_METHODS);
        OastPayload payload = new OastPayload("callback.example.test/path", "canary");
        when(service.getNewPayload()).thenReturn(payload.getPayload());
        when(service.getNewOastPayload()).thenReturn(payload);
        // When / Then
        assertThat(service.getNewPayload(secure), is(payload.getPayload()));
        assertThat(service.getNewOastPayload(secure), is(sameInstance(payload)));
    }
}
