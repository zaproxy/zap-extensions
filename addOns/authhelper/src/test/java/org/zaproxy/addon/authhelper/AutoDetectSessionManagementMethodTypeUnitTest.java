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
package org.zaproxy.addon.authhelper;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.authhelper.AutoDetectSessionManagementMethodType.AutoDetectSessionManagementMethod;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.testutils.TestUtils;

class AutoDetectSessionManagementMethodTypeUnitTest extends TestUtils {

    @Test
    void shouldPersistAndLoadFromSession() throws Exception {
        // Given
        AutoDetectSessionManagementMethod method1 = new AutoDetectSessionManagementMethod();
        SessionManagementMethod method2 = new AutoDetectSessionManagementMethod();
        Session session = mock(Session.class);

        method1.getType().persistMethodToSession(session, 1, method1);

        // When
        method2 = method2.getType().loadMethodFromSession(session, 1);

        // Then
        assertThat(method2.getClass(), is(equalTo(AutoDetectSessionManagementMethod.class)));
    }
}
