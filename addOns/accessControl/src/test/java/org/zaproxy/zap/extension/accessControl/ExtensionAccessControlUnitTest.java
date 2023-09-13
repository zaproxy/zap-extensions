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
package org.zaproxy.zap.extension.accessControl;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link ExtensionAccessControl}. */
class ExtensionAccessControlUnitTest {

    private ExtensionAccessControl extension;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        extension = new ExtensionAccessControl();
    }

    @AfterEach
    void cleanUp() {
        Constant.messages = null;
    }

    @Test
    void shouldHaveExampleAlerts() {
        // Given / When
        List<Alert> exampleAlerts = extension.getExampleAlerts();
        // Then
        assertThat(exampleAlerts, is(not(empty())));
    }
}
