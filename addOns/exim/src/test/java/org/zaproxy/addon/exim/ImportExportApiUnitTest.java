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
package org.zaproxy.addon.exim;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import net.sf.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ImportExportApi}. */
class ImportExportApiUnitTest extends TestUtils {

    private ImportExportApi api;

    @BeforeEach
    void prepare() {
        mockMessages(new ExtensionExim());
        api = new ImportExportApi();
    }

    @Test
    void shouldThrowApiExceptionIfMaxMessagesNegative() {
        // Given
        JSONObject params = new JSONObject();
        params.put("data", "{}");
        params.put("maxMessages", "-1");
        // When / Then
        ApiException exception =
                assertThrows(ApiException.class, () -> api.handleApiAction("importHar", params));
        assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
        assertThat(exception.toString(), containsString("(illegal_parameter): maxMessages"));
    }
}
