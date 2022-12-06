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
package org.zaproxy.addon.retest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import net.sf.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.api.ApiException;

class RetestAPIUnitTest {

    private ExtensionRetest extRetest;

    private RetestAPI retestAPI;
    private JSONObject params;

    @BeforeEach
    void setUp() throws Exception {
        params = new JSONObject();
        extRetest = mock(ExtensionRetest.class);
        retestAPI = new RetestAPI(extRetest);
    }

    @Test
    void shouldThrowBadActionIfActionUnknown() {
        // Given
        String actionName = "_NotKnownAction_";
        // When / Then
        ApiException exception =
                assertThrows(
                        ApiException.class, () -> retestAPI.handleApiAction(actionName, params));
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_ACTION)));
    }
}
