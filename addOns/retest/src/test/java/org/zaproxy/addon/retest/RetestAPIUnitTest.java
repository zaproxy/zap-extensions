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
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import net.sf.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.RecordAlert;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.testutils.TestUtils;

class RetestAPIUnitTest extends TestUtils {

    private ExtensionRetest extRetest;
    private ExtensionAutomation extAutomation;

    private RetestAPI retestAPI;
    private JSONObject params;

    @BeforeEach
    void setUp() throws Exception {
        mockMessages(new ExtensionRetest());
        super.setUpZap();
        params = new JSONObject();
        params.put(RetestAPI.ALERT_IDS, "1,2");
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        extRetest = mock(ExtensionRetest.class, withSettings().lenient());
        extAutomation = mock(ExtensionAutomation.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionAutomation.class)).willReturn(extAutomation);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        retestAPI = new RetestAPI(extRetest);

        RecordAlert recordOne =
                new RecordAlert(
                        1,
                        1,
                        100,
                        "Test Alert One",
                        1,
                        1,
                        "Test Description One",
                        "Test Uri One",
                        "Test Param One",
                        "Test Attack One",
                        "Test OtherInfo One",
                        "Test Solution One",
                        "100Test Reference One",
                        "Test Evidence One",
                        1,
                        1,
                        1,
                        1,
                        1,
                        "100Test Alert Reference");
        RecordAlert recordTwo =
                new RecordAlert(
                        2,
                        1,
                        100,
                        "Test Alert One",
                        1,
                        1,
                        "Test Description One",
                        "Test Uri One",
                        "Test Param One",
                        "Test Attack One",
                        "Test OtherInfo One",
                        "Test Solution One",
                        "100Test Reference One",
                        "Test Evidence One",
                        1,
                        1,
                        1,
                        1,
                        1,
                        "100Test Alert Reference");

        TableHistory historyTable = mock(TableHistory.class);
        HistoryReference.setTableHistory(historyTable);
        TableAlert alertTable = mock(TableAlert.class);
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
