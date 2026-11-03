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
package org.zaproxy.addon.oast.services.callback;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JComboBox;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.OptionsParam;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class CallbackOptionsPanelTabUnitTest extends TestUtils {

    private CallbackParam param;
    private OptionsParam options;
    private CallbackOptionsPanelTab panel;

    @BeforeAll
    static void setUpAll() {
        mockMessages(new ExtensionOast());
    }

    @BeforeEach
    void setUp() {
        param = new CallbackParam();
        param.load(new ZapXmlConfiguration());

        options = mock(OptionsParam.class);
        given(options.getParamSet(CallbackParam.class)).willReturn(param);

        CallbackService callbackService = mock(CallbackService.class);
        given(callbackService.getName()).willReturn("Callback");
        given(callbackService.getCallbackAddress()).willReturn("http://localhost:1234/");
        given(callbackService.getAddress("", 0, false)).willReturn("http://localhost:0/");

        panel = new CallbackOptionsPanelTab(callbackService);
        panel.initParam(options);
    }

    @Test
    void shouldPreserveAddressesWhenSavingWithoutSelections() {
        String localAddress = param.getLocalAddress();
        String remoteAddress = param.getRemoteAddress();
        List<JComboBox<?>> addressFields = new ArrayList<>();
        for (Component component : panel.getComponents()) {
            if (component instanceof JComboBox<?> comboBox) {
                addressFields.add(comboBox);
            }
        }
        assertThat(addressFields, hasSize(2));
        addressFields.forEach(field -> field.setSelectedItem(null));

        assertDoesNotThrow(() -> panel.saveParam(options));

        assertThat(param.getLocalAddress(), is(localAddress));
        assertThat(param.getRemoteAddress(), is(remoteAddress));
    }
}
