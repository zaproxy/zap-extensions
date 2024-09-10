/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.oast.services.boast.BoastService;
import org.zaproxy.addon.oast.services.callback.CallbackService;
import org.zaproxy.addon.oast.services.interactsh.InteractshService;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ExtensionOastUnitTests extends TestUtils {

    private ExtensionOast ext;

    @Mock(strictness = org.mockito.Mock.Strictness.LENIENT)
    Model model;

    @Mock(strictness = org.mockito.Mock.Strictness.LENIENT)
    Session session;

    @Mock(strictness = org.mockito.Mock.Strictness.LENIENT)
    ExtensionNetwork extNetwork;

    @BeforeEach
    void setUp() throws Exception {
        given(model.getSession()).willReturn(session);
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionNetwork.class)).willReturn(extNetwork);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        ext = new ExtensionOast();
        ext.init();
        ext.hook(mock(ExtensionHook.class));
        ext.getParams().load(new ZapXmlConfiguration());
    }

    @Test
    void shouldGetActiveService() throws Exception {
        // Given / When
        OastService service = ext.getActiveScanOastService();

        // Then
        assertThat(service, is(nullValue()));
    }

    @Test
    void shouldSetActiveService() throws Exception {
        // Given / When
        ext.setActiveScanOastService("BOAST");
        OastService service = ext.getActiveScanOastService();

        // Then
        assertThat(service, is(notNullValue()));
    }

    @Test
    void shouldRejectInvalidActiveService() throws Exception {
        // Given / When
        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> {
                            ext.setActiveScanOastService("BAD");
                        });

        // Then
        assertThat(exception.getMessage(), is("No service with the given name exists: BAD"));
    }

    @Test
    void shouldGetServices() throws Exception {
        // Given / When
        Map<String, OastService> service = ext.getOastServices();

        // Then
        assertThat(service.size(), is(3));
        assertThat(service.containsKey("BOAST"), is(true));
        assertThat(service.containsKey("Interactsh"), is(true));
        assertThat(service.containsKey("Callback"), is(true));
    }

    @Test
    void shouldGetBoastService() throws Exception {
        // Given / When
        BoastService service = ext.getBoastService();

        // Then
        assertThat(service, is(notNullValue()));
        assertThat(service.getName(), is("BOAST"));
    }

    @Test
    void shouldGetCallbackService() throws Exception {
        // Given / When
        CallbackService service = ext.getCallbackService();

        // Then
        assertThat(service, is(notNullValue()));
        assertThat(service.getName(), is("Callback"));
    }

    @Test
    void shouldGetInteractshService() throws Exception {
        // Given / When
        InteractshService service = ext.getInteractshService();

        // Then
        assertThat(service, is(notNullValue()));
        assertThat(service.getName(), is("Interactsh"));
    }
}
