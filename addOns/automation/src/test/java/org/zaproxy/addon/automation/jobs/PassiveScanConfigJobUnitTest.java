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
package org.zaproxy.addon.automation.jobs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class PassiveScanConfigJobUnitTest {

    private static MockedStatic<CommandLine> mockedCmdLine;

    @BeforeAll
    public static void init() {
        mockedCmdLine = Mockito.mockStatic(CommandLine.class);
    }

    @AfterAll
    public static void close() {
        mockedCmdLine.close();
    }

    @BeforeEach
    public void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);
    }

    @Test
    public void shouldReturnDefaultFields() {
        // Given
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        ExtensionPassiveScan extPscan = mock(ExtensionPassiveScan.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionPassiveScan.class)).willReturn(extPscan);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        // When
        PassiveScanConfigJob job = new PassiveScanConfigJob();

        // Then
        assertThat(job.getType(), is(equalTo("passiveScan-config")));
        assertThat(job.getName(), is(equalTo("passiveScan-config")));
        assertThat(job.getOrder(), is(equalTo(Order.CONFIGS)));
        assertThat(job.getParamMethodObject(), is(extPscan));
        assertThat(job.getParamMethodName(), is("getPassiveScanParam"));
    }

    @Test
    public void shouldReturnNoCustomConfigParams() {
        // Given
        PassiveScanConfigJob job = new PassiveScanConfigJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(0)));
    }
}
