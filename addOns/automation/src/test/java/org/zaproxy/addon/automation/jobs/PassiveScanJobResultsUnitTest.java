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
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class PassiveScanJobResultsUnitTest {

    private static MockedStatic<CommandLine> mockedCmdLine;

    @BeforeAll
    static void init() {
        mockedCmdLine = Mockito.mockStatic(CommandLine.class);
    }

    @AfterAll
    static void close() {
        mockedCmdLine.close();
    }

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);
    }

    @Test
    void shouldReturnJobData() {
        // Given
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        ExtensionStats extStats = mock(ExtensionStats.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionStats.class)).willReturn(extStats);

        InMemoryStats stats = new InMemoryStats();
        given(extStats.getInMemoryStats()).willReturn(stats);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        // When
        stats.counterInc("stats.pscan.test1", 10);
        stats.counterInc("stats.pscan.test2", 20);
        List<PluginPassiveScanner> list = new ArrayList<>();
        list.add(new TestPluginPassiveScanner("test1", 1));
        list.add(new TestPluginPassiveScanner("test2", 2));
        PassiveScanJobResultData data = new PassiveScanJobResultData("test", list);

        // Then
        assertThat(data, is(notNullValue()));
        assertThat(data.getKey(), is(equalTo("passiveScanData")));
        assertThat(data.getAllRuleData().size(), is(equalTo(2)));
        assertThat(data.getRuleData(1), is(notNullValue()));
        assertThat(data.getRuleData(1).getId(), is(equalTo(1)));
        assertThat(data.getRuleData(1).getName(), is(equalTo("test1")));
        assertThat(data.getRuleData(1).getThreshold(), is(equalTo(AlertThreshold.MEDIUM)));
        assertThat(data.getRuleData(1).getTimeTakenMs(), is(equalTo(10L)));
        assertThat(data.getRuleData(2), is(notNullValue()));
        assertThat(data.getRuleData(2).getId(), is(equalTo(2)));
        assertThat(data.getRuleData(2).getName(), is(equalTo("test2")));
        assertThat(data.getRuleData(2).getThreshold(), is(equalTo(AlertThreshold.MEDIUM)));
        assertThat(data.getRuleData(2).getTimeTakenMs(), is(equalTo(20L)));
    }

    private class TestPluginPassiveScanner extends PluginPassiveScanner {

        private String name;
        private int pluginId;

        public TestPluginPassiveScanner(String name, int pluginId) {
            this.name = name;
            this.pluginId = pluginId;
        }

        @Override
        public void setParent(PassiveScanThread parent) {}

        @Override
        public String getName() {
            return name;
        }

        @Override
        public int getPluginId() {
            return pluginId;
        }
    }
}
