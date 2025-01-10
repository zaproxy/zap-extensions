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
package org.zaproxy.addon.client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.client.spider.ClientSpider;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.internal.FirefoxProfileManager;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ExtensionClientIntegrationUnitTest extends TestUtils {

    @Test
    void shouldCreateFirefoxPrefFile() throws IOException {
        // Given
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        ExtensionSelenium extSel = mock(ExtensionSelenium.class);
        when(extensionLoader.getExtension(ExtensionSelenium.class)).thenReturn(extSel);
        FirefoxProfileManager fpm = mock(FirefoxProfileManager.class);
        when(extSel.getProfileManager(Browser.FIREFOX)).thenReturn(fpm);
        Path path = Files.createTempDirectory("zap-browser-test");
        when(fpm.getOrCreateProfile(ExtensionClientIntegration.ZAP_FIREFOX_PROFILE_NAME))
                .thenReturn(path);

        ExtensionClientIntegration extClient = new ExtensionClientIntegration();

        // When
        extClient.postInit();
        File prefFile = new File(path.toFile(), "extension-preferences.json");

        // Then
        assertThat(prefFile.exists(), is(true));
    }

    @Test
    void shouldLeaveValidFirefoxPrefIniFile() throws IOException {
        // Given
        List<String> validProfiles =
                List.of(
                        "[Profile0]",
                        "Name=zap-client-profile",
                        "IsRelative=1",
                        "Path=Profiles/abcd1234.zap-client-profile");
        Path iniPath = Files.createTempFile("fx-profiles", ".ini");
        Files.write(iniPath, validProfiles, StandardCharsets.UTF_8, StandardOpenOption.APPEND);
        ExtensionClientIntegration extClient = new ExtensionClientIntegration();

        // When
        extClient.checkFirefoxProfilesFile(iniPath, Path.of("ignored"));
        List<String> updatedProfiles = Files.readAllLines(iniPath, StandardCharsets.UTF_8);

        // Then
        assertEquals(validProfiles, updatedProfiles);
    }

    @Test
    void shouldAddZapProfileToFirefoxPrefIniFile() throws IOException {
        // Given
        List<String> validProfiles =
                List.of(
                        "[Profile2]",
                        "Name=default",
                        "IsRelative=1",
                        "Path=Profiles/efgh5678.default");
        List<String> expectedProfiles = new ArrayList<>();
        expectedProfiles.addAll(validProfiles);
        expectedProfiles.addAll(
                List.of(
                        "",
                        "[Profile3]",
                        "Name=zap-client-profile",
                        "IsRelative=1",
                        "Path=Profiles/abcd1234.zap-client-profile"));

        Path iniPath = Files.createTempFile("fx-profiles", ".ini");
        Files.write(iniPath, validProfiles, StandardCharsets.UTF_8, StandardOpenOption.APPEND);
        ExtensionClientIntegration extClient = new ExtensionClientIntegration();

        // When
        extClient.checkFirefoxProfilesFile(
                iniPath, Path.of("Profiles/abcd1234.zap-client-profile"));
        List<String> updatedProfiles = Files.readAllLines(iniPath, StandardCharsets.UTF_8);

        // Then
        assertEquals(expectedProfiles, updatedProfiles);
    }

    @Test
    void shouldStartSpider() throws IOException {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        Model model = mock(Model.class);
        Session session = mock(Session.class);
        when(model.getSession()).thenReturn(session);
        Control.initSingletonForTesting(model, extensionLoader);
        when(extensionLoader.getExtension(ExtensionHistory.class))
                .thenReturn(mock(ExtensionHistory.class));
        ExtensionSelenium extSel = mock(ExtensionSelenium.class);
        when(extensionLoader.getExtension(ExtensionSelenium.class)).thenReturn(extSel);
        ExtensionCommonlib extCommonLib = mock(ExtensionCommonlib.class);
        when(extensionLoader.getExtension(ExtensionCommonlib.class)).thenReturn(extCommonLib);
        ExtensionClientIntegration extClient = new ExtensionClientIntegration();
        extClient.initModel(model);
        extClient.init();
        ClientOptions options = new ClientOptions();
        options.load(new ZapXmlConfiguration());
        options.setThreadCount(1);

        try {
            // When
            int spiderId =
                    extClient.startScan("https://www.example.com", options, null, null, false);
            ClientSpider spider = extClient.getScan(spiderId);
            boolean isRunning = spider.isRunning();
            spider.stopScan();

            // Then
            assertEquals(true, isRunning);
        } finally {
            extClient.unload();
        }
    }
}
