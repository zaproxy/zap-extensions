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
package org.zaproxy.zap.extension.selenium;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link SeleniumOptions}. */
class SeleniumOptionsUnitTest extends TestUtils {

    private Path seleniumExtensionsDir;
    private SeleniumOptions options;

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();
        seleniumExtensionsDir = Paths.get(Constant.getZapHome(), "selenium", "extensions");

        options = new SeleniumOptions();
    }

    @Test
    void shouldCreateSeleniumExtensionsDirOnLoad() {
        // Given / When
        options.load(new ZapXmlConfiguration());
        // Then
        assertThat(Files.isDirectory(seleniumExtensionsDir), is(equalTo(true)));
    }

    @Test
    void shouldNotFailToSetBrowserExtensionsIfExtensionsDirDoesNotExist() throws Exception {
        // Given
        options.load(new ZapXmlConfiguration());
        Files.deleteIfExists(seleniumExtensionsDir);
        // When / Then
        assertDoesNotThrow(() -> options.setBrowserExtensions(Collections.emptyList()));
    }
}
