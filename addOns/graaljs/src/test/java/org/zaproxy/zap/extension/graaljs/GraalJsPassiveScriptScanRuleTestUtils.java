/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.graaljs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.mockito.Mockito.mock;

import java.util.List;
import java.util.ResourceBundle;
import org.junit.jupiter.api.BeforeEach;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadataProvider;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.scanrules.PassiveScriptScanRule;
import org.zaproxy.zap.testutils.PassiveScannerTestUtils;
import org.zaproxy.zap.testutils.ScriptScanRuleTestUtils;

public abstract class GraalJsPassiveScriptScanRuleTestUtils
        extends PassiveScannerTestUtils<PassiveScriptScanRule> implements ScriptScanRuleTestUtils {

    private final ScriptEngineWrapper scriptEngineWrapper =
            new GraalJsEngineWrapper(
                    GraalJsPassiveScriptScanRuleTestUtils.class.getClassLoader(), List.of(), null);

    @Override
    public ScriptEngineWrapper getScriptEngineWrapper() {
        return scriptEngineWrapper;
    }

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        setUpExtScript();
    }

    @Override
    public void setUpMessages() {
        mockMessages(new ExtensionGraalJs());
    }

    @Override
    public void shouldHaveI18nNonEmptyName(String name, ResourceBundle extensionResourceBundle) {
        assertThat(name, is(not(emptyOrNullString())));
    }

    @Override
    protected PassiveScriptScanRule createScanner() {
        try {
            return new PassiveScriptScanRule(
                    mock(ScriptWrapper.class),
                    getScriptInterface(ScanRuleMetadataProvider.class).getMetadata());
        } catch (Exception e) {
            throw new RuntimeException("Could not create passive scan rule from script", e);
        }
    }
}
