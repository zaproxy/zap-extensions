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
package org.zaproxy.zap.extension.websocket.pscan.scripts;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.UndeclaredThrowableException;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata;
import org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadataProvider;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;

class WebSocketScriptMetadataUtilsUnitTest {

    @Test
    void shouldReturnNullWhenScriptHasNoInterface() throws Exception {
        // Given
        ExtensionScript extScript = mock(ExtensionScript.class);
        ScriptWrapper script = mock(ScriptWrapper.class);
        when(extScript.getInterface(script, ScanRuleMetadataProvider.class)).thenReturn(null);

        // When / Then
        assertThat(WebSocketScriptMetadataUtils.getMetadata(extScript, script), is(nullValue()));
        assertThat(WebSocketScriptMetadataUtils.providesMetadata(extScript, script), is(false));
    }

    @Test
    void shouldReturnMetadataWhenScriptImplementsIt() throws Exception {
        // Given
        var metadata = new ScanRuleMetadata(12345, "Test Scan Rule");
        ExtensionScript extScript = mock(ExtensionScript.class);
        ScriptWrapper script = mock(ScriptWrapper.class);
        ScanRuleMetadataProvider provider = () -> metadata;
        when(extScript.getInterface(script, ScanRuleMetadataProvider.class)).thenReturn(provider);

        // When / Then
        assertThat(WebSocketScriptMetadataUtils.getMetadata(extScript, script), is(metadata));
        assertThat(WebSocketScriptMetadataUtils.providesMetadata(extScript, script), is(true));
    }

    @Test
    void shouldTreatUndeclaredMethodProxyAsNoMetadata() throws Exception {
        // Given — some script engines (Python, Kotlin) return a proxy for any declared interface,
        // even one the script doesn't actually implement, and throw this when the method is called
        ExtensionScript extScript = mock(ExtensionScript.class);
        ScriptWrapper script = mock(ScriptWrapper.class);
        ScanRuleMetadataProvider provider =
                () -> {
                    throw new UndeclaredThrowableException(null, "getMetadata");
                };
        when(extScript.getInterface(script, ScanRuleMetadataProvider.class)).thenReturn(provider);

        // When / Then — so the script must still be treated as having no metadata, not skipped
        // from the legacy bundling scanner
        assertThat(WebSocketScriptMetadataUtils.getMetadata(extScript, script), is(nullValue()));
        assertThat(WebSocketScriptMetadataUtils.providesMetadata(extScript, script), is(false));
    }

    @Test
    void providesMetadataShouldTreatGenuineErrorsAsNoMetadata() throws Exception {
        // Given — a real bug in the script's getMetadata(); providesMetadata() is only used to
        // decide whether to skip the legacy scanner, so it must not propagate the exception here —
        // it will surface again, and be handled, when the script actually runs
        ExtensionScript extScript = mock(ExtensionScript.class);
        ScriptWrapper script = mock(ScriptWrapper.class);
        ScanRuleMetadataProvider provider =
                () -> {
                    throw new RuntimeException("boom");
                };
        when(extScript.getInterface(script, ScanRuleMetadataProvider.class)).thenReturn(provider);

        // When / Then
        assertThat(WebSocketScriptMetadataUtils.providesMetadata(extScript, script), is(false));
    }
}
