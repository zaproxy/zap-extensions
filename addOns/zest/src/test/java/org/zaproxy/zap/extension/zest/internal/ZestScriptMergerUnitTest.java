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
package org.zaproxy.zap.extension.zest.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestClientWindowClose;
import org.zaproxy.zest.core.v1.ZestClientWindowHandle;
import org.zaproxy.zest.core.v1.ZestComment;
import org.zaproxy.zest.core.v1.ZestJSON;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;

/** Unit test for {@link ZestScriptMerger}. */
class ZestScriptMergerUnitTest extends TestUtils {

    @BeforeAll
    static void setupAll() {
        mockMessages(new ExtensionZest());
    }

    @BeforeEach
    void setup() {
        ExtensionZest extensionZest =
                mock(ExtensionZest.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionZest.convertStringToElement(anyString()))
                .willAnswer(invocation -> ZestJSON.fromString(invocation.getArgument(0)));
        given(extensionZest.convertElementToString(any()))
                .willAnswer(invocation -> ZestJSON.toString(invocation.getArgument(0)));

        var extLoader = mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(mock(Model.class), extLoader);
        given(extLoader.getExtension(ExtensionZest.class)).willReturn(extensionZest);
        given(extLoader.getExtension(ExtensionZest.NAME)).willReturn(extensionZest);
    }

    static Stream<List<ZestScriptWrapper>> invalidScriptLists() {
        return Stream.of(null, List.of());
    }

    @ParameterizedTest
    @MethodSource("invalidScriptLists")
    void shouldRejectInvalidScriptList(List<ZestScriptWrapper> scripts) {
        // When / Then
        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> ZestScriptMerger.mergeScripts(scripts, "chain", ZestJSON::toString));

        assertThat(exception.getMessage(), containsString("must not be null or empty"));
    }

    @Test
    void shouldThrowWhenScriptSerializerIsNull() {
        // Given
        ZestScriptWrapper script1 = createMockZestWrapperWithClientLaunch("script1", 2, 1);

        // When / Then
        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> ZestScriptMerger.mergeScripts(List.of(script1), "chain", null));

        assertThat(exception.getMessage(), containsString("Script serializer must not be null"));
    }

    @Test
    void shouldBuildChainFromTwoScripts() {
        // Given (first script must have launch when chain has 2+ scripts)
        ZestScriptWrapper script1 = createMockZestWrapperWithClientLaunch("script1", 2, 1);
        ZestScriptWrapper script2 = createMockZestWrapper("script2", 3);

        // When
        ZestScriptWrapper merged =
                ZestScriptMerger.mergeScripts(
                        List.of(script1, script2), "chain", ZestJSON::toString);

        // Then
        assertThat(merged, is(notNullValue()));
        assertThat(merged.getName(), is(equalTo("chain")));
        assertThat(merged.getZestFailureContext(), is(equalTo("")));

        ZestScript mergedScript = merged.getZestScript();
        assertThat(mergedScript.getTitle(), is(equalTo("chain")));
        assertThat(mergedScript.getDescription(), is(equalTo("")));
    }

    @Test
    void shouldBuildChainFromThreeScripts() {
        // Given (first script must have launch when chain has 2+ scripts)
        ZestScriptWrapper script1 = createMockZestWrapperWithClientLaunch("script1", 2, 1);
        ZestScriptWrapper script2 = createMockZestWrapper("script2", 3);
        ZestScriptWrapper script3 = createMockZestWrapper("script3", 1);

        // When
        ZestScriptWrapper merged =
                ZestScriptMerger.mergeScripts(
                        List.of(script1, script2, script3), "chain_triple", ZestJSON::toString);

        // Then
        assertThat(merged, is(notNullValue()));
        assertThat(merged.getName(), is(equalTo("chain_triple")));

        ZestScript mergedScript = merged.getZestScript();
        assertThat(mergedScript.getDescription(), is(equalTo("")));
    }

    @Test
    void shouldHandleSingleScript() {
        // Given
        ZestScriptWrapper script1 = createMockZestWrapperWithClientLaunch("script1", 5, 1);

        // When
        ZestScriptWrapper merged =
                ZestScriptMerger.mergeScripts(List.of(script1), "single", ZestJSON::toString);

        // Then
        assertThat(merged, is(notNullValue()));
        assertThat(merged.getName(), is(equalTo("single")));

        ZestScript mergedScript = merged.getZestScript();
        assertThat(mergedScript.getDescription(), is(equalTo("")));
    }

    @Test
    void shouldHandleScriptWithNoStatements() {
        // Given (first script must have launch; "empty" has only a launch statement)
        ZestScriptWrapper script1 = createMockZestWrapperWithClientLaunch("empty", 1, 1);
        ZestScriptWrapper script2 = createMockZestWrapper("script2", 2);

        // When
        ZestScriptWrapper merged =
                ZestScriptMerger.mergeScripts(
                        List.of(script1, script2), "chain", ZestJSON::toString);

        // Then
        assertThat(merged, is(notNullValue()));
    }

    @Test
    void shouldAttachChainProvenance() {
        // Given
        ZestScriptWrapper script1 = createMockZestWrapperWithClientLaunch("script1", 2, 1);
        ZestScriptWrapper script2 = createMockZestWrapperWithClientLaunch("script2", 3, 1);

        // When
        ZestScriptWrapper merged =
                ZestScriptMerger.mergeScripts(
                        List.of(script1, script2), "chain", ZestJSON::toString);

        // Then (describe maps source members; synthetic close uses "-" placeholder label)
        assertThat(merged.getChainProvenance().isPresent(), is(equalTo(true)));
        var prov = merged.getChainProvenance().orElseThrow();
        ZestScript mergedZest = merged.getZestScript();
        assertThat(
                prov.describe(mergedZest.getStatements().get(0).getIndex()),
                containsString("script1"));
        assertThat(
                prov.describe(mergedZest.getStatements().get(2).getIndex()),
                containsString("script2"));
        ZestStatement lastStmt =
                mergedZest.getStatements().get(mergedZest.getStatements().size() - 1);
        assertThat(lastStmt, is(instanceOf(ZestClientWindowClose.class)));
        assertThat(prov.describe(lastStmt.getIndex()), containsString("source script \"-\""));
    }

    @Test
    void shouldMapDisabledClientLaunchInProvenance() {
        // Given
        ZestScriptWrapper script1 = createMockZestWrapperWithClientLaunch("script1", 2, 1);
        ZestScriptWrapper script2 = createMockZestWrapperWithClientLaunch("script2", 3, 1);

        // When
        ZestScriptWrapper merged =
                ZestScriptMerger.mergeScripts(
                        List.of(script1, script2), "chain", ZestJSON::toString);

        // Then
        var prov = merged.getChainProvenance().orElseThrow();
        boolean found = false;
        for (ZestStatement st : merged.getZestScript().getStatements()) {
            if (st instanceof ZestClientLaunch zcl && !zcl.isEnabled()) {
                assertThat(prov.describe(st.getIndex()), containsString("script2"));
                found = true;
                break;
            }
        }
        assertThat(found, is(equalTo(true)));
    }

    @Test
    void shouldUseOriginalZestIndexInProvenance() {
        // Given: source statement indexes are non-sequential / not list-position based.
        ZestScript script1 = new ZestScript();
        script1.setTitle("script1");
        script1.setType(ZestScript.Type.StandAlone);
        ZestClientLaunch launch = new ZestClientLaunch("browser", "firefox", "http://example.com");
        ZestComment firstComment = new ZestComment("source-idx-42");
        script1.add(launch);
        script1.add(firstComment);
        String script1Json =
                ZestJSON.toString(script1)
                        .replaceFirst("\"index\"\\s*:\\s*1", "\"index\": 10")
                        .replaceFirst("\"index\"\\s*:\\s*2", "\"index\": 42");
        ScriptWrapper script1Sw = new ScriptWrapper();
        script1Sw.setName("script1");
        script1Sw.setContents(script1Json);
        ScriptType scriptType =
                mock(ScriptType.class, withSettings().strictness(Strictness.LENIENT));
        given(scriptType.getName()).willReturn(ExtensionScript.TYPE_STANDALONE);
        script1Sw.setType(scriptType);
        ZestScriptWrapper wrapper1 = new ZestScriptWrapper(script1Sw);

        ZestScript script2 = new ZestScript();
        script2.setTitle("script2");
        script2.setType(ZestScript.Type.StandAlone);
        ZestComment secondComment = new ZestComment("source-idx-77");
        script2.add(secondComment);
        String script2Json =
                ZestJSON.toString(script2).replaceFirst("\"index\"\\s*:\\s*1", "\"index\": 77");
        ScriptWrapper script2Sw = new ScriptWrapper();
        script2Sw.setName("script2");
        script2Sw.setContents(script2Json);
        script2Sw.setType(scriptType);
        ZestScriptWrapper wrapper2 = new ZestScriptWrapper(script2Sw);

        // When
        ZestScriptWrapper merged =
                ZestScriptMerger.mergeScripts(
                        List.of(wrapper1, wrapper2), "chain", ZestJSON::toString);

        // Then (non-sequential Zest indices still resolve to the correct source script in describe)
        var prov = merged.getChainProvenance().orElseThrow();
        boolean found42 = false;
        boolean found77 = false;
        for (ZestStatement st : merged.getZestScript().getStatements()) {
            if (st instanceof ZestComment c) {
                String line = prov.describe(st.getIndex());
                if ("source-idx-42".equals(c.getComment())) {
                    assertThat(line, containsString("script1"));
                    assertThat(line, containsString("zest index 42"));
                    found42 = true;
                } else if ("source-idx-77".equals(c.getComment())) {
                    assertThat(line, containsString("script2"));
                    assertThat(line, containsString("zest index 77"));
                    found77 = true;
                }
            }
        }
        assertThat(found42, is(equalTo(true)));
        assertThat(found77, is(equalTo(true)));
    }

    @Test
    void shouldMarkSyntheticWindowCloseInProvenance() {
        // Given
        ZestScriptWrapper script1 = createMockZestWrapperWithClientLaunch("script1", 2, 1);
        ZestScriptWrapper script2 = createMockZestWrapper("script2", 1);

        // When
        ZestScriptWrapper merged =
                ZestScriptMerger.mergeScripts(
                        List.of(script1, script2), "chain", ZestJSON::toString);

        // Then
        var prov = merged.getChainProvenance().orElseThrow();
        boolean foundClose = false;
        for (ZestStatement st : merged.getZestScript().getStatements()) {
            if (st instanceof ZestClientWindowClose) {
                assertThat(prov.describe(st.getIndex()), containsString("ZestClientWindowClose"));
                assertThat(prov.describe(st.getIndex()), containsString("source script \"-\""));
                assertThat(prov.describe(st.getIndex()), containsString("zest index -"));
                foundClose = true;
            }
        }
        assertThat(foundClose, is(equalTo(true)));
    }

    @Test
    void shouldDisableClientLaunchInSecondScript() {
        // Given
        ZestScriptWrapper script1 = createMockZestWrapperWithClientLaunch("script1", 3, 1);
        ZestScriptWrapper script2 = createMockZestWrapperWithClientLaunch("script2", 3, 1);

        // When
        ZestScriptWrapper merged =
                ZestScriptMerger.mergeScripts(
                        List.of(script1, script2), "chain", ZestJSON::toString);

        // Then
        ZestScript mergedScript = merged.getZestScript();
        List<ZestStatement> statements = mergedScript.getStatements();
        int enabledLaunchCount = 0;
        int disabledLaunchCount = 0;
        for (ZestStatement stmt : statements) {
            if (stmt instanceof ZestClientLaunch) {
                if (stmt.isEnabled()) {
                    enabledLaunchCount++;
                } else {
                    disabledLaunchCount++;
                }
            }
        }

        // First script's launch should be enabled, second should be disabled
        assertThat(enabledLaunchCount, is(equalTo(1)));
        assertThat(disabledLaunchCount, is(equalTo(1)));
    }

    @Test
    void shouldDisableClientLaunchInThirdScript() {
        // Given
        ZestScriptWrapper script1 = createMockZestWrapperWithClientLaunch("script1", 2, 1);
        ZestScriptWrapper script2 = createMockZestWrapperWithClientLaunch("script2", 2, 1);
        ZestScriptWrapper script3 = createMockZestWrapperWithClientLaunch("script3", 2, 1);

        // When
        ZestScriptWrapper merged =
                ZestScriptMerger.mergeScripts(
                        List.of(script1, script2, script3), "chain", ZestJSON::toString);

        // Then
        ZestScript mergedScript = merged.getZestScript();
        List<ZestStatement> statements = mergedScript.getStatements();
        int enabledLaunchCount = 0;
        int disabledLaunchCount = 0;
        for (ZestStatement stmt : statements) {
            if (stmt instanceof ZestClientLaunch) {
                if (stmt.isEnabled()) {
                    enabledLaunchCount++;
                } else {
                    disabledLaunchCount++;
                }
            }
        }

        // Only first script's launch should be enabled
        assertThat(enabledLaunchCount, is(equalTo(1)));
        assertThat(disabledLaunchCount, is(equalTo(2)));
    }

    @Test
    void shouldPreserveFirstScriptMetadata() {
        // Given (first script must have launch when chain has 2+ scripts)
        ZestScriptWrapper script1 = createMockZestWrapperWithClientLaunch("first_script", 2, 1);
        ZestScriptWrapper script2 = createMockZestWrapper("second_script", 3);
        script1.getZestScript().setType("StandAlone");

        // When
        ZestScriptWrapper merged =
                ZestScriptMerger.mergeScripts(
                        List.of(script1, script2), "chain", ZestJSON::toString);

        // Then
        ZestScript mergedScript = merged.getZestScript();
        assertThat(mergedScript.getType(), is(equalTo("StandAlone")));
        assertThat(merged.getType().getName(), is(equalTo(ExtensionScript.TYPE_STANDALONE)));
    }

    @Test
    void shouldDeepCopyStatements() {
        // Given
        ZestScriptWrapper script1 = createMockZestWrapperWithClientLaunch("script1", 2, 1);
        ZestScript originalScript = script1.getZestScript();
        ZestStatement originalFirstStatement = originalScript.getStatements().get(0);

        // When
        ZestScriptWrapper merged =
                ZestScriptMerger.mergeScripts(List.of(script1), "chain", ZestJSON::toString);

        // Then
        ZestScript mergedScript = merged.getZestScript();
        ZestStatement mergedFirstStatement = mergedScript.getStatements().get(0);
        assertThat(mergedFirstStatement, is(notNullValue()));

        // Chained copy is not the same instance as the original statement
        assertThat(mergedFirstStatement, is(not(sameInstance(originalFirstStatement))));

        // Mutating the original does not affect the chain script
        originalFirstStatement.setEnabled(false);
        assertThat(mergedFirstStatement.isEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldAddBrowserCloseAtEndWhenFirstScriptLaunchesBrowser() {
        // Given
        ZestScriptWrapper script1 = createMockZestWrapperWithClientLaunch("script1", 2, 1);
        ZestScriptWrapper script2 = createMockZestWrapper("script2", 1);

        // When
        ZestScriptWrapper merged =
                ZestScriptMerger.mergeScripts(
                        List.of(script1, script2), "chain", ZestJSON::toString);

        // Then: copied source statements, then a synthetic ZestClientWindowClose for the browser
        // handle
        List<ZestStatement> statements = merged.getZestScript().getStatements();
        assertThat(statements, hasSize(4));
        ZestStatement lastStatement = statements.get(statements.size() - 1);
        assertThat(lastStatement, is(instanceOf(ZestClientWindowClose.class)));
        assertThat(
                ((ZestClientWindowClose) lastStatement).getWindowHandle(), is(equalTo("browser")));
    }

    @Test
    void shouldCloseAllWindowHandlesIncludingThoseFromWindowHandleStatements() {
        // Given
        ZestScript script1 = new ZestScript();
        script1.setTitle("script1");
        script1.setType(ZestScript.Type.StandAlone);
        script1.add(new ZestClientLaunch("main", "firefox", "http://example.com"));
        script1.add(new ZestClientWindowHandle("popup", "http://popup.example.com", false));
        ZestScriptWrapper wrapper1 = createWrapperFromScript(script1, "script1");
        ZestScriptWrapper script2 = createMockZestWrapper("script2", 1);

        // When
        ZestScriptWrapper merged =
                ZestScriptMerger.mergeScripts(
                        List.of(wrapper1, script2), "chain", ZestJSON::toString);

        // Then
        List<ZestStatement> statements = merged.getZestScript().getStatements();
        List<String> closeHandles =
                statements.stream()
                        .filter(ZestClientWindowClose.class::isInstance)
                        .map(s -> ((ZestClientWindowClose) s).getWindowHandle())
                        .toList();
        assertThat(closeHandles, hasSize(2));
        assertThat(closeHandles, hasItem("main"));
        assertThat(closeHandles, hasItem("popup"));
    }

    private static ZestScriptWrapper createWrapperFromScript(ZestScript script, String name) {
        String json = ZestJSON.toString(script);
        ScriptWrapper sw = new ScriptWrapper();
        sw.setName(name);
        sw.setContents(json);
        ScriptType scriptType =
                mock(ScriptType.class, withSettings().strictness(Strictness.LENIENT));
        given(scriptType.getName()).willReturn(ExtensionScript.TYPE_STANDALONE);
        sw.setType(scriptType);
        return new ZestScriptWrapper(sw);
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void shouldThrowWhenFirstScriptHasNoClientLaunch(int chainSize) {
        // Given
        ZestScriptWrapper script1 = createMockZestWrapper("script1", 2);
        List<ZestScriptWrapper> scripts = new ArrayList<>();
        scripts.add(script1);
        if (chainSize == 2) {
            scripts.add(createMockZestWrapper("script2", 1));
        }

        // When / Then
        IllegalArgumentException e =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> ZestScriptMerger.mergeScripts(scripts, "chain", ZestJSON::toString));
        assertThat(e.getMessage(), containsString("First script in chain must contain"));
        assertThat(e.getMessage(), containsString("script1"));
    }

    private ZestScriptWrapper createMockZestWrapper(String name, int statementCount) {
        ZestScript script = new ZestScript();
        script.setTitle(name);
        script.setDescription("Test script: " + name);
        script.setType(ZestScript.Type.StandAlone);

        for (int i = 0; i < statementCount; i++) {
            script.add(new ZestComment("Statement " + (i + 1) + " from " + name));
        }
        String json = ZestJSON.toString(script);
        ScriptWrapper sw = new ScriptWrapper();
        sw.setName(name);
        sw.setContents(json);
        ScriptType scriptType =
                mock(ScriptType.class, withSettings().strictness(Strictness.LENIENT));
        given(scriptType.getName()).willReturn(ExtensionScript.TYPE_STANDALONE);
        sw.setType(scriptType);
        return new ZestScriptWrapper(sw);
    }

    private ZestScriptWrapper createMockZestWrapperWithClientLaunch(
            String name, int statementCount, int clientLaunchCount) {
        ZestScript script = new ZestScript();
        script.setTitle(name);
        script.setDescription("Test script: " + name);
        script.setType(ZestScript.Type.StandAlone);
        for (int i = 0; i < clientLaunchCount; i++) {
            script.add(new ZestClientLaunch("browser", "firefox", "http://example.com"));
        }
        for (int i = 0; i < statementCount - clientLaunchCount; i++) {
            script.add(new ZestComment("Statement " + (i + 1) + " from " + name));
        }
        String json = ZestJSON.toString(script);

        ScriptWrapper sw = new ScriptWrapper();
        sw.setName(name);
        sw.setContents(json);

        ScriptType scriptType =
                mock(ScriptType.class, withSettings().strictness(Strictness.LENIENT));
        given(scriptType.getName()).willReturn(ExtensionScript.TYPE_STANDALONE);
        sw.setType(scriptType);

        return new ZestScriptWrapper(sw);
    }
}
