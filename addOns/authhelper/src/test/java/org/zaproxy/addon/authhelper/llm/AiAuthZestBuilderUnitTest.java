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
package org.zaproxy.addon.authhelper.llm;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;

import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.zaproxy.zest.core.v1.ZestActionSleep;
import org.zaproxy.zest.core.v1.ZestClientElementClear;
import org.zaproxy.zest.core.v1.ZestClientElementClick;
import org.zaproxy.zest.core.v1.ZestClientElementScrollTo;
import org.zaproxy.zest.core.v1.ZestClientElementSendKeys;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;

class AiAuthZestBuilderUnitTest {

    private static final String LOGIN_URL = "http://example.com/login";

    @Nested
    class StatementStructure {

        @Test
        void shouldProduceOnlyLaunchForEmptyActions() {
            ZestScript zs = buildScript("firefox", List.of());

            List<ZestStatement> stmts = zs.getStatements();
            assertThat(stmts, hasSize(1));
            assertThat(stmts.get(0), instanceOf(ZestClientLaunch.class));
        }

        @Test
        void shouldMapSendKeysToScrollPlusElementClearPlusSendKeys() {
            var action = AiAuthActionResult.ok(AiAuthActionType.SEND_KEYS, "#user", "{{username}}");

            ZestScript zs = buildScript("firefox", List.of(action));

            List<ZestStatement> stmts = zs.getStatements();
            assertThat(stmts, hasSize(4));
            assertThat(stmts.get(1), instanceOf(ZestClientElementScrollTo.class));
            assertThat(stmts.get(2), instanceOf(ZestClientElementClear.class));
            assertThat(stmts.get(3), instanceOf(ZestClientElementSendKeys.class));

            var sendKeys = (ZestClientElementSendKeys) stmts.get(3);
            assertThat(sendKeys.getElement(), is("#user"));
            assertThat(sendKeys.getType(), is("cssSelector"));
            assertThat(sendKeys.getValue(), is("{{username}}"));
        }

        @Test
        void shouldMapClickToScrollPlusElementClick() {
            var action = AiAuthActionResult.ok(AiAuthActionType.CLICK, "#submit", null);

            ZestScript zs = buildScript("firefox", List.of(action));

            List<ZestStatement> stmts = zs.getStatements();
            assertThat(stmts, hasSize(3));
            assertThat(stmts.get(1), instanceOf(ZestClientElementScrollTo.class));
            assertThat(stmts.get(2), instanceOf(ZestClientElementClick.class));

            var scrollTo = (ZestClientElementScrollTo) stmts.get(1);
            assertThat(scrollTo.getElement(), is("#submit"));
            assertThat(scrollTo.getType(), is("cssSelector"));

            var click = (ZestClientElementClick) stmts.get(2);
            assertThat(click.getElement(), is("#submit"));
            assertThat(click.getType(), is("cssSelector"));
        }

        @Test
        void shouldMapSelectToScrollPlusElementSendKeys() {
            var action = AiAuthActionResult.ok(AiAuthActionType.SELECT, "#domain", "Project1");

            ZestScript zs = buildScript("firefox", List.of(action));

            List<ZestStatement> stmts = zs.getStatements();
            assertThat(stmts, hasSize(3));
            assertThat(stmts.get(1), instanceOf(ZestClientElementScrollTo.class));
            assertThat(stmts.get(2), instanceOf(ZestClientElementSendKeys.class));

            var sendKeys = (ZestClientElementSendKeys) stmts.get(2);
            assertThat(sendKeys.getElement(), is("#domain"));
            assertThat(sendKeys.getValue(), is("Project1"));
        }

        @Test
        void shouldMapWaitToActionSleepWithMilliseconds() {
            // WAIT actions use "wait" as the sentinel selector value (see AiAuthScriptGenerator)
            var action = AiAuthActionResult.ok(AiAuthActionType.WAIT, "wait", "3");

            ZestScript zs = buildScript("firefox", List.of(action));

            List<ZestStatement> stmts = zs.getStatements();
            assertThat(stmts, hasSize(2));
            assertThat(stmts.get(1), instanceOf(ZestActionSleep.class));

            var sleep = (ZestActionSleep) stmts.get(1);
            assertThat(sleep.getMilliseconds(), is(3000L));
        }

        @Test
        void shouldSkipFailedActions() {
            var ok = AiAuthActionResult.ok(AiAuthActionType.CLICK, "#btn", null);
            var failed = AiAuthActionResult.failed(AiAuthActionType.CLICK, "not found");

            ZestScript zs = buildScript("firefox", List.of(ok, failed));

            assertThat(zs.getStatements(), hasSize(3)); // launch + scrollTo + click
        }

        @Test
        void shouldSkipActionsWithNullSelector() {
            var click = AiAuthActionResult.ok(AiAuthActionType.CLICK, null, null);

            ZestScript zs = buildScript("firefox", List.of(click));

            assertThat(zs.getStatements(), hasSize(1)); // launch only
        }
    }

    @Nested
    class BrowserIdParsing {

        @ParameterizedTest
        @MethodSource("org.zaproxy.addon.authhelper.llm.AiAuthZestBuilderUnitTest#browserIds")
        void shouldParseBrowserId(String browserId, String expectedType, boolean expectedHeadless) {
            ZestScript zs = buildScript(browserId, List.of());

            var launch = (ZestClientLaunch) zs.getStatements().get(0);
            assertThat(launch.getBrowserType(), is(expectedType));
            assertThat(launch.isHeadless(), is(expectedHeadless));
        }

        @Test
        void shouldSetLoginUrlOnLaunchStatement() {
            ZestScript zs = buildScript("firefox", List.of());

            var launch = (ZestClientLaunch) zs.getStatements().get(0);
            assertThat(launch.getUrl(), is(LOGIN_URL));
        }
    }

    @Nested
    class ScriptMetadata {

        @Test
        void shouldSetScriptTitle() {
            ZestScript zs =
                    AiAuthZestBuilder.buildZestScript(
                            "My Auth Script", LOGIN_URL, "firefox", List.of());

            assertThat(zs.getTitle(), is("My Auth Script"));
        }

        @Test
        void shouldAddUsernameAndPasswordParameters() {
            ZestScript zs = buildScript("firefox", List.of());

            var vars = zs.getParameters().getVariablesMap();
            assertThat(vars, hasKey("username"));
            assertThat(vars, hasKey("password"));
        }

        @Test
        void shouldSetStatementDelayTo1000ms() {
            ZestScript zs = buildScript("firefox", List.of());

            assertThat(zs.getOptions(), hasEntry(ZestScript.STATEMENT_DELAY_MS, "1000"));
        }
    }

    private static Stream<Arguments> browserIds() {
        return Stream.of(
                Arguments.of("firefox-headless", "firefox", true),
                Arguments.of("chrome", "chrome", false),
                Arguments.of(null, "firefox", false));
    }

    private static ZestScript buildScript(String browserId, List<AiAuthActionResult> actions) {
        return AiAuthZestBuilder.buildZestScript("test", LOGIN_URL, browserId, actions);
    }
}
