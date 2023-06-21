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
package org.zaproxy.zap.extension.spiderAjax;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.util.stream.Stream;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** Unit test for {@link ExtensionAjax}. */
class ExtensionAjaxUnitTest {

    private ExtensionAjax extension;

    @BeforeEach
    void setup() throws Exception {
        resetLogConfig();

        extension = new ExtensionAjax();
    }

    private void resetLogConfig() throws Exception {
        Configurator.reconfigure(getClass().getResource("/log4j2-test.properties").toURI());
    }

    @AfterEach
    void cleanup() throws Exception {
        resetLogConfig();
    }

    @ParameterizedTest
    @MethodSource("chattyCrawljaxClassesWithDefaultLevel")
    void shouldHaveCrawljaxChattyClassesSetToAppropriateLevel(
            String classname, Level defaultLevel) {
        // Given
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration configuration = ctx.getConfiguration();
        // When
        extension.init();
        // Then
        LoggerConfig loggerConfig = configuration.getLoggerConfig(classname);
        assertThat(loggerConfig, is(notNullValue()));
        assertThat(loggerConfig.getLevel(), is(equalTo(defaultLevel)));
    }

    static Stream<Arguments> chattyCrawljaxClassesWithDefaultLevel() {
        return Stream.of(
                arguments("com.crawljax.core.Crawler", Level.WARN),
                arguments("com.crawljax.core.state.StateMachine", Level.WARN),
                arguments("com.crawljax.core.UnfiredCandidateActions", Level.WARN),
                arguments("com.crawljax.forms.FormHandler", Level.OFF));
    }

    @ParameterizedTest
    @MethodSource("chattyCrawljaxClassesWithDefaultLevel")
    void shouldNotChangeCrawljaxChattyClassesIfAlreadyConfigured(String classname) {
        // Given
        Level customLevel = Level.DEBUG;
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration configuration = ctx.getConfiguration();
        configuration.addLogger(
                classname,
                LoggerConfig.newBuilder()
                        .withLoggerName(classname)
                        .withLevel(customLevel)
                        .withConfig(configuration)
                        .build());
        ctx.updateLoggers();
        // When
        extension.init();
        // Then
        LoggerConfig loggerConfig = configuration.getLoggerConfig(classname);
        assertThat(loggerConfig, is(notNullValue()));
        assertThat(loggerConfig.getLevel(), is(equalTo(customLevel)));
    }
}
