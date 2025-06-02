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
package org.zaproxy.addon.network;

import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.StringLayout;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.layout.PatternLayout;

/** An appender that allows to consume all log messages. */
public class TestLogAppender extends AbstractAppender {

    private static final Property[] NO_PROPERTIES = {};

    private final Consumer<String> logConsumer;

    public TestLogAppender(Consumer<String> logConsumer) {
        this("%m%n", logConsumer);
    }

    public TestLogAppender(String pattern, Consumer<String> logConsumer) {
        super(
                "TestLogAppender",
                null,
                PatternLayout.newBuilder()
                        .withDisableAnsi(true)
                        .withCharset(StandardCharsets.UTF_8)
                        .withPattern(pattern)
                        .build(),
                true,
                NO_PROPERTIES);
        this.logConsumer = logConsumer;
        start();
    }

    @Override
    public void append(LogEvent event) {
        logConsumer.accept(((StringLayout) getLayout()).toSerializable(event));
    }
}
