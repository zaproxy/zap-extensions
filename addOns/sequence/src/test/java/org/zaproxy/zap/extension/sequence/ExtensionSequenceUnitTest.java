/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.zap.extension.sequence;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ExtensionSequence}. */
class ExtensionSequenceUnitTest extends TestUtils {

    private ExtensionSequence extension;

    @BeforeEach
    void setUp() {
        extension = new ExtensionSequence();
        extension.init();

        mockMessages(extension);
    }

    @Test
    void shouldHaveName() {
        assertThat(extension.getName(), is(equalTo("ExtensionSequence")));
    }

    @Test
    void shouldHaveUiName() {
        assertThat(extension.getUIName(), is(not(emptyString())));
    }

    @Test
    void shouldHaveDescription() {
        assertThat(extension.getDescription(), is(not(emptyString())));
    }

    @Test
    void shouldHaveScriptType() {
        assertThat(extension.getScriptType(), is(notNullValue()));
    }
}
