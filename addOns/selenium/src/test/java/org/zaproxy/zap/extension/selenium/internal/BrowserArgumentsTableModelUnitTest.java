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
package org.zaproxy.zap.extension.selenium.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link BrowserArgumentsTableModel}. */
class BrowserArgumentsTableModelUnitTest {

    @BeforeAll
    static void setUpAll() {
        Constant.messages = mock(I18N.class);
    }

    @Test
    void shouldCreateCopyOfCollectionAndValues() {
        // Given
        BrowserArgumentsTableModel model = new BrowserArgumentsTableModel();
        List<BrowserArgument> arguments = new ArrayList<>();
        BrowserArgument original = new BrowserArgument("--arg", false);
        arguments.add(original);
        // When
        model.setArguments(arguments);
        model.setAllEnabled(true);
        arguments.clear();
        // Then
        assertThat(original.isEnabled(), is(equalTo(false)));
        assertThat(model.getElements(), hasSize(1));
        assertThat(model.getElements().get(0).isEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldSetEnabledStateOfArgument() {
        // Given
        BrowserArgumentsTableModel model = new BrowserArgumentsTableModel();
        model.setArguments(
                List.of(
                        new BrowserArgument("--arg1", false),
                        new BrowserArgument("--arg2", false)));
        // When
        model.setValueAt(true, 1, 0);
        // Then
        assertThat(model.getElements().get(0).isEnabled(), is(equalTo(false)));
        assertThat(model.getElements().get(1).isEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldGetEnabledStateFromArgument() {
        // Given
        BrowserArgumentsTableModel model = new BrowserArgumentsTableModel();
        model.setArguments(
                List.of(new BrowserArgument("--arg1", true), new BrowserArgument("--arg2", false)));
        // When
        Object enabled = model.getValueAt(0, 0);
        // Then
        assertThat(enabled, is(equalTo(true)));
    }

    @Test
    void shouldGetArgument() {
        // Given
        BrowserArgumentsTableModel model = new BrowserArgumentsTableModel();
        model.setArguments(
                List.of(
                        new BrowserArgument("--arg1", false),
                        new BrowserArgument("--arg2", false)));
        // When
        Object argument = model.getValueAt(1, 1);
        // Then
        assertThat(argument, is(equalTo("--arg2")));
    }

    @Test
    void shouldGetArgumentsAsString() {
        // Given
        BrowserArgumentsTableModel model = new BrowserArgumentsTableModel();
        model.setArguments(
                List.of(
                        new BrowserArgument("--argA", true),
                        new BrowserArgument("--argB", false),
                        new BrowserArgument("--argC", true)));
        // When
        String arguments = model.getArgumentsAsString();
        // Then
        assertThat(arguments, is(equalTo("--argA --argC")));
    }
}
