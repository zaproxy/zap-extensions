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
package org.zaproxy.addon.exim;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.Test;

/** Unit test for {@link ImporterResult}. */
class ImporterResultUnitTest {

    @Test
    void shouldHaveZeroCountByDefault() {
        // Given
        ImporterResult result = new ImporterResult();
        // When
        int count = result.getCount();
        // Then
        assertThat(count, is(equalTo(0)));
    }

    @Test
    void shouldIncrementCount() {
        // Given
        ImporterResult result = new ImporterResult();
        // When
        result.incrementCount();
        result.incrementCount();
        // Then
        assertThat(result.getCount(), is(equalTo(2)));
    }

    @Test
    void shouldNotHaveErrorsByDefault() {
        // Given
        ImporterResult result = new ImporterResult();
        // When / Then
        assertThat(result.getErrors(), is(empty()));
        assertThat(result.getCause(), is(nullValue()));
    }

    @Test
    void shouldHaveAddedErrors() {
        // Given
        ImporterResult result = new ImporterResult();
        // When
        result.addError("Error 1");
        result.addError("Error 2");
        // Then
        assertThat(result.getErrors(), contains("Error 1", "Error 2"));
        assertThat(result.getCause(), is(nullValue()));
    }

    @Test
    void shouldHaveErrorAndCause() {
        // Given
        ImporterResult result = new ImporterResult();
        Exception exception = new Exception();
        // When
        result.addError("Error A", exception);
        // Then
        assertThat(result.getErrors(), contains("Error A"));
        assertThat(result.getCause(), is(equalTo(exception)));
    }

    @Test
    void shouldOverrideCauses() {
        // Given
        ImporterResult result = new ImporterResult();
        Exception exceptionA = new Exception();
        Exception exceptionB = new Exception();
        // When
        result.addError("Error A", exceptionA);
        result.addError("Error B", exceptionB);
        // Then
        assertThat(result.getErrors(), contains("Error A", "Error B"));
        assertThat(result.getCause(), is(equalTo(exceptionB)));
    }
}
