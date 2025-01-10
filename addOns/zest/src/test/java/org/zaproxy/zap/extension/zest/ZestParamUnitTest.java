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
package org.zaproxy.zap.extension.zest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link ZestParam}. */
class ZestParamUnitTest {

    @Test
    void shouldCopyStateWithCopyConstructor() {
        // Given
        ZestParam original = new ZestParam();
        original.load(new ZapXmlConfiguration());
        original.setIgnoredHeaders(List.of("A", "B"));
        original.setIncludeResponses(false);
        original.setScriptFormat("YAML");
        // When
        ZestParam copy = new ZestParam(original);
        // Then
        assertEqualsNotSameInstance(copy.getIgnoredHeaders(), original.getIgnoredHeaders());
        assertThat(copy.isIncludeResponses(), is(equalTo(original.isIncludeResponses())));
        assertThat(copy.getScriptFormat(), is(equalTo(original.getScriptFormat())));
        assertEqualsNotSameInstance(copy.getAllHeaders(), original.getAllHeaders());
        assertThat(copy.getConfig(), is(nullValue()));
    }

    private static void assertEqualsNotSameInstance(Object actual, Object expected) {
        assertThat(actual, is(equalTo(expected)));
        assertThat(actual, is(not(sameInstance(expected))));
    }
}
