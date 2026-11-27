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
package org.zaproxy.addon.dev;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Unit test for {@link DevUtils}. */
class DevUtilsUnitTest {

    @Test
    void shouldGetDefaultLongParamWithoutQuery() {
        assertThat(DevUtils.getLongParam(null, "delay", 3000, 30000), is(3000L));
    }

    @ParameterizedTest
    @CsvSource({
        "delay=0,0",
        "delay=1500,1500",
        "a=b&delay=250,250",
        "delay=250&a=b,250",
        "delay=999999,30000",
        "delay=-5,0",
        "delay=abc,3000",
        "other=1,3000",
        "delay=,3000",
        "mydelay=5,3000"
    })
    void shouldGetLongParamFromQuery(String query, long expected) {
        assertThat(DevUtils.getLongParam(query, "delay", 3000, 30000), is(expected));
    }
}
