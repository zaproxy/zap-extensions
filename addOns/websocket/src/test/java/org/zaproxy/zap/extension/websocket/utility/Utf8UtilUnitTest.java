/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.utility;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class Utf8UtilUnitTest {

    @Test
    void shouldEncodeEmptyBytesToEmptyString() throws Exception {
        // given
        byte[] utf8 = new byte[0];
        // when
        String s = Utf8Util.encodePayloadToUtf8(utf8);
        // then
        assertThat(s, is(equalTo("")));
    }

    @Test
    void shouldFailOnGivenInvalidUtf8Bytes() throws Exception {
        // given
        byte[] invalidUtf8 = new byte[] {-1};
        // when / then
        assertThrows(InvalidUtf8Exception.class, () -> Utf8Util.encodePayloadToUtf8(invalidUtf8));
    }

    @Test
    void shouldEncodeSimpleUtf8Bytes() throws Exception {
        // given
        byte[] utf8 = new byte[] {49, 50, 51};
        // when
        String s = Utf8Util.encodePayloadToUtf8(utf8);
        // then
        assertThat(s, is(equalTo("123")));
    }
}
