/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.tokengen;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

/** Unit test for {@link TokenRandomStream}. */
@RunWith(MockitoJUnitRunner.class)
public class TokenRandomStreamUnitTest {

    @Mock CharacterFrequencyMap characterFrequencyMap;

    TokenRandomStream stream;

    @Before
    public void setUp() throws Exception {
        stream = new TokenRandomStream(characterFrequencyMap);
    }

    @Test
    public void shouldAlwaysReturnMinusOneWhenStreamIsClosed() throws Exception {
        // Given
        stream.closeInputStream();
        // When/Then
        assertThat(stream.readByte(), is((byte) -1));
        assertThat(stream.readInt(), is(-1));
        assertThat(stream.readLong(), is(-1L));
    }

    // TODO Add more tests

}
