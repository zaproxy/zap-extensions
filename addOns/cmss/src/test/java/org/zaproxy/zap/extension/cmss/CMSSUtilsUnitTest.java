/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.cmss;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.zaproxy.zap.extension.cmss.CMSSUtils.checksum;

import org.junit.Test;

public class CMSSUtilsUnitTest {

    @Test
    public void checksumOfInputStringShouldReturnMD5Hash() throws Exception {
        // expected results generated using http://www.miraclesalad.com/webtools/md5.php
        assertThat(checksum("".getBytes()), is("d41d8cd98f00b204e9800998ecf8427e"));
        assertThat(checksum(" ".getBytes()), is("7215ee9c7d9dc229d2921a40e899ec5f"));
        assertThat(checksum("test1".getBytes()), is("5a105e8b9d40e1329780d62ea2265d8a"));
        assertThat(checksum("test2".getBytes()), is("ad0234829205b9033196ba818f7a872b"));
    }

    @Test(expected = NullPointerException.class)
    public void checksumOfNullShouldThrowException() throws Exception {
        checksum(null);
    }

    @Test
    public void checksumOfEmptyBytesArrayIsEqualToMD5HashOfEmptyString() throws Exception {
        assertThat(checksum(new byte[0]), is(checksum("".getBytes())));
    }
}
