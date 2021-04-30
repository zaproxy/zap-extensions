/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.retire;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class RetireUtilUnitTest {

    @Test
    void versions_should_be_above() {
        assertTrue(RetireUtil.isAtOrAbove("0.0.1", "0.0.0"));
        assertTrue(RetireUtil.isAtOrAbove("0.1.0", "0.0.9"));
        assertTrue(RetireUtil.isAtOrAbove("0.10.1", "0.9.0"));
        assertTrue(RetireUtil.isAtOrAbove("0.0.10", "0.0.9"));
        assertTrue(RetireUtil.isAtOrAbove("0.0.10", "0.0.09"));
        assertTrue(RetireUtil.isAtOrAbove("0.1", "0.0.1"));
        assertTrue(RetireUtil.isAtOrAbove("0.2.0", "0.1"));
        assertTrue(RetireUtil.isAtOrAbove("0.0.1-beta", "0.0.1-alpha"));
        assertTrue(RetireUtil.isAtOrAbove("0.0.1", "0.0.1-alpha"));
    }

    @Test
    void versions_should_be_at() {
        assertTrue(RetireUtil.isAtOrAbove("0.0.1", "0.0.1"));
        assertTrue(RetireUtil.isAtOrAbove("0.1.1", "0.1.1"));
        assertTrue(RetireUtil.isAtOrAbove("0.1.0", "0.1"));
    }

    @Test
    void versions_should_not_be_above() {
        assertFalse(RetireUtil.isAtOrAbove("0.0.1", "0.0.2"));
        assertFalse(RetireUtil.isAtOrAbove("0.0.9", "0.0.10"));
        assertFalse(RetireUtil.isAtOrAbove("0.1.1", "0.1.2"));
        assertFalse(RetireUtil.isAtOrAbove("0.0.9", "0.1"));
        assertFalse(RetireUtil.isAtOrAbove("0.1", "0.2.0"));
    }
}
