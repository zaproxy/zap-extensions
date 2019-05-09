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
package org.zaproxy.zap.extension.soap;

import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;
import org.zaproxy.zap.testutils.TestUtils;

public class ExtensionImportWSDLTestCase extends TestUtils {

    ExtensionImportWSDL extension;

    @Before
    public void setUp() {
        extension = new ExtensionImportWSDL();
        mockMessages(extension);
    }

    @Test
    public void getAuthorTest() {
        assertNotNull(extension.getAuthor());
    }

    @Test
    public void getDescriptionTest() {
        assertNotNull(extension.getDescription());
    }

    @Test
    public void getURLTest() {
        assertNotNull(extension.getURL());
    }
}
