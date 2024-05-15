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
package org.zaproxy.addon.grpc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.testutils.TestUtils;

class ExtensionGrpcUnitTest extends TestUtils {
    private ExtensionGrpc extensionGrpc;

    @BeforeEach
    void setup() throws Exception {
        extensionGrpc = new ExtensionGrpc();
        mockMessages(extensionGrpc);
    }

    @Test
    void shouldHaveNameAndDescription() {
        assertEquals(Constant.messages.getString("grpc.name"), extensionGrpc.getUIName());
        assertEquals(Constant.messages.getString("grpc.desc"), extensionGrpc.getDescription());
    }
}
