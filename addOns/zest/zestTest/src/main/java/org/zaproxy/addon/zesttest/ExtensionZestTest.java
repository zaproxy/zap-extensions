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
package org.zaproxy.addon.zesttest;

import java.util.Optional;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.zaproxy.addon.dev.ExtensionDev;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.zesttest.shadowdom.ShadowDomRootDir;

public class ExtensionZestTest extends ExtensionAdaptor {

    public static final String NAME = "ExtensionZestTest";

    private static final String ZEST_PARENT_PATH = "zest";
    private static final String SHADOW_DOM_NAME = "shadow-dom";

    private TestProxyServer server;

    public ExtensionZestTest() {
        super(NAME);
    }

    private static Optional<TestProxyServer> getDevServer() {
        return Optional.ofNullable(
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionDev.class))
                .flatMap(ExtensionDev::getTestServer);
    }

    @Override
    public void optionsLoaded() {
        if (server == null) {
            getDevServer()
                    .ifPresent(
                            s -> {
                                server = s;
                                s.addDirectory(
                                        ZEST_PARENT_PATH, new ShadowDomRootDir(s, SHADOW_DOM_NAME));
                            });
        }
    }

    @Override
    public void unload() {
        if (server != null) {
            server.removeDirectory(ZEST_PARENT_PATH + "/" + SHADOW_DOM_NAME);
            server = null;
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }
}
