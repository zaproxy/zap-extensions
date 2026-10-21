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
package org.zaproxy.addon.authhelpertest;

import java.util.Optional;
import java.util.function.Supplier;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.zaproxy.addon.authhelpertest.multistep.MultiStepAuthDir;
import org.zaproxy.addon.dev.ExtensionDev;
import org.zaproxy.addon.dev.TestProxyServer;

/**
 * Plugs the test apps for the authhelper add-on into the dev add-on's test server.
 *
 * <p>The mock LLM rule set is provided as a file, see the {@code zapHomeFiles}.
 */
public class ExtensionAuthhelperTest extends ExtensionAdaptor {

    public static final String NAME = "ExtensionAuthhelperTest";

    static final String AUTH_PARENT_PATH = "auth";
    static final String MULTI_STEP_AUTH_NAME = "multi-step-auth";

    private final Supplier<Optional<TestProxyServer>> serverSupplier;
    private TestProxyServer server;

    public ExtensionAuthhelperTest() {
        this(ExtensionAuthhelperTest::getDevServer);
    }

    ExtensionAuthhelperTest(Supplier<Optional<TestProxyServer>> serverSupplier) {
        super(NAME);
        this.serverSupplier = serverSupplier;
    }

    private static Optional<TestProxyServer> getDevServer() {
        return Optional.ofNullable(
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionDev.class))
                .flatMap(ExtensionDev::getTestServer);
    }

    // The dev add-on creates its server when it is hooked, so plug in once all have been hooked.
    @Override
    public synchronized void optionsLoaded() {
        if (server == null) {
            serverSupplier
                    .get()
                    .ifPresent(
                            s -> {
                                s.addDirectory(
                                        AUTH_PARENT_PATH,
                                        new MultiStepAuthDir(s, MULTI_STEP_AUTH_NAME));
                                server = s;
                            });
        }
    }

    @Override
    public synchronized void unload() {
        if (server != null) {
            server.removeDirectory(AUTH_PARENT_PATH + "/" + MULTI_STEP_AUTH_NAME);
            server = null;
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }
}
