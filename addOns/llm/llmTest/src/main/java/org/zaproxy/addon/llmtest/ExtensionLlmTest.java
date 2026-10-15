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
package org.zaproxy.addon.llmtest;

import java.util.Optional;
import java.util.function.Supplier;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.zaproxy.addon.dev.ExtensionDev;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.llmtest.mock.MockLlmDir;

/**
 * Plugs the test apps for the LLM add-on into the dev add-on's test server.
 *
 * <p>Other test add-ons can get the mock LLM, to add their own rule sets, with {@link
 * #getMockLlm()}.
 */
public class ExtensionLlmTest extends ExtensionAdaptor {

    public static final String NAME = "ExtensionLlmTest";

    static final String PARENT_PATH = "llm";
    static final String MOCK_LLM_NAME = "mock";

    private final Supplier<Optional<TestProxyServer>> serverSupplier;
    private TestProxyServer server;
    private MockLlmDir mockLlm;

    public ExtensionLlmTest() {
        this(ExtensionLlmTest::getDevServer);
    }

    ExtensionLlmTest(Supplier<Optional<TestProxyServer>> serverSupplier) {
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
    public void optionsLoaded() {
        getMockLlm();
    }

    /**
     * Gets the mock LLM, plugging it into the test server if that has not been done yet.
     *
     * @return the mock LLM, empty if the test server is not available, for example when ZAP is not
     *     in dev mode.
     */
    public synchronized Optional<MockLlmDir> getMockLlm() {
        if (mockLlm == null) {
            serverSupplier
                    .get()
                    .ifPresent(
                            s -> {
                                server = s;
                                mockLlm = new MockLlmDir(s, MOCK_LLM_NAME);
                                s.addDirectory(PARENT_PATH, mockLlm);
                            });
        }
        return Optional.ofNullable(mockLlm);
    }

    @Override
    public synchronized void unload() {
        if (mockLlm != null) {
            server.removeDirectory(PARENT_PATH + "/" + MOCK_LLM_NAME);
            mockLlm = null;
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }
}
