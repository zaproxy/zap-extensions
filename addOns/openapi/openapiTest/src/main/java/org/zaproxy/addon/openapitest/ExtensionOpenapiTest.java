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
package org.zaproxy.addon.openapitest;

import java.util.Optional;
import java.util.function.Supplier;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.zaproxy.addon.dev.ExtensionDev;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.openapitest.simpleauth.OpenApiSimpleAuthDir;
import org.zaproxy.addon.openapitest.simpleoauth2.OpenApiSimpleOAuth2Dir;
import org.zaproxy.addon.openapitest.simpletoken.OpenApiSimpleTokenDir;
import org.zaproxy.addon.openapitest.simpleunauth.OpenApiSimpleUnauthDir;

/** Plugs the test apps for the openapi add-on into the dev add-on's test server. */
public class ExtensionOpenapiTest extends ExtensionAdaptor {

    public static final String NAME = "ExtensionOpenapiTest";

    static final String PARENT_PATH = "api/openapi";
    static final String SIMPLE_AUTH_NAME = "simple-auth";
    static final String SIMPLE_UNAUTH_NAME = "simple-unauth";
    static final String SIMPLE_TOKEN_NAME = "simple-token";
    static final String SIMPLE_OAUTH2_NAME = "simple-oauth2";

    private final Supplier<Optional<TestProxyServer>> serverSupplier;
    private TestProxyServer server;

    public ExtensionOpenapiTest() {
        this(ExtensionOpenapiTest::getDevServer);
    }

    ExtensionOpenapiTest(Supplier<Optional<TestProxyServer>> serverSupplier) {
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
                                        PARENT_PATH, new OpenApiSimpleAuthDir(s, SIMPLE_AUTH_NAME));
                                s.addDirectory(
                                        PARENT_PATH,
                                        new OpenApiSimpleUnauthDir(s, SIMPLE_UNAUTH_NAME));
                                s.addDirectory(
                                        PARENT_PATH,
                                        new OpenApiSimpleTokenDir(s, SIMPLE_TOKEN_NAME));
                                s.addDirectory(
                                        PARENT_PATH,
                                        new OpenApiSimpleOAuth2Dir(s, SIMPLE_OAUTH2_NAME));
                                server = s;
                            });
        }
    }

    @Override
    public synchronized void unload() {
        if (server != null) {
            server.removeDirectory(PARENT_PATH + "/" + SIMPLE_AUTH_NAME);
            server.removeDirectory(PARENT_PATH + "/" + SIMPLE_UNAUTH_NAME);
            server.removeDirectory(PARENT_PATH + "/" + SIMPLE_TOKEN_NAME);
            server.removeDirectory(PARENT_PATH + "/" + SIMPLE_OAUTH2_NAME);
            server = null;
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }
}
