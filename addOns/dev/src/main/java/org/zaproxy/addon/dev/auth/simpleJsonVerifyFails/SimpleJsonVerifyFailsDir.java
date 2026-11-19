/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.dev.auth.simpleJsonVerifyFails;

import java.util.concurrent.atomic.AtomicInteger;
import org.zaproxy.addon.dev.TestAuthDirectory;
import org.zaproxy.addon.dev.TestProxyServer;

/**
 * A login page which uses one JSON request to login endpoint and always succeeds with valid
 * credentials, but the verification URL fails. By default it always fails, it can be configured (in
 * the config page) to only fail after a number of successful verifications. Exercises the failed
 * authentication verification handling.
 */
public class SimpleJsonVerifyFailsDir extends TestAuthDirectory {

    private final AtomicInteger verifications = new AtomicInteger();
    private volatile int failAfter;

    public SimpleJsonVerifyFailsDir(TestProxyServer server, String name) {
        super(server, name);
        onReset(() -> verifications.set(0));
        this.addPage(new SimpleJsonVerifyFailsLoginPage(server));
        this.addPage(new SimpleJsonVerifyFailsVerificationPage(server));
        this.addPage(new SimpleJsonVerifyFailsConfigPage(server));
    }

    /**
     * Tells if the verification being done should succeed, counting it.
     *
     * @return {@code true} if it is one of the first {@code failAfter} verifications, {@code false}
     *     otherwise, always the case if {@code failAfter} is zero.
     */
    boolean nextVerificationSucceeds() {
        return failAfter > 0 && verifications.incrementAndGet() <= failAfter;
    }

    int getFailAfter() {
        return failAfter;
    }

    int getVerifications() {
        return verifications.get();
    }

    /**
     * Sets the number of verifications that succeed before they all fail, restarting the count.
     *
     * @param failAfter the number of verifications, zero (or less) to always fail.
     */
    void setFailAfter(int failAfter) {
        this.failAfter = Math.max(0, failAfter);
        verifications.set(0);
    }
}
