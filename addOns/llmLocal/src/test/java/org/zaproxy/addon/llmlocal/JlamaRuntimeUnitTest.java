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
package org.zaproxy.addon.llmlocal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

import java.lang.reflect.InvocationTargetException;
import org.junit.jupiter.api.Test;

class JlamaRuntimeUnitTest {

    @Test
    void rootCauseMessageShouldExplainMissingVectorApi() {
        Throwable nested =
                new RuntimeException(
                        new InvocationTargetException(
                                new NoClassDefFoundError("jdk/incubator/vector/FloatVector")));

        String message = JlamaRuntime.rootCauseMessage(nested);

        assertThat(message, containsString("--add-modules jdk.incubator.vector"));
        assertThat(message, containsString("--enable-preview"));
        assertThat(JlamaRuntime.isMissingVectorApi(nested), is(true));
    }

    @Test
    void rootCauseMessageShouldExplainArm128WithoutNativeSimd() {
        Throwable nested =
                new RuntimeException(
                        new UnsupportedOperationException(
                                new UnsupportedOperationException("ARM_128")));

        String message = JlamaRuntime.rootCauseMessage(nested);

        assertThat(message, containsString("--enable-preview"));
        assertThat(message, containsString("ARM_128"));
        assertThat(JlamaRuntime.isArm128Unsupported(nested), is(true));
    }

    @Test
    void rootCauseMessageShouldExplainMissingNativePreview() {
        Throwable nested =
                new UnsupportedClassVersionError(
                        "Preview features are not enabled for"
                                + " com/github/tjake/jlama/tensor/operations/cnative/NativeSimd"
                                + " (class file version 65.65535)."
                                + " Try running with '--enable-preview'");

        String message = JlamaRuntime.rootCauseMessage(nested);

        assertThat(message, containsString("--enable-preview"));
        assertThat(JlamaRuntime.isMissingNativePreview(nested), is(true));
    }

    @Test
    void rootCauseMessageShouldIncludeDeepestCause() {
        Throwable nested =
                new RuntimeException(
                        new InvocationTargetException(new IllegalStateException("boom")));

        assertThat(JlamaRuntime.rootCauseMessage(nested), is("IllegalStateException: boom"));
    }

    @Test
    void withAddOnClassLoaderShouldRestorePreviousLoader() {
        ClassLoader original = Thread.currentThread().getContextClassLoader();
        ClassLoader seen =
                JlamaRuntime.withAddOnClassLoader(
                        () -> Thread.currentThread().getContextClassLoader());

        assertThat(seen, is(JlamaRuntime.class.getClassLoader()));
        assertThat(Thread.currentThread().getContextClassLoader(), is(original));
    }
}
