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

import java.lang.reflect.InvocationTargetException;
import org.apache.commons.lang3.StringUtils;

/** Runtime checks and helpers for using Jlama inside ZAP. */
public final class JlamaRuntime {

    static final String VECTOR_API_MODULE_OPTION = "--add-modules jdk.incubator.vector";

    static final String ENABLE_PREVIEW_OPTION = "--enable-preview";

    /**
     * JVM options needed for Jlama Vector API plus native SIMD (jlama-native). Native SIMD is
     * required on Apple Silicon for many Q4 models; without it Jlama falls back to Panama ops that
     * throw {@code UnsupportedOperationException: ARM_128} for F32×Q4 kernels.
     */
    static final String RECOMMENDED_JVM_OPTIONS =
            VECTOR_API_MODULE_OPTION + " " + ENABLE_PREVIEW_OPTION;

    private static final String FLOAT_VECTOR_CLASS = "jdk.incubator.vector.FloatVector";

    private static final String NATIVE_SIMD_OPS_CLASS =
            "com.github.tjake.jlama.tensor.operations.NativeSimdTensorOperations";

    private JlamaRuntime() {}

    /**
     * Returns {@code true} when the Java Vector API is available to this JVM (typically requires
     * {@value #VECTOR_API_MODULE_OPTION} on Java releases where the API is still an incubator
     * module).
     *
     * @return {@code true} if {@code jdk.incubator.vector.FloatVector} can be loaded
     */
    public static boolean isVectorApiAvailable() {
        try {
            Class.forName(FLOAT_VECTOR_CLASS);
            return true;
        } catch (ClassNotFoundException | LinkageError e) {
            return false;
        }
    }

    /**
     * Returns {@code true} when Jlama's native SIMD backend can be loaded. On Java 21 the multi-
     * release classes in {@code jlama-native} are compiled with preview features, so this typically
     * requires {@value #ENABLE_PREVIEW_OPTION}.
     *
     * @return {@code true} if {@code NativeSimdTensorOperations} initializes successfully
     */
    public static boolean isNativeSimdAvailable() {
        return withAddOnClassLoader(
                () -> {
                    try {
                        Class.forName(
                                NATIVE_SIMD_OPS_CLASS, true, JlamaRuntime.class.getClassLoader());
                        return true;
                    } catch (Throwable e) {
                        return false;
                    }
                });
    }

    /**
     * Returns a useful message for nested load failures (for example {@link
     * InvocationTargetException} wrapping {@link NoClassDefFoundError}).
     *
     * @param throwable the thrown error
     * @return the deepest non-blank message, or the throwable's class name
     */
    static String rootCauseMessage(Throwable throwable) {
        if (isMissingVectorApi(throwable)) {
            return "Java Vector API is not available; start ZAP with " + RECOMMENDED_JVM_OPTIONS;
        }
        if (isArm128Unsupported(throwable) || isMissingNativePreview(throwable)) {
            return "Jlama native SIMD is not available; start ZAP with "
                    + RECOMMENDED_JVM_OPTIONS
                    + " (without native SIMD, some Q4 models fail on ARM with UnsupportedOperationException: ARM_128)";
        }
        Throwable root = throwable;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        String message = StringUtils.trimToNull(root.getMessage());
        if (message != null) {
            return root.getClass().getSimpleName() + ": " + message;
        }
        message = StringUtils.trimToNull(throwable.getMessage());
        if (message != null) {
            return message;
        }
        return root.getClass().getName();
    }

    static boolean isMissingVectorApi(Throwable throwable) {
        for (Throwable current = throwable; current != null; current = current.getCause()) {
            if (current instanceof ClassNotFoundException
                    || current instanceof NoClassDefFoundError) {
                String message = current.getMessage();
                if (message != null
                        && (message.contains("FloatVector")
                                || message.contains("jdk.incubator.vector")
                                || message.contains("jdk/incubator/vector"))) {
                    return true;
                }
            }
        }
        return false;
    }

    static boolean isArm128Unsupported(Throwable throwable) {
        for (Throwable current = throwable; current != null; current = current.getCause()) {
            if (current instanceof UnsupportedOperationException) {
                String message = current.getMessage();
                if (message != null && message.contains("ARM_128")) {
                    return true;
                }
            }
        }
        return false;
    }

    static boolean isMissingNativePreview(Throwable throwable) {
        for (Throwable current = throwable; current != null; current = current.getCause()) {
            if (current instanceof UnsupportedClassVersionError) {
                String message = current.getMessage();
                if (message != null
                        && message.contains("enable-preview")
                        && message.contains("NativeSimd")) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Runs {@code action} with this add-on's classloader as the thread context classloader. Needed
     * so libraries such as Jinjava (used by Jlama prompt templates) can load their own classes from
     * add-on {@code libs/}.
     *
     * @param <T> the result type
     * @param action the action to run
     * @return the action result
     */
    public static <T> T withAddOnClassLoader(java.util.function.Supplier<T> action) {
        ClassLoader previous = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(JlamaRuntime.class.getClassLoader());
            return action.get();
        } finally {
            Thread.currentThread().setContextClassLoader(previous);
        }
    }
}
