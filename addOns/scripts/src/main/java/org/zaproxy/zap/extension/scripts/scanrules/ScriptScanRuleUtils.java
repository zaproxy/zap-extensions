/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.scripts.scanrules;

import java.lang.reflect.UndeclaredThrowableException;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.Consumer;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.commonlib.scanrules.AlertReferenceMetadata;

class ScriptScanRuleUtils {

    static void overrideWithAlertRefMetadata(
            Alert.Builder builder, AlertReferenceMetadata override) {
        if (override == null) {
            return;
        }
        setIfNotNull(override.getName(), builder::setName);
        setIfNotNull(override.getDescription(), builder::setDescription);
        setIfNotNull(override.getSolution(), builder::setSolution);
        setIfNotNull(override.getCweId(), builder::setCweId);
        setIfNotNull(override.getWascId(), builder::setWascId);
        setIfNotNull(override.getOtherInfo(), builder::setOtherInfo);
        if (override.getRisk() != null) {
            builder.setRisk(override.getRisk().getValue());
        }
        if (override.getConfidence() != null) {
            builder.setConfidence(override.getConfidence().getValue());
        }
        if (override.getReferences() != null) {
            builder.setReference(mergeReferences(override.getReferences()));
        }
        if (override.getAlertTags() != null) {
            builder.setTags(override.getAlertTags());
        }
    }

    static String mergeReferences(List<String> references) {
        if (references != null && !references.isEmpty()) {
            return String.join("\n", references);
        }
        return "";
    }

    private static <T> void setIfNotNull(T value, Consumer<T> setter) {
        if (value != null) {
            setter.accept(value);
        }
    }

    /**
     * Provided for syntactical sugar when the method to call does not return anything. See {@link
     * #callOptionalScriptMethod(Callable)}.
     */
    static void callOptionalScriptMethod(ThrowingRunnable method) throws Exception {
        callOptionalScriptMethod(
                () -> {
                    method.run();
                    return null;
                });
    }

    /**
     * Calls the given method, handling exceptions thrown by some script engines when the method is
     * not defined.
     *
     * @param method the method to call.
     * @return the result of the method call, or {@code null} if the method is not defined.
     * @param <T> the type of the method's result.
     * @throws Exception any other exception thrown by the method.
     */
    static <T> T callOptionalScriptMethod(Callable<T> method) throws Exception {
        try {
            return method.call();
        } catch (UndeclaredThrowableException ignored) {
            // Python and Kotlin scripts throw this exception when the method is not implemented
            return null;
        } catch (Exception e) {
            if (e.getCause() != null
                    && "groovy.lang.MissingMethodException"
                            .equals(e.getCause().getClass().getCanonicalName())) {
                // Groovy scripts throw this exception when the method is not implemented
                return null;
            }
            throw e;
        }
    }

    @FunctionalInterface
    interface ThrowingRunnable {
        void run() throws Exception;
    }
}
