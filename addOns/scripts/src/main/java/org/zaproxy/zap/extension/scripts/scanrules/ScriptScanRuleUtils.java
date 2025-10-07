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

import java.util.List;
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
}
