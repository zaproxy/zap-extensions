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
package org.zaproxy.addon.exim;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry of exporter types that extensions can register to provide additional export formats.
 *
 * @since 0.14.0
 */
public final class ExporterTypeRegistry {

    private static final Map<String, Exporter.ExporterType> TYPES = new ConcurrentHashMap<>();
    private static final Map<String, String> DISPLAY_NAMES = new ConcurrentHashMap<>();

    private ExporterTypeRegistry() {}

    static void register(String typeId, Exporter.ExporterType exporterType, String displayName) {
        if (typeId != null && !typeId.isBlank() && exporterType != null && displayName != null) {
            TYPES.put(typeId.toLowerCase(), exporterType);
            DISPLAY_NAMES.put(typeId.toLowerCase(), displayName);
        }
    }

    static void unregister(String typeId) {
        if (typeId != null) {
            String key = typeId.toLowerCase();
            TYPES.remove(key);
            DISPLAY_NAMES.remove(key);
        }
    }

    static Exporter.ExporterType getExporterType(String typeId) {
        return typeId != null ? TYPES.get(typeId.toLowerCase()) : null;
    }

    static String getDisplayName(String typeId) {
        return typeId != null ? DISPLAY_NAMES.get(typeId.toLowerCase()) : null;
    }

    static List<ExporterTypeInfo> getRegisteredTypes() {
        List<ExporterTypeInfo> list = new ArrayList<>();
        for (Map.Entry<String, String> e : DISPLAY_NAMES.entrySet()) {
            list.add(new ExporterTypeInfo(e.getKey(), e.getValue()));
        }
        return list;
    }

    /** Info about a registered exporter type. */
    public record ExporterTypeInfo(String id, String displayName) {}
}
