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
package org.zaproxy.addon.exim.sites;

import java.io.Writer;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.addon.exim.ExporterType;

/** Exporter for Sites Tree YAML format. Does not support message export. */
public class YamlExporter extends ExporterType {

    public static final String ID = "yaml";

    public YamlExporter() {
        super(ID, Constant.messages.getString("exim.exporter.type.yaml"));
    }

    public static boolean isYamlExporter(String id) {
        return ID.equalsIgnoreCase(id);
    }

    @Override
    public boolean supportsMessageExport() {
        return false;
    }

    @Override
    public void begin(Writer writer) {
        // Not used for message export.
    }

    @Override
    public void write(Writer writer, HistoryReference ref) {
        // Not used for message export.
    }

    @Override
    public void end(Writer writer) {
        // Not used for message export.
    }
}
