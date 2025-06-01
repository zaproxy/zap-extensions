/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.exim.har;

import com.fasterxml.jackson.core.JsonGenerator;
import de.sstoehr.harreader.model.HarLog;
import java.io.IOException;
import java.io.Writer;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.addon.exim.Exporter.ExporterType;

public class HarExporter implements ExporterType {

    private JsonGenerator generator;

    @Override
    public void begin(Writer writer) throws IOException {
        generator = HarUtils.JSON_MAPPER.createGenerator(writer).useDefaultPrettyPrinter();

        generator.writeStartObject();
        generator.writeObjectFieldStart("log");
        HarLog log = HarUtils.createZapHarLog();
        generator.writeStringField("version", log.getVersion());
        generator.writePOJOField("creator", log.getCreator());
        generator.writeArrayFieldStart("entries");
    }

    @Override
    public void write(Writer writer, HistoryReference ref) throws IOException {
        try {
            generator.writePOJO(
                    HarUtils.createHarEntry(
                            ref.getHistoryId(), ref.getHistoryType(), ref.getHttpMessage()));
        } catch (DatabaseException ignore) {
            // The message is cached in the HistoryReference.
        }
    }

    @Override
    public void end(Writer writer) throws IOException {
        generator.writeEndArray();
        generator.writeEndObject();
        generator.writeEndObject();
        generator.flush();
    }
}
