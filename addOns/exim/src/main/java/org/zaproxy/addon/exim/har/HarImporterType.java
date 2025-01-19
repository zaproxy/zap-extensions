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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import de.sstoehr.harreader.model.HarEntry;
import java.io.IOException;
import java.io.Reader;
import java.util.Objects;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.exim.Importer.ImporterType;
import org.zaproxy.addon.exim.ImporterOptions.MessageHandler;

public class HarImporterType implements ImporterType {

    private static final String LOG_FIELD = "log";
    private static final String ENTRIES_FIELD = "entries";

    private JsonParser parser;

    @Override
    public void begin(Reader reader) throws IOException {
        parser = HarUtils.JSON_MAPPER.createParser(reader);

        validateNextToken(JsonToken.START_OBJECT, null);
        validateNextToken(JsonToken.FIELD_NAME, LOG_FIELD);
        validateNextToken(JsonToken.START_OBJECT, LOG_FIELD);

        while (!isNextToken(JsonToken.FIELD_NAME, ENTRIES_FIELD)) {
            parser.skipChildren();
        }

        validateNextToken(JsonToken.START_ARRAY, ENTRIES_FIELD);
        parser.nextToken();
    }

    private boolean isNextToken(JsonToken wantedToken, String wantedName) throws IOException {
        JsonToken token = parser.nextToken();
        if (token == null) {
            throw new IOException("Failed to find entries property in HAR log.");
        }
        if (token != wantedToken) {
            return false;
        }

        return wantedName.equals(parser.currentName());
    }

    private void validateNextToken(JsonToken expectedToken, String expectedName)
            throws IOException {
        JsonToken token = parser.nextToken();
        if (token != expectedToken) {
            throw new IOException("Unexpected token " + token + ", expected: " + expectedToken);
        }

        String name = parser.currentName();
        if (!Objects.equals(name, expectedName)) {
            throw new IOException("Unexpected name " + name + ", expected: " + expectedName);
        }
    }

    @Override
    public void read(Reader reader, MessageHandler handler) throws Exception {
        HarEntry entry;
        while ((entry = parser.readValueAs(HarEntry.class)) != null) {
            HttpMessage message = HarUtils.createHttpMessage(entry);
            handler.handle(message);
        }
    }

    @Override
    public void end(Reader reader) throws IOException {
        // Nothing else to do once the "entries" is consumed.
    }
}
