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
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.exim.ImporterOptions.MessageHandler;
import org.zaproxy.addon.exim.ImporterType;

/** Importer type that imports messages from HAR format. */
public class HarImporterType extends ImporterType {

    public static final String ID = "har";

    public HarImporterType() {
        super(ID, Constant.messages.getString("exim.importer.type.har"));
    }

    private static final String LOG_FIELD = "log";
    private static final String ENTRIES_FIELD = "entries";

    @Override
    public void importData(Reader reader, MessageHandler handler) throws Exception {
        JsonParser parser = HarUtils.JSON_MAPPER.createParser(reader);

        validateNextToken(parser, JsonToken.START_OBJECT, null);
        validateNextToken(parser, JsonToken.FIELD_NAME, LOG_FIELD);
        validateNextToken(parser, JsonToken.START_OBJECT, LOG_FIELD);

        while (!isNextToken(parser, JsonToken.FIELD_NAME, ENTRIES_FIELD)) {
            parser.skipChildren();
        }

        validateNextToken(parser, JsonToken.START_ARRAY, ENTRIES_FIELD);
        parser.nextToken();

        HarEntry entry;
        while ((entry = parser.readValueAs(HarEntry.class)) != null) {
            HttpMessage message = HarUtils.createHttpMessage(entry);
            handler.handle(message);
        }
    }

    private static boolean isNextToken(JsonParser parser, JsonToken wantedToken, String wantedName)
            throws IOException {
        JsonToken token = parser.nextToken();
        if (token == null) {
            throw new IOException("Failed to find entries property in HAR log.");
        }
        if (token != wantedToken) {
            return false;
        }

        return wantedName.equals(parser.currentName());
    }

    private static void validateNextToken(
            JsonParser parser, JsonToken expectedToken, String expectedName) throws IOException {
        JsonToken token = parser.nextToken();
        if (token != expectedToken) {
            throw new IOException("Unexpected token " + token + ", expected: " + expectedToken);
        }

        String name = parser.currentName();
        if (!Objects.equals(name, expectedName)) {
            throw new IOException("Unexpected name " + name + ", expected: " + expectedName);
        }
    }
}
