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
package org.zaproxy.zap.extension.zest.exim;

import java.io.IOException;
import java.io.Reader;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.exim.ImporterOptions.MessageHandler;
import org.zaproxy.addon.exim.ImporterType;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zest.core.v1.ZestElement;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;

/** Importer type that imports messages from Zest script format. */
public class ZestImporterType extends ImporterType {

    public static final String ID = "zest";

    public ZestImporterType() {
        super(ID, Constant.messages.getString("zest.exim.type"));
    }

    @Override
    public void importData(Reader reader, MessageHandler handler) throws Exception {
        String content = readFully(reader);
        if (content == null || content.isBlank()) {
            throw new IOException(Constant.messages.getString("zest.exim.file.import.error.empty"));
        }
        ZestScript script;
        try {
            ZestElement element = ZestZapUtils.parseZestScript(content);
            if (element instanceof ZestScript) {
                script = (ZestScript) element;
            } else {
                throw new IOException(
                        Constant.messages.getString("zest.exim.file.import.error.not.script"));
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(
                    Constant.messages.getString(
                            "zest.exim.file.import.error.parse", e.getMessage()),
                    e);
        }

        for (ZestStatement statement : script.getStatements()) {
            if (statement instanceof ZestRequest) {
                ZestRequest request = (ZestRequest) statement;
                try {
                    HttpMessage msg = ZestZapUtils.toHttpMessage(request, request.getResponse());
                    if (msg != null) {
                        handler.handle(msg);
                    }
                } catch (Exception e) {
                    // Skip requests that fail to convert
                }
            }
        }
    }

    private static String readFully(Reader reader) throws IOException {
        StringBuilder sb = new StringBuilder();
        char[] buf = new char[8192];
        int n;
        while ((n = reader.read(buf)) != -1) {
            sb.append(buf, 0, n);
        }
        return sb.toString();
    }
}
