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
package org.zaproxy.addon.authhelper;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;

public class DiagnosticDataLoader {

    public static List<HttpMessage> loadTestData(File file) throws Exception {
        List<HttpMessage> messages = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            HttpMessage currentMessage = null;
            StringBuilder headerBuilder = new StringBuilder();
            StringBuilder bodyBuilder = new StringBuilder();
            boolean isResponse = false;
            boolean isHeader = true;

            while ((line = reader.readLine()) != null) {
                if (line.startsWith(">>>>>")) {
                    // Start/end of the request
                    if (currentMessage != null) {
                        // Save previous message
                        if (!headerBuilder.isEmpty()) {
                            currentMessage.setResponseHeader(
                                    new HttpResponseHeader(headerBuilder.toString()));
                        }
                        if (!bodyBuilder.isEmpty()) {
                            currentMessage.setResponseBody(bodyBuilder.toString());
                            currentMessage
                                    .getResponseHeader()
                                    .setContentLength(currentMessage.getResponseBody().length());
                        }
                        messages.add(currentMessage);
                    }
                    // Start new request message
                    currentMessage = new HttpMessage();
                    headerBuilder.setLength(0);
                    bodyBuilder.setLength(0);
                    isHeader = true;
                    isResponse = false;
                } else if (line.startsWith("<<<")) {
                    // Start of the response
                    currentMessage.setRequestHeader(
                            new HttpRequestHeader(headerBuilder.toString()));
                    if (!bodyBuilder.isEmpty()) {
                        currentMessage.setRequestBody(bodyBuilder.toString());
                        currentMessage
                                .getRequestHeader()
                                .setContentLength(currentMessage.getRequestBody().length());
                    }
                    isResponse = true;
                    headerBuilder.setLength(0);
                    bodyBuilder.setLength(0);
                } else if (line.isEmpty()) {
                    if (isHeader) {
                        isHeader = false;
                    }
                } else {
                    if (isHeader) {
                        if (headerBuilder.length() == 0 && !isResponse) {
                            headerBuilder.append(line).append(" HTTP/1.1 \r\n");
                        } else {
                            headerBuilder.append(line).append("\r\n");
                        }

                    } else {
                        bodyBuilder.append(line).append("\n");
                    }
                }
            }
        }
        return messages;
    }
}
