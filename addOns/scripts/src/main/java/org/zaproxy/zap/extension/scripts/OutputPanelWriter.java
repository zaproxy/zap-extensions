/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.scripts;

import java.io.IOException;
import java.io.Writer;
import org.parosproxy.paros.view.OutputPanel;

public class OutputPanelWriter extends Writer {

    private final OutputPanel outputPanel;
    private final String sourceName;
    private final StringBuffer buffer = new StringBuffer();

    public OutputPanelWriter(OutputPanel outputPanel, String sourceName) {
        this.outputPanel = outputPanel;
        this.sourceName = sourceName;
    }

    @Override
    public void write(int c) throws IOException {
        buffer.append(c);
    }

    @Override
    public void write(String str, int off, int len) throws IOException {
        buffer.append(str, off, len);
    }

    @Override
    public void write(char[] cbuf, int off, int len) throws IOException {
        buffer.append(cbuf, off, len);
    }

    @Override
    public void flush() {
        outputPanel.append(buffer.toString(), sourceName);
        buffer.setLength(0);
    }

    @Override
    public void close() throws IOException {
        // Ignore
    }
}
