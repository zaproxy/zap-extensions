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

public class OutputPanelWriter extends Writer {

    private OutputPanel outputPanel;
    private boolean enabled = true;

    public OutputPanelWriter(OutputPanel outputPanel) {
        this.outputPanel = outputPanel;
    }

    @Override
    public void write(int c) throws IOException {
        if (enabled) {
            outputPanel.append(String.valueOf((char) c));
        }
    }

    @Override
    public void write(String str, int off, int len) throws IOException {
        if (enabled) {
            outputPanel.append(str.substring(off, len));
        }
    }

    @Override
    public void write(char[] cbuf, int off, int len) throws IOException {
        if (enabled) {
            outputPanel.append(new String(cbuf, off, len));
        }
    }

    @Override
    public void flush() throws IOException {
        // Ignore
    }

    @Override
    public void close() throws IOException {
        // Ignore
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
