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
import java.io.Writer;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.addon.exim.ExporterType;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestScript;

/** Exports history messages to Zest script format. */
public class ZestExporter extends ExporterType {

    public static final String ID = "zest";

    private final ExtensionZest extensionZest;
    private ZestScript script;

    public ZestExporter(ExtensionZest extensionZest) {
        super(ID, Constant.messages.getString("zest.exim.type"));
        this.extensionZest = extensionZest;
    }

    @Override
    public void begin(Writer writer) throws IOException {
        script = new ZestScript();
        script.setTitle("Exported from ZAP " + Constant.PROGRAM_VERSION + " History");
        script.setType(ZestScript.Type.StandAlone.name());
    }

    @Override
    public void write(Writer writer, HistoryReference ref) throws IOException {
        if (ref.getHistoryType() == HistoryReference.TYPE_TEMPORARY) {
            return;
        }
        try {
            var msg = ref.getHttpMessage();
            if (msg != null) {
                ZestRequest request =
                        ZestZapUtils.toZestRequest(msg, true, extensionZest.getParam());
                script.add(request);
            }
        } catch (Exception e) {
            // Skip messages that fail to convert
        }
    }

    @Override
    public void end(Writer writer) throws IOException {
        writer.write(extensionZest.convertElementToString(script));
    }

    @Override
    public ExporterType createForExport() {
        return new ZestExporter(extensionZest);
    }
}
