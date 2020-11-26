/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest;

import javax.script.ScriptException;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScript;
import org.zaproxy.zap.extension.pscan.scanner.ScriptsPassiveScanner;
import org.zaproxy.zest.core.v1.ZestRequest;

public class ZestPassiveRunner extends ZestZapRunner implements PassiveScript {

    private ZestScriptWrapper script = null;
    private ScriptsPassiveScanner sps = null;
    private HttpMessage msg = null;
    private ExtensionZest extension = null;

    private Logger logger = Logger.getLogger(ZestPassiveRunner.class);

    public ZestPassiveRunner(ExtensionZest extension, ZestScriptWrapper script) {
        super(extension, script);
        this.extension = extension;
        // this.runner = this.getExtension().getRunner(script);
        this.script = script;
    }

    @Override
    public void scan(ScriptsPassiveScanner scriptsPassiveScanner, HttpMessage msg, Source source)
            throws ScriptException {
        logger.debug("Zest PassiveScan script: " + this.script.getName());
        this.sps = scriptsPassiveScanner;
        this.msg = msg;

        try {
            // Create the previous request so the script has something to run against
            ZestRequest req = ZestZapUtils.toZestRequest(msg, false, true, extension.getParam());
            req.setResponse(ZestZapUtils.toZestResponse(msg));

            this.run(script.getZestScript(), req, null);

        } catch (Exception e) {
            throw new ScriptException(e);
        }
    }

    @Override
    public void alertFound(Alert alert) {
        // Override this as we can put in more info from the script and message
        sps.newAlert()
                .setRisk(alert.getRisk())
                .setConfidence(alert.getConfidence())
                .setName(alert.getName())
                .setDescription(script.getDescription())
                .setMessage(msg)
                .raise();
    }
}
