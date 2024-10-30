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
package org.zaproxy.zap.extension.sequence;

import java.io.IOException;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.zap.extension.ascan.ActiveScan;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestZapRunner;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;
import org.zaproxy.zest.core.v1.ZestActionFailException;
import org.zaproxy.zest.core.v1.ZestAssertFailException;
import org.zaproxy.zest.core.v1.ZestAssignFailException;
import org.zaproxy.zest.core.v1.ZestClientFailException;
import org.zaproxy.zest.core.v1.ZestInvalidCommonTestException;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestResponse;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;

public class StdActiveScanRunner extends ZestZapRunner {

    private static final int SEQUENCE_HISTORY_TYPE = HistoryReference.TYPE_SEQUENCE_TEMPORARY;
    private static final Logger LOGGER = LogManager.getLogger(StdActiveScanRunner.class);

    private ZestScriptWrapper wrapper;
    private ScanPolicy scanPolicy;
    private User user;

    private final String name;
    private final SiteNode fakeRoot;
    private final SiteNode fakeDirectory;
    private int step;

    private final ExtensionHistory extHistory;
    private final ExtensionSequence extSeq;

    public StdActiveScanRunner(ZestScriptWrapper wrapper, ScanPolicy scanPolicy, User user) {
        super(
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionZest.class),
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionNetwork.class),
                wrapper);

        this.wrapper = wrapper;
        this.scanPolicy = scanPolicy;
        this.user = user;

        this.extHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
        this.extSeq =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSequence.class);

        this.name = wrapper.getName();
        fakeRoot = new SiteNode(null, HistoryReference.TYPE_SEQUENCE_TEMPORARY, name);
        fakeDirectory = new SiteNode(null, HistoryReference.TYPE_SEQUENCE_TEMPORARY, name);
        fakeRoot.add(fakeDirectory);
        step = 0;
    }

    @Override
    public String run(ZestScript script, Map<String, String> params)
            throws ZestAssertFailException,
                    ZestActionFailException,
                    IOException,
                    ZestInvalidCommonTestException,
                    ZestAssignFailException,
                    ZestClientFailException {
        return super.run(this.wrapper.getZestScript(), params);
    }

    @Override
    public ZestResponse runStatement(
            ZestScript script, ZestStatement stmt, ZestResponse lastResponse)
            throws ZestAssertFailException,
                    ZestActionFailException,
                    ZestInvalidCommonTestException,
                    IOException,
                    ZestAssignFailException,
                    ZestClientFailException {
        ZestResponse resp = super.runStatement(script, stmt, lastResponse);

        if (stmt instanceof ZestRequest) {
            step += 1;
            HttpMessage msg =
                    ZestZapUtils.toHttpMessage(this.getLastRequest(), this.getLastResponse());
            SiteNode node = messageToSiteNode(msg, step);
            if (node != null) {
                fakeDirectory.add(node);

                int scanId =
                        extSeq.getExtActiveScan()
                                .startScan(new Target(node), user, new Object[] {scanPolicy});

                ActiveScan ascan = extSeq.getExtActiveScan().getScan(scanId);
                while (ascan.isRunning()) {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        // Ignore
                    }
                }
            }
        }

        return resp;
    }

    private SiteNode messageToSiteNode(HttpMessage msg, int step) {
        SiteNode temp = null;
        try {
            temp =
                    new SiteNode(
                            null,
                            SEQUENCE_HISTORY_TYPE,
                            Constant.messages.getString("sequence.automation.step", step));
            HistoryReference ref =
                    new HistoryReference(
                            extHistory.getModel().getSession(), SEQUENCE_HISTORY_TYPE, msg);

            extHistory.addHistory(ref);
            // The "ALERT-TAG" prefix means these tags will propagate to any alerts raised against
            // them dropping that prefix.
            // FIXME: replace with core constant after 2.16
            ref.addTag("ALERT-TAG:ZAP-SEQ-NAME=" + wrapper.getName());
            ref.addTag("ALERT-TAG:ZAP-SEQ-INDEX=" + step);

            temp.setHistoryReference(ref);

        } catch (Exception e) {
            LOGGER.error(
                    "An exception occurred while converting a HttpMessage to SiteNode: {}",
                    e.getMessage(),
                    e);
        }
        return temp;
    }
}
