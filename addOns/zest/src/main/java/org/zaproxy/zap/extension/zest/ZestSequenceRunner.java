/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.script.SequenceScript;
import org.zaproxy.zap.model.StructuralNode;
import org.zaproxy.zap.model.StructuralSiteNode;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zest.core.v1.ZestAssignFailException;
import org.zaproxy.zest.core.v1.ZestAssignment;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestResponse;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ZestSequenceRunner extends ZestZapRunner implements SequenceScript {

    private ZestScriptWrapper script = null;
    private static final Logger logger = Logger.getLogger(ZestSequenceRunner.class);

    private static final int SEQUENCE_HISTORY_TYPE = HistoryReference.TYPE_SEQUENCE_TEMPORARY;

    private static final Map<String, String> EMPTYPARAMS = new HashMap<String, String>();
    private AbstractPlugin currentPlugin = null;
    private ZestResponse tempLastResponse = null;
    private ExtensionHistory extHistory = null;
    private ExtensionActiveScan extAscan = null;

    /**
     * Initialize a ZestSequenceRunner.
     *
     * @param extension The Zest Extension.
     * @param wrapper A wrapper for the current script.
     */
    public ZestSequenceRunner(ExtensionZest extension, ZestScriptWrapper wrapper) {
        super(extension, wrapper);
        this.script = wrapper;
        this.setStopOnAssertFail(false);
    }

    @Override
    public List<HttpMessage> getAllRequestsInScript() {
        ArrayList<HttpMessage> requests = new ArrayList<HttpMessage>();

        for (ZestStatement stmt : this.script.getZestScript().getStatements()) {
            try {
                if (stmt instanceof ZestRequest) {
                    ZestRequest req = (ZestRequest) stmt;
                    HttpMessage scrMessage = ZestZapUtils.toHttpMessage(req, req.getResponse());
                    requests.add(scrMessage);
                }
            } catch (Exception e) {
                logger.debug(
                        "Exception occurred while fetching HttpMessages from sequence script: "
                                + e.getMessage());
            }
        }
        return requests;
    }

    @Override
    public HttpMessage runSequenceBefore(HttpMessage msg, AbstractPlugin plugin) {
        HttpMessage msgOriginal = msg.cloneAll();

        this.currentPlugin = plugin;
        try {
            // Get the subscript for the message to be scanned, and run it. The subscript will
            // contain all
            // prior statements in the script.
            HttpMessage msgScript = getMatchingMessageFromScript(msg);
            ZestScript scr = getBeforeSubScript(msgScript);

            run(scr, EMPTYPARAMS);

            // Once the script has run, update the message with results from
            mergeRequestBodyFromScript(msgOriginal);
            String reqBody = msgOriginal.getRequestBody().toString();
            reqBody = java.net.URLDecoder.decode(reqBody, "UTF-8");
            reqBody = this.replaceVariablesInString(reqBody, false);
            msgOriginal.setRequestBody(reqBody);
            msgOriginal.getRequestHeader().setContentLength(msgOriginal.getRequestBody().length());
        } catch (Exception e) {
            logger.debug(
                    "Error running Sequence script in 'runSequenceBefore' method : "
                            + e.getMessage());
        }
        return msgOriginal;
    }

    private void mergeRequestBodyFromScript(HttpMessage msg) {
        HttpMessage scrMsg = getMatchingMessageFromScript(msg);

        if (scrMsg != null) {
            String reqBodyFromScript = scrMsg.getRequestBody().toString();
            if (reqBodyFromScript == null || reqBodyFromScript.isEmpty()) {
                return;
            }
            String[] nameValuePairs = reqBodyFromScript.split("&");

            for (String pair : nameValuePairs) {
                String[] entry = pair.split("=");
                if (entry[1].startsWith("{{") && entry[1].endsWith("}}")) {
                    String reqBodyFromOriginal = msg.getRequestBody().toString();
                    if (reqBodyFromOriginal.contains(entry[0])) {
                        String mergedRequestBody = "";
                        String[] originalPairs = reqBodyFromOriginal.split("&");
                        for (int i = 0; i < originalPairs.length; i++) {
                            String originalPair = originalPairs[i];
                            String[] originalEntry = originalPair.split("=");
                            if (originalEntry[0].equals(entry[0])) {
                                originalEntry[1] = entry[1];
                            }
                            mergedRequestBody += originalEntry[0] + "=" + originalEntry[1];
                            if (i < (originalPairs.length - 1)) {
                                mergedRequestBody += "&";
                            }
                        }
                        msg.setRequestBody(mergedRequestBody);
                    }
                }
            }
        }
    }

    @Override
    public void runSequenceAfter(HttpMessage msg, AbstractPlugin plugin) {

        try {
            this.tempLastResponse = ZestZapUtils.toZestResponse(msg);
        } catch (Exception e) {
            // Ignore - probably initial request, and therefore no "last response" available.
        }

        this.currentPlugin = plugin;
        try {
            HttpMessage msgScript = getMatchingMessageFromScript(msg);
            ZestScript scr = getAfterSubScript(msgScript);

            run(scr, EMPTYPARAMS);

        } catch (Exception e) {
            logger.debug(
                    "Error running Sequence script in 'runSequenceAfter' method : "
                            + e.getMessage());
        }
    }

    @Override
    public ZestResponse send(ZestRequest request) throws IOException {
        HttpMessage msg = ZestZapUtils.toHttpMessage(request, null);
        HostProcess parent = currentPlugin.getParent();
        HttpSender httpSender = parent.getHttpSender();
        msg.setRequestingUser(httpSender.getUser(msg));
        httpSender.sendAndReceive(msg, request.isFollowRedirects());
        parent.notifyNewMessage(currentPlugin, msg);
        return ZestZapUtils.toZestResponse(msg);
    }

    @Override
    public boolean isPartOfSequence(HttpMessage msg) {
        for (ZestStatement stmt : script.getZestScript().getStatements()) {
            if (isSameRequest(msg, stmt)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String handleAssignment(
            ZestScript script, ZestAssignment assign, ZestResponse lastResponse)
            throws ZestAssignFailException {
        if (lastResponse == null) {
            lastResponse = this.tempLastResponse;
            this.tempLastResponse = null;
        }
        return super.handleAssignment(script, assign, lastResponse);
    }

    private boolean isSameRequest(HttpMessage msg, ZestStatement stmt) {
        try {
            if (stmt instanceof ZestRequest) {
                ZestRequest zr = (ZestRequest) stmt;
                Session session = Model.getSingleton().getSession();
                SiteNode msgNode = session.getSiteTree().findNode(msg);
                if (msgNode == null) {
                    return false;
                }
                SiteNode stmtNode =
                        session.getSiteTree().findNode(ZestZapUtils.toHttpMessage(zr, null));
                if (stmtNode == null) {
                    return false;
                }
                if (msgNode.equals(stmtNode)) {
                    return true;
                } else {
                    return false;
                }
            }
        } catch (Exception e) {
            logger.debug("Exception in ZestSequenceRunner isSameRequest:" + e.getMessage());
        }
        return false;
    }

    private HttpMessage getMatchingMessageFromScript(HttpMessage msg) {
        try {
            for (ZestStatement stmt : this.script.getZestScript().getStatements()) {
                if (isSameRequest(msg, stmt)) {
                    ZestRequest req = (ZestRequest) stmt;
                    return ZestZapUtils.toHttpMessage(req, req.getResponse());
                }
            }
        } catch (Exception e) {
            logger.debug("Exception in getMatchingMessageFromScript: " + e.getMessage());
        }
        return null;
    }

    // Gets a script containing all statements prior to the supplied HttpMessage.
    private ZestScript getBeforeSubScript(HttpMessage msg) {
        ZestScript scr = new ZestScript();
        ArrayList<ZestStatement> stmts = new ArrayList<ZestStatement>();

        for (ZestStatement stmt : this.script.getZestScript().getStatements()) {
            if (isSameRequest(msg, stmt)) {
                break;
            }
            stmts.add(stmt);
        }
        scr.setStatements(stmts);
        return scr;
    }

    // Gets a script containing all statements after the supplied HttpMessage.
    private ZestScript getAfterSubScript(HttpMessage msg) {
        ZestScript scr = new ZestScript();
        ArrayList<ZestStatement> stmts = new ArrayList<ZestStatement>();
        boolean foundMatch = false;
        for (ZestStatement stmt : this.script.getZestScript().getStatements()) {
            if (!foundMatch && isSameRequest(msg, stmt)) {
                foundMatch = true;
                continue;
            }

            if (foundMatch) {
                stmts.add(stmt);
            }
        }
        scr.setStatements(stmts);
        return scr;
    }

    @Override
    public void scanSequence() {
        String name =
                Constant.messages.getString("zest.script.sequence.scanname", script.getName());
        SiteNode fakeRoot = new SiteNode(null, SEQUENCE_HISTORY_TYPE, name);
        SiteNode fakeDirectory = new SiteNode(null, SEQUENCE_HISTORY_TYPE, name);

        for (ZestStatement stmt : script.getZestScript().getStatements()) {
            try {
                if (stmt instanceof ZestRequest) {
                    ZestRequest req = (ZestRequest) stmt;
                    HttpMessage msg = ZestZapUtils.toHttpMessage(req, req.getResponse());
                    SiteNode node = messageToSiteNode(msg);
                    if (node != null) {
                        fakeDirectory.add(node);
                    }
                }
            } catch (Exception e) {
                logger.error(
                        "An exception occurred while scanning sequence directly: " + e.getMessage(),
                        e);
            }
        }
        fakeRoot.add(fakeDirectory);

        URI uri = null;
        try {
            // Use dummy URI for fake nodes
            uri = new URI("http://zest-scan-sequence.zap/", true);
        } catch (URIException ignore) {
            // It's a valid URI.
        }
        Target target =
                new SequenceTarget(new SequenceStructuralSiteNode(fakeRoot, name, uri), name);
        target.setRecurse(true);
        getActiveScanner().startScan(target);
    }

    private SiteNode messageToSiteNode(HttpMessage msg) {
        SiteNode temp = null;
        try {
            temp = new SiteNode(null, SEQUENCE_HISTORY_TYPE, "");
            HistoryReference ref =
                    new HistoryReference(
                            getHistory().getModel().getSession(), SEQUENCE_HISTORY_TYPE, msg);
            getHistory().addHistory(ref);
            temp.setHistoryReference(ref);
        } catch (Exception e) {
            logger.error(
                    "An exception occurred while converting a HttpMessage to SiteNode: "
                            + e.getMessage(),
                    e);
        }
        return temp;
    }

    private ExtensionHistory getHistory() {
        if (extHistory == null) {
            extHistory =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionHistory.class);
        }
        return extHistory;
    }

    private ExtensionActiveScan getActiveScanner() {
        if (extAscan == null) {
            extAscan =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionActiveScan.class);
        }
        return extAscan;
    }

    private static class SequenceStructuralSiteNode extends StructuralSiteNode {

        private final String customName;
        private final URI customURI;
        private final SequenceStructuralSiteNode childNode;

        public SequenceStructuralSiteNode(SiteNode rootNode, String customName, URI customURI) {
            super(rootNode);
            this.customName = customName;
            this.customURI = customURI;
            this.childNode =
                    new SequenceStructuralSiteNode(
                            (SiteNode) rootNode.getChildAt(0), customName, customURI, null);
        }

        private SequenceStructuralSiteNode(
                SiteNode node, String customName, URI customURI, Object dummy) {
            super(node);
            this.customName = customName;
            this.customURI = customURI;
            this.childNode = null;
        }

        @Override
        public String getName() {
            return customName;
        }

        @Override
        public URI getURI() {
            return customURI;
        }

        @Override
        public Iterator<StructuralNode> getChildIterator() {
            if (childNode != null) {
                return new SingleStructuralSiteNodeIterator(childNode);
            }
            return super.getChildIterator();
        }

        private static class SingleStructuralSiteNodeIterator implements Iterator<StructuralNode> {

            private final SequenceStructuralSiteNode node;
            private boolean exhausted;

            public SingleStructuralSiteNodeIterator(SequenceStructuralSiteNode node) {
                this.node = node;
            }

            @Override
            public boolean hasNext() {
                return !exhausted;
            }

            @Override
            public StructuralSiteNode next() {
                if (exhausted) {
                    throw new NoSuchElementException("No more (fake) sequence nodes.");
                }
                exhausted = true;
                return node;
            }

            @Override
            public void remove() {}
        }
    }

    private static class SequenceTarget extends Target {

        private final String displayName;

        public SequenceTarget(StructuralSiteNode node, String displayName) {
            super(node);
            this.displayName = displayName;
        }

        @Override
        public String getDisplayName() {
            return displayName;
        }
    }
}
