/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.authenticationhelper.statusscan;

import java.awt.EventQueue;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import org.apache.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.authenticationhelper.ExtensionAuthenticationHelper;
import org.zaproxy.zap.extension.authenticationhelper.OptionsParamAuthenticationHelper;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusTableEntry.AuthenticationStatus;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.ui.AuthenticationHelperDialog;
import org.zaproxy.zap.model.GenericScanner2;
import org.zaproxy.zap.model.StructuralNode;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;

public class AuthenticationStatusScanner implements GenericScanner2 {

    private static final Logger logger = Logger.getLogger(AuthenticationStatusScanner.class);

    /**
     * Constant indicating the state of the {@code AuthenticationStatusScanner}. Can be one of
     * {@code NOT_STARTED}, {@code RUNNING}, {@code PAUSED}, {@code FINISHED} or {@code STOPPED}.
     */
    private static enum State {
        NOT_STARTED,
        RUNNING,
        PAUSED,
        FINISHED,
        STOPPED
    };

    public static enum IndicatorStatus {
        FOUND,
        NOT_FOUND,
        NOT_DEFINED,
        COULD_NOT_VERIFY;
    }

    /**
     * The {@link Target} of the scan, never null. Initially set via the {@link
     * AuthenticationHelperDialog}.
     */
    private final Target target;

    /**
     * The selected {@link User}, never null. Initially set via the {@link
     * AuthenticationHelperDialog}.
     */
    private final User user;

    private final ConnectionParam connectionParam;

    private AuthenticationStatusTableModel authenticationStatusTableModel;
    private String displayName;
    private int scanId;
    private HttpSender httpSender;
    private int progress;
    private int tasksDoneCount;
    private int tasksTotalCount;
    private volatile State state;
    private Pattern loggedInIndicatorPattern;
    private Pattern loggedOutIndicatorPattern;

    private int numberOfSuccessfulAuthentications;
    private int numberOfFailedAuthentications;
    private int numberOfConflictingAuthentications;
    private int numberOfUnknownAuthentications;

    private final int MAXIMUM_SEND_AND_RECEIVE_ERROR_COUNT = 3;
    private int sendAndReceiveErrorCount;

    private final List<HistoryReference> historyReferencesToScan;

    private Thread thread;

    private AuthenticationStatusScanListenner authenticationStatusListener = null;

    private ExtensionAuthenticationHelper extAuthHelper;
    private OptionsParamAuthenticationHelper config;

    public AuthenticationStatusScanner(
            ExtensionAuthenticationHelper extAuthHelper,
            String displayName,
            Target target,
            User scanUser,
            int scanId,
            ConnectionParam connectionParam) {
        this.extAuthHelper = extAuthHelper;
        this.target = target;
        this.scanId = scanId;
        this.user = scanUser;
        this.connectionParam = connectionParam;

        setDisplayName(displayName);

        historyReferencesToScan = new ArrayList<>();

        progress = 0;
        numberOfSuccessfulAuthentications = 0;
        numberOfFailedAuthentications = 0;
        numberOfConflictingAuthentications = 0;
        numberOfUnknownAuthentications = 0;

        sendAndReceiveErrorCount = 0;

        state = State.NOT_STARTED;

        authenticationStatusTableModel = new AuthenticationStatusTableModel();
    }

    public void start() {
        reset();
        if (State.NOT_STARTED.equals(state)) {
            state = State.RUNNING;
            logger.info("Started authentication status check scan for  " + getDisplayName());

            progress = 0;
            thread = new Thread(this);
            thread.setName("AuthenticationStatusScanThread");
            thread.start();
        }
    }

    @Override
    public void run() {
        try {
            if (target.getStartNodes() != null) {
                collectHistoryReferencesToScan();
                tasksTotalCount = historyReferencesToScan.size();

                // if the start node is in the ignore list
                if (tasksTotalCount == 0) {
                    authenticationStatusListener.updateProgress(
                            scanId, getDisplayName(), 100, 0, 0, 0, 0);
                    complete();
                }

                while (isRunning()) {
                    for (HistoryReference historyReference : historyReferencesToScan) {
                        scanAndNotifyResult(historyReference);
                    }
                }
            }
        } catch (Exception e) {
            logger.error("An error occured while checking authentication status: ", e);
        }
    }

    private void collectHistoryReferencesToScan() {
        List<StructuralNode> nodes = target.getStartNodes();

        for (StructuralNode node : nodes) {
            addHistoryReferenceToScan(node);
        }
    }

    private void addHistoryReferenceToScan(StructuralNode node) {
        if (ignoreFromScanning(node)) {
            return;
        }

        historyReferencesToScan.add(node.getHistoryReference());
        Iterator<StructuralNode> iterator = node.getChildIterator();
        while (iterator.hasNext()) {
            StructuralNode child = iterator.next();
            addHistoryReferenceToScan(child);
        }
    }

    private boolean ignoreFromScanning(StructuralNode node) {
        List<Pattern> patternsToIgnore = config.getRexesPatternsToIgnore();

        collectRegexesToIgnoreFromOtherOptions(patternsToIgnore);

        for (Pattern pattern : patternsToIgnore) {
            Matcher m = pattern.matcher(node.getURI().toString());
            if (m.matches()) {
                if (logger.isDebugEnabled()) {
                    logger.debug(node.getName() + " is ignored from authentication status check");
                }
                return true;
            }
        }
        return false;
    }

    private void collectRegexesToIgnoreFromOtherOptions(List<Pattern> patternsToIgnore) {
        Session session = extAuthHelper.getModel().getSession();
        List<String> excludeList = new ArrayList<>();
        excludeList.addAll(session.getExcludeFromScanRegexs());
        excludeList.addAll(session.getExcludeFromProxyRegexs());
        excludeList.addAll(session.getExcludeFromSpiderRegexs());
        excludeList.addAll(session.getGlobalExcludeURLRegexs());

        excludeList = excludeList.stream().distinct().collect(Collectors.toList());

        for (String regex : excludeList) {
            try {
                if (regex.trim().length() > 0) {
                    patternsToIgnore.add(Pattern.compile(regex.trim(), Pattern.CASE_INSENSITIVE));
                }
            } catch (PatternSyntaxException e) {
                if (logger.isDebugEnabled()) {
                    logger.error("Could not add " + regex + "to ignore list", e);
                }
                continue;
            }
        }
    }

    private void scanAndNotifyResult(HistoryReference historyReference) {
        try {
            if (!isRunning()) return;

            HttpMessage msg = getMsgWithRequiredParamsSet(historyReference);

            if (msg == null) return; // failure result already sent

            msg = sendAndReceive(msg);

            if (msg == null) return; // failure result already sent

            notifyNewResult(
                    historyReference,
                    getIndicatorStatus(loggedInIndicatorPattern, msg),
                    getIndicatorStatus(loggedOutIndicatorPattern, msg));

        } finally {
            postTaskExecution();
        }
    }

    private HttpMessage getMsgWithRequiredParamsSet(HistoryReference historyReference) {
        try {
            if (!isRunning()) return null;

            HttpMessage msg = historyReference.getHttpMessage();

            if (msg == null) {
                notifyFailure(historyReference);
                return null;
            }

            msg.setRequestingUser(user);

            msg.getRequestHeader().setHeader(HttpRequestHeader.COOKIE, null);

            return msg;
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            logger.error("unable to get message from history reference" + e.getMessage(), e);
            notifyFailure(historyReference);
            return null;
        }
    }

    private HttpMessage sendAndReceive(HttpMessage msg) {
        try {
            if (!isRunning()) {
                notifyFailure(msg.getHistoryRef());
                return null;
            }
            getHttpSender().sendAndReceive(msg);
            return msg;
        } catch (IOException e) {
            logger.error("unable to send message " + e.getMessage(), e);
            sendAndReceiveErrorCount++;
            if (shouldStop()) {
                complete();
            }
            notifyFailure(msg.getHistoryRef());
            return null;
        }
    }

    private boolean shouldStop() {
        return sendAndReceiveErrorCount == MAXIMUM_SEND_AND_RECEIVE_ERROR_COUNT;
    }

    private IndicatorStatus getIndicatorStatus(Pattern indicatorPattern, HttpMessage msg) {
        String body = msg.getResponseBody().toString();
        String header = msg.getResponseHeader().toString();

        if (indicatorPattern == null) return IndicatorStatus.NOT_DEFINED;
        if (indicatorPattern.matcher(body).find() || indicatorPattern.matcher(header).find())
            return IndicatorStatus.FOUND;

        return IndicatorStatus.NOT_FOUND;
    }

    private void notifyFailure(HistoryReference historyReference) {
        notifyNewResult(
                historyReference,
                IndicatorStatus.COULD_NOT_VERIFY,
                IndicatorStatus.COULD_NOT_VERIFY);
    }

    private void postTaskExecution() {
        if (!isRunning()) {
            return;
        }
        tasksDoneCount++;
        int percentageComplete = tasksDoneCount * 100 / tasksTotalCount;

        if (progress != percentageComplete) {
            progress = percentageComplete;
            authenticationStatusListener.updateProgress(
                    scanId,
                    getDisplayName(),
                    percentageComplete,
                    getSuccessfulAuthenticationCount(),
                    getFailedAuthenticationCount(),
                    getConflictingAuthenticationCount(),
                    getUnknownAuthenticationCount());
        }

        if (tasksDoneCount == tasksTotalCount) {
            complete();
        }
    }

    private void complete() {
        if (!isRunning()) {
            return;
        }
        logger.info("Authentication status checking is complete. Shutting down...");
        state = State.FINISHED;
        if (httpSender != null) {
            getHttpSender().shutdown();
            httpSender = null;
        }

        if (authenticationStatusListener != null)
            authenticationStatusListener.scanCompleted(scanId, getDisplayName());
    }

    public int getSuccessfulAuthenticationCount() {
        return numberOfSuccessfulAuthentications;
    }

    public int getFailedAuthenticationCount() {
        return numberOfFailedAuthentications;
    }

    public int getConflictingAuthenticationCount() {
        return numberOfConflictingAuthentications;
    }

    public int getUnknownAuthenticationCount() {
        return numberOfUnknownAuthentications;
    }

    public void setScanListener(AuthenticationStatusScanListenner listener) {
        authenticationStatusListener = listener;
    }

    public void setLoggedInIndicatorPattern(Pattern loggedInIndicatorPattern) {
        this.loggedInIndicatorPattern = loggedInIndicatorPattern;
    }

    public void setLoggedOutIndicatorPattern(Pattern loggedOutIndicatorPattern) {
        this.loggedOutIndicatorPattern = loggedOutIndicatorPattern;
    }

    public void notifyNewResult(
            HistoryReference historyReference,
            IndicatorStatus loggedInIndicatorStatus,
            IndicatorStatus loggedOutIndicatorStatus) {

        AuthenticationStatus authenticationStatus =
                determineAuthenticationStatus(loggedInIndicatorStatus, loggedOutIndicatorStatus);
        if (logger.isDebugEnabled()) {
            logger.debug(
                    "Authentication status: "
                            + authenticationStatus
                            + " URI: "
                            + historyReference.getURI());
        }

        updateAuthenticationStatusCounts(authenticationStatus);

        if (View.isInitialised()) {
            addMessageToAuthenticationStatusTableModel(
                    historyReference,
                    authenticationStatus,
                    loggedInIndicatorStatus,
                    loggedOutIndicatorStatus);
        }
    }

    private void updateAuthenticationStatusCounts(AuthenticationStatus authenticationStatus) {
        switch (authenticationStatus) {
            case SUCCESSFULL:
                numberOfSuccessfulAuthentications++;
                break;
            case FAILED:
                numberOfFailedAuthentications++;
                break;
            case CONFLICTING:
                numberOfConflictingAuthentications++;
                break;
            case UNKNOWN:
                numberOfUnknownAuthentications++;
                break;
        }
    }

    public AuthenticationStatus determineAuthenticationStatus(
            IndicatorStatus loggedInIndicatorStatus, IndicatorStatus loggedOutIndicatorStatus) {
        if (loggedInIndicatorStatus.equals(IndicatorStatus.COULD_NOT_VERIFY)
                || loggedOutIndicatorStatus.equals(IndicatorStatus.COULD_NOT_VERIFY)) {
            return AuthenticationStatus.FAILED;
        }

        boolean inFound = loggedInIndicatorStatus.equals(IndicatorStatus.FOUND);
        boolean inNotFound = loggedInIndicatorStatus.equals(IndicatorStatus.NOT_FOUND);
        boolean inNotDefined = loggedInIndicatorStatus.equals(IndicatorStatus.NOT_DEFINED);

        boolean outFound = loggedOutIndicatorStatus.equals(IndicatorStatus.FOUND);
        boolean outNotFound = loggedOutIndicatorStatus.equals(IndicatorStatus.NOT_FOUND);
        boolean outNotDefined = loggedOutIndicatorStatus.equals(IndicatorStatus.NOT_DEFINED);

        if (inFound && (outNotFound || outNotDefined)) return AuthenticationStatus.SUCCESSFULL;

        // in -> found or not found or not defined
        // out -> found or not found or not defined
        // if in found then out not found

        if (inFound) return AuthenticationStatus.CONFLICTING;

        // in -> not found or not defined
        // out -> found or not found or not defined

        if (outFound) return AuthenticationStatus.FAILED;

        // in -> not found or not defined
        // out -> not found or not defined

        if (inNotFound && outNotDefined) return AuthenticationStatus.FAILED;

        // in -> not found or not defined
        // out -> not found or not defined
        // if in not found then out not found

        if (inNotFound) return AuthenticationStatus.UNKNOWN;

        // in -> not defined
        // out -> not found or not defined

        if (inNotDefined && outNotFound) return AuthenticationStatus.SUCCESSFULL;

        // in -> not defined
        // out -> not defined
        throw new IllegalArgumentException(
                "atleast one of logged in or logged out indicator should be defined");
    }

    private void addMessageToAuthenticationStatusTableModel(
            final HistoryReference historyReference,
            final AuthenticationStatus authenticationStatus,
            final IndicatorStatus loggedInIndicatorStatus,
            final IndicatorStatus loggedOutIndicatorStatus) {

        EventQueue.invokeLater(
                () -> {
                    authenticationStatusTableModel.addEntry(
                            new AuthenticationStatusTableEntry(
                                    historyReference,
                                    authenticationStatus,
                                    loggedInIndicatorStatus,
                                    loggedOutIndicatorStatus));
                });
    }

    private void reset() {
        if (!View.isInitialised() || EventQueue.isDispatchThread()) {
            authenticationStatusTableModel.clear();
        } else {
            EventQueue.invokeLater(() -> reset());
        }
    }

    @Override
    public int getScanId() {
        return scanId;
    }

    @Override
    public int getProgress() {
        return progress;
    }

    @Override
    public String getDisplayName() {
        return displayName;
    }

    @Override
    public void setDisplayName(String name) {
        displayName = name;
    }

    @Override
    public int getMaximum() {
        return 100;
    }

    @Override
    public void pauseScan() {
        if (isRunning()) {
            logger.debug("Authentication status check paused for " + getDisplayName());
            state = State.PAUSED;
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                logger.error(thread.getName() + " was interrupted while pausing", e);
            }
        }
    }

    @Override
    public void stopScan() {
        if (!isStopped()) {
            logger.info("Authentication status check stopped for " + getDisplayName());
            state = State.STOPPED;
            try {
                if (authenticationStatusListener != null)
                    authenticationStatusListener.scanCompleted(scanId, getDisplayName());
                thread.join();
            } catch (InterruptedException e) {
                logger.error(thread.getName() + " was interrupted while stopping", e);
            }
        }
    }

    @Override
    public void resumeScan() {
        if (isPaused()) {
            logger.debug("Authentication status check resumed for " + getDisplayName());
            state = State.RUNNING;
        }
    }

    @Override
    public boolean isStopped() {
        return state.equals(State.STOPPED) || state.equals(State.FINISHED);
    }

    @Override
    public boolean isPaused() {
        return state.equals(State.PAUSED);
    }

    @Override
    public boolean isRunning() {
        return state.equals(State.RUNNING);
    }

    @Override
    public void setScanId(int scanId) {
        this.scanId = scanId;
    }

    private HttpSender getHttpSender() {
        if (httpSender == null) {
            // TODO: update to HttpSender.AUTHENTICATION_HELPER_INITIATOR);
            httpSender = new HttpSender(connectionParam, true, 14);
            httpSender.setRemoveUserDefinedAuthHeaders(true);
            httpSender.setUser(user);
            httpSender.setFollowRedirect(false);
        }
        return httpSender;
    }

    public AuthenticationStatusTableModel getAuthenticationStatusTableModel() {
        return authenticationStatusTableModel;
    }

    public void setOptionsParam(OptionsParamAuthenticationHelper obj) {
        config = obj;
    }
}
