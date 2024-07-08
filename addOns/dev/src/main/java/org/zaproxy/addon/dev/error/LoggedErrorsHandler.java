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
package org.zaproxy.addon.dev.error;

import java.awt.EventQueue;
import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;
import javax.swing.SwingUtilities;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.StringLayout;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.filter.LevelMatchFilter;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.ScanStatus;

public class LoggedErrorsHandler {

    private final boolean loaded;
    private ScanStatus scanStatus;

    public LoggedErrorsHandler() {
        loaded =
                org.zaproxy.zap.extension.log4j.ExtensionLog4j.class.getAnnotation(Deprecated.class)
                                != null
                        && Constant.isDevMode()
                        && View.isInitialised();

        if (loaded) {
            scanStatus =
                    new ScanStatus(
                            DisplayUtils.getScaledIcon(
                                    getClass()
                                            .getResource(
                                                    "/org/zaproxy/addon/dev/icons/fugue/bug.png")),
                            Constant.messages.getString("dev.error.icon.title"));

            LoggerContext.getContext()
                    .getConfiguration()
                    .getRootLogger()
                    .addAppender(new ErrorAppender(this::handleError), null, null);

            View.getSingleton()
                    .getMainFrame()
                    .getMainFooterPanel()
                    .addFooterToolbarRightLabel(scanStatus.getCountLabel());
        }
    }

    public void hook(ExtensionHook extensionHook) {
        if (!loaded) {
            return;
        }

        extensionHook.addSessionListener(new ResetCounterOnSessionChange(scanStatus));
    }

    public void unload() {
        if (!loaded) {
            return;
        }

        LoggerContext.getContext()
                .getConfiguration()
                .getRootLogger()
                .removeAppender(ErrorAppender.NAME);

        View.getSingleton()
                .getMainFrame()
                .getMainFooterPanel()
                .removeFooterToolbarRightLabel(scanStatus.getCountLabel());
    }

    private void handleError(String message) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> handleError(message));
            return;
        }

        scanStatus.incScanCount();
        View.getSingleton().getOutputPanel().append(message);
    }

    static class ErrorAppender extends AbstractAppender {

        private static final String NAME = "ZAP-ErrorAppender";

        private static final Property[] NO_PROPERTIES = {};

        private final Consumer<String> logConsumer;

        ErrorAppender(Consumer<String> logConsumer) {
            super(
                    NAME,
                    LevelMatchFilter.newBuilder().setLevel(Level.ERROR).build(),
                    PatternLayout.newBuilder()
                            .withDisableAnsi(true)
                            .withCharset(StandardCharsets.UTF_8)
                            .withPattern("%m%n")
                            .build(),
                    true,
                    NO_PROPERTIES);
            this.logConsumer = logConsumer;
            start();
        }

        @Override
        public void append(LogEvent event) {
            logConsumer.accept(((StringLayout) getLayout()).toSerializable(event));
        }
    }

    private static class ResetCounterOnSessionChange implements SessionChangedListener {
        /** Keep track of errors logged while the session changes. */
        private int previousCount;

        /** Do not reset the counter if ZAP is starting. */
        private boolean starting;

        private ScanStatus scanStatus;

        public ResetCounterOnSessionChange(ScanStatus scanStatus) {
            this.scanStatus = scanStatus;
            this.starting = true;
        }

        @Override
        public void sessionAboutToChange(Session session) {
            EventQueue.invokeLater(() -> previousCount = scanStatus.getScanCount());
        }

        @Override
        public void sessionChanged(Session session) {
            if (starting) {
                starting = false;
                return;
            }

            EventQueue.invokeLater(
                    () -> {
                        scanStatus.setScanCount(scanStatus.getScanCount() - previousCount);
                        previousCount = 0;
                    });
        }

        @Override
        public void sessionScopeChanged(Session session) {
            // Nothing to do.
        }

        @Override
        public void sessionModeChanged(Mode mode) {
            // Nothing to do.
        }
    }
}
