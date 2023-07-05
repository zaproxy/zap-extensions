/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.ratelimit;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import org.jdesktop.swingx.renderer.DefaultTableRenderer;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.internal.client.CloseableHttpSenderImpl;
import org.zaproxy.addon.network.internal.ui.ratelimit.RateLimitDomainMenu;
import org.zaproxy.addon.network.internal.ui.ratelimit.RateLimitHostMenu;
import org.zaproxy.addon.network.internal.ui.ratelimit.RateLimitOptionsPanel;
import org.zaproxy.addon.network.internal.ui.ratelimit.RateLimiterTableModel;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.ZapTable;
import org.zaproxy.zap.view.popup.PopupMenuHttpMessageContainer;
import org.zaproxy.zap.view.renderer.DateFormatStringValue;

/** Network extension parts for rate limiting. */
public class RateLimitExtensionHelper {
    private static final ImageIcon RATE_LIMIT_ICON;

    static {
        RATE_LIMIT_ICON =
                View.isInitialised()
                        ? new ImageIcon(
                                ExtensionNetwork.class.getResource("resources/ratelimit.png"))
                        : null;
    }

    private RateLimitOptions rateLimitOptions;
    private RateLimitOptionsPanel rateLimitOptionsPanel;
    private AbstractPanel rateLimitStatusPanel;
    private PopupMenuHttpMessageContainer rateLimitPopupMenu;
    private RateLimiter rateLimiter;
    private RateLimiterTableModel rateLimiterTableModel;
    private AtomicLong rateLimiterLastUpdate;
    private CloseableHttpSenderImpl<?> httpSenderNetwork;

    public RateLimitExtensionHelper() {
        rateLimitOptions = new RateLimitOptions();
    }

    public void init(CloseableHttpSenderImpl<?> httpSenderNetwork) {
        this.httpSenderNetwork = httpSenderNetwork;
        rateLimiter = null;
        rateLimiterLastUpdate = new AtomicLong();
        httpSenderNetwork.setRateLimiter(new NopRateLimiter());
    }

    public void hook(ExtensionHook extensionHook) {
        extensionHook.addOptionsParamSet(rateLimitOptions);
        rateLimitOptions.setObserver(
                param -> {
                    if (rateLimiter == null) {
                        if (param.getRules().isEmpty()) {
                            return;
                        }
                        rateLimiter = new RateLimiterImpl();
                        httpSenderNetwork.setRateLimiter(rateLimiter);
                        configureRateLimiterForStatusPanel();
                    }
                    rateLimiter.configChange(param);
                    if (rateLimiterTableModel != null) {
                        rateLimiterTableModel.update(rateLimiter);
                    }
                });

        if (View.isInitialised()) {
            extensionHook.getHookView().addStatusPanel(getRateLimitStatusPanel());
            extensionHook.getHookMenu().addPopupMenuItem(getRateLimitPopupMenu());
        }
    }

    public void reset() {
        if (rateLimiter != null) {
            rateLimiter.reset();
        }
    }

    public RateLimitOptions getRateLimitOptions() {
        return rateLimitOptions;
    }

    public RateLimitOptionsPanel getRateLimitOptionsPanel() {
        if (rateLimitOptionsPanel == null) {
            rateLimitOptionsPanel = new RateLimitOptionsPanel();
        }
        return rateLimitOptionsPanel;
    }

    private PopupMenuHttpMessageContainer getRateLimitPopupMenu() {
        if (rateLimitPopupMenu == null) {
            rateLimitPopupMenu =
                    new PopupMenuHttpMessageContainer(
                            Constant.messages.getString("network.ui.ratelimit.context.title"));
            rateLimitPopupMenu.setIcon(DisplayUtils.getScaledIcon(RATE_LIMIT_ICON));
            rateLimitPopupMenu.add(
                    new RateLimitHostMenu(
                            rateLimitOptions,
                            Constant.messages.getString(
                                    "network.ui.ratelimit.context.limithost.title")));
            rateLimitPopupMenu.add(
                    new RateLimitDomainMenu(
                            rateLimitOptions,
                            Constant.messages.getString(
                                    "network.ui.ratelimit.context.limitdomain.title")));
        }
        return rateLimitPopupMenu;
    }

    /**
     * Configures the status panel for listening to rate limit changes. This method is separate from
     * status panel instantiation because the rate limiter could be null before rules are
     * configured.
     */
    private void configureRateLimiterForStatusPanel() {
        if (rateLimiter == null || rateLimiterTableModel == null) {
            return;
        }
        rateLimiter.setObserver(
                limiter -> {
                    if ((System.currentTimeMillis() - rateLimiterLastUpdate.get()) > 1000) {
                        rateLimiterLastUpdate.set(System.currentTimeMillis());
                        SwingUtilities.invokeLater(() -> rateLimiterTableModel.update(limiter));
                    }
                });
    }

    private AbstractPanel getRateLimitStatusPanel() {
        if (rateLimitStatusPanel == null) {
            rateLimiterTableModel = new RateLimiterTableModel();
            configureRateLimiterForStatusPanel();

            ZapTable limiterTable = new ZapTable(rateLimiterTableModel);
            limiterTable.setColumnSelectionAllowed(false);
            limiterTable.setCellSelectionEnabled(false);
            limiterTable.setRowSelectionAllowed(false);
            limiterTable.setAutoCreateRowSorter(true);
            limiterTable.setAutoCreateColumnsFromModel(true);
            limiterTable.setColumnControlVisible(true);
            limiterTable.setDoubleBuffered(true);
            limiterTable.setDefaultRenderer(
                    Date.class, new DefaultTableRenderer(new DateFormatStringValue()));

            JScrollPane scroller = new JScrollPane();
            scroller.setName("RateLimiterPane");
            scroller.setViewportView(limiterTable);
            limiterTable.packAll();

            rateLimitStatusPanel = new AbstractPanel();
            rateLimitStatusPanel.setLayout(new BorderLayout());
            rateLimitStatusPanel.setName(
                    Constant.messages.getString("network.ui.ratelimit.status.title"));
            rateLimitStatusPanel.setIcon(RATE_LIMIT_ICON);
            rateLimitStatusPanel.add(scroller);

            JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton optionsButton = new JButton();
            optionsButton.setToolTipText(
                    Constant.messages.getString("network.ui.ratelimit.panel.title"));
            optionsButton.setIcon(
                    DisplayUtils.getScaledIcon(
                            ExtensionNetwork.class.getResource("/resource/icon/16/041.png")));
            optionsButton.addActionListener(
                    e ->
                            Control.getSingleton()
                                    .getMenuToolsControl()
                                    .options(RateLimitOptionsPanel.PANEL_NAME));
            controlPanel.add(optionsButton);
            rateLimitStatusPanel.add(BorderLayout.NORTH, controlPanel);

            rateLimiterTableModel.fireTableDataChanged();
        }
        return rateLimitStatusPanel;
    }
}
