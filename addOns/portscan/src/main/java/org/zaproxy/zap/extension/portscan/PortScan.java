/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2010 The ZAP Development Team
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
package org.zaproxy.zap.extension.portscan;

import java.awt.EventQueue;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import javax.swing.DefaultListModel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.network.ConnectionOptions;
import org.zaproxy.addon.network.common.HttpProxy;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.ScanListenner;
import org.zaproxy.zap.model.ScanThread;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.users.User;

public class PortScan extends ScanThread implements ScanListenner {

    private String site;
    private PortScanResultsTableModel resultsTableModel = new PortScanResultsTableModel();
    private boolean stopScan = false;
    private boolean pauseScan = false;
    private boolean unpauseScan = false;
    private boolean isPaused = false;
    private ScanListenner listener;
    private int maxPort = 0;
    private int threads = 0;
    private int threadIndex = -1;
    private int port = 0;
    private int progress = 0;
    private int timeout = 0;
    private boolean useProxy = true;
    private List<PortScan> subThreads = new ArrayList<>();

    private static final Logger LOGGER = LogManager.getLogger(PortScan.class);

    public PortScan(String site, ScanListenner listener, PortScanParam portScanParam) {
        super(site, listener);
        this.site = site;
        this.listener = listener;
        this.maxPort = portScanParam.getMaxPort();
        this.threads = portScanParam.getThreadPerScan();
        this.timeout = portScanParam.getTimeoutInMs();
        this.useProxy = portScanParam.isUseProxy();

        LOGGER.debug("PortScan : {} threads: {}", site, threads);
    }

    private PortScan(
            String site,
            ScanListenner listener,
            PortScanResultsTableModel resultsTableModel,
            int maxPort,
            int threads,
            int threadIndex) {
        super(site, listener);
        this.site = site;
        this.listener = listener;
        this.maxPort = maxPort;
        this.threads = threads;
        this.threadIndex = threadIndex;

        this.resultsTableModel = resultsTableModel;
        LOGGER.debug("PortScan : {} threads: {} threadIndex: {}", site, threads, threadIndex);
    }

    @Override
    public void run() {
        if (threads > 1 && threadIndex == -1) {
            // Start the sub threads
            runSubThreads();
        } else {
            // This is a sub thread
            runScan();
        }
        if (this.listener != null) {
            this.listener.scanFinshed(site);
        }
        stopScan = true;
    }

    private void runScan() {
        // Do the scan
        // If there are multiple sub threads then they will start at a different point
        Date start = new Date();
        LOGGER.debug("Starting scan on {} at {}", site, start);
        reset();

        stopScan = false;
        int startPort = threadIndex;
        if (startPort < 1) {
            startPort = 1;
        }

        Proxy proxy = getProxy();

        for (port = startPort; port < maxPort; port += threads) {
            try {
                if (pauseScan) {
                    pauseScan = false;
                    isPaused = true;
                    for (PortScan ps : subThreads) {
                        ps.pauseScan();
                    }
                    while (!stopScan && !unpauseScan) {
                        try {
                            sleep(500);
                        } catch (InterruptedException e) {
                            // Ignore
                        }
                    }
                    isPaused = false;
                    for (PortScan ps : subThreads) {
                        ps.resumeScan();
                    }
                }
                if (stopScan) {
                    LOGGER.debug("Scanned stopped");
                    break;
                }
                if (this.listener != null) {
                    this.listener.scanProgress(site, port, maxPort);
                }

                if (proxy != Proxy.NO_PROXY) {

                    FutureTask<Integer> ft =
                            new FutureTask<>(
                                    () -> {
                                        SocketAddress endpoint = new InetSocketAddress(site, port);
                                        try (Socket s = new Socket(proxy)) {
                                            s.connect(endpoint, timeout);
                                        } catch (IOException e) {
                                            return null;
                                        }
                                        return port;
                                    });
                    new Thread(ft).start();
                    try {
                        ft.get(2, TimeUnit.SECONDS);
                    } catch (Exception e) {
                        ft.cancel(true);
                        throw new IOException();
                    }

                } else {
                    // Not using a proxy
                    try (Socket s = new Socket()) {
                        s.connect(new InetSocketAddress(site, port), timeout);
                    }
                }
                LOGGER.debug("Site : {} open port: {}", site, port);

                addResult(port);
            } catch (IOException ex) {
                // The host is not listening on this port
            }
        }
        Date stop = new Date();
        LOGGER.debug("Finished scan on {} at {}", site, stop);
        LOGGER.debug("Took {} mins", ((stop.getTime() - start.getTime()) / 60000));
    }

    private Proxy getProxy() {
        if (useProxy) {
            ConnectionOptions connectionOptions =
                    Model.getSingleton().getOptionsParam().getParamSet(ConnectionOptions.class);
            if (connectionOptions.isUseHttpProxy(site)) {
                HttpProxy proxy = connectionOptions.getHttpProxy();
                SocketAddress sa = new InetSocketAddress(proxy.getHost(), proxy.getPort());
                return new Proxy(Proxy.Type.SOCKS, sa);
            }
        }
        return Proxy.NO_PROXY;
    }

    private void addResult(final int port) {
        if (EventQueue.isDispatchThread()) {
            resultsTableModel.addPort(port);
        } else {
            EventQueue.invokeLater(() -> addResult(port));
        }
    }

    private void runSubThreads() {
        for (int i = 0; i < threads; i++) {
            PortScan ps = new PortScan(site, this, resultsTableModel, maxPort, threads, i + 1);
            subThreads.add(ps);
            ps.start();
        }
        boolean running = true;
        while (running) {
            running = false;
            for (PortScan st : subThreads) {
                if (stopScan) {
                    st.stopScan();
                }
                if (pauseScan) {
                    unpauseScan = false;
                    st.pauseScan();
                }
                if (unpauseScan) {
                    pauseScan = false;
                    st.resumeScan();
                }
                if (st.isAlive()) {
                    running = true;
                }
            }
            if (running) {
                try {
                    sleep(500);
                } catch (InterruptedException e) {
                    // Ignore
                }
            }
        }
    }

    @Override
    public void stopScan() {
        stopScan = true;
    }

    @Override
    public boolean isStopped() {
        return stopScan;
    }

    @Override
    public boolean isRunning() {
        return this.isAlive();
    }

    @Override
    public String getSite() {
        return site;
    }

    @Override
    public int getProgress() {
        return progress;
    }

    int getMaxPort() {
        return this.maxPort;
    }

    /**
     * @deprecated (7) No longer supported, throws UnsupportedOperationException. Use {@code
     *     getResultsTableModel()} instead. Port Scan results are shown in a table thus it uses a
     *     {@code TableModel} ({@code PortScanResultsTableModel}).
     * @throws UnsupportedOperationException to indicate that is no longer supported.
     * @see PortScanResultsTableModel
     * @see #getResultsTableModel()
     */
    @Override
    @Deprecated
    public DefaultListModel<Integer> getList() {
        throw new UnsupportedOperationException("");
    }

    public PortScanResultsTableModel getResultsTableModel() {
        return resultsTableModel;
    }

    @Override
    public void scanFinshed(String host) {
        // Ignore
    }

    @Override
    public void scanProgress(String host, int progress, int maximum) {
        if (progress > this.progress) {
            this.progress = progress;
            this.listener.scanProgress(site, progress, maximum);
        }
    }

    @Override
    public void pauseScan() {
        this.pauseScan = true;
        this.unpauseScan = false;
        this.isPaused = true;
    }

    @Override
    public void resumeScan() {
        this.unpauseScan = true;
        this.pauseScan = false;
        this.isPaused = false;
    }

    @Override
    public boolean isPaused() {
        return this.isPaused;
    }

    @Override
    public int getMaximum() {
        return maxPort;
    }

    @Override
    public void reset() {
        if (EventQueue.isDispatchThread()) {
            resultsTableModel.clear();
        } else {
            EventQueue.invokeLater(this::reset);
        }
    }

    @Override
    public void setJustScanInScope(boolean scanInScope) {
        // Dont support
    }

    @Override
    public boolean getJustScanInScope() {
        // Dont support
        return false;
    }

    @Override
    public void setScanChildren(boolean scanChildren) {
        // Dont support
    }

    @Override
    public void setScanContext(Context context) {
        // Don't support
    }

    @Override
    public void setScanAsUser(User user) {
        // Don't support
    }

    @Override
    public void setTechSet(TechSet techSet) {
        // Don't support
    }
}
