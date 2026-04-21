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
package org.zaproxy.zap.extension.quickstart;

import java.net.URL;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.extension.ascan.ActiveScan;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.utils.Stats;

public class AttackThread extends Thread {

    public enum Progress {
        notstarted,
        started,
        spider,
        ajaxspider,
        ascan,
        failed,
        complete,
        stopped
    }

    private ExtensionQuickStart extension;
    private URL url;
    private TraditionalSpider traditionalSpider;
    private PlugableSpider plugableSpider;
    private boolean stopAttack = false;
    private boolean useStdSpider;
    private String scanPolicyName;

    private static final Logger LOGGER = LogManager.getLogger(AttackThread.class);

    private static final HttpRequestConfig REQ_CONFIG =
            HttpRequestConfig.builder().setFollowRedirects(true).build();

    public AttackThread(ExtensionQuickStart ext, boolean useStdSpider) {
        super("ZAP-QuickStart-AttackThread");
        this.extension = ext;
        this.useStdSpider = useStdSpider;
    }

    public void setURL(URL url) {
        this.url = url;
    }

    public void setTraditionalSpider(TraditionalSpider traditionalSpider) {
        this.traditionalSpider = traditionalSpider;
    }

    public void setScanPolicyName(String scanPolicyName) {
        this.scanPolicyName = scanPolicyName;
    }

    public void setPlugableSpider(PlugableSpider plugableSpider) {
        this.plugableSpider = plugableSpider;
    }

    @Override
    public void run() {
        stopAttack = false;
        boolean completed = false;
        try {
            Stats.incCounter("stats.quickstart.attack");
            extension.notifyProgress(Progress.started);
            SiteNode startNode = this.extension.accessNode(this.url, REQ_CONFIG, true);

            if (startNode == null) {
                LOGGER.debug("Failed to access URL {}", url);
                // Dont notify progress here - it will have been done where we know more about
                // the problem
                return;
            }
            if (stopAttack) {
                LOGGER.debug("Attack stopped manually");
                extension.notifyProgress(Progress.stopped);
                return;
            }
            Target target = new Target(startNode);
            target.setRecurse(true);
            if (plugableSpider != null) {
                plugableSpider.init();
            }
            if (this.useStdSpider) {

                if (traditionalSpider == null) {
                    LOGGER.error("No spider");
                    extension.notifyProgress(Progress.failed);
                    return;
                }

                extension.notifyProgress(Progress.spider);
                TraditionalSpider.Scan spiderScan =
                        traditionalSpider.startScan(target.getDisplayName(), target);

                // Give some time to the spider to finish to setup and start itself.
                sleep(1500);

                try {
                    // Wait for the spider to complete
                    while (!spiderScan.isStopped()) {
                        sleep(500);
                        if (this.stopAttack) {
                            spiderScan.stopScan();
                            break;
                        }
                        extension.notifyProgress(Progress.spider, spiderScan.getProgress());
                    }
                } catch (InterruptedException e) {
                    // Ignore
                }
                if (stopAttack) {
                    LOGGER.debug("Attack stopped manually");
                    extension.notifyProgress(Progress.stopped);
                    return;
                }

                // Pause after the spider seems to help
                sleep(2000);
            }

            if (stopAttack) {
                LOGGER.debug("Attack stopped manually");
                extension.notifyProgress(Progress.stopped);
                return;
            }

            // optionally invoke ajax spider here
            if (plugableSpider != null && plugableSpider.isSelected()) {
                plugableSpider.startScan(this.url.toURI());
                sleep(1500);

                try {
                    // Wait for the ajax spider to complete
                    while (plugableSpider.isRunning()) {
                        sleep(500);
                        if (this.stopAttack) {
                            plugableSpider.stopScan();
                            break;
                        }
                        extension.notifyProgress(Progress.ajaxspider);
                    }
                } catch (InterruptedException e) {
                    // Ignore
                }
            }

            // Need to go back to the SitesTree to find the right parent
            String urlStr = url.toString();
            if (urlStr.endsWith("/")) {
                urlStr = urlStr.substring(0, urlStr.length() - 1);
            }
            SiteNode attackNode =
                    Model.getSingleton().getSession().getSiteTree().findNode(new URI(urlStr, true));
            if (attackNode == null) {
                // Fallback to accessed node if not found
                attackNode = startNode;
            }
            target.setStartNode(attackNode);
            LOGGER.info("Attacking {}", attackNode.getHierarchicNodeName());

            ExtensionActiveScan extAscan =
                    (ExtensionActiveScan)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionActiveScan.NAME);
            int scanId;
            if (extAscan == null) {
                LOGGER.error("No active scanner");
                extension.notifyProgress(Progress.failed);
                return;
            } else {
                extension.notifyProgress(Progress.ascan);
                ScanPolicy scanPolicy = null;
                if (scanPolicyName != null && !scanPolicyName.isEmpty()) {
                    try {
                        scanPolicy = extAscan.getPolicyManager().getPolicy(scanPolicyName);
                    } catch (Exception ex) {
                        LOGGER.warn("Failed to load policy {}, using default", scanPolicyName);
                    }
                }
                if (scanPolicy == null) {
                    scanPolicy = extAscan.getPolicyManager().getDefaultScanPolicy();
                }
                scanId = extAscan.startScan(target, null, new Object[] {scanPolicy});
            }

            try {
                ActiveScan ascan = extAscan.getScan(scanId);
                // Wait for the active scanner to complete
                while (!ascan.isStopped()) {
                    sleep(500);
                    if (this.stopAttack) {
                        extAscan.stopScan(scanId);
                    }
                    extension.notifyProgress(Progress.ascan, ascan.getProgress());
                }
            } catch (InterruptedException e) {
                // Ignore
            }
            completed = true;

        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            extension.notifyProgress(
                    Progress.failed,
                    Constant.messages.getString(
                            "quickstart.progress.failed.reason", e.getMessage()));
        } finally {
            if (!completed) {
                // Already handled
            } else if (stopAttack) {
                LOGGER.debug("Attack stopped manually");
                extension.notifyProgress(Progress.stopped);
            } else {
                LOGGER.debug("Attack completed");
                extension.notifyProgress(Progress.complete);
            }
        }
    }

    public void stopAttack() {
        this.stopAttack = true;
    }
}
