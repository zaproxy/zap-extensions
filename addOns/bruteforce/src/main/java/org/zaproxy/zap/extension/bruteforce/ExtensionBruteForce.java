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
package org.zaproxy.zap.extension.bruteforce;

import com.sittinglittleduck.DirBuster.BaseCase;
import java.awt.EventQueue;
import java.io.File;
import java.io.FilenameFilter;
import java.net.URL;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.tree.TreeNode;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.AddonFilesChangedListener;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.utils.FilenameExtensionFilter;
import org.zaproxy.zap.view.SiteMapListener;
import org.zaproxy.zap.view.SiteMapTreeCellRenderer;

public class ExtensionBruteForce extends ExtensionAdaptor
        implements SessionChangedListener,
                ProxyListener,
                SiteMapListener,
                AddonFilesChangedListener,
                BruteForceListenner {

    private static final Logger logger = Logger.getLogger(ExtensionBruteForce.class);

    // Could be after the last one that saves the HttpMessage, as this ProxyListener doesn't change
    // the HttpMessage.
    public static final int PROXY_LISTENER_ORDER = ProxyListenerLog.PROXY_LISTENER_ORDER + 1;

    public static final String HAMMER_ICON_RESOURCE = "/resource/icon/fugue/hammer.png";

    private BruteForcePanel bruteForcePanel = null;
    private OptionsBruteForcePanel optionsBruteForcePanel = null;
    private PopupMenuBruteForceSite popupMenuBruteForceSite = null;
    private PopupMenuBruteForceDirectory popupMenuBruteForceDirectory = null;
    private PopupMenuBruteForceDirectoryAndChildren popupMenuBruteForceDirectoryAndChildren = null;

    private BruteForceParam params = null;
    private List<ScanTarget> activeScans = new ArrayList<>();
    private Map<ScanTarget, BruteForce> bruteForceMap = new HashMap<>();
    private Map<Integer, BruteForce> bruteForceIndexes = new HashMap<>();
    private List<ForcedBrowseFile> fileList = null;
    private String fileDirectory = Constant.getZapHome() + "fuzzers/dirbuster";
    private String customFileDirectory = Constant.getInstance().DIRBUSTER_CUSTOM_DIR;
    private String fileExtension = ".txt";
    private int lastScanId = 0;

    public ExtensionBruteForce() {
        super("ExtensionBruteForce");
        this.setOrder(32);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        extensionHook.addSessionListener(this);
        extensionHook.addProxyListener(this);
        extensionHook.addSiteMapListener(this);
        extensionHook.addAddonFilesChangedListener(this);

        extensionHook.addOptionsParamSet(getBruteForceParam());

        if (getView() != null) {
            @SuppressWarnings("unused")
            ExtensionHookView pv = extensionHook.getHookView();
            extensionHook.getHookView().addStatusPanel(getBruteForcePanel());
            extensionHook.getHookView().addOptionPanel(getOptionsBruteForcePanel());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuBruteForceSite());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuBruteForceDirectory());
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(getPopupMenuBruteForceDirectoryAndChildren());

            ExtensionHelp.enableHelpKey(getBruteForcePanel(), "addon.bruteforce.tab");
        }
    }

    @Override
    public void unload() {
        if (getView() != null) {
            getBruteForcePanel().unload();
        }

        super.unload();
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public List<String> getActiveActions() {
        if (getView() == null) {
            return Collections.emptyList();
        }

        String activeActionPrefix = Constant.messages.getString("bruteforce.activeActionPrefix");
        List<String> activeActions = new ArrayList<>();
        for (BruteForce scan : getBruteForceScans()) {
            if (scan.isAlive()) {
                activeActions.add(
                        MessageFormat.format(
                                activeActionPrefix, scan.getScanTarget().toPlainString()));
            }
        }
        return activeActions;
    }

    private BruteForceParam getBruteForceParam() {
        if (params == null) {
            params = new BruteForceParam();
        }
        return params;
    }

    protected BruteForcePanel getBruteForcePanel() {
        if (bruteForcePanel == null) {
            bruteForcePanel = new BruteForcePanel(this, getBruteForceParam());
        }
        return bruteForcePanel;
    }

    @Override
    public void optionsLoaded() {
        if (getView() != null) {
            this.getBruteForcePanel().setDefaultFile(this.getBruteForceParam().getDefaultFile());
        }
    }

    public int bruteForceSite(SiteNode siteNode, String payloadFileName) {
        for (ForcedBrowseFile file : this.getFileList()) {
            if (file.getFile().getName().equals(payloadFileName)) {
                return this.bruteForceSite(siteNode, file.getFile());
            }
        }
        throw new IllegalArgumentException("File not found: " + payloadFileName);
    }

    public int bruteForceSite(SiteNode siteNode, File payloadFile) {
        if (siteNode == null) {
            throw new IllegalArgumentException("Null site node supplied");
        }
        ScanTarget scanTarget = createScanTarget(siteNode);
        BruteForce bf = this.startScan(scanTarget, null, payloadFile, false);
        return bf.getScanId();
    }

    private BruteForce getBruteForce(int scanId) {
        BruteForce bf = this.bruteForceIndexes.get(scanId);
        if (bf != null) {
            return bf;
        }
        throw new IllegalArgumentException("ScanId not found: " + scanId);
    }

    public boolean isRunning(int scanId) {
        return !this.getBruteForce(scanId).isStopped();
    }

    public boolean isPaused(int scanId) {
        return this.getBruteForce(scanId).isPaused();
    }

    public int getProgress(int scanId) {
        BruteForce bf = this.getBruteForce(scanId);
        return 100 * bf.getWorkDone() / bf.getWorkTotal();
    }

    public boolean stopScan(int scanId) {
        BruteForce bf = this.getBruteForce(scanId);
        if (bf.isStopped()) {
            return false;
        }
        bf.stopScan();
        return true;
    }

    public boolean pauseScan(int scanId) {
        BruteForce bf = this.getBruteForce(scanId);
        if (bf.isPaused()) {
            return false;
        }
        bf.pauseScan();
        return true;
    }

    public boolean resumeScan(int scanId) {
        BruteForce bf = this.getBruteForce(scanId);
        if (!bf.isPaused()) {
            return false;
        }
        bf.unpauseScan();
        return true;
    }

    public List<ScanTarget> getActiveScans() {
        return this.activeScans;
    }

    BruteForce getBruteForce(ScanTarget target) {
        return this.bruteForceMap.get(target);
    }

    int addBruteForce(ScanTarget target, BruteForce bruteForce) {
        this.bruteForceMap.put(target, bruteForce);
        int scanId = ++lastScanId;
        this.bruteForceIndexes.put(scanId, bruteForce);
        return scanId;
    }

    boolean stopScan(ScanTarget target) {
        BruteForce bruteForce = getBruteForce(target);
        if (bruteForce != null) {
            logger.debug("Stopping scan on " + target);
            bruteForce.stopScan();
            return true;
        }
        logger.debug("Failed to find scan on " + target);
        return false;
    }

    boolean pauseScan(ScanTarget target) {
        BruteForce bruteForce = getBruteForce(target);
        if (bruteForce != null) {
            logger.debug("Pausing scan on " + target);
            bruteForce.pauseScan();
            return true;
        }
        logger.debug("Failed to find scan on " + target);
        return false;
    }

    boolean resumeScan(ScanTarget target) {
        BruteForce bruteForce = getBruteForce(target);
        if (bruteForce != null) {
            logger.debug("Resuming scan on " + target);
            bruteForce.unpauseScan();
            return true;
        }
        logger.debug("Failed to find scan on " + target);
        return false;
    }

    BruteForce startScan(
            ScanTarget currentSite, String directory, File file, boolean onlyUnderDirectory) {

        this.activeScans.add(currentSite);

        BruteForce bruteForce =
                new BruteForce(currentSite, file, this, this.getBruteForceParam(), directory);
        if (onlyUnderDirectory) {
            bruteForce.setOnlyUnderDirectory(onlyUnderDirectory);
        }
        int scanId = addBruteForce(currentSite, bruteForce);

        bruteForce.start();
        bruteForce.setScanId(scanId);

        currentSite.setScanned(true);
        return bruteForce;
    }

    public Collection<BruteForce> getBruteForceScans() {
        return bruteForceMap.values();
    }

    public void stopAllScans() {
        for (BruteForce scanner : bruteForceMap.values()) {
            scanner.stopScan();
            scanner.clearModel();
        }
        // Allow 2 secs for the threads to stop - if we wait 'for ever' then we can get deadlocks
        for (int i = 0; i < 20; i++) {
            if (activeScans.size() == 0) {
                break;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                // Ignore
            }
        }
        bruteForceMap.clear();
        activeScans.clear();
    }

    @Override
    public void sessionChanged(final Session session) {
        if (getView() == null) {
            return;
        }

        if (EventQueue.isDispatchThread()) {
            sessionChangedEventHandler(session);

        } else {
            try {
                EventQueue.invokeAndWait(
                        new Runnable() {
                            @Override
                            public void run() {
                                sessionChangedEventHandler(session);
                            }
                        });
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
        }
    }

    private void sessionChangedEventHandler(Session session) {
        stopAllScans();
        lastScanId = 0;

        if (getView() != null) {
            this.getBruteForcePanel().reset();
            if (session == null) {
                // Closedown
                return;
            }
            // Add new hosts
            SiteNode root = session.getSiteTree().getRoot();
            @SuppressWarnings("unchecked")
            Enumeration<TreeNode> en = root.children();
            while (en.hasMoreElements()) {
                HistoryReference hRef = ((SiteNode) en.nextElement()).getHistoryReference();
                if (hRef != null) {
                    this.getBruteForcePanel().addSite(hRef.getURI());
                }
            }
        }
    }

    @Override
    public int getArrangeableListenerOrder() {
        return PROXY_LISTENER_ORDER;
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
        if (getView() != null) {
            this.getBruteForcePanel().addSite(msg.getRequestHeader().getURI());
        }
        return true;
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {
        // Do nothing
        return true;
    }

    @Override
    public void nodeSelected(SiteNode node) {
        // Event from SiteMapListenner
        this.getBruteForcePanel().nodeSelected(node);
    }

    @Override
    public void onReturnNodeRendererComponent(
            SiteMapTreeCellRenderer component, boolean leaf, SiteNode value) {}

    private PopupMenuBruteForceSite getPopupMenuBruteForceSite() {
        if (popupMenuBruteForceSite == null) {
            popupMenuBruteForceSite =
                    new PopupMenuBruteForceSite(
                            Constant.messages.getString("bruteforce.site.popup"));
            popupMenuBruteForceSite.setExtension(this);
        }
        return popupMenuBruteForceSite;
    }

    private PopupMenuBruteForceDirectory getPopupMenuBruteForceDirectory() {
        if (popupMenuBruteForceDirectory == null) {
            popupMenuBruteForceDirectory =
                    new PopupMenuBruteForceDirectory(
                            Constant.messages.getString("bruteforce.dir.popup"));
            popupMenuBruteForceDirectory.setExtension(this);
        }
        return popupMenuBruteForceDirectory;
    }

    private PopupMenuBruteForceDirectoryAndChildren getPopupMenuBruteForceDirectoryAndChildren() {
        if (popupMenuBruteForceDirectoryAndChildren == null) {
            popupMenuBruteForceDirectoryAndChildren =
                    new PopupMenuBruteForceDirectoryAndChildren(
                            Constant.messages.getString("bruteforce.dir.and.children.popup"));
            popupMenuBruteForceDirectoryAndChildren.setExtension(this);
        }
        return popupMenuBruteForceDirectoryAndChildren;
    }

    private OptionsBruteForcePanel getOptionsBruteForcePanel() {
        if (optionsBruteForcePanel == null) {
            optionsBruteForcePanel = new OptionsBruteForcePanel(this);
        }
        return optionsBruteForcePanel;
    }

    public int getThreadPerScan() {
        return this.getOptionsBruteForcePanel().getThreadPerScan();
    }

    public boolean getRecursive() {
        return this.getOptionsBruteForcePanel().getRecursive();
    }

    protected ScanTarget createScanTarget(SiteNode node) {
        if (node != null) {
            while (node.getParent() != null && node.getParent().getParent() != null) {
                node = node.getParent();
            }

            HistoryReference hRef = node.getHistoryReference();
            if (hRef != null) {
                return new ScanTarget(hRef.getURI());
            }
        }
        return null;
    }

    public boolean isScanning(SiteNode node) {
        ScanTarget target = createScanTarget(node);
        if (target != null) {
            BruteForce bf = getBruteForce(target);
            if (bf != null) {
                return bf.isAlive();
            }
        }
        return false;
    }

    public void refreshFileList() {
        fileList = null;
        if (getView() != null) {
            this.getBruteForcePanel().refreshFileList();
        }
    }

    public List<ForcedBrowseFile> getFileList() {
        if (fileList == null) {
            fileList = new ArrayList<>();
            File dir = new File(fileDirectory);
            FilenameFilter filter = new FilenameExtensionFilter(fileExtension, true);
            File[] files = dir.listFiles(filter);
            if (files != null) {
                Arrays.sort(files);
                for (File file : files) {
                    fileList.add(new ForcedBrowseFile(file));
                }
            }

            // handle local/custom files
            File customDir = new File(customFileDirectory);
            if (!dir.equals(customDir)) {
                File[] customFiles = customDir.listFiles();
                if (customFiles != null) {
                    Arrays.sort(customFiles);
                    for (File file : customFiles) {
                        if (!file.isDirectory()) {
                            fileList.add(new ForcedBrowseFile(file));
                        }
                    }
                }
            }
            Collections.sort(fileList);
        }

        return fileList;
    }

    public List<String> getFileNamesList() {
        List<String> names = new ArrayList<String>();
        for (ForcedBrowseFile file : this.getFileList()) {
            names.add(file.getFile().getName());
        }
        return names;
    }

    public void setDefaultFile(ForcedBrowseFile file) {
        if (getView() != null) {
            this.getBruteForcePanel().setDefaultFile(file);
        }
    }

    @Override
    public void sessionAboutToChange(Session session) {}

    @Override
    public String getDescription() {
        return Constant.messages.getString("bruteforce.desc");
    }

    @Override
    public void sessionScopeChanged(Session session) {
        if (getView() != null) {
            this.getBruteForcePanel().sessionScopeChanged(session);
        }
    }

    @Override
    public void sessionModeChanged(Mode mode) {
        if (mode.equals(Mode.safe)) {
            stopAllScans();
        }
        if (getView() != null) {
            this.getBruteForcePanel().sessionModeChanged(mode);
        }
    }

    @Override
    public void filesAdded() {
        this.refreshFileList();
    }

    @Override
    public void filesRemoved() {
        this.refreshFileList();
    }

    @Override
    public void scanFinshed(ScanTarget target) {
        this.activeScans.remove(target);
        if (getView() != null) {
            this.getBruteForcePanel().scanFinshed(target);
        }
    }

    @Override
    public void scanProgress(ScanTarget target, int done, int todo) {
        if (getView() != null) {
            this.getBruteForcePanel().scanProgress(target, done, todo);
        }
    }

    @Override
    public void foundDir(
            URL url,
            int statusCode,
            String response,
            String baseCase,
            String rawResponse,
            BaseCase baseCaseObj) {}
}
