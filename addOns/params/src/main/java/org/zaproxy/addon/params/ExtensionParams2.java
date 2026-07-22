/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2011 The ZAP Development Team
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
package org.zaproxy.addon.params;

import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import javax.swing.tree.TreeNode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.core.scanner.VariantMultipartFormParameters;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.DatabaseUnsupportedException;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.params.internal.db.ParamsDao;
import org.zaproxy.addon.params.internal.db.ParamsTableJdo;
import org.zaproxy.addon.params.internal.db.RecordParam;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.control.ExtensionFactory;
import org.zaproxy.zap.extension.anticsrf.ExtensionAntiCSRF;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.extension.httpsessions.ExtensionHttpSessions;
import org.zaproxy.zap.extension.params.ExtensionParams;
import org.zaproxy.zap.extension.search.ExtensionSearch;
import org.zaproxy.zap.utils.ErrorUtils;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zap.view.SiteMapListener;
import org.zaproxy.zap.view.SiteMapTreeCellRenderer;

public class ExtensionParams2 extends ExtensionAdaptor {

    public static final String NAME = "ExtensionParams2";

    private ParamsPanel paramsPanel = null;
    private PopupMenuParamSearch popupMenuSearch = null;
    private PopupMenuAddAntiCSRF popupMenuAddAntiCsrf = null;
    private PopupMenuRemoveAntiCSRF popupMenuRemoveAntiCsrf = null;
    private PopupMenuAddSession popupMenuAddSession = null;
    private PopupMenuRemoveSession popupMenuRemoveSession = null;
    private Map<String, SiteParameters> siteParamsMap = new HashMap<>();

    private static final Logger LOGGER = LogManager.getLogger(ExtensionParams2.class);

    private static boolean attemptedCoreExtensionFactoryRemoval;

    // TODO: Remove migration logic once targetting 2.18
    private boolean deferToCore;

    private ExtensionHttpSessions extensionHttpSessions;
    private ParamScanner paramScanner;
    private ParamsTableJdo paramsTableJdo;

    public ExtensionParams2() {
        super(NAME);
        this.setOrder(59);
    }

    @Override
    public AddOn getAddOn() {
        handleCoreParamsCoexistenceOnce();
        return super.getAddOn();
    }

    public boolean isDeferringToCore() {
        return deferToCore;
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void databaseOpen(Database db) throws DatabaseException, DatabaseUnsupportedException {
        super.databaseOpen(db);
        if (deferToCore) {
            return;
        }
        try {
            paramsTableJdo = new ParamsTableJdo(db);
        } catch (Exception e) {
            LOGGER.warn("Could not initialize Params session database: {}", e.getMessage(), e);
        }
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("params.name");
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        if (isCoreParamsInLoader()) {
            deferToCore = true;
        }
        if (deferToCore) {
            return;
        }

        extensionHook.addApiImplementor(new ParamsAPI(this));
        extensionHook.addSessionListener(new SessionChangedListenerImpl());
        extensionHook.addSiteMapListener(new SiteMapListenerImpl());

        if (getView() != null) {
            ExtensionHookView pv = extensionHook.getHookView();
            pv.addStatusPanel(getParamsPanel());

            final ExtensionLoader extLoader = Control.getSingleton().getExtensionLoader();
            if (extLoader.isExtensionEnabled(ExtensionSearch.NAME)) {
                extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuParamSearch());
            }

            if (extLoader.isExtensionEnabled(ExtensionAntiCSRF.NAME)) {
                extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuAddAntiCSRF());
                extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuRemoveAntiCSRF());
            }

            if (extLoader.isExtensionEnabled(ExtensionHttpSessions.NAME)) {
                extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuAddSession());
                extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuRemoveSession());
            }

            ExtensionHelp.enableHelpKey(getParamsPanel(), "params");
        }

        ExtensionPassiveScan2 extensionPassiveScan =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionPassiveScan2.class);
        if (extensionPassiveScan != null) {
            paramScanner = new ParamScanner(this);
            extensionPassiveScan.getPassiveScannersManager().add(paramScanner);
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        ExtensionPassiveScan2 extensionPassiveScan =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionPassiveScan2.class);
        if (extensionPassiveScan != null && paramScanner != null) {
            extensionPassiveScan.getPassiveScannersManager().remove(paramScanner);
        }
    }

    @Override
    public void destroy() {
        if (paramsTableJdo != null) {
            paramsTableJdo.unload();
            paramsTableJdo = null;
        }
        super.destroy();
    }

    private PopupMenuParamSearch getPopupMenuParamSearch() {
        if (popupMenuSearch == null) {
            popupMenuSearch = new PopupMenuParamSearch();
            popupMenuSearch.setExtension(this);
        }
        return popupMenuSearch;
    }

    private PopupMenuAddAntiCSRF getPopupMenuAddAntiCSRF() {
        if (popupMenuAddAntiCsrf == null) {
            popupMenuAddAntiCsrf = new PopupMenuAddAntiCSRF();
            popupMenuAddAntiCsrf.setExtension(this);
        }
        return popupMenuAddAntiCsrf;
    }

    private PopupMenuRemoveAntiCSRF getPopupMenuRemoveAntiCSRF() {
        if (popupMenuRemoveAntiCsrf == null) {
            popupMenuRemoveAntiCsrf = new PopupMenuRemoveAntiCSRF();
            popupMenuRemoveAntiCsrf.setExtension(this);
        }
        return popupMenuRemoveAntiCsrf;
    }

    private PopupMenuAddSession getPopupMenuAddSession() {
        if (popupMenuAddSession == null) {
            popupMenuAddSession = new PopupMenuAddSession();
            popupMenuAddSession.setExtension(this);
        }
        return popupMenuAddSession;
    }

    private PopupMenuRemoveSession getPopupMenuRemoveSession() {
        if (popupMenuRemoveSession == null) {
            popupMenuRemoveSession = new PopupMenuRemoveSession();
            popupMenuRemoveSession.setExtension(this);
        }
        return popupMenuRemoveSession;
    }

    protected ParamsPanel getParamsPanel() {
        if (paramsPanel == null) {
            paramsPanel = new ParamsPanel(this);
        }
        return paramsPanel;
    }

    /**
     * Gets the ExtensionHttpSessions, if it's enabled
     *
     * @return the Http Sessions extension or null, if it's not available
     */
    protected ExtensionHttpSessions getExtensionHttpSessions() {
        if (extensionHttpSessions == null) {
            extensionHttpSessions =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionHttpSessions.class);
        }
        return extensionHttpSessions;
    }

    public boolean onHttpRequestSend(HttpMessage msg) {

        // Check we know the site
        String site =
                msg.getRequestHeader().getHostName() + ":" + msg.getRequestHeader().getHostPort();

        if (getView() != null) {
            this.getParamsPanel().addSite(site);
        }

        SiteParameters sps = this.siteParamsMap.get(site);
        if (sps == null) {
            sps = new SiteParameters(this, site);
            this.siteParamsMap.put(site, sps);
        }

        // Cookie Parameters
        TreeSet<HtmlParameter> params;
        Iterator<HtmlParameter> iter;
        try {
            params = msg.getRequestHeader().getCookieParams();
            iter = params.iterator();
            while (iter.hasNext()) {
                persist(sps.addParam(site, iter.next(), msg));
            }
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Failed to obtain the cookies: {}", e.getMessage(), e);
        }

        // URL Parameters
        params = msg.getUrlParams();
        iter = params.iterator();
        while (iter.hasNext()) {
            persist(sps.addParam(site, iter.next(), msg));
        }

        // Form Parameters
        // TODO flag anti csrf url ones too?

        ExtensionAntiCSRF extAntiCSRF =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAntiCSRF.class);

        params = msg.getFormParams();
        iter = params.iterator();
        HtmlParameter param;
        while (iter.hasNext()) {
            param = iter.next();
            if (extAntiCSRF != null && extAntiCSRF.isAntiCsrfToken(param.getName())) {
                param.addFlag(HtmlParameter.Flags.anticsrf.name());
            }
            persist(sps.addParam(site, param, msg));
        }

        VariantMultipartFormParameters params2 = new VariantMultipartFormParameters();
        params2.setMessage(msg);
        for (NameValuePair nvp : params2.getParamList()) {
            if (nvp.getType() == NameValuePair.TYPE_MULTIPART_DATA_PARAM
                    || nvp.getType() == NameValuePair.TYPE_MULTIPART_DATA_FILE_NAME) {
                persist(
                        sps.addParam(
                                site,
                                new HtmlParameter(
                                        HtmlParameter.Type.multipart,
                                        nvp.getName(),
                                        nvp.getValue()),
                                msg));
            }
        }

        return true;
    }

    private String setToString(Set<String> set) {
        StringBuilder sb = new StringBuilder();
        if (set == null) {
            return "";
        }
        // Despite the SonarLint warning we do need to sync on the set
        synchronized (set) {
            for (String str : set) {
                if (sb.length() > 0) {
                    sb.append(',');
                }
                // Escape all commas in the values
                sb.append(str.replace(",", "%2C"));
            }
        }
        return sb.toString();
    }

    private void persist(HtmlParameterStats param) {
        var pmf = ParamsTableJdo.getPmf();
        if (pmf == null) {
            return;
        }
        try {
            if (param.getId() < 0) {
                RecordParam rp =
                        ParamsDao.insert(
                                pmf,
                                param.getSite(),
                                param.getType().name(),
                                param.getName(),
                                param.getTimesUsed(),
                                setToString(param.getFlags()),
                                setToString(param.getValues()));
                param.setId(rp.paramId());
            } else {
                ParamsDao.update(
                        pmf,
                        param.getId(),
                        param.getTimesUsed(),
                        setToString(param.getFlags()),
                        setToString(param.getValues()));
            }
        } catch (Exception e) {
            if (!ErrorUtils.handleDiskSpaceException(e)) {
                LOGGER.error(e.getMessage(), e);
            }
        }
    }

    public boolean onHttpResponseReceive(HttpMessage msg) {

        // Check we know the site
        String site =
                msg.getRequestHeader().getHostName() + ":" + msg.getRequestHeader().getHostPort();

        if (getView() != null) {
            this.getParamsPanel().addSite(site);
        }

        SiteParameters sps = this.getSiteParameters(site);

        // Cookie Parameters
        try {
            TreeSet<HtmlParameter> params = msg.getResponseHeader().getCookieParams();
            Iterator<HtmlParameter> iter = params.iterator();
            while (iter.hasNext()) {
                persist(sps.addParam(site, iter.next(), msg));
            }
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Failed to obtain the cookies: {}", e.getMessage(), e);
        }

        // Header "Parameters"
        List<HttpHeaderField> headersList = msg.getResponseHeader().getHeaders();
        List<String> setCookieHeaders =
                Arrays.asList(
                        HttpHeader.SET_COOKIE.toLowerCase(), HttpHeader.SET_COOKIE2.toLowerCase());
        for (HttpHeaderField hdrField : headersList) {
            if (setCookieHeaders.contains(hdrField.getName().toLowerCase())) {
                continue;
            }
            HtmlParameter headerParam =
                    new HtmlParameter(
                            HtmlParameter.Type.header, hdrField.getName(), hdrField.getValue());
            ThreadUtils.invokeLater(() -> persist(sps.addParam(site, headerParam, msg)));
        }

        // TODO Only do if response URL different to request?
        // URL Parameters
        /*
        params = msg.getUrlParams();
        iter = params.iterator();
        while (iter.hasNext()) {
        	sps.addParam(iter.next());
        }
        */

        return true;
    }

    protected void searchForSelectedParam() {

        HtmlParameterStats item = getParamsPanel().getSelectedParam();
        if (item != null) {
            ExtensionSearch extSearch =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionSearch.class);

            if (extSearch != null) {
                if (HtmlParameter.Type.url.equals(item.getType())) {
                    extSearch.search(
                            "[?&]" + Pattern.quote(item.getName()) + "=.*",
                            ExtensionSearch.Type.URL,
                            true,
                            false);
                } else if (HtmlParameter.Type.cookie.equals(item.getType())) {
                    extSearch.search(
                            Pattern.quote(item.getName()) + "=.*",
                            ExtensionSearch.Type.Header,
                            true,
                            false);
                } else if (HtmlParameter.Type.header.equals(item.getType())) {
                    extSearch.search(
                            Pattern.quote(item.getName()) + ":.*",
                            ExtensionSearch.Type.Header,
                            true,
                            false);
                } else if (HtmlParameter.Type.multipart.equals(item.getType())) {
                    extSearch.search(
                            "(?i)\\s*content-disposition\\s*:.*\\s+name\\s*\\=?\\s*\\\"?"
                                    + Pattern.quote(item.getName()),
                            ExtensionSearch.Type.Request,
                            true,
                            false);
                } else {
                    // FORM
                    extSearch.search(
                            Pattern.quote(item.getName()) + "=.*",
                            ExtensionSearch.Type.Request,
                            true,
                            false);
                }
            }
        }
    }

    public void addAntiCsrfToken() {
        HtmlParameterStats item = this.getParamsPanel().getSelectedParam();

        ExtensionAntiCSRF extAntiCSRF =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAntiCSRF.class);

        if (extAntiCSRF != null && item != null) {
            extAntiCSRF.addAntiCsrfTokenName(item.getName());
            item.addFlag(HtmlParameter.Flags.anticsrf.name());
            // Repaint so change shows up
            this.getParamsPanel().getParamsTable().repaint();

            // Dont think we need to do this... at least until rescan option implemented ...
            // Control.getSingleton().getMenuToolsControl().options(Constant.messages.getString("options.acsrf.title"));

        }
    }

    public void removeAntiCsrfToken() {
        HtmlParameterStats item = this.getParamsPanel().getSelectedParam();

        ExtensionAntiCSRF extAntiCSRF =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAntiCSRF.class);

        if (extAntiCSRF != null && item != null) {
            extAntiCSRF.removeAntiCsrfTokenName(item.getName());
            item.removeFlag(HtmlParameter.Flags.anticsrf.name());
            // Repaint so change shows up
            this.getParamsPanel().getParamsTable().repaint();

            // Dont think we need to do this... at least until rescan option implemented ...
            // Control.getSingleton().getMenuToolsControl().options(Constant.messages.getString("options.acsrf.title"));
        }
    }

    /**
     * Tells whether or not the given {@code site} was already seen.
     *
     * @param site the site that will be checked
     * @return {@code true} if the given {@code site} was already seen, {@code false} otherwise.
     * @see #hasParameters(String)
     */
    public boolean hasSite(String site) {
        return siteParamsMap.containsKey(site);
    }

    /**
     * Tells whether or not the given {@code site} has parameters.
     *
     * @param site the site that will be checked
     * @return {@code true} if the given {@code site} has parameters, {@code false} if not, or was
     *     not yet seen.
     * @see #hasSite(String)
     */
    public boolean hasParameters(String site) {
        SiteParameters siteParameters = siteParamsMap.get(site);
        if (siteParameters == null) {
            return false;
        }
        return siteParameters.hasParams();
    }

    public SiteParameters getSiteParameters(String site) {
        SiteParameters sps = this.siteParamsMap.get(site);
        if (sps == null) {
            sps = new SiteParameters(this, site);
            siteParamsMap.put(site, sps);
        }
        return sps;
    }

    public Collection<SiteParameters> getAllSiteParameters() {
        return this.siteParamsMap.values();
    }

    /**
     * Adds a new session token from the selected parameter. Also notifies the {@link
     * ExtensionHttpSessions} if it's active.
     */
    public void addSessionToken() {
        // Get the selected parameter
        HtmlParameterStats item = this.getParamsPanel().getSelectedParam();
        if (item != null) {

            // If the HttpSessions extension is active, notify it of the new session token
            ExtensionHttpSessions extSession = this.getExtensionHttpSessions();
            if (extSession != null) {
                extSession.addHttpSessionToken(
                        this.getParamsPanel().getCurrentSite(), item.getName());
            }

            // Flag the item accordingly
            item.addFlag(HtmlParameter.Flags.session.name());
            // Repaint so change shows up
            this.getParamsPanel().getParamsTable().repaint();
        }
    }

    /**
     * Removes the currently selected parameter as a session token. Also notifies the {@link
     * ExtensionHttpSessions} if it's active.
     */
    public void removeSessionToken() {
        HtmlParameterStats item = this.getParamsPanel().getSelectedParam();

        if (item != null) {
            // If the HttpSessions extension is active, notify it of the removed session token
            ExtensionHttpSessions extSession = this.getExtensionHttpSessions();
            if (extSession != null) {
                extSession.removeHttpSessionToken(
                        this.getParamsPanel().getCurrentSite(), item.getName());
            }

            // Unflag the item accordingly
            item.removeFlag(HtmlParameter.Flags.session.name());
            // Repaint so change shows up
            this.getParamsPanel().getParamsTable().repaint();
        }
    }

    public HtmlParameterStats getSelectedParam() {
        return this.getParamsPanel().getSelectedParam();
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("params.desc");
    }

    private class SiteMapListenerImpl implements SiteMapListener {

        @Override
        public void nodeSelected(SiteNode node) {
            getParamsPanel().nodeSelected(node);
        }

        @Override
        public void onReturnNodeRendererComponent(
                SiteMapTreeCellRenderer component, boolean leaf, SiteNode value) {}
    }

    private static boolean isCoreParamsInLoader() {
        Control control = Control.getSingleton();
        return control != null
                && control.getExtensionLoader().getExtension(ExtensionParams.class) != null;
    }

    private void handleCoreParamsCoexistenceOnce() {
        if (attemptedCoreExtensionFactoryRemoval) {
            return;
        }
        attemptedCoreExtensionFactoryRemoval = true;

        if (isCoreParamsInLoader()) {
            deferToCore = true;
            return;
        }

        Extension core = ExtensionFactory.getExtension(ExtensionParams.NAME);
        if (core == null) {
            return;
        }

        LOGGER.debug("Replacing core params extension with add-on.");
        ExtensionFactory.unloadAddOnExtension(core);
    }

    /** For unit tests only. */
    static void resetCoreExtensionFactoryRemovalAttemptedForUnitTests() {
        attemptedCoreExtensionFactoryRemoval = false;
    }

    private class SessionChangedListenerImpl implements SessionChangedListener {

        @Override
        public void sessionAboutToChange(Session session) {
            // Nothing to do
        }

        @Override
        public void sessionChanged(final Session session) {
            ThreadUtils.invokeAndWaitHandled(() -> sessionChangedEventHandler(session));
        }

        private void sessionChangedEventHandler(Session session) {
            // Clear all scans
            siteParamsMap = new HashMap<>();
            if (getView() != null) {
                getParamsPanel().reset();
            }
            if (session == null) {
                // Closedown
                return;
            }

            // Repopulate
            SiteNode root = session.getSiteTree().getRoot();
            @SuppressWarnings("unchecked")
            Enumeration<TreeNode> en = root.children();
            while (en.hasMoreElements()) {
                String site = ((SiteNode) en.nextElement()).getNodeName();
                if (getView() != null) {
                    getParamsPanel().addSite(site);
                }
            }

            try {
                var pmf = ParamsTableJdo.getPmf();
                if (pmf == null) {
                    return;
                }
                List<RecordParam> params = ParamsDao.getAll(pmf);

                for (RecordParam param : params) {
                    SiteParameters sps = getSiteParameters(param.site());
                    sps.addParam(param.site(), param);
                }
            } catch (Exception e) {
                LOGGER.error(e.getMessage(), e);
            }
        }

        @Override
        public void sessionScopeChanged(Session session) {
            // Nothing to do
        }

        @Override
        public void sessionModeChanged(Mode mode) {
            // Nothing to do
        }
    }
}
