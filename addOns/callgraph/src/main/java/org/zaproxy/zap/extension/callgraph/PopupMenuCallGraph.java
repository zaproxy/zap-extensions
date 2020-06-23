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
package org.zaproxy.zap.extension.callgraph;

import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.paros.ParosDatabase;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.view.popup.PopupMenuHttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

/**
 * @author 70pointer@gmail.com Popup to allow the user to select all sites, or one site, and to
 *     display the Call Graph for their selection
 */
class PopupMenuCallGraph extends PopupMenuHttpMessageContainer {

    private static final long serialVersionUID = -237315557930044572L;

    private static final Logger log = Logger.getLogger(PopupMenuCallGraph.class);

    private static final String POPUP_MENU_LABEL =
            Constant.messages.getString("callgraph.popup.option");
    private static final String POPUP_MENU_ALL_SITES =
            Constant.messages.getString("callgraph.popup.option.allsites");
    private static final String POPUP_MENU_ONE_SITE =
            Constant.messages.getString("callgraph.popup.option.onesite");

    private static enum NodeType {
        ALL_SITES,
        ONE_SITE
    }

    public PopupMenuCallGraph() {
        super(POPUP_MENU_LABEL);

        setButtonStateOverriddenByChildren(false);

        CallGraphPopupMenuItem menuitemAllSites =
                new CallGraphPopupMenuItem(POPUP_MENU_ALL_SITES, NodeType.ALL_SITES);
        add(menuitemAllSites);
        CallGraphPopupMenuItem menuitemOneSite =
                new CallGraphPopupMenuItem(POPUP_MENU_ONE_SITE, NodeType.ONE_SITE);
        add(menuitemOneSite);

        // TODO This add-on only supports the 'Paos' HSQLDB database
        if (!(Model.getSingleton().getDb() instanceof ParosDatabase)) {
            log.warn(
                    "Note: The database is not a 'ParosDatabase' instance, so the Call Graph Extension is disabled");
            menuitemAllSites.setEnabled(false);
            menuitemOneSite.setEnabled(false);
        }
    }

    @Override
    public boolean precedeWithSeparator() {
        return true;
    }

    private static class CallGraphPopupMenuItem extends PopupMenuItemHttpMessageContainer {

        private static final long serialVersionUID = -4108212857830575776L;

        private final NodeType nodeType;

        // private CallGraphFrame callGraphFrame = null;

        public CallGraphPopupMenuItem(String label, NodeType nodeType) {
            super(label);
            this.nodeType = nodeType;
        }

        @Override
        public boolean isButtonEnabledForSelectedHttpMessage(HttpMessage httpMessage) {
            if (httpMessage == null) {
                // if there was no message passed, the user can only select "ALL_SITES", and not
                // "ONE_SITE"
                switch (nodeType) {
                    case ALL_SITES:
                        return true;
                    case ONE_SITE:
                        return false;
                    default:
                        return false;
                }
            } else {
                // for a valid message, either option is valid
                return true;
            }
        }

        @Override
        public void performAction(HttpMessage httpMessage) {
            // get the URI of the message
            String uri = null;
            String sitePattern = ".*";
            String title = null;
            if (httpMessage != null) {
                try {
                    uri = httpMessage.getRequestHeader().getURI().getURI();
                } catch (Exception e1) {
                    log.debug("The URI is not valid");
                }
            }

            switch (nodeType) {
                case ALL_SITES:
                    log.debug("Doing stuff for the entire site, given message: " + uri);
                    sitePattern = ".*";
                    title = POPUP_MENU_ALL_SITES;
                    break;
                case ONE_SITE:
                    log.debug("Doing stuff for the subtree, given message: " + uri);
                    // parse out the scheme and authority, which is what we will use to filter
                    // requests for a single site.
                    try {
                        // sitePattern = httpMessage.getRequestHeader().getURI().getAboveHierPath()
                        // + "/.*";
                        URI x = httpMessage.getRequestHeader().getURI();
                        sitePattern = x.getScheme() + "://" + x.getAuthority() + "/.*";
                        title = sitePattern;
                    } catch (URIException e) {
                        sitePattern = "";
                        title = Constant.messages.getString("callgraph.title.unknownsite");
                        log.error("The URL is invalid");
                    }
                    break;
            }
            // now create the frame and display it.
            if (log.isDebugEnabled())
                log.debug("Creating regular expression based on ^" + sitePattern + "$");
            Pattern urlPattern = Pattern.compile("^" + sitePattern + "$", Pattern.CASE_INSENSITIVE);

            CallGraphFrame dialog = getCallGraphFrame(title, urlPattern);
            dialog.setVisible(true);
        }

        // allow a new instance of the frame each time.
        CallGraphFrame getCallGraphFrame(String title, Pattern urlPattern) {
            // if (callGraphFrame == null) {
            CallGraphFrame callGraphFrame = new CallGraphFrame(urlPattern);
            // callGraphFrame.setView(getView());
            // callGraphFrame.setPreferredSize(new Dimension(600, 600));
            callGraphFrame.setTitle(POPUP_MENU_LABEL + " - " + title);
            // }
            return callGraphFrame;
        }

        @Override
        public boolean isSafe() {
            return true;
        }
    }
}
