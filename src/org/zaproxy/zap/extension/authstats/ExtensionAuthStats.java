/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.zaproxy.zap.extension.authstats;

import java.util.regex.Pattern;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.network.HttpSenderListener;
import org.zaproxy.zap.utils.Stats;

/**
 * Authentication Statistics - Records logged in/out statistics for all contexts in scope 
 * @author psiinon
 *
 */
public class ExtensionAuthStats extends ExtensionAdaptor implements HttpSenderListener {
    
    private static final Logger log = Logger.getLogger(ExtensionAuthStats.class);

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        HttpSender.addListener(this);
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @Override
    public String getName() {
        return "ExtensionAuthStats";
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("authstats.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("authstats.desc");
    }
    
    @Override
    public boolean canUnload() {
        // TODO change when unload() can be implemented
        return false;
    }

    @Override
    public void unload() {
        super.unload();
        // TODO change to use HttpSender.removeListener when available
    }

    @Override
    public int getListenerOrder() {
        return 0;
    }

    @Override
    public void onHttpRequestSend(HttpMessage msg, int initiator, HttpSender sender) {
        // Ignore        
    }

    @Override
    public void onHttpResponseReceive(HttpMessage msg, int initiator, HttpSender sender) {
        String comp;
        switch (initiator) {
        case HttpSender.ACTIVE_SCANNER_INITIATOR:	comp = "ascan";		break;
        case HttpSender.AUTHENTICATION_INITIATOR:	comp = "auth";		break;
        case HttpSender.FUZZER_INITIATOR:			comp = "fuzz";		break;
        case HttpSender.MANUAL_REQUEST_INITIATOR:	comp = "manual";	break;
        case HttpSender.PROXY_INITIATOR:			comp = "proxy";		break;
        case HttpSender.SPIDER_INITIATOR:			comp = "spider";	break;
        default:									comp = Integer.toString(initiator);	break;
        }
        Session session = Model.getSingleton().getSession();
        URI uri = msg.getRequestHeader().getURI();
        try {
            String site = SessionStructure.getHostName(msg);
            for (Context context : session.getContexts()) {
                if (context.isInScope()) {
                    if (context.isInContext(uri.toString())) {
                        String prefix = "stats.auth." + comp + ".state.";
                        if (! msg.getResponseHeader().isHtml()) {
                            // Record for info 
                            Stats.incCounter(site, prefix + "nothtml");
                        } else if (! HttpStatusCode.isSuccess(msg.getResponseHeader().getStatusCode())) {
                            // Record for info 
                            Stats.incCounter(site, prefix + "notsuccess");
                        } else {
                            AuthenticationMethod auth = context.getAuthenticationMethod();
                            Pattern loggedInPattern = auth.getLoggedInIndicatorPattern();
                            Pattern loggedOutPattern = auth.getLoggedOutIndicatorPattern();
                            
                            if (loggedInPattern == null && loggedOutPattern == null) {
                                Stats.incCounter(site, prefix + "noindicator");
                            } else {
                                String fullResponse = msg.getResponseHeader().toString() + "\r\n\r\n" +
                                        msg.getResponseBody().toString();
                                
                                boolean loggedIn = loggedInPattern != null && 
                                        loggedInPattern.matcher(fullResponse).find();
        
                                boolean loggedOut = loggedOutPattern != null && 
                                        loggedOutPattern.matcher(fullResponse).find();
                                
                                if (loggedIn && loggedOut) {
                                    Stats.incCounter(site, prefix + "loggedinandout");
                                } else if (loggedIn) {
                                    Stats.incCounter(site, prefix + "loggedin");
                                } else if (loggedOut) {
                                    Stats.incCounter(site, prefix + "loggedout");
                                } else {
                                    Stats.incCounter(site, prefix + "unknown");
                                }
                            }
                        }
                    }
                }
            }
        } catch (URIException e) {
            log.error(e.getMessage(), e);
        }
    }
}
