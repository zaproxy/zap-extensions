package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.session.WebSession;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.addon.authhelper.BrowserBasedAuthenticationMethodType.BrowserBasedAuthenticationMethod;
import org.zaproxy.addon.authhelper.internal.AuthenticationStep;


public class ReplayTotpActiveScanRule extends AbstractHostPlugin implements CommonActiveScanRuleInfo{
    private static final Logger LOGGER = LogManager.getLogger(ReplayTotpActiveScanRule.class);
    private static final Map<String, String> ALERT_TAGS = new HashMap<>();
                      
    @Override
    public int getId() {
        return 40049;
    }
    @Override
    public String getName() {
        return "Replay TOTP Scan Rule";
    }
    @Override
    public String getDescription() {
        return "TOTP Page found";
    }
    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
    }
    @Override
    public String getSolution() {
        return "N/A";
    }
    @Override
    public String getReference() {
        return "N/A";
    }
    @Override
    public void scan() {
        try {
            ExtensionUserManagement usersExtension =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionUserManagement.class);

            // Get target URL from request
            HttpMessage msg = getBaseMsg();
            String targetUrl = msg.getRequestHeader().getURI().toString();

            // Find session context that matches the target URL 
            Context activeContext = null;
            Session session = Model.getSingleton().getSession();
            for (Context context : session.getContexts()) {
                if (context.isInContext(targetUrl)) {
                    activeContext = context;
                    break;
                }
            }
            BrowserBasedAuthenticationMethod browserAuthMethod = null;
            List<AuthenticationStep> authSteps = null;
            AuthenticationStep totpStep = null;
            // Check if the context is found
            if (activeContext != null) {
                AuthenticationMethod authMethod = activeContext.getAuthenticationMethod();
                // Check if the authentication method is browser based
                if (authMethod instanceof BrowserBasedAuthenticationMethod) {
                    browserAuthMethod = (BrowserBasedAuthenticationMethod) authMethod;
                    // Check if the authentication method has TOTP step
                    authSteps = browserAuthMethod.getAuthenticationSteps();
                    boolean totpFound = false;
                    for (AuthenticationStep step : authSteps) {
                        // Checks for TOTP_field type step or currently also allows for 
                        // custom field b/c of the way TOTP_field step currently implemented
                        if (step.getType() == AuthenticationStep.Type.TOTP_FIELD || (step.getType() == AuthenticationStep.Type.CUSTOM_FIELD && step.getDescription().toLowerCase().contains("totp"))) {
                            totpFound = true;
                            totpStep = step;
                            break;
                        }
                    }
                    if (!totpFound) {
                        return;
                    }
                    
                }
                else{
                    //LOGGER.error("Authentication Method is not browser based.");
                    return;
                } 
            }
            else {
                //LOGGER.error("No context found for target URL: " + targetUrl);
                return;
            }

            //Start vulnerability testing if TOTP step is found
            //LOGGER.error("TOTP authentication is enabled, proceeding with tests.");

            // Get user credentials(username,password) & user from the context to run browser based web session
            List<User> users = null;
            if (usersExtension == null) {
                //LOGGER.error("Users extension not found.");
                return;
            }
            users = usersExtension.getContextUserAuthManager(activeContext.getId()).getUsers();
            if (users == null || users.isEmpty()) {
                //LOGGER.error("No users found in the context.");
                return;
            }
            User user = users.get(0);
            UsernamePasswordAuthenticationCredentials credentials = (UsernamePasswordAuthenticationCredentials) user.getAuthenticationCredentials();
            SessionManagementMethod sessionManagementMethod = activeContext.getSessionManagementMethod();

            //Check if user provided valid code & check if initial authentication works with normal passcode
            if(totpStep.getValue() != null || !totpStep.getValue().isEmpty()){
                WebSession webSession = browserAuthMethod.authenticate(sessionManagementMethod, credentials, user);
                if (webSession == null) {
                    //LOGGER.error("Normal Authentication unsuccessful. TOTP not configured correctly.");
                    return;
                }
                // Check for passcode reuse vulnerability
                WebSession webSession_redo = browserAuthMethod.authenticate(sessionManagementMethod, credentials, user);
                if (webSession_redo != null) {
                    LOGGER.error("Authentication with reused passcode. Vulnerability found.");
                    buildAlert("TOTP Replay Attack Vulnerability", 
                    "The application is vulnerable to replay attacks, allowing attackers to reuse previously intercepted TOTP codes to authenticate.",
                    "Ensure that TOTP codes are validated only once per session and are invalidated after use.", msg).raise();
                }
            }
        } catch (Exception e) { 
            LOGGER.error("Error in TOTP Page Scan Rule: {}",e.getMessage(), e);
        }
    }
    private AlertBuilder buildAlert(String name, String description, String solution, HttpMessage msg) {
        return newAlert()
        .setConfidence(Alert.CONFIDENCE_HIGH)
        .setName(name)
        .setDescription(description)
        .setSolution(solution)
        .setMessage(msg);
    }
}


