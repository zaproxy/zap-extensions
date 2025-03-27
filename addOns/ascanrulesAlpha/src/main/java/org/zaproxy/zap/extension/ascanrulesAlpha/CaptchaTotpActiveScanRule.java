package org.zaproxy.zap.extension.ascanrulesAlpha;
import java.util.HashMap;
import java.util.ArrayList;
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
public class CaptchaTotpActiveScanRule extends AbstractHostPlugin implements CommonActiveScanRuleInfo{
    private static final Logger LOGGER = LogManager.getLogger(BlankTotpActiveScanRule.class);
    private static final Map<String, String> ALERT_TAGS = new HashMap<>();
                      
    @Override
    public int getId() {
        return 40051;
    }
    @Override
    public String getName() {
        return "Captcha or Lockout TOTP Scan Rule";
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

            //Check if lockout or captcha mechanism is detected
            boolean captchaDetected = false;
            boolean lockoutDetected = false; 

            // Run 10 incorrect authentications and store the responses
            // Check responses for any changes or any common captcha technology 
            List<List<HttpMessage>> allHttpResponses = new ArrayList<>();
            for (int i = 0; i < 10; i++) {
                LOGGER.error("Session number: " + i);
                WebSession testSession = testAuthenticatSession(totpStep, "111111", authSteps, browserAuthMethod, sessionManagementMethod, credentials, user);
               //Add the response to the httpResponses list
                List <HttpMessage> messages= browserAuthMethod.getRecordedHttpMessages();

               //Check for key captcha words in the responses
                String[] captchaKeywords = {
                "captcha", "g-recaptcha", "hcaptcha", "data-sitekey", "verify you are human",
                "challenge-response", "bot detection", "recaptcha/api.js", "hcaptcha.com/1/api.js",
                "please solve the captcha", "captcha verification", "input type=\"hidden\" name=\"g-recaptcha-response\""};
                for (String keyword : captchaKeywords) {
                    for (HttpMessage response : messages) {
                        if (response.getResponseBody().toString().toLowerCase().contains(keyword)) {
                            LOGGER.error("Captcha detected");
                            captchaDetected = true;
                            return;
                        }
                    }
                }

                //Check for lockout words in the responses
                String[] lockoutKeywords = {
                "lockout", "locked", "too many failed attempts", "too many login attempts","reset your password", "account disabled", "unlock"};
                for (String keyword : lockoutKeywords) {
                    for (HttpMessage response : messages) {
                        if (response.getResponseBody().toString().toLowerCase().contains(keyword)) {
                            LOGGER.error("lockout detected" + response.getResponseBody().toString() );
                            LOGGER.error("keyword" + keyword );
                            lockoutDetected = true;
                            return;
                        }
                        else if (response.getResponseHeader().getStatusCode() == 403){
                            lockoutDetected = true;
                            LOGGER.error("lockout detected");
                            return;
                        }
                    }
                }
               LOGGER.error("responseLength: " + messages.size());
               allHttpResponses.add(messages);
            }
            LOGGER.error("No lockout or captcha detected yet");
            //Iterate over the messages from each web session and check for any changes in the response (could indicate lockout/captcha)
            // for (List<HttpMessage> httpResponsesFromSession : allHttpResponses) {
            //     for (HttpMessage response : httpResponsesFromSession) {
            //         // Check for changes to the response's indicating a potential lockout/captcha mechanism
            //         if (response.getResponseBody().toString().toLowerCase().contains("captcha")) {
            //             captchaDetected = true;
            //         }
            //         if (response.getResponseBody().toString().contains("lockout")) {
            //             lockoutDetected = true;
            //         }
            //     }
            // }
            
            if (!captchaDetected && !lockoutDetected) {
                //LOGGER.error("");
                buildAlert("No Lockout or Captcha Mechanism Detected", 
                    "\"The application does not enforce CAPTCHA or account lockout mechanisms, making it vulnerable to brute-force attacks.",
                    "Implement CAPTCHA verification and/or account lockout policies after multiple failed login attempts.", msg).raise();
            }
        } catch (Exception e) { 
            LOGGER.error("Error in TOTP Page Scan Rule: {}",e.getMessage(), e);
        }
    }

    private WebSession testAuthenticatSession(AuthenticationStep totpStep, String newTotpValue, List<AuthenticationStep> authSteps , BrowserBasedAuthenticationMethod browserAuthMethod, SessionManagementMethod sessionManagementMethod, UsernamePasswordAuthenticationCredentials credentials, User user){
        totpStep.setValue(newTotpValue);
        browserAuthMethod.setAuthenticationSteps(authSteps); 
        return browserAuthMethod.authenticate(sessionManagementMethod, credentials, user);
    }
    private AlertBuilder buildAlert(String name, String description, String solution, HttpMessage msg) {
        return newAlert()
        .setConfidence(Alert.CONFIDENCE_MEDIUM)
        .setName(name)
        .setDescription(description)
        .setSolution(solution)
        .setMessage(msg);
    }
}




