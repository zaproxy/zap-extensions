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
package org.zaproxy.zap.extension.tokengen;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;
import java.util.Vector;
import java.util.concurrent.TimeUnit;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.params.HtmlParameterStats;

/*
 * An example ZAP extension which adds a right click menu item to all of the main
 * tabs which list messages.
 *
 * This class is defines the extension.
 */
public class ExtensionTokenGen extends ExtensionAdaptor {

    public static final String NAME = "ExtensionTokenGen";

    private TokenGenPopupMenu popupTokenGenMenu = null;
    private TokenPanel tokenPanel = null;
    private GenerateTokensDialog genTokensDialog = null;
    private AnalyseTokensDialog analyseTokensDialog = null;

    private TokenParam tokenParam = null;
    private TokenOptionsPanel tokenOptionsPanel;

    private List<TokenGenerator> generators = Collections.emptyList();
    private int runningGenerators = 0;
    private CharacterFrequencyMap cfm = null;
    private boolean manuallyStopped = false;

    private static Logger log = Logger.getLogger(ExtensionTokenGen.class);

    /** */
    public ExtensionTokenGen() {
        super(NAME);
        this.setI18nPrefix("tokengen");
    }

    @Override
    public void init() {
        super.init();

        TokenAnalysisTestResult.setResourceBundle(getMessages());
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        extensionHook.addSessionListener(new SessionChangedListenerImpl());

        extensionHook.addOptionsParamSet(getTokenParam());

        if (getView() != null) {
            // Register our popup menu item, as long as we're not running as a daemon
            extensionHook.getHookMenu().addPopupMenuItem(getPopupTokenGen());
            extensionHook.getHookView().addStatusPanel(getTokenPanel());
            this.getTokenPanel()
                    .setDisplayPanel(getView().getRequestPanel(), getView().getResponsePanel());

            extensionHook.getHookView().addOptionPanel(getTokenOptionsPanel());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        stopTokenGeneration();

        if (getView() != null) {
            if (analyseTokensDialog != null) {
                analyseTokensDialog.dispose();
            }

            if (genTokensDialog != null) {
                genTokensDialog.dispose();
            }

            getView()
                    .getMainFrame()
                    .getMainFooterPanel()
                    .removeFooterToolbarRightLabel(getTokenPanel().getScanStatus().getCountLabel());
        }

        super.unload();
    }

    @Override
    public List<String> getActiveActions() {
        if (runningGenerators == 0) {
            return null;
        }

        List<String> activeActions = new ArrayList<>(1);
        activeActions.add(Constant.messages.getString("tokengen.activeAction"));
        return activeActions;
    }

    private TokenPanel getTokenPanel() {
        if (tokenPanel == null) {
            tokenPanel = new TokenPanel(this, this.getTokenParam());
        }
        return tokenPanel;
    }

    private TokenParam getTokenParam() {
        if (tokenParam == null) {
            tokenParam = new TokenParam();
        }
        return tokenParam;
    }

    private TokenOptionsPanel getTokenOptionsPanel() {
        if (tokenOptionsPanel == null) {
            tokenOptionsPanel = new TokenOptionsPanel();
        }
        return tokenOptionsPanel;
    }

    // TODO This method is also in ExtensionAntiCSRF - put into a helper class?
    public String getTokenValue(HttpMessage tokenMsg, String tokenName) {
        Source source = new Source(tokenMsg.getResponseBody().toString());
        List<Element> formElements = source.getAllElements(HTMLElementName.FORM);

        if (formElements != null && formElements.size() > 0) {
            // Loop through all of the FORM tags

            for (Element formElement : formElements) {
                List<Element> inputElements = formElement.getAllElements(HTMLElementName.INPUT);

                if (inputElements != null && inputElements.size() > 0) {
                    // Loop through all of the INPUT elements
                    for (Element inputElement : inputElements) {
                        String id = inputElement.getAttributeValue("ID");
                        if (id != null && id.equalsIgnoreCase(tokenName)) {
                            return inputElement.getAttributeValue("VALUE");
                        }
                        String name = inputElement.getAttributeValue("NAME");
                        if (name != null && name.equalsIgnoreCase(tokenName)) {
                            return inputElement.getAttributeValue("VALUE");
                        }
                    }
                }
            }
        }
        return null;
    }

    public Vector<String> getFormInputFields(HttpMessage tokenMsg) {
        Source source = new Source(tokenMsg.getResponseBody().toString());
        List<Element> formElements = source.getAllElements(HTMLElementName.FORM);
        Vector<String> fifs = new Vector<>();

        if (formElements != null && formElements.size() > 0) {
            // Loop through all of the FORM tags

            for (Element formElement : formElements) {
                List<Element> inputElements = formElement.getAllElements(HTMLElementName.INPUT);

                if (inputElements != null && inputElements.size() > 0) {
                    // Loop through all of the INPUT elements
                    for (Element inputElement : inputElements) {
                        String id = inputElement.getAttributeValue("ID");
                        if (id != null && id.length() > 0) {
                            fifs.add(id);
                        } else {
                            String name = inputElement.getAttributeValue("NAME");
                            if (name != null && name.length() > 0) {
                                fifs.add(name);
                            }
                        }
                    }
                }
            }
        }
        return fifs;
    }

    protected void addTokenResult(HttpMessage msg, HtmlParameterStats targetToken) {
        // Extract the token
        String token = null;
        switch (targetToken.getType()) {
            case cookie:
                TreeSet<HtmlParameter> cookies = msg.getCookieParams();
                Iterator<HtmlParameter> iter = cookies.iterator();
                while (iter.hasNext()) {
                    HtmlParameter cookie = iter.next();
                    if (cookie.getName().equals(targetToken.getName())) {
                        token = cookie.getValue();
                        break;
                    }
                }
                break;
            case form:
                token = this.getTokenValue(msg, targetToken.getName());
                break;
            case url:
                // TODO
                break;
        }
        if (token != null) {
            this.cfm.addToken(token);
            msg.setNote(token);
        }

        this.getTokenPanel().addTokenResult(new MessageSummary(msg));
    }

    private TokenGenPopupMenu getPopupTokenGen() {
        if (popupTokenGenMenu == null) {
            popupTokenGenMenu =
                    new TokenGenPopupMenu(
                            getMessages().getString("tokengen.generate.popup.generate"));
            popupTokenGenMenu.setExtension(this);
        }
        return popupTokenGenMenu;
    }

    private GenerateTokensDialog getGenerateTokensDialog() {
        if (this.genTokensDialog == null) {
            this.genTokensDialog = new GenerateTokensDialog(getMessages());
            this.genTokensDialog.setExtension(this);
        }
        return this.genTokensDialog;
    }

    public void showGenerateTokensDialog(HttpMessage msg) {
        this.getGenerateTokensDialog().setMessage(msg);
        this.getGenerateTokensDialog().setVisible(true);
    }

    private AnalyseTokensDialog getAnalyseTokensDialog() {
        if (this.analyseTokensDialog == null) {
            this.analyseTokensDialog = new AnalyseTokensDialog(getMessages());
            this.analyseTokensDialog.setExtension(this);
        }
        return this.analyseTokensDialog;
    }

    public void showAnalyseTokensDialog(CharacterFrequencyMap cfm) {
        this.getAnalyseTokensDialog().reset();
        this.getAnalyseTokensDialog().setVisible(true);
        this.getAnalyseTokensDialog().startAnalysis(cfm);
    }

    public void showAnalyseTokensDialog() {
        this.showAnalyseTokensDialog(this.cfm);
    }

    @SuppressWarnings("fallthrough")
    public void startTokenGeneration(
            HttpMessage msg,
            int numGen,
            HtmlParameterStats htmlParameterStats,
            boolean shouldRemoveCookie) {
        switch (Control.getSingleton().getMode()) {
            case safe:
                throw new IllegalStateException("Token generation is not allowed in Safe mode");
            case protect:
                if (!msg.isInScope()) {
                    throw new IllegalStateException(
                            "Token generation is not allowed with a message not in scope when in Protected mode: "
                                    + msg.getRequestHeader().getURI());
                }
            case standard:
            case attack:
                // No problem
                break;
        }

        this.cfm = new CharacterFrequencyMap();
        log.debug("startTokenGeneration " + msg.getRequestHeader().getURI() + " # " + numGen);
        this.getTokenPanel().scanStarted(numGen);

        int numThreads = this.getTokenParam().getThreadsPerScan();
        this.manuallyStopped = false;

        generators = new ArrayList<>();

        for (int i = 0; i < numThreads; i++) {
            TokenGenerator gen = new TokenGenerator();
            generators.add(gen);

            gen.setExtension(this);
            gen.setHttpMessage(msg);
            gen.setNumberTokens(numGen / numThreads); // TODO what about remainder?
            gen.setTargetToken(htmlParameterStats);
            gen.setRequestDelay(getTokenParam().getRequestDelayInMs(), TimeUnit.MILLISECONDS);
            gen.setShouldRemoveCookie(shouldRemoveCookie);
            gen.execute();
            this.runningGenerators++;
        }
    }

    protected void generatorStopped(TokenGenerator gen) {
        this.runningGenerators--;
        log.debug("generatorStopped runningGenerators " + runningGenerators);

        if (this.runningGenerators <= 0) {
            log.debug("generatorStopped scanFinished");
            this.getTokenPanel().scanFinshed();

            if (!manuallyStopped) {
                this.showAnalyseTokensDialog();
            }
        }
    }

    public void stopTokenGeneration() {
        this.manuallyStopped = true;
        for (TokenGenerator gen : generators) {
            gen.stopGenerating();
        }
    }

    public void pauseTokenGeneration() {
        for (TokenGenerator gen : generators) {
            gen.setPaused(true);
        }
    }

    public void resumeTokenGeneration() {
        for (TokenGenerator gen : generators) {
            gen.setPaused(false);
        }
    }

    @Override
    public String getDescription() {
        return getMessages().getString("tokengen.desc");
    }

    private class SessionChangedListenerImpl implements SessionChangedListener {

        @Override
        public void sessionChanged(Session session) {}

        @Override
        public void sessionAboutToChange(Session session) {
            stopTokenGeneration();
            generators = Collections.emptyList();

            if (tokenPanel != null) {
                tokenPanel.reset();
            }

            if (analyseTokensDialog != null) {
                analyseTokensDialog.setVisible(false);
            }

            if (genTokensDialog != null) {
                genTokensDialog.setVisible(false);
            }
        }

        @Override
        public void sessionScopeChanged(Session session) {}

        @Override
        public void sessionModeChanged(Mode mode) {
            if (Mode.safe.equals(mode)) {
                stopTokenGeneration();
            } else if (Mode.protect.equals(mode)) {
                if (!generators.isEmpty() && !generators.get(0).getHttpMessage().isInScope()) {
                    stopTokenGeneration();
                }
            }
        }
    }
}
