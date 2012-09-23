/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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
package org.zaproxy.zap.extension.tokengen;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ResourceBundle;
import java.util.TreeSet;
import java.util.Vector;

import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
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

	private TokenParam tokenParam = null;;
	
	private List<TokenGenerator> generators = new ArrayList<>();
	private int runningGenerators = 0;
	private CharacterFrequencyMap cfm = null; 
	private boolean manuallyStopped = false;
	
    private static Logger log = Logger.getLogger(ExtensionTokenGen.class);

    protected static ResourceBundle messages = null;

	/**
     * 
     */
    public ExtensionTokenGen() {
        super();
 		initialize();
    }

    /**
     * @param name
     */
    public ExtensionTokenGen(String name) {
        super(name);
    }

	/**
	 * This method initializes this
	 * 
	 */
	private void initialize() {
        this.setName(NAME);
        // Load extension specific language files - these are held in the extension jar
        messages = ResourceBundle.getBundle(
        		this.getClass().getPackage().getName() + ".Messages", Constant.getLocale());
	}
	
	@Override
	public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);
	    
	    if (getView() != null) {
	    	// Register our popup menu item, as long as we're not running as a daemon
	    	extensionHook.getHookMenu().addPopupMenuItem(getPopupTokenGen());
	        extensionHook.getHookView().addStatusPanel(getTokenPanel());
	        this.getTokenPanel().setDisplayPanel(getView().getRequestPanel(), getView().getResponsePanel());
	    }
	}

	private TokenPanel getTokenPanel() {
		if (tokenPanel == null) {
			tokenPanel = new TokenPanel(this, this.getTokenParam());
		}
		return tokenPanel;
	}

	private TokenParam getTokenParam() {
		if (tokenParam  == null) {
			tokenParam = new TokenParam();
		}
		return tokenParam;
	}

	// TODO This method is also in ExtensionAntiCSRF - put into a helper class?
	public String getTokenValue(HttpMessage tokenMsg, String tokenName) {
		String response = tokenMsg.getResponseHeader().toString() + tokenMsg.getResponseBody().toString();
		Source source = new Source(response);
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
		String response = tokenMsg.getResponseHeader().toString() + tokenMsg.getResponseBody().toString();
		Source source = new Source(response);
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
		
		this.getTokenPanel().addTokenResult(msg);
	}

	private TokenGenPopupMenu getPopupTokenGen() {
		if (popupTokenGenMenu  == null) {
			popupTokenGenMenu = new TokenGenPopupMenu(messages.getString("token.generate.popup.generate"));
			popupTokenGenMenu.setExtension(this);
		}
		return popupTokenGenMenu;
	}
	
	private GenerateTokensDialog getGenerateTokensDialog() {
		if (this.genTokensDialog == null) {
			this.genTokensDialog = new GenerateTokensDialog();
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
			this.analyseTokensDialog = new AnalyseTokensDialog();
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

	public void startTokenGeneration(HttpMessage msg, int numGen, HtmlParameterStats htmlParameterStats) {
		this.cfm = new CharacterFrequencyMap();
		log.debug("startTokenGeneration " + msg.getRequestHeader().getURI() + " # " + numGen);
		this.getTokenPanel().scanStarted(numGen);
		
		int numThreads = this.getTokenParam().getThreadPerScan();
		this.manuallyStopped = false;
		
		generators = new ArrayList<>();
		
		for (int i=0; i < numThreads; i++) {
			TokenGenerator gen = new TokenGenerator();
			generators.add(gen);
			
			gen.setExtension(this);
			gen.setHttpMessage(msg);
			gen.setNumberTokens(numGen / numThreads);	// TODO what about remainder?
			gen.setTargetToken(htmlParameterStats);
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
			
			if (! manuallyStopped) {
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
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return messages.getString("token.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_EXTENSIONS_PAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}
}