package org.zaproxy.zap.extension.highlighter;

import java.net.MalformedURLException;
import java.net.URL;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

/*
 * Implements the Extension Interface for HighlighterManager and HighlighterPanel
 */
public class ExtensionHighlighter extends ExtensionAdaptor {

	public static final String NAME = "ExtensionHighlighter";
	private HighlighterPanel highlighterPanel;
		
	public ExtensionHighlighter() {
		this.setName(NAME);
		this.setOrder(69);
	}

	@Override
	public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        
        if (getView() != null) {
            extensionHook.getHookView().addStatusPanel(getHighlighterPanel());

            // TODO enable (and correct the key) once the add-on provides help
            // ExtensionHelp.enableHelpKey(getHighlighterPanel(), "ui.tabs.hilighter");
        }
    }
	
	@Override
	public boolean canUnload() {
    	return true;
    }
	
    protected HighlighterPanel getHighlighterPanel() {
        if (highlighterPanel == null) {
        	highlighterPanel = new HighlighterPanel(this);
        }
        return highlighterPanel;
    }
	
	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
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
