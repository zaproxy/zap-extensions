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
package org.zaproxy.zap.extension.multiFuzz.impl.http;

import java.awt.Color;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import javax.swing.JTextArea;
import javax.swing.text.Highlighter;

import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.fuzz.FuzzableComponent;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.multiFuzz.FuzzLocation;
import org.zaproxy.zap.extension.multiFuzz.MFuzzableMessage;
import org.zaproxy.zap.extension.multiFuzz.MultiExtensionFuzz;
import org.zaproxy.zap.extension.multiFuzz.MFuzzableComponent;
import org.zaproxy.zap.extension.multiFuzz.FuzzerContentPanel;
import org.zaproxy.zap.extension.multiFuzz.FuzzerHandler;
import org.zaproxy.zap.extension.search.SearchResult;

public class HttpFuzzerHandler implements FuzzerHandler {

    private HttpFuzzerContentPanel fuzzerPanel;
    private boolean showTokenRequests;
    
    public HttpFuzzerHandler() {
        super();
        
        showTokenRequests = false;
    }
    
    void setShowTokenRequests(boolean showTokenRequests) {
        this.showTokenRequests = showTokenRequests;
    }
    
    @Override
    public void showFuzzDialog(Component comp) {
    	final JTextArea compbase = new JTextArea(((JTextArea) comp).getDocument());
    	compbase.setSelectionStart(((JTextArea) comp).getSelectionStart());
    	compbase.setSelectionEnd(((JTextArea) comp).getSelectionEnd());
    	final FuzzableComponent fuzzbase = (FuzzableComponent) comp;
    	MFuzzableComponent fuzzableComponent = new MFuzzableComponent() {
			@Override
			public String getFuzzTarget() {
				return fuzzbase.getFuzzTarget();
			}
			@Override
			public Component underlyingComponent(){
				return compbase;
			}
			
			@Override
			public void highLight(ArrayList<FuzzLocation> fl, int curr) {
				removeHighlights();
				Highlighter highlight = compbase.getHighlighter();
				for(int i = 0; i < fl.size(); i++){
					HttpFuzzLocation f = (HttpFuzzLocation) fl.get(i);
					int pos = f.start;
					int len = f.end - f.start;
					try {
						highlight.addHighlight( pos, pos+len, new MyHighlightPainter(getColor(i+1)));
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
			private Color getColor(int n) {
				float hue = (float) (n % 5) / 5;
				float sat = (float) Math.ceil((float)n/5)/2;
				float bright = (float) Math.ceil((float)n/5);
				return Color.getHSBColor(hue, sat, bright);
			}
			
			private void removeHighlights() {
				Highlighter hilite = compbase.getHighlighter();
				Highlighter.Highlight[] hilites = hilite.getHighlights();

				for (int i = 0; i < hilites.length; i++) {
					if (hilites[i].getPainter() instanceof MyHighlightPainter) {
						hilite.removeHighlight(hilites[i]);
					}
				}
			}
			
			@Override
			public Class<? extends Message> getMessageClass() {
				return fuzzbase.getMessageClass();
			}
			
			@Override
			public MFuzzableMessage getFuzzableMessage() {
				return new HttpFuzzableMessage((HttpMessage) (fuzzbase.getFuzzableMessage().getMessage()));
			}
			
			@Override
			public FuzzLocation currentSelection() {
				int s = compbase.getSelectionStart();
				int e = compbase.getSelectionEnd();
				String header = ((HttpMessage)fuzzbase.getFuzzableMessage().getMessage()).getRequestHeader().toString();
				int headerLen = header.length();
				int hl = 0;
				int pos = 0;
				while (((pos = header.indexOf("\r\n", pos)) != -1) && (pos <= s + hl)) {
					pos += 2;
					++hl;
				}
				if(headerLen > s+hl){
					String cut = header.substring(s+hl,e+hl);
					boolean head = getFuzzTarget().equals(cut);
					return new HttpFuzzLocation(s, e, head);
				}
				else{
					return new HttpFuzzLocation(s, e, false);
				}
			}
			
			@Override
			public boolean canFuzz() {
				return fuzzbase.canFuzz();
			}
		}; 
        showTokenRequests = false;
        getDialog(fuzzableComponent).setVisible(true);
    }

    @Override
    public FuzzerContentPanel getFuzzerContentPanel() {
        return getContentPanel();
    }
    
    private HttpFuzzDialog getDialog(MFuzzableComponent fuzzableComponent) {
        MultiExtensionFuzz ext = (MultiExtensionFuzz) Control.getSingleton().getExtensionLoader().getExtension(MultiExtensionFuzz.NAME);
        return new HttpFuzzDialog(this, ext, fuzzableComponent);
    }
    
    private FuzzerContentPanel getContentPanel() {
        if (fuzzerPanel == null) {
            fuzzerPanel = new HttpFuzzerContentPanel();
            fuzzerPanel.setDisplayPanel(View.getSingleton().getRequestPanel(), View.getSingleton().getResponsePanel());
        }
        fuzzerPanel.setShowTokenRequests(showTokenRequests);
        return fuzzerPanel;
    }
    
    @Override
    public List<SearchResult> searchResults(Pattern pattern, boolean inverse) {
        return fuzzerPanel.searchResults(pattern, inverse);
    }
}
