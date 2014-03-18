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
package org.zaproxy.zap.extension.multiFuzz;

import java.awt.Color;
import java.awt.Component;
import java.util.ArrayList;

import javax.swing.text.DefaultHighlighter.DefaultHighlightPainter;

import org.zaproxy.zap.extension.httppanel.Message;

public abstract class MFuzzableComponent extends Component implements org.zaproxy.zap.extension.fuzz.FuzzableComponent{

    public abstract Class<? extends Message> getMessageClass();

    public abstract MFuzzableMessage getFuzzableMessage();

    public abstract boolean canFuzz();
    
    public abstract FuzzLocation currentSelection();
    
    public abstract Component underlyingComponent();
    
    public abstract void highLight(ArrayList<FuzzLocation> fl, int curr);
    
    public String getFuzzTarget(FuzzLocation l){
    	MFuzzableMessage fm = getFuzzableMessage();
    	return fm.representName(l);
    }
    
	protected class MyHighlightPainter extends DefaultHighlightPainter {
		public MyHighlightPainter(Color color) {
			super(color);
		}
	}

}
