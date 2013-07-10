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
package org.zaproxy.zap.extension.diff;

import java.util.List;

import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.view.PopupMenuHistoryReference;

public class PopupMenuDiff extends PopupMenuHistoryReference {

	private static final long serialVersionUID = 1L;
    private ExtensionDiff ext = null;

    /**
     * @param label
     */
    public PopupMenuDiff(String label, ExtensionDiff ext) {
        super(label, true);
        this.setName("DiffPopup");
        this.ext = ext;
    }


    public boolean isEnableForInvoker(Invoker invoker) {
    	return true;
    }

	@Override
    public boolean isEnabledForHistoryReferences (List<HistoryReference> hrefs) {
	    if (hrefs.size() != 2) {
	        return false;
	    }
	    
	    for (HistoryReference hRef : hrefs) {
	        if (hRef == null) {
	            return false;
	        }
	    }
	    
    	return true;
    }

	@Override
    public void performActions (List<HistoryReference> hrefs) throws Exception {
    	if (hrefs.size() == 2) {
    		this.ext.showDiffDialog(hrefs.get(0).getHttpMessage(), hrefs.get(1).getHttpMessage());
    	}
    }


	@Override
	public void performAction(HistoryReference href) throws Exception {
		// Ignore
	}
}