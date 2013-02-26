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

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.diff.ZapDiffRowGenerator.Builder;
import org.zaproxy.zap.extension.diff.diff_match_patch.Diff;

import difflib.DiffRow;

/**
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public class ExtensionDiff extends ExtensionAdaptor {

    private PopupMenuDiff popupMenuDiff = null;
    private DiffDialog diffDialog = null;

    /**
     * 
     */
    public ExtensionDiff() {
        super();
 		initialize();
    }

    /**
     * @param name
     */
    public ExtensionDiff(String name) {
        super(name);
    }

    @Override
	public boolean canUnload() {
    	return true;
    }

	/**
	 * This method initializes this
	 * 
	 * @return void
	 */
	private void initialize() {
        this.setName("ExtensionDiff");
        this.setOrder(75);
	}
	

	public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);

	    if (getView() != null) {	        
	        extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuDiff());
	    }

	}

    private PopupMenuDiff getPopupMenuDiff() {
        if (popupMenuDiff== null) {
        	popupMenuDiff = new PopupMenuDiff(Constant.messages.getString("diff.diff.popup"), this);
        }
        return popupMenuDiff;
    }
    
	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

    private void stringToList(String str, List<String> list) {
    	for (String s : str.split("\n")) {
    		list.add(s);
    	}
    }
    
    private DiffDialog getDiffDialog() {
    	if (diffDialog == null) {
    		diffDialog = new DiffDialog(getView().getMainFrame(), false);
    	}
    	return diffDialog;
    }

    public void showDiffDialog (HttpMessage msg1, HttpMessage msg2) throws Exception {
    	/* 
    	 * This _is_ fairly nasty ;)
    	 * This method uses 2 different classes/projects to work out the diffs.
    	 * It uses diffutils to get the differing lines, and then diff_match_patch to identify the 
    	 * diffs in the pairs of lines.
    	 * Be delighted if anyone can implement a cleaner option ;)
    	 */
    	
    	if (msg1 == null || msg2 == null) {
    		return;
    	}
    	DiffDialog diffDialog = this.getDiffDialog();
    	if (diffDialog.isVisible()) {
    		return;
    	}
    	List<String> msgList1 = new ArrayList<String>();
		List<String> msgList2 = new ArrayList<String>();
		
		stringToList(msg1.getResponseHeader().toString(), msgList1);
		stringToList(msg1.getResponseBody().toString(), msgList1);
		stringToList(msg2.getResponseHeader().toString(), msgList2);
		stringToList(msg2.getResponseBody().toString(), msgList2);
		
		
		Builder builder = new ZapDiffRowGenerator.Builder();
		ZapDiffRowGenerator drg = builder.build();

		List<DiffRow> res = drg.generateDiffRows(msgList1, msgList2);
		int leftLine = 0;
		int rightLine = 0;
		for (DiffRow dr : res) {
	    	diff_match_patch dmp = new diff_match_patch();

			switch(dr.getTag()) {
			case CHANGE:
				if (dr.getOldLine().length() > 0) {
					diffDialog.appendLeftText(leftLine + " : ", true);
				}
				if (dr.getNewLine().length() > 0) {
					diffDialog.appendRightText(rightLine + " : ", true);
				}
				
				/*
				 * Apply the highlighters after adding all the text.
				 * Bit nasty, but otherwise when you insert test if moves the end of the highlighter
				 * so everything is highlighted.
				 */
				
				List <int[]> leftHighlighters = new ArrayList<int[]>(); 
				List <int[]> rightHighlighters = new ArrayList<int[]>(); 
				
		    	LinkedList<Diff> diffs = dmp.diff_main(dr.getOldLine(), dr.getNewLine());
		    	for (Diff diff : diffs) {
		    		int end = 0;
		    		switch (diff.operation) {
		    		case EQUAL:
		    			diffDialog.appendLeftText(diff.text, false);
		    			diffDialog.appendRightText(diff.text, false);
		    			break;
		    		case DELETE:
		    			end = diffDialog.appendLeftText(diff.text, false);
		    			leftHighlighters.add(new int[] {end - diff.text.length(), end});
		    			break;
		    		case INSERT:
		    			end = diffDialog.appendRightText(diff.text, false);
		    			rightHighlighters.add(new int[] {end - diff.text.length(), end});
		    			break;
		    		}
		    	}
		    	
		    	// These spaces prevent the next lines from moving any highlights at the end of the line
    			diffDialog.appendLeftText(" ", false);
    			diffDialog.appendRightText(" ", false);
    			
		    	for (int[] hl : leftHighlighters) {
		    		diffDialog.highlightLeftText(hl[0], hl[1]);
		    	}
		    	for (int[] hl : rightHighlighters) {
		    		diffDialog.highlightRightText(hl[0], hl[1]);
		    	}

				if (dr.getOldLine().length() > 0) {
					leftLine++; 
				}
				if (dr.getNewLine().length() > 0) {
					rightLine++; 
				}
				break;
			case EQUAL:		
				diffDialog.appendLeftText(leftLine + " : ", false);
				diffDialog.appendRightText(rightLine + " : ", false);

				diffDialog.appendLeftText(dr.getOldLine(), (dr.getTag() != DiffRow.Tag.EQUAL));
				diffDialog.appendRightText(dr.getNewLine(), (dr.getTag() != DiffRow.Tag.EQUAL));
				leftLine++; rightLine++; 
				break;
			case DELETE:	
				diffDialog.appendLeftText(leftLine + " : ", (dr.getTag() != DiffRow.Tag.EQUAL));
				diffDialog.appendLeftText(dr.getOldLine(), (dr.getTag() != DiffRow.Tag.EQUAL));
				leftLine++; 
				break;
			case INSERT:	
				diffDialog.appendRightText(rightLine + " : ", (dr.getTag() != DiffRow.Tag.EQUAL));
				diffDialog.appendRightText(dr.getNewLine(), (dr.getTag() != DiffRow.Tag.EQUAL));
				rightLine++; 
				break;
			}
			diffDialog.appendLeftText("\n", false);
			diffDialog.appendRightText("\n", false);
		}
		diffDialog.setLeftHeader(msg1.getRequestHeader().getURI().toString());
		diffDialog.setRightHeader(msg2.getRequestHeader().getURI().toString());

    	diffDialog.setVisible(true);

		// TODO scroll to first diff - initial attempts to do this have failed..
    }


}
