/*
 *
 * Paros and its related class files.
 * 
 * Paros is an HTTP/HTTPS proxy for assessing web application security.
 * Copyright (C) 2003-2004 Chinotec Technologies Company
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the Clarified Artistic License
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Clarified Artistic License for more details.
 * 
 * You should have received a copy of the Clarified Artistic License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
// ZAP: 2012/01/02 Separate param and attack
// ZAP: 2012/04/25 Added @Override annotation to all appropriate methods.
// ZAP: 2012/08/01 Removed the "(non-Javadoc)" comments.
// ZAP: 2012/12/28 Issue 447: Include the evidence in the attack field
// ZAP: 2015/07/27 Issue 1618: Target Technology Not Honored

package org.zaproxy.zap.extension.ascanrules;

import java.util.regex.Pattern;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;


public class TestServerSideInclude extends AbstractAppParamPlugin {

	/**
	 * Prefix for internationalised messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "ascanrules.testserversideinclude.";

    private static final String SSI_UNIX = "<!--#EXEC cmd=\"ls /\"-->";
    private static final String SSI_UNIX2 = "\">" +SSI_UNIX + "<";
    private static final String SSI_WIN = "<!--#EXEC cmd=\"dir \\\"-->";
    private static final String SSI_WIN2 = "\">" +SSI_WIN + "<";

	
	private static Pattern patternSSIUnix = Pattern.compile("\\broot\\b.*\\busr\\b", PATTERN_PARAM);
	private static Pattern patternSSIWin = Pattern.compile("\\bprogram files\\b.*\\b(WINDOWS|WINNT)\\b", PATTERN_PARAM);

    @Override
    public int getId() {
        return 40009;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }


    @Override
    public String[] getDependency() {
        return null;
    }

    @Override
    public boolean targets(TechSet technologies) {
        if (technologies.includes(Tech.OS.Linux) || technologies.includes(Tech.OS.MacOS)
                || technologies.includes(Tech.OS.Windows)) {
            return true;
        }
        return false;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
         return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public void init() {

    }
    


    @Override
    public void scan(HttpMessage msg, String param, String value) {
        
		StringBuilder evidence = new StringBuilder();

		if (this.inScope(Tech.Linux) || this.inScope(Tech.MacOS)) {
			try {
				setParameter(msg, param, SSI_UNIX);
	            sendAndReceive(msg);
	    		//result = msg.getResponseBody().toString();
	    		if (matchBodyPattern(msg, patternSSIUnix, evidence)) {
	    			bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, null, param, evidence.toString(), SSI_UNIX, msg);
	    			return;
	    		}
	
	        } catch (Exception e) {
	        }

			try {
			    msg = getNewMsg();
				setParameter(msg, param, SSI_UNIX2);
	            sendAndReceive(msg);
	    		//result = msg.getResponseBody().toString();
	    		if (matchBodyPattern(msg, patternSSIUnix, evidence)) {    		    
	    			bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, null, param, evidence.toString(), SSI_UNIX2, msg);
	    			return;
	    		}
	
	        } catch (Exception e) {
	        }	
		}

		if (this.inScope(Tech.Windows)) {
			try {
			    msg = getNewMsg();
				setParameter(msg, param, SSI_WIN);
	            sendAndReceive(msg);
	    		//result = msg.getResponseBody().toString();
	    		if (matchBodyPattern(msg, patternSSIWin, evidence)) {    		    
	    			bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, null, param, evidence.toString(), SSI_WIN, msg);
	    			return;
	    		}
	
	        } catch (Exception e) {
	        }	
	
			try {
			    msg = getNewMsg();
				setParameter(msg, param, SSI_WIN2);
	            sendAndReceive(msg);
	    		//result = msg.getResponseBody().toString();
	    		if (matchBodyPattern(msg, patternSSIWin, evidence)) {    		    
	    			bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, null, param, evidence.toString(), SSI_WIN2, msg);
	    			return;
	    		}
	
	        } catch (Exception e) {
	        }	
		}

	}

	@Override
	public int getRisk() {
		return Alert.RISK_HIGH;
	}

	@Override
	public int getCweId() {
		return 97;
	}

	@Override
	public int getWascId() {
		return 31;
	}
       
}
