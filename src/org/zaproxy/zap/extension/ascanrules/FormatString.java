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

/**
 * A Format String  scan rule 
 * Copyright (C) 2015 Institute for Defense Analyses
 * @author Mark Rader based upon the example active scanner by psiinon
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE
 */


package org.zaproxy.zap.extension.ascanrules;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.model.Tech;    
import org.zaproxy.zap.model.TechSet;  


public class FormatString extends AbstractAppParamPlugin  {

	
	/**
	 * Prefix for internationalised messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "ascanrules.formatstring.";
	private static final int PLUGIN_ID = 30002;
	private static Logger log = Logger.getLogger(FormatString.class);
	
	@Override
	public int getId() {
		return PLUGIN_ID;
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
		return technologies.includes(Tech.Lang.C); 
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
	
	private String getError(char c) {
		return Constant.messages.getString(MESSAGE_PREFIX + "error"+c);
	}

	@Override
	public void init() {

	}

	/*
	 * This method is called by the active scanner for each GET and POST parameter for every page 
	 * @see org.parosproxy.paros.core.scanner.AbstractAppParamPlugin#scan(org.parosproxy.paros.network.HttpMessage, java.lang.String, java.lang.String)
	 */
	@Override
	public void scan(HttpMessage msg, String param, String value) {
		
		if (this.isStop()) { // Check if the user stopped things
			if (log.isDebugEnabled()) {
				log.debug("Scanner "+getName()+" Stopping.");
			}
			return; // Stop!
		}
		
		try {
		
		
			/*
			 * This represents the meaning of format string variables.
			 * %%  character (literal)  Reference  
			 * %p  External representation of a pointer to void  Reference  
			 * %d  Decimal  Value  
			 * %c  Character   
			 * %u  Unsigned decimal  Value  
			 * %x  Hexadecimal  Value  
			 * %s  String  Reference  
			 * %n  Writes the number of characters into a pointer  Reference  
			 */
			// Always use getNewMsg() for each new request
			msg = getNewMsg();
			String initialMessage = "ZAP";
			setParameter(msg, param, initialMessage);
			sendAndReceive(msg);
			HttpResponseBody initialResponseBody= msg.getResponseBody();
			int initialResponseLength = initialResponseBody.length();
		//  The following section of the code attacks GNU and generic C compiler format 
		//	string errors.  It does not attack specific Microsoft format string  errors.
			String initialAttackMessage = initialMessage;
			StringBuilder sb = new StringBuilder();
			sb.append(initialAttackMessage);
			int i;
			//  Use a large number of %s in series;  Because `%s' displays memory from an address
			//  that is supplied on the stack, where a lot of other data is stored, too, our 
			//  chances are high to read from an illegal address, which is not mapped. Also 
			//  you can use `%n' to write to the addresses on the stack a few times, which 
			//  should reliably produce a crash, too.

			for (i=0;i<20;i++)
			{
				sb.append("%n%s");
			}
			sb.append('\n');
			initialAttackMessage = sb.toString();

			msg = getNewMsg();
			setParameter(msg, param, initialAttackMessage);
			sendAndReceive(msg);
     		if (msg.getResponseHeader().getStatusCode() == HttpStatusCode.INTERNAL_SERVER_ERROR)
    		{
    			String secondAttackMessage ;	
    			StringBuilder sb1 = new StringBuilder();
    			sb1.append(initialMessage);
    			for (i=0;i<10;i++)
    			{
    				sb1.append("%x");
    			}
    			sb1.append('\n');
    			secondAttackMessage = sb1.toString();

    			msg = getNewMsg();
    			setParameter(msg, param, secondAttackMessage);
    			sendAndReceive(msg);
         		HttpResponseBody secondAttackResponseBody= msg.getResponseBody();
    			if (secondAttackResponseBody.length() > initialResponseLength + 20 && msg.getResponseHeader().getStatusCode() == HttpStatusCode.OK){
    				bingo(getRisk(), 
    						Alert.CONFIDENCE_MEDIUM, 
    						null, 
    						param, 
    						initialMessage, 
    						getError('2') ,
    						msg);
    			} else 
    			{
    				msg = getNewMsg();
        			setParameter(msg, param, initialAttackMessage);
    				bingo(getRisk(), 
    						Alert.CONFIDENCE_MEDIUM, 
    						null, 
    						param, 
    						initialMessage, 
    						getError('1') ,
    						msg);
    			}
    			return;
    		}
    		//  The following section of the code only attacks Microsoft C compiler format string errors.  It is only
    		//  used if the GNU and generic C compiler check fails to find a vulnerability.
     		if (this.isStop()) { // Check if the user stopped things
    			if (log.isDebugEnabled()) {
    				log.debug("Scanner "+getName()+" Stopping.");
    			}
    			return; // Stop!
    		}
    		StringBuilder sb2 = new StringBuilder();
			sb2.append(initialMessage);
			sb2.append(' ');
			for (i=0;i<20;i++)
			{
				sb2.append('%');
				sb2.append(i+1);
				sb2.append("!s");
			}
			for (i=20;i<40;i++)
			{
				sb2.append('%');
				sb2.append(i+1);
				sb2.append("!n");
			}
			sb2.append('\n');
			String microsoftAttackMessage = sb2.toString();
			msg = getNewMsg();
			setParameter(msg, param, microsoftAttackMessage);
			sendAndReceive(msg);
			if (msg.getResponseHeader().getStatusCode() == HttpStatusCode.INTERNAL_SERVER_ERROR)
			{
				bingo(getRisk(), 
						Alert.CONFIDENCE_MEDIUM, 
						null,
						param, 
						initialMessage, 
						getError('3') ,
						msg);
			}
			return;	



			
		} catch (Exception e) {
			log.error(e.getMessage(), e);
		}	
	}

	@Override
	public int getRisk() {
		return Alert.RISK_MEDIUM;
	}

	@Override
	public int getCweId() {
		// The CWE id
		return 134;
	}

	@Override
	public int getWascId() {
		// The WASC ID
		return 6;
	}

}

