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
package org.zaproxy.zap.extension.ascanrules;

import java.text.MessageFormat;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.httputils.HtmlContext;
import org.zaproxy.zap.httputils.HtmlContextAnalyser;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

public class TestPersistentXSSAttack extends AbstractAppParamPlugin {

    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_8");
    private static Logger log = Logger.getLogger(TestPersistentXSSAttack.class);

    @Override
    public int getId() {
        return 40014;
    }

    @Override
    public String getName() {
    	AscanUtils.registerI18N();
    	return Constant.messages.getString("ascanrules.pxss.attack.name");
    }

    @Override
    public String[] getDependency() {
        return new String[] {"TestPersistentXSSSpider"};
    }

    @Override
    public String getDescription() {
    	if (vuln != null) {
    		return vuln.getDescription();
    	}
    	return "Failed to load vulnerability description from file";
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
    	if (vuln != null) {
    		return vuln.getSolution();
    	}
    	return "Failed to load vulnerability solution from file";
    }

    @Override
    public String getReference() {
    	if (vuln != null) {
    		StringBuilder sb = new StringBuilder();
    		for (String ref : vuln.getReferences()) {
    			if (sb.length() > 0) {
    				sb.append('\n');
    			}
    			sb.append(ref);
    		}
    		return sb.toString();
    	}
    	return "Failed to load vulnerability reference from file";
    }

    @Override
    public void init() {
    }
    
    private List<HtmlContext> performAttack (HttpMessage sourceMsg, String param, String attack,
    		HttpMessage sinkMsg, HtmlContext targetContext, int ignoreFlags) {
		HttpMessage sourceMsg2 = sourceMsg.cloneRequest();
		setParameter(sourceMsg2, param, attack);
        try {
			sendAndReceive(sourceMsg2);
		} catch (Exception e) {
			log.error(e.getMessage(), e);
		}
        
		HttpMessage sinkMsg2 = sinkMsg.cloneRequest();
        try {
			sendAndReceive(sinkMsg2);
		} catch (Exception e) {
			log.error(e.getMessage(), e);
		}

        HtmlContextAnalyser hca = new HtmlContextAnalyser(sinkMsg2);
        if (Plugin.AlertThreshold.HIGH.equals(this.getAlertThreshold())) {
        	// High level, so check all results are in the expected context
        	return hca.getHtmlContexts(attack, targetContext, ignoreFlags);
        }
        return hca.getHtmlContexts(attack);
    }
    	
    @Override
    public void scan(HttpMessage sourceMsg, String param, String value) {
    	String otherInfo = MessageFormat.format(
				Constant.messages.getString("ascanrules.pxss.otherinfo"), 
				sourceMsg.getRequestHeader().getURI().toString());
    	
		try {
			Set<HttpMessage> sinks = PersistentXSSUtils.getSinksForSource(sourceMsg, param);

			if (sinks != null) {
				// Loop through each one
			
		    	// Inject the 'safe' eyecatcher
				boolean attackWorked = false;
				setParameter(sourceMsg, param, Constant.getEyeCatcher());
	            sendAndReceive(sourceMsg);

	            // Check each sink
	            for (HttpMessage sinkMsg : sinks) {
	            	sinkMsg = sinkMsg.cloneRequest();
		            setParameter(sinkMsg, param, Constant.getEyeCatcher());
		            sendAndReceive(sinkMsg);
		            
		            HtmlContextAnalyser hca = new HtmlContextAnalyser(sinkMsg);
		            List<HtmlContext> contexts = hca.getHtmlContexts(Constant.getEyeCatcher(), null, 0);
		            
		            for (HtmlContext context : contexts) {
		            	// Loop through the returned contexts and lauch targetted attacks
		            	if (attackWorked) {
		            		break;
		            	}
		            	if (context.getTagAttribute() != null) {
		            		// its in a tag attribute - lots of attack vectors possible
		         
		        			if (context.isInScriptAttribute()) {
		            			// Good chance this will be vulnerable
		        				// Try a simple alert attack
		        	            List<HtmlContext> contexts2 = performAttack (sourceMsg, param, ";alert(1)", sinkMsg, context, 0);
		        	            
		        	            for (HtmlContext context2 : contexts2) {
		        	            	if (context2.getTagAttribute() != null &&
		        	            			context2.isInScriptAttribute()) {
		        	            		// Yep, its vulnerable
		        						bingo(Alert.RISK_HIGH, Alert.WARNING, null, param, context2.getTarget(), 
		        								otherInfo, context2.getMsg());
		        						attackWorked = true;
		        						break;
		        	            	}
		        	            }
		        	            if (!attackWorked) {
		        	            	log.debug("Failed to find vuln in script attribute on " + sourceMsg.getRequestHeader().getURI());
		        	            }
		
		        			} else if (context.isInUrlAttribute()) {
		        				// Its a url attribute
		        	            List<HtmlContext> contexts2 = performAttack (sourceMsg, param, "javascript:alert(1);", sinkMsg, context, 0);
		
		        	            if (contexts2.size() > 0) {
		    	            		// Yep, its vulnerable
		    						bingo(Alert.RISK_HIGH, Alert.WARNING, null, param, contexts2.get(0).getTarget(), 
		    								otherInfo, contexts2.get(0).getMsg());
		    						attackWorked = true;
		        	            }
		        	            if (!attackWorked) {
		        	            	log.debug("Failed to find vuln in url attribute on " + sourceMsg.getRequestHeader().getURI());
		        	            }
		        			}
		            		if (! attackWorked && context.isInTagWithSrc()) {
		            			// Its in an attribute in a tag which supports src attributes
		        	            List<HtmlContext> contexts2 = performAttack (sourceMsg, param, 
		        	            		context.getSurroundingQuote() + " src=http://badsite.com", sinkMsg, context, HtmlContext.IGNORE_TAG);
		
		        	            if (contexts2.size() > 0) {
		    						bingo(Alert.RISK_HIGH, Alert.WARNING, null, param, contexts2.get(0).getTarget(), 
		    								otherInfo, contexts2.get(0).getMsg());
		    						attackWorked = true;
		        	            }
		        	            if (!attackWorked) {
		        	            	log.debug("Failed to find vuln in tag with src attribute on " + sourceMsg.getRequestHeader().getURI());
		        	            }
		            		}
		        			
		        			if (! attackWorked) {
		        				// Try a simple alert attack
		        	            List<HtmlContext> contexts2 = performAttack (sourceMsg, param, 
		        	            		context.getSurroundingQuote() + "><script>alert(1);</script>", sinkMsg, context, HtmlContext.IGNORE_TAG);
		        	            if (contexts2.size() > 0) {
		    	            		// Yep, its vulnerable
		    						bingo(Alert.RISK_HIGH, Alert.WARNING, null, param, contexts2.get(0).getTarget(), 
		    								otherInfo, contexts2.get(0).getMsg());
		    						attackWorked = true;
		        	            }
		        	            if (!attackWorked) {
		        	            	log.debug("Failed to find vuln with simple script attack " + sourceMsg.getRequestHeader().getURI());
		        	            }
		        			}
		        			if (! attackWorked) {
			            		// Try adding an onMouseOver
		        	            List<HtmlContext> contexts2 = performAttack (sourceMsg, param, 
		        	            		context.getSurroundingQuote() + " onMouseOver=" + context.getSurroundingQuote() + "alert(1);", 
		        	            		sinkMsg, context, HtmlContext.IGNORE_TAG);
		        	            if (contexts2.size() > 0) {
		    	            		// Yep, its vulnerable
		    						bingo(Alert.RISK_HIGH, Alert.WARNING, null, param, contexts2.get(0).getTarget(), 
		    								otherInfo, contexts2.get(0).getMsg());
		    						attackWorked = true;
		    	            	}
		        	            if (!attackWorked) {
		        	            	log.debug("Failed to find vuln in with simple onmounseover " + sourceMsg.getRequestHeader().getURI());
		        	            }
		        			}
		            	} else if (context.isHtmlComment()) {
		            		// Try breaking out of the comment
		    	            List<HtmlContext> contexts2 = performAttack (sourceMsg, param, 
		    	            		"--><script>alert(1);</script><!--", sinkMsg, context, HtmlContext.IGNORE_HTML_COMMENT);
		    	            if (contexts2.size() > 0) {
			            		// Yep, its vulnerable
								bingo(Alert.RISK_HIGH, Alert.WARNING, null, param, contexts2.get(0).getTarget(), 
										otherInfo, contexts2.get(0).getMsg());
								attackWorked = true;
		    	            } else {
		    	            	// Maybe they're blocking script tags
		        	            contexts2 = performAttack (sourceMsg, param, 
					            		"--><b onMouseOver=alert(1);>test</b><!--", sinkMsg, context, HtmlContext.IGNORE_HTML_COMMENT);
		        	            if (contexts2.size() > 0) {
				            		// Yep, its vulnerable
									bingo(Alert.RISK_HIGH, Alert.WARNING, null, param, contexts2.get(0).getTarget(), 
											otherInfo, contexts2.get(0).getMsg());
									attackWorked = true;
					            }
		    	            }
		            	} else {
		            		// its not in a tag attribute
		            		if ("body".equalsIgnoreCase(context.getParentTag())) {
		            			// Immediately under a body tag
		        				// Try a simple alert attack
		        	            List<HtmlContext> contexts2 = performAttack (sourceMsg, param, 
		        	            		"<script>alert(1);</script>", sinkMsg, null, HtmlContext.IGNORE_PARENT);
		        	            if (contexts2.size() > 0) {
		        	            		// Yep, its vulnerable
		        						bingo(Alert.RISK_HIGH, Alert.WARNING, null, param, contexts2.get(0).getTarget(), 
		        								otherInfo, contexts2.get(0).getMsg());
		        						attackWorked = true;
		        	            } else {
		        	            	// Maybe they're blocking script tags
		            	            contexts2 = performAttack (sourceMsg, param, 
		    			            		"<b onMouseOver=alert(1);>test</b>", sinkMsg, context, HtmlContext.IGNORE_PARENT);
		    			            for (HtmlContext context2 : contexts2) {
		    			            	if ("body".equalsIgnoreCase(context2.getParentTag()) ||
		    			            			"script".equalsIgnoreCase(context2.getParentTag())) {
		    			            		// Yep, its vulnerable
		    								bingo(Alert.RISK_HIGH, Alert.WARNING, null, param, contexts2.get(0).getTarget(), 
		    										otherInfo, contexts2.get(0).getMsg());
		    								attackWorked = true;
		    								break;
		    			            	}
		    			            }
		        	            }
		            		} else if (context.getParentTag() != null){
		            			// Its not immediately under a body tag, try to close the tag
		        	            List<HtmlContext> contexts2 = performAttack (sourceMsg, param, 
		        	            		"</" + context.getParentTag() + "><script>alert(1);</script><" + context.getParentTag() + ">", 
		        	            		sinkMsg, context, HtmlContext.IGNORE_IN_SCRIPT);
		        	            if (contexts2.size() > 0) {
		       	            		// Yep, its vulnerable
		       						bingo(Alert.RISK_HIGH, Alert.WARNING, null, param, contexts2.get(0).getTarget(), 
		       								otherInfo, contexts2.get(0).getMsg());
		    						attackWorked = true;
		        	            } else if ("script".equalsIgnoreCase(context.getParentTag())){
		        	            	// its in a script tag...
		            	            contexts2 = performAttack (sourceMsg, param, 
		            	            		context.getSurroundingQuote() + ";alert(1);" + context.getSurroundingQuote(), 
		            	            		sinkMsg, context, 0);
		            	            if (contexts2.size() > 0) {
		           	            		// Yep, its vulnerable
		           						bingo(Alert.RISK_HIGH, Alert.WARNING, null, param, contexts2.get(0).getTarget(), 
		           								otherInfo, contexts2.get(0).getMsg());
		        						attackWorked = true;
		            	            }
		        	            }
		            		}
		            	}
		            }
	            }
			}
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }
    
	@Override
	public int getRisk() {
		return Alert.RISK_HIGH;
	}

	@Override
	public int getCweId() {
		return 79;
	}

	@Override
	public int getWascId() {
		return 8;
	}

}
