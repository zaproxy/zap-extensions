package org.zaproxy.zap.extension.spiderAjax;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.w3c.dom.NodeList;

import com.crawljax.core.CandidateElement;
import com.crawljax.core.CrawlSession;
import com.crawljax.core.CrawljaxException;
import com.crawljax.core.configuration.CrawljaxConfiguration;
import com.crawljax.core.configuration.CrawljaxConfigurationReader;
import com.crawljax.core.plugin.PreStateCrawlingPlugin;
import com.crawljax.core.state.Eventable;

//before crawling the new site, we check the url
public class test2 implements PreStateCrawlingPlugin {
	private static final Logger logger = Logger.getLogger(ExtensionAjax.class);
	ArrayList<String> urls;
	boolean replaceInput = false;
	private ExtensionAjax extension;
	private SpiderThread thread;

	public test2(ExtensionAjax e, SpiderThread t) {
		this.extension = e;
		this.thread = t;
	}

	@Override
	public void preStateCrawling(CrawlSession session, List<CandidateElement> candidates) {
		
		String currentUrl = session.getBrowser().getCurrentUrl();
		
		//for each candidate
		 for(CandidateElement c: candidates){
			 //we find all the attributes
            for(int i=0;i<c.getElement().getAttributes().getLength();i++){
            	
            	String candidateUrl=c.getElement().getAttributes().item(i).getNodeValue();
            	String guessedUrl = null;
            	//here we try to guess the candidate URL...
        		guessedUrl = candidateUrl;
        		URL u;
				try {
					//System.out.println(currentUrl+" "+candidateUrl);
					if(!candidateUrl.toLowerCase().contains("javascript") && (candidateUrl.contains(".")|| candidateUrl.contains("/")) ){
					u = new URL(new URL(currentUrl), candidateUrl);
					} else{
						u = new URL(currentUrl);
					}
	        		guessedUrl = u.toString();
				} catch (MalformedURLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
            	//and compare them with out rules
            	for (String regex : this.extension.getModel().getSession().getExcludeFromSpiderRegexs()) {
    				String filtered=regex.replace("\\Q", "").replace("\\E.*", "").replace("\\E", "");
    				if (guessedUrl.toLowerCase().contains(filtered.toLowerCase())) {
    					logger.info("The following URL is filtered: " + filtered);
    					logger.info("Candidate Element removed: " + guessedUrl);
    					session.getCurrentState().getUnprocessedCandidateElements().remove(c.getElement());
    					candidates.remove(c.getElement());				
    				}
            	}
            	
            }
         }
		
		
		
	}
}
