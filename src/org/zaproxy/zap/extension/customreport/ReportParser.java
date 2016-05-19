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
package org.zaproxy.zap.extension.customreport;

import java.util.List;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.zaproxy.zap.model.Context;


public class ReportParser {
	
	public static StringBuilder deleteNotInScope( List<Context> contexts, StringBuilder sb){
		
        Document doc = null;
		try {
			doc = DocumentHelper.parseText( sb.toString() );
		} catch (DocumentException e) {
			e.printStackTrace();
		}
        
	    Element report = doc.getRootElement();
	    @SuppressWarnings("unchecked")
        List<Element> sites = report.elements("site");
	    
	    // iterate through sites
	    for ( int site_i=sites.size()-1 ; site_i>=0 ; site_i-- ) {
	    	   Element site = sites.get(site_i);
	    	   if (contexts.size() == 0){
	    		   sites.remove(site);
	    		   continue;
	    	   }
	    	   // check if included in scope
	    	   for( int i = 0 ; i < contexts.size(); i++){
	    		   Context context = contexts.get(i);
	    		   String url = site.attributeValue("name").toString();
	    		   if ( !context.isIncluded(url) ){
	    			   sites.remove(site);
	    		   }
	    	   }
	    }
	    return new StringBuilder( doc.asXML());
	}
	
	@SuppressWarnings("unchecked")
	public static StringBuilder selectExpectedAlerts( StringBuilder sb, List<String> selectedAlerts ){

		Document doc = null;
		try {
			doc = DocumentHelper.parseText( sb.toString() );
		} catch (DocumentException e) {
			e.printStackTrace();
		}
	    Element report = doc.getRootElement();
	    List<Element> sites = report.elements("site");
	    
	    // iterate through sites
	    for ( int site_i=0 ; site_i<sites.size() ;site_i++ ) {
	    	   Element site = sites.get(site_i);
	    	   if ( site == null ) continue;
               
	    	   // iterate every alerts
	    	   Element alertRoot = site.element("alerts");
	    	   List<Element> alerts = alertRoot.elements("alertitem");
	    	   
               for( int alert_i = 0; alert_i < alerts.size(); alert_i++ ){
            	   Element alert = alerts.get(alert_i);
            	   
            	   String alertname = alert.elementText("alert");
            	   // delete is not selected
            	   if( !selectedAlerts.contains( alertname ) ){
            		   alertRoot.remove(alert);
            	   }
                   
               }
	    }
	    return new StringBuilder( doc.asXML());
	}

}
