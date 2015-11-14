package org.zaproxy.zap.extension.advreport;

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
	    List sites = report.elements("site");
	    
	    // iterate through sites
	    for ( int site_i=sites.size()-1 ; site_i>=0 ; site_i-- ) {
	    	   Element site = (Element) sites.get(site_i);
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
	
	public static StringBuilder selectExpectedAlerts( StringBuilder sb, List<String> selectedAlerts ){

		Document doc = null;
		try {
			doc = DocumentHelper.parseText( sb.toString() );
		} catch (DocumentException e) {
			e.printStackTrace();
		}
	    Element report = doc.getRootElement();
	    List sites = report.elements("site");
	    
	    // iterate through sites
	    for ( int site_i=0 ; site_i<sites.size() ;site_i++ ) {
	    	   Element site = (Element) sites.get(site_i);
	    	   if ( site == null ) continue;
               
	    	   // iterate every alerts
	    	   Element alertRoot = site.element("alerts");
	    	   List alerts = alertRoot.elements("alertitem");
	    	   
               for( int alert_i = 0; alert_i < alerts.size(); alert_i++ ){
            	   Element alert = (Element)alerts.get(alert_i);
            	   
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
