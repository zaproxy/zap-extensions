package org.zaproxy.zap.extension.passivescan;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.htmlparser.jericho.Source;
import net.htmlparser.jericho.StartTag;

import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.encoder.Base64;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PassiveScanner;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class ViewstateScanner extends PluginPassiveScanner implements
		PassiveScanner {
	
	
    private PassiveScanThread parent = null;
    private static Pattern hiddenFieldPattern = Pattern.compile("__.*");

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Nothing to do on send
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        Map<String, StartTag> hiddenFields = getHiddenFields(source);
         if (hiddenFields.isEmpty())
             return;

        Viewstate v = extractViewstate(hiddenFields);

        // If the viewstate is invalid, we stop here
        // TODO: in the future, we might want to differentiate an encrypted viewstate and still consider it as valid.
        if (! v.isValid())
        	return;
         
        if (! v.hasMACtest1() || ! v.hasMACtest2())
        	if (! v.hasMACtest1() && ! v.hasMACtest2())
        		alertNoMACforSure(msg, id);
        	else
        		alertNoMACUnsure(msg, id);

        if (! v.isLatestAspNetVersion())
            alertOldAspVersion(msg, id);
        
        List<ViewstateAnalyzerResult> listOfMatches = ViewstateAnalyzer.getSearchResults(v, this);
    	for(ViewstateAnalyzerResult var : listOfMatches) {
    		if (var.hasResults())
    			alertViewstateAnalyzerResult(msg, id, var);
        }
        
        if (v.isSplit())
        	alertSplitViewstate(msg, id);
    }
    
    private void alertViewstateAnalyzerResult(HttpMessage msg, int id, ViewstateAnalyzerResult var) {
        Alert alert = new Alert(
                getId(),
                Alert.RISK_MEDIUM,
                Alert.WARNING,
                var.pattern.getAlertHeader()
            );

        alert.setDetail(
        		var.pattern.getAlertDescription(),
                msg.getRequestHeader().getURI().toString(),
                "",
                "",
                var.getResultExtract().toString(), 
                "Verify the provided information isn't confidential.",
                "",
                msg);
        
        parent.raiseAlert(id, alert);
    }

    private void alertOldAspVersion(HttpMessage msg, int id) {
        Alert alert = new Alert(
                getId(),
                Alert.RISK_LOW,
                Alert.WARNING,
                "Old Asp.Net version in use"
            );

        alert.setDetail(
                "*** EXPERIMENTAL ***\nThis website uses ASP.NET version 1.0 or 1.1.\n\n",
                msg.getRequestHeader().getURI().toString(),
                "", "", "",
                "Ensure the engaged framework is still supported by Microsoft",
                "",
                msg);
        
        parent.raiseAlert(id, alert);
    }
    
    //TODO: see if this alert triggers too often, as the detection rule is far from being robust for the moment
    private void alertNoMACUnsure(HttpMessage msg, int id) {
        Alert alert = new Alert(
                                getId(),
                                Alert.RISK_HIGH,
                                Alert.SUSPICIOUS,
                                "Viewstate without MAC signature (Unsure)"
                            );
        alert.setDetail(
                "*** EXPERIMENTAL ***\nThis website uses ASP.NET's Viewstate but maybe without any MAC.\n\n",
                msg.getRequestHeader().getURI().toString(),
                "", "", "",
                "Ensure the MAC is set for all pages on this website.",
                "msdn.microsoft.com/en-us/library/ff649308.aspx",
                msg);

        parent.raiseAlert(id, alert);
    }

    private void alertNoMACforSure(HttpMessage msg, int id) {
        Alert alert = new Alert(
                                getId(),
                                Alert.RISK_HIGH,
                                Alert.WARNING,
                                "Viewstate without MAC signature (Sure)"
                            );
        alert.setDetail(
            "*** EXPERIMENTAL ***\nThis website uses ASP.NET's Viewstate but without any MAC.\n\n",
            msg.getRequestHeader().getURI().toString(),
            "", "", "",
            "Ensure the MAC is set for all pages on this website.",
            "msdn.microsoft.com/en-us/library/ff649308.aspx",
            msg);

        parent.raiseAlert(id, alert);
    }
    
    private void alertSplitViewstate(HttpMessage msg, int id) {
        Alert alert = new Alert(
                                getId(),
                                Alert.RISK_INFO,
                                Alert.RISK_INFO,
                                "Split viewstate in use"
                            );
        alert.setDetail(
            "*** EXPERIMENTAL ***\nThis website uses ASP.NET's Viewstate and its value is split into several chunks\n",
            msg.getRequestHeader().getURI().toString(),
            "", "", "",
            "None - the guys running the server may have tuned the configuration as this isn't the default setting",
            "",
            msg);

        parent.raiseAlert(id, alert);
    }

    // TODO: is this ID OK?
    private int getId() {
        return 40001;
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        this.parent = parent;

    }

    @Override
    public String getName() {
        return "Viewstate scanner";
    }


    private Map<String, StartTag> getHiddenFields(Source source) {
        List<StartTag> result = source.getAllStartTags("input");

        // Searching for name only tags only makes sense for Asp.Net 1.1 websites
        // TODO: Enhance this ugly code code
        List<StartTag> hiddenNames = source.getAllStartTags("name", hiddenFieldPattern);
        for (StartTag st : hiddenNames)
            if (! result.contains(st))
                result.add(st);

        // Creating a key:StartTag map based on the previous results
        Map<String, StartTag> stMap = new TreeMap<String, StartTag>();
        for (StartTag st : result) {
        	// TODO: fix exception occuring here (st == null?)
            String name = (st.getAttributeValue("id") == null) ? st.getAttributeValue("name") : st.getAttributeValue("id");
             
            // <input type="hidden" /> will generate a null pointer exception otherwise
            if (name != null)
            	stMap.put(name, st);
        }
        return stMap;
    }

    // TODO: see how to manage exceptions in this class...
    private Viewstate extractViewstate(Map<String, StartTag> lstHiddenFields) {
    	// If the viewstate isn't split, we simply return the Viewstate object based on the field
        if (! lstHiddenFields.containsKey("__VIEWSTATEFIELDCOUNT"))
            return new Viewstate(lstHiddenFields.get("__VIEWSTATE"));

        // Otherwise we concatenate manually the viewstate 
        StringBuilder tmpValue = new StringBuilder();

        tmpValue.append( lstHiddenFields.get("__VIEWSTATE").getAttributeValue("value") );

        int max = Integer.parseInt(
                    lstHiddenFields.get("__VIEWSTATEFIELDCOUNT").getAttributeValue("value")
                    );
        for (int i = 1; i < max ; i++) {
            tmpValue.append( lstHiddenFields.get("__VIEWSTATE" + i).getAttributeValue("value") );
        }

        return new Viewstate(tmpValue.toString(), true);
    }
    
    private class ViewstateAnalyzerResult {
    	
    	private ViewstateAnalyzerPattern pattern;
    	private Set<String> resultExtract = new HashSet<String>();
    	
    	public ViewstateAnalyzerResult(ViewstateAnalyzerPattern vap) {
    		this.pattern = vap;
    	}
    	
    	public void addResults(String s) {
    		this.resultExtract.add(s);
    	}
    	
    	public Set<String> getResultExtract() {
    		return this.resultExtract;
    	}
    	
    	public boolean hasResults() {
    		return ! this.resultExtract.isEmpty();
    	}
    }
    
    // TODO: enhance this class with searches for e.g. passwords, ODBC strings, etc
    private static enum ViewstateAnalyzerPattern {
    	
    	EMAIL(
    			Pattern.compile("[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}", Pattern.CASE_INSENSITIVE),
    			"Emails found in the viewstate",
    			"The following emails were found being serialized in the viewstate field:",
    			"Email pattern - http://www.regular-expressions.info/regexbuddy/email.html"),
    	
    	// TODO: once the viewstate parser is implemented, filter out all the version numbers of the serialized objects which also trigger this filter
    	// Example: Microsoft.SharePoint.WebControls.SPControlMode, Microsoft.SharePoint, Version=12.0.0.0, Culture=neutral, 
    	// TODO: maybe replace this regex by a tigher rule, avoiding detecting 999.999.999.999
    	IPADDRESS(
    			Pattern.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"),
    			"Potential IP addresses found in the viewstate",
    			"The following potential IP addresses were found being serialized in the viewstate field:",
    			"IP pattern - http://www.regular-expressions.info/examples.html");

    	ViewstateAnalyzerPattern(Pattern p, String alertHeader, String alertDescription, String sourceRegex) {
    		this.pattern = p;
    		this.alertHeader = alertHeader;
    		this.alertDescription = alertDescription;
    		this.sourceRegex = sourceRegex;
    	}
    	
    	private Pattern pattern;
    	private String alertHeader;
    	private String alertDescription;
    	private String sourceRegex;
    	
    	public Pattern getPattern() {
    		return this.pattern;
    	}
    	   	
    	public String getAlertDescription() {
    		return this.alertDescription;
    	}
    	
    	public String getAlertHeader() {
    		return this.alertHeader;
    	}
    }
    
    private static class ViewstateAnalyzer {

    	public static List<ViewstateAnalyzerResult> getSearchResults(Viewstate v, ViewstateScanner s)
    	{
    		List<ViewstateAnalyzerResult> result = new ArrayList<ViewstateAnalyzerResult>();
    		
    		for (ViewstateAnalyzerPattern vap : ViewstateAnalyzerPattern.values())
    		{
    			Matcher m = vap.getPattern().matcher(v.decodedValue);
    			ViewstateAnalyzerResult var = s.new ViewstateAnalyzerResult(vap);
    			   			
    			while(m.find()) {
        			// TODO: if we find the text in the viewstate, we also need to check it isn't already in clear text in the page
    				var.addResults(m.group());
    				}
    			
    			result.add(var);
    		}
    		
    		return result;
    	}
    }
    
    public enum ViewstateVersion {
    	
    	ASPNET1	(1f, 1.1f, false),
    	ASPNET2	(2f, 4f, true),
    	UNKNOWN (-1f, -1f, false);
    	
    	private final float minVersion;
    	private final float maxVersion;
    	private final boolean isLatest;
    	
    	ViewstateVersion(float minVersion, float maxVersion, boolean isLatest) {
    		this.minVersion = minVersion;
    		this.maxVersion = maxVersion;
    		this.isLatest = isLatest;
    	}
    	
    	public boolean isLatest() {
    		return this.isLatest;
    	}
    }


    // inner class Viewstate
    private class Viewstate {

        private String base64Value;
        private String decodedValue;
        private boolean isValid = false;
        private boolean isSplit;
        private ViewstateVersion version;

        public Viewstate(StartTag s) {
    		this(s, false);
        }

        
        public Viewstate(StartTag s, boolean wasSplit) {
        	if (s != null)
        	{
        		this.isValid = true;
        		this.isSplit = wasSplit;
        		this.base64Value = s.getAttributeValue("value");
        		this.decodedValue = Base64.decodeToString(this.base64Value);
        		this.setVersion();
        	}
        }
        
        // TODO: tidy up these two constructors
        // TODO: check if splitting was possible with ASP.NET 1.1
        public Viewstate(String s, boolean wasSplit) {
        	if (s != null)
        	{
        		this.isValid = true;
        		this.isSplit = wasSplit;
        		this.base64Value = s;
        		this.decodedValue = Base64.decodeToString(s);
        		this.setVersion();
        	}
        }


        public boolean isValid() {
        	return this.isValid && ( this.getVersion() != ViewstateVersion.UNKNOWN);
        }
        
        public boolean isSplit() {
        	return this.isSplit;
        }
        
        // TODO: enhance this code, as it WILL fail at least in the following cases:
        //			- MAC is set to another value than the default (e.g. bigger or smaller than 20 characters)
        //			- some ASP.NET 3.5 stuff, especially linked with SharePoint, don't seem to use 'd' as null character
        //			- some Viewstates don't have their last 2 objects set to null
        
        // TODO: replace this bool by a more fuzzy indicator
        public boolean hasMACtest1() {
        	int l = this.decodedValue.length();
        	// By default, the MAC is 20 characters long
        	String lastCharsBeforeMac = this.decodedValue.substring(l-22, l-20); 
        	
            if (this.version.equals(ViewstateVersion.ASPNET2))
            	return lastCharsBeforeMac.equals("dd");
            
            if (this.version.equals(ViewstateVersion.ASPNET1))
            	return lastCharsBeforeMac.equals(">>");
            
            return true;
        }
        
        public boolean hasMACtest2() {
        	int l = this.decodedValue.length();
        	// By default, the MAC is 20 characters long
        	String lastCharsBeforeMac = this.decodedValue.substring(l-2); 
        	
            if (this.version.equals(ViewstateVersion.ASPNET2))
            	return ! lastCharsBeforeMac.equals("dd");
            
            if (this.version.equals(ViewstateVersion.ASPNET1))
            	return ! lastCharsBeforeMac.equals(">>");
            
            return true;
        }
        
        public String getDecodedValue() {
        	return this.decodedValue;
        }

        public boolean isLatestAspNetVersion() {
            return this.getVersion().isLatest();
        }
        
        public ViewstateVersion getVersion() {
        	return this.version;
        }
        
        private void setVersion() {
        	this.version =  ViewstateVersion.UNKNOWN;
        	
        	if (this.base64Value.startsWith("/w"))
        		this.version = ViewstateVersion.ASPNET2;
        	
        	if (this.base64Value.startsWith("dD"))
        		this.version = ViewstateVersion.ASPNET1;      		
        }
        
        /* TODO once we have good Viewstate 1 & 2 parsers */
        public Object[] getObjectTree() throws Exception {
        	throw new Exception("Not implemented (yet)");
        }
        
        public Object[] getStateBagTree() throws Exception {
        	throw new Exception("Not implemented (yet)");
        }
        
        public Object[] getSerializedComponentsTree() throws Exception {
        	throw new Exception("Not implemented (yet)");
        }
    }
}
