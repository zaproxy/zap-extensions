package org.zaproxy.addon.report2iriusrisk;

import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.parosproxy.paros.view.View;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ClientApiException;



public class GenerateReportXML {
    private static final String ZAP_ADDRESS = "localhost";
    private static final int ZAP_PORT = 8080;
    // Change to match the API key set in ZAP, or use NULL if the API key is disabled
    private static final String ZAP_API_KEY = "veqep5usrrf1vtjk5unp94a7e6";
    // The URL of the application to be tested
    private static final String TARGET = "https://public-firing-range.appspot.com";

    public static String generate() {
        View.getSingleton().showMessageDialog("Generating Report");
        String title = "Zap-Report";
        String template = "traditional-xml";
        /* 
        String theme = "Report Theme";
        String description = "Report Description";
        String contexts = "Default Context|My Context";
        String sites = "https://example.com|https://example.org";
        String sections = "";
        String includedConfidences = "False Positive|Low|Medium|High|Confirmed";
        String includedRisks = "Informational|Low|Medium|High";
        String reportFileName = "ZAP-Report";
        String reportFileNamePattern = "";
        String reportDir = "/reports";
        String display = "true";
        */
        String theme = "";
        String description = "";
        String contexts = "";
        String sites = "";
        String sections = "";
        String includedConfidences = "";
        String includedRisks = "";
        String reportFileName = "";
        String reportFileNamePattern = "";
        String reportDir = "";
        String display = "";
        //ApiResponse resp = api.reports.generate("report","traditional-xml", "theme", "Description", "Default Context|My Context", "", "", "False Positive|Low|Medium|High|Confirmed","Informational|Low|Medium|High", );
        //ApiResponse resp = api.reports.generate("report","traditional-xml");
        try{
            ClientApi api = new ClientApi(ZAP_ADDRESS, ZAP_PORT, ZAP_API_KEY);
            ApiResponse resp = api.reports.generate(
                    title,
                    template,
                    theme,
                    description,
                    contexts,
                    sites,
                    sections,
                    includedConfidences,
                    includedRisks,
                    reportFileName,
                    reportFileNamePattern,
                    reportDir,
                    display
                );
            
            View.getSingleton().getOutputPanel().append("The XML has been generated in: ");
            View.getSingleton().getOutputPanel().append(resp.toString()+ "\n");
            return resp.toString();

        } catch(ClientApiException e) {
            View.getSingleton().getOutputPanel().append("Failed: ");
            View.getSingleton().getOutputPanel().append(e.getDetail());
            View.getSingleton().getOutputPanel().append(e.toString());
            e.printStackTrace(); // Or use a more appropriate exception handling strategy
            return null;
        }
        
    }
}
