package org.zaproxy.addon.myaddon;

import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.parosproxy.paros.view.View;
import org.zaproxy.clientapi.core.ClientApi;


public class GenerateReportXML {
    private static final String ZAP_ADDRESS = "localhost";
    private static final int ZAP_PORT = 8080;
    // Change to match the API key set in ZAP, or use NULL if the API key is disabled
    private static final String ZAP_API_KEY = "veqep5usrrf1vtjk5unp94a7e6";
    // The URL of the application to be tested
    private static final String TARGET = "https://public-firing-range.appspot.com";

    public static void generate() {
        View.getSingleton().showMessageDialog("Generating Report");
        ClientApi api = new ClientApi(ZAP_ADDRESS, ZAP_PORT, ZAP_API_KEY);
        //ApiResponse resp = api.reports.generate("report","traditional-xml", "theme", "Description", "Default Context|My Context", "", "", "False Positive|Low|Medium|High|Confirmed","Informational|Low|Medium|High", );
        ApiResponse resp = api.reports.generate("report","traditional-xml");
        
        
    }
}
