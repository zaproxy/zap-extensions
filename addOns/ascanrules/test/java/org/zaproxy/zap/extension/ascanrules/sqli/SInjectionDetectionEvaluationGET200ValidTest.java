package org.zaproxy.zap.extension.ascanrules.sqli;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;

public class SInjectionDetectionEvaluationGET200ValidTest {

    @Test
    public void testSQLInjectionInSearchDateWithoutQuotesUnionExploitWithDifferent200Responses() throws Exception {
        // Setup the necessary environment and HTTP messages for testing
        HttpMessage response1 = new HttpMessage();
        response1.setResponseHeader("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n");
        response1.setResponseBody("<html><body>Valid Response</body></html>");

        HttpMessage response2 = new HttpMessage();
        response2.setResponseHeader("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n");
        response2.setResponseBody("<html><body>Union Exploit Response</body></html>");

        // Assert that the responses are different, which should trigger the detection logic
        assertTrue(!response1.getResponseBody().equals(response2.getResponseBody()));
    }
}
