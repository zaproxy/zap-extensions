/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.pscanrulesBeta;

import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.net.URL;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

public class InformationDisclosureSuspiciousCommentsUnitTest
        extends PassiveScannerTest<InformationDisclosureSuspiciousComments> {
	
    private HttpMessage msg;
    
    @Override
    protected InformationDisclosureSuspiciousComments createScanner() {
    	return new InformationDisclosureSuspiciousComments();
    }
    
	    protected HttpMessage createHttpMessageWithRespBody(String responseBody,
	    		String contentType) throws HttpMalformedHeaderException, URIException {
	
            HttpRequestHeader requestHeader = new HttpRequestHeader();
            requestHeader.setURI(new URI("http://example.com", false));

            msg = new HttpMessage();
            msg.setRequestHeader(requestHeader);
	        msg.setResponseBody(responseBody);
	        msg.setResponseHeader(
	                "HTTP/1.1 200 OK\r\n"
	                        + "Server: Apache-Coyote/1.1\r\n"
	                        + "Content-Type: " + contentType + "\r\n"
	                        + "Content-Length: " + responseBody.length() + "\r\n");
	        return msg;
	    }
       
        @Test
        public void shouldSuspiciousCommentsFile() {
            // Given
            String suspiciousCommentsFilePath = "/xml/suspicious-comments.txt";
            // When
            URL suspiciousCommentsFile = getClass().getResource(suspiciousCommentsFilePath);
            // Then
            assertThat(suspiciousCommentsFile, notNullValue());
        }
        
        @Test
        public void containsSuspiciousCommentInJavaScriptResponse() 
        		throws HttpMalformedHeaderException, URIException {
        	
        	String body = "Some text <script>Some Script Element FixMe: DO something </script>\nLine 2\n";
            // Given
            HttpMessage msg = createHttpMessageWithRespBody(body, 
            		"text/javascript;charset=ISO-8859-1");
            
            assertTrue(msg.getResponseHeader().isText());
            assertTrue(msg.getResponseHeader().isJavaScript());
            
            // When
            rule.scanHttpResponseReceive(msg, -1, createSource(msg));
            
            // Then
            assertEquals(1, alertsRaised.size());
        }
        
        @Test
        public void suspiciousCommentIsPartOfWordInJavaScriptResponse() 
        		throws HttpMalformedHeaderException, URIException {
        	
        	String body = "Some text <script>Some Script Element FixMeNot: DO something </script>\nLine 2\n";
            // Given
            HttpMessage msg = createHttpMessageWithRespBody(body, 
            		"text/javascript;charset=ISO-8859-1");
            
            assertTrue(msg.getResponseHeader().isText());
            assertTrue(msg.getResponseHeader().isJavaScript());
            
            // When
            rule.scanHttpResponseReceive(msg, -1, createSource(msg));
            
            // Then
            assertEquals(0, alertsRaised.size());
        }
        
        @Test
        public void noSuspiciousCommentInJavaScriptResponse() 
        		throws HttpMalformedHeaderException, URIException {
        	
        	String body = "Some <script>text, nothing suspicious here...</script>\nLine 2\n";
            // Given
            HttpMessage msg = createHttpMessageWithRespBody(body, 
            		"text/javascript;charset=ISO-8859-1");
            
            assertTrue(msg.getResponseHeader().isText());
            assertTrue(msg.getResponseHeader().isJavaScript());
            
            // When
            rule.scanHttpResponseReceive(msg, -1, createSource(msg));
            
            // Then
            assertEquals(0, alertsRaised.size());
        }
        
        @Test
        public void containsSuspiciousCommentInElements() 
        		throws HttpMalformedHeaderException, URIException {
        	
        	String body = "<h1>Some text <script>Some Html Element FixMe DO something </script></h1>\n"
        			+ "<b>No script here</b>\n";
            // Given
            HttpMessage msg = createHttpMessageWithRespBody(body, "text/html;charset=ISO-8859-1");
            
            assertTrue(msg.getResponseHeader().isText());
            assertFalse(msg.getResponseHeader().isJavaScript());
            
            // When
            rule.scanHttpResponseReceive(msg, -1, createSource(msg));
            
            // Then
            assertEquals(1, alertsRaised.size());
        }
        
        @Test
        public void noSuspiciousCommentInElements() 
        		throws HttpMalformedHeaderException, URIException {
        	
        	String body = "<h1>Some text <script>Some Html Element Fix: DO something </script></h1>\n"
        			+ "<b>No script here</b>\n";
            // Given
            HttpMessage msg = createHttpMessageWithRespBody(body, "text/html;charset=ISO-8859-1");
            
            assertTrue(msg.getResponseHeader().isText());
            assertFalse(msg.getResponseHeader().isJavaScript());
            
            // When
            rule.scanHttpResponseReceive(msg, -1, createSource(msg));
            
            // Then
            assertEquals(0, alertsRaised.size());
        }
        
        @Test
        public void containsSuspiciousCommentInHTML() 
        		throws HttpMalformedHeaderException, URIException {
        	
        	String body = "<h1>Some text <!--Some Html comment FixMe: DO something --></h1>\n"
        			+ "<b>No script here</b>\n";
            // Given
            HttpMessage msg = createHttpMessageWithRespBody(body, "text/html;charset=ISO-8859-1");
            
            assertTrue(msg.getResponseHeader().isText());
            assertFalse(msg.getResponseHeader().isJavaScript());
            
            // When
            rule.scanHttpResponseReceive(msg, -1, createSource(msg));
            
            // Then
            assertEquals(1, alertsRaised.size());
        }
        
        @Test
        public void noSuspiciousCommentInHTML() throws HttpMalformedHeaderException, URIException {
        	String body = "<h1>Some text <!--Some Html comment Fix: DO something --></h1>\n"
        			+ "<b>No script here</b>\n";
            // Given
            HttpMessage msg = createHttpMessageWithRespBody(body, "text/html;charset=ISO-8859-1");
            
            assertTrue(msg.getResponseHeader().isText());
            assertFalse(msg.getResponseHeader().isJavaScript());
            
            // When
            rule.scanHttpResponseReceive(msg, -1, createSource(msg));
            
            // Then
            assertEquals(0, alertsRaised.size());
        }

        @Test
        public void passesIfResponseIsEmpty() throws HttpMalformedHeaderException, URIException {
            HttpMessage msg = createHttpMessageWithRespBody("", "text/html;charset=ISO-8859-1");

            rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

            assertEquals(0, alertsRaised.size());
        }

        @Test
        public void passesIfResponseIsNotText() throws HttpMalformedHeaderException, URIException {
            HttpMessage msg = createHttpMessageWithRespBody(
            		"Some text <script>Some Script Element FixMe: DO something </script>\nLine 2\n",
            		"application/octet-stream;charset=ISO-8859-1");

            rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

            assertEquals(0, alertsRaised.size());
        }
}
