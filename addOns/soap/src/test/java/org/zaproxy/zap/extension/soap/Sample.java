/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.soap;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

public class Sample {

    /* Global methods to make a WSDL retrieval test message. */
    public static HttpMessage setRequestHeaderContent(HttpMessage msg)
            throws HttpMalformedHeaderException {
        msg.setRequestHeader(
                "GET http://localhost/test/WS_162_https.wsdl HTTP/1.1"
                        + "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0;)"
                        + "Pragma: no-cache"
                        + "Cache-Control: no-cache"
                        + "Content-Length: 0"
                        + "Host: localhost");
        return msg;
    }

    public static HttpMessage setResponseHeaderContent(HttpMessage msg)
            throws HttpMalformedHeaderException {
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Date: Sun, 10 Aug 2014 15:35:20 GMT\r\n"
                        + "Server: Apache/2.4.3 (Win32) OpenSSL/1.0.1c PHP/5.4.7\r\n"
                        + "Content-Type: application/wsdl+xml\r\n");
        return msg;
    }

    public static HttpMessage setResponseBodyContent(HttpMessage msg) throws IOException {
        /* Gets test wsdl file and retrieves its content as String. */
        InputStream in = Sample.class.getResourceAsStream("resources/test.wsdl");
        Reader fr = new InputStreamReader(in, "UTF-8");
        BufferedReader br = new BufferedReader(fr);
        StringBuilder sb = new StringBuilder();
        String line = "";
        line = br.readLine();
        do {
            sb.append(line + "\r\n");
        } while ((line = br.readLine()) != null);
        String wsdlContent = sb.toString();
        msg.setResponseBody(wsdlContent);
        return msg;
    }

    /* Global methods to make SOAP requests and responses. */
    public static HttpMessage setOriginalRequest(HttpMessage msg)
            throws HttpMalformedHeaderException {
        msg.setRequestHeader(
                "POST https://192.168.145.131:8443/axis2/services/SampleService.SampleServiceHttpsSoap11Endpoint/ HTTP/1.1 \r\n"
                        + "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0;) \r\n"
                        + "Pragma: no-cache \r\n"
                        + "Cache-Control: no-cache \r\n"
                        + "Content-Length: 275 \r\n"
                        + "Content-Type: text/xml; charset=UTF-8 \r\n"
                        + "SOAPAction: urn:sayHelloWorld \r\n"
                        + "Host: 192.168.145.131:8443\r\n");
        msg.setRequestBody(
                "<?xml version=\"1.0\" encoding= \"UTF-8\" ?>"
                        + "<s11:Envelope xmlns:s11='http://schemas.xmlsoap.org/soap/envelope/'>"
                        + "<s11:Body>"
                        + "<ns:sayHelloWorld xmlns:ns='http://main.soaptest.org'>"
                        + "<ns:args0>paramValue</ns:args0>"
                        + "</ns:sayHelloWorld>"
                        + "</s11:Body>"
                        + "</s11:Envelope>");
        /* Sets true length. */
        int bodyLength = msg.getRequestBody().length();
        HttpRequestHeader requestHeader = msg.getRequestHeader();
        requestHeader.setContentLength(bodyLength);
        msg.setRequestHeader(requestHeader);
        return msg;
    }

    public static HttpMessage setOriginalResponse(HttpMessage msg)
            throws HttpMalformedHeaderException {
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/xml;charset=UTF-8\r\n"
                        + "Date: Sat, 09 Aug 2014 11:32:48 GMT\r\n");
        msg.setResponseBody(
                "<?xml version='1.0' encoding='UTF-8'?>"
                        + "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                        + "<soapenv:Body>"
                        + "<ns:sayHelloWorldResponse xmlns:ns=\"http://main.soaptest.org\">"
                        + "<ns:return>Hello world from paramValue</ns:return>"
                        + "</ns:sayHelloWorldResponse></soapenv:Body>"
                        + "</soapenv:Envelope>");
        return msg;
    }

    public static HttpMessage setByeActionRequest(HttpMessage msg) {
        HttpRequestHeader header = msg.getRequestHeader();
        header.setHeader("SOAPAction", "urn:sayByeWorld");
        msg.setRequestHeader(header);
        return msg;
    }

    public static HttpMessage setByeResponse(HttpMessage msg) throws HttpMalformedHeaderException {
        msg.setResponseBody(
                "<?xml version='1.0' encoding='UTF-8'?>"
                        + "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                        + "<soapenv:Body>"
                        + "<ns:sayByeWorldResponse xmlns:ns=\"http://main.soaptest.org\">"
                        + "<ns:return>Bye world from paramValue</ns:return>"
                        + "</ns:sayByeWorldResponse>"
                        + "</soapenv:Body>"
                        + "</soapenv:Envelope>");
        return msg;
    }

    public static HttpMessage setEmptyBodyResponse(HttpMessage msg) {
        msg.setResponseBody(" ");
        return msg;
    }

    public static HttpMessage setInvalidFormatResponse(HttpMessage msg) {
        msg.setResponseBody(
                "<?xml version='1.0' encoding='UTF-8'?>"
                        + "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                        + "<soapenv:Body>"
                        + "</soapenv:Envelope>");
        return msg;
    }

    public static HttpMessage setSoapVersionTwoRequest(HttpMessage msg)
            throws HttpMalformedHeaderException {
        msg.setRequestHeader(
                "POST https://www.example.com/Soap12Endpoint/ HTTP/1.1"
                        + "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0;)"
                        + "Pragma: no-cache"
                        + "Cache-Control: no-cache"
                        + "Content-Length: 275"
                        + "Content-Type: application/soap+xml; charset=UTF-8; action= https://www.example.com/xml/sayHelloWorld"
                        + "Host: www.example.com");
        msg.setRequestBody(
                "<?xml version='1.0' encoding= 'UTF-8' ?>"
                        + "<s12:Envelope xmlns:s12='http://www.w3.org/2003/05/soap-envelope'>"
                        + "<s12:Body>"
                        + "<ns:sayHelloWorld xmlns:ns='http://main.soaptest.org'>"
                        + "<ns:args0>paramValue</ns:args0>"
                        + "</ns:sayHelloWorld>"
                        + "</s12:Body>"
                        + "</s12:Envelope>");
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
        return msg;
    }
}
