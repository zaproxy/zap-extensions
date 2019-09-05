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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.encoder.Base64;

import static org.hamcrest.Matchers.equalToIgnoringWhiteSpace;
import static org.junit.Assert.assertThat;

public class ViewStateDecoderTest {

    private ViewStateDecoder viewStateDecoder = new ViewStateDecoder();

    @Test
    public void shouldDecodeHMAC_SHA0_Viewstate() throws Exception {
        // Given
        String viewState =
                "/wEPDwUJODczNjQ5OTk0D2QWAgIDD2QWAgIFDw8WAh4EV"
                        + "GV4dAUWSSBMb3ZlIERvdG5ldEN1cnJ5LmNvbWRkZMHbBY9JqBTvB5"
                        + "/6kXnY15AUSAwa";

        // When
        String content = viewStateDecoder.decodeAsXML(Base64.decode(viewState.getBytes()));

        // Then
        assertThat(
                content,
                equalToIgnoringWhiteSpace(
                        "<?xml version=\"1.0\" ?>\n"
                                + "<viewstate>\n"
                                + "   <encrypted>false</encrypted>\n"
                                + "   <pair>\n"
                                + "      <pair>\n"
                                + "         <string>873649994</string>\n"
                                + "         <pair>\n"
                                + "            <emptynode></emptynode>\n"
                                + "            <objectarray size=\"2\">\n"
                                + "               <uint32>3</uint32>\n"
                                + "               <pair>\n"
                                + "                  <emptynode></emptynode>\n"
                                + "                  <objectarray size=\"2\">\n"
                                + "                     <uint32>5</uint32>\n"
                                + "                     <pair>\n"
                                + "                        <pair>\n"
                                + "                           <objectarray size=\"2\">\n"
                                + "                              <string>Text</string>\n"
                                + "                              <string>I Love DotnetCurry.com</string>\n"
                                + "                           </objectarray>\n"
                                + "                           <emptynode></emptynode>\n"
                                + "                        </pair>\n"
                                + "                        <emptynode></emptynode>\n"
                                + "                     </pair>\n"
                                + "                  </objectarray>\n"
                                + "               </pair>\n"
                                + "            </objectarray>\n"
                                + "         </pair>\n"
                                + "      </pair>\n"
                                + "      <emptynode></emptynode>\n"
                                + "   </pair>\n"
                                + "   <hmac>true</hmac>\n"
                                + "   <hmactype>HMAC-SHA0/HMAC-SHA1</hmactype>\n"
                                + "   <hmaclength>20</hmaclength>\n"
                                + "   <hmacvalue>0xc1db058f49a814ef079ffa9179d8d79014480c1a</hmacvalue>\n"
                                + "</viewstate>\n"));
    }

    @Test
    public void shouldDecodeViewstate() throws Exception {
        // Given
        String viewState =
                "/wEPDwUJODczNjQ5OTk0D2QWAgIDD2QWAgIFDw8WAh4EVGV4dAUWSSBMb3ZlIERvdG5ldEN1cnJ5LmNvbWRkZA==";

        // When
        String content = viewStateDecoder.decodeAsXML(Base64.decode(viewState.getBytes()));

        // Then
        assertThat(
                content,
                equalToIgnoringWhiteSpace(
                        "<?xml version=\"1.0\" ?>\n"
                                + "<viewstate>\n"
                                + "   <encrypted>false</encrypted>\n"
                                + "   <pair>\n"
                                + "      <pair>\n"
                                + "         <string>873649994</string>\n"
                                + "         <pair>\n"
                                + "            <emptynode></emptynode>\n"
                                + "            <objectarray size=\"2\">\n"
                                + "               <uint32>3</uint32>\n"
                                + "               <pair>\n"
                                + "                  <emptynode></emptynode>\n"
                                + "                  <objectarray size=\"2\">\n"
                                + "                     <uint32>5</uint32>\n"
                                + "                     <pair>\n"
                                + "                        <pair>\n"
                                + "                           <objectarray size=\"2\">\n"
                                + "                              <string>Text</string>\n"
                                + "                              <string>I Love DotnetCurry.com</string>\n"
                                + "                           </objectarray>\n"
                                + "                           <emptynode></emptynode>\n"
                                + "                        </pair>\n"
                                + "                        <emptynode></emptynode>\n"
                                + "                     </pair>\n"
                                + "                  </objectarray>\n"
                                + "               </pair>\n"
                                + "            </objectarray>\n"
                                + "         </pair>\n"
                                + "      </pair>\n"
                                + "      <emptynode></emptynode>\n"
                                + "   </pair>\n"
                                + "   <hmac>false</hmac>\n"
                                + "</viewstate>\n"));
    }

    @Rule public ExpectedException thrown = ExpectedException.none();

    @Test
    public void shouldRejectContentWithInvalidViewstatePreample() throws Exception {
        // Then
        thrown.expect(Exception.class);
        thrown.expectMessage("Invalid Viewstate preamble");

        // Given
        String viewState = "emFwCg==";

        // When
        viewStateDecoder.decodeAsXML(Base64.decode(viewState.getBytes()));
    }

    @Before
    public void setUp() {
        Constant.setLocale("en_US");
    }
}
