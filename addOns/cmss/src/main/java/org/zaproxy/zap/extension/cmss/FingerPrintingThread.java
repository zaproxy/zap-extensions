/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.cmss;

import java.net.URL;
import java.util.ArrayList;

public class FingerPrintingThread extends Thread {
    private ArrayList<String> wtfpList = new ArrayList<String>();
    private ArrayList<String> resultList = new ArrayList<String>();
    private int POrAOption;
    private URL targetUrl;

    public FingerPrintingThread(URL targetUrl, ArrayList<String> wtfpList, int POrAOption) {
        this.wtfpList = wtfpList;
        this.POrAOption = POrAOption;
        this.targetUrl = targetUrl;
    }

    @Override
    public void run() {
        try {
            resultList = FastFingerprinter.filterResults(this.targetUrl, wtfpList, this.POrAOption);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (Throwable e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public ArrayList<String> getFingerPrintingResult() {
        return this.resultList;
    }
}
