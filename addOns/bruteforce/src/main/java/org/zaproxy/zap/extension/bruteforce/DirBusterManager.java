/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2010 The ZAP Development Team
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
package org.zaproxy.zap.extension.bruteforce;

import com.sittinglittleduck.DirBuster.BaseCase;
import com.sittinglittleduck.DirBuster.Manager;
import java.net.URL;
import org.apache.log4j.Logger;

public class DirBusterManager extends Manager {

    private BruteForceListenner listenner;
    private int done = 0;
    private int total = 100;
    private boolean finished = false;
    private static Logger log = Logger.getLogger(DirBusterManager.class);

    public DirBusterManager(BruteForceListenner listenner) {
        super();
        this.listenner = listenner;
    }

    @Override
    public synchronized void foundDir(
            URL url,
            int statusCode,
            String responce,
            String baseCase,
            String rawResponce,
            BaseCase baseCaseObj) {
        if (url.toString().endsWith("//")) {
            // For some reason DirBuster can go recursive and never finish
            log.debug("Ignoring url " + url.toString());
            return;
        }
        super.foundDir(url, statusCode, responce, baseCase, rawResponce, baseCaseObj);
        log.debug("DirBusterManager.foundDir " + url.toString() + " code:" + statusCode);
        listenner.foundDir(url, statusCode, responce, baseCase, rawResponce, baseCaseObj);
    }

    @Override
    public synchronized void foundFile(
            URL url,
            int statusCode,
            String responce,
            String baseCase,
            String rawResponce,
            BaseCase baseCaseObj) {
        super.foundFile(url, statusCode, responce, baseCase, rawResponce, baseCaseObj);
        listenner.foundDir(url, statusCode, responce, baseCase, rawResponce, baseCaseObj);
    }

    @Override
    public synchronized void foundError(URL url, String reason) {
        super.foundError(url, reason);
        log.warn("DirBusterManager.foundError " + url.toString() + " reason:" + reason);
    }

    @Override
    public void youAreFinished() {
        super.youAreFinished();
        finished = true;
    }

    public boolean hasFinished() {
        return finished;
    }

    @Override
    public int getTotalDone() {
        if (this.areWorkersAlive()) {
            done = super.getTotalDone();
        }
        return done;
    }

    public int getTotal() {
        if (this.areWorkersAlive()) {
            long bigTotal = this.getTotalToDo();
            if (bigTotal > Integer.MAX_VALUE) {
                total = Integer.MAX_VALUE;
            } else if (bigTotal > total) {
                // More work - ignore if less than before - this happens if its stopped early
                total = (int) bigTotal;
            }
            if (total == 0) {
                // Havt started yet
                total = 100;
            }
        }
        return total;
    }

    private long getTotalToDo() {
        int totalDirs = 1;

        if (this.isRecursive() && this.getDoDirs()) {
            totalDirs = 1 + this.getTotalDirsFound();
        }

        int doingFiles = 1;

        // only if we are doing both files and dirs do we need to times by 2
        if (this.getDoFiles() && this.getDoDirs()) {
            doingFiles = 1 + this.getExtToUse().size();
        } else if ((this.getDoFiles() && !this.getDoDirs())) {
            doingFiles = this.getExtToUse().size();
        }

        long totalToDo = ((long) this.getTotalPass()) * totalDirs * doingFiles;

        // add the number of base cases and the frist inital request
        totalToDo = totalToDo + this.getNumberOfBaseCasesProduced();

        // correct to deal with the intial dir we need to test
        if (this.getDoDirs()) {
            totalToDo = totalToDo + 1;
        }

        // add the process parsed links
        totalToDo = totalToDo + this.getParsedLinksProcessed();

        // correct the total to do but removing items we have skipped
        totalToDo = totalToDo - this.getWorkAmountCorrection();
        return totalToDo;
    }
}
