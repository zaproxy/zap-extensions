/*
 * WorkerGeneratorURLFuzz.java
 *
 * Created on 11 November 2005, 20:33
 *
 * Copyright 2007 James Fisher
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

package com.sittinglittleduck.DirBuster.workGenerators;

import com.sittinglittleduck.DirBuster.BaseCase;
import com.sittinglittleduck.DirBuster.Config;
import com.sittinglittleduck.DirBuster.DirToCheck;
import com.sittinglittleduck.DirBuster.GenBaseCase;
import com.sittinglittleduck.DirBuster.HTTPHeader;
import com.sittinglittleduck.DirBuster.Manager;
import com.sittinglittleduck.DirBuster.WorkUnit;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Vector;
import java.util.concurrent.BlockingQueue;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.HeadMethod;
import org.apache.log4j.Logger;

/** Produces the work to be done, when we are reading from a list */
public class WorkerGeneratorURLFuzz implements Runnable {

    private final Manager manager;
    private BlockingQueue<WorkUnit> workQueue;
    private BlockingQueue<DirToCheck> dirQueue;
    private String inputFile;
    private String firstPart;
    private String fileExtention;
    private String finished;
    private String started;
    private boolean stopMe = false;
    private boolean skipCurrent = false;
    // find bug UuF
    // private String failString = "thereIsNoWayThat-You-CanBeThere";
    // private HttpURLConnection urlConn;
    // find bug UuF
    // HttpState initialState;
    HttpClient httpclient;

    private String urlFuzzStart;
    private String urlFuzzEnd;

    /* Logger object for the class */
    private static final Logger LOG = Logger.getLogger(WorkerGeneratorURLFuzz.class);

    /**
     * Creates a new instance of WorkerGenerator
     *
     * @param manager Manager object
     */
    public WorkerGeneratorURLFuzz(Manager manager) {
        this.manager = manager;
        workQueue = manager.workQueue;
        dirQueue = manager.dirQueue;
        if (manager.isBlankExt()) {
            fileExtention = "";
        } else {
            fileExtention = "." + manager.getFileExtention();
        }

        // get the vector of all the file extention we need to use
        // extToCheck = manager.getExtToUse();
        inputFile = manager.getInputFile();
        firstPart = manager.getFirstPartOfURL();

        httpclient = manager.getHttpclient();

        urlFuzzStart = manager.getUrlFuzzStart();
        urlFuzzEnd = manager.getUrlFuzzEnd();
    }

    /** Thread run method */
    public void run() {

        /*
         * Read in all the items and create all the work we need to.
         */

        BufferedReader d = null;
        try {
            manager.setURLFuzzGenFinished(false);
            String currentDir = "/";
            int failcode = 404;
            String line;
            Vector extToCheck = new Vector(10, 5);
            boolean recursive = true;
            int passTotal = 0;

            try {
                d = new BufferedReader(new InputStreamReader(new FileInputStream(inputFile)));
                passTotal = 0;
                while ((line = d.readLine()) != null) {
                    if (!line.startsWith("#")) {
                        passTotal++;
                    }
                }
                manager.setTotalPass(passTotal);
            } catch (FileNotFoundException ex) {
                LOG.error(String.format("File '%s' not found!", inputFile), ex);
            } catch (IOException ex) {
                LOG.error(ex);
            }

            if (manager.getAuto()) {
                try {
                    URL headurl = new URL(firstPart);
                    HeadMethod httphead = new HeadMethod(headurl.toString());
                    Vector HTTPheaders = manager.getHTTPHeaders();
                    for (int a = 0; a < HTTPheaders.size(); a++) {
                        HTTPHeader httpHeader = (HTTPHeader) HTTPheaders.elementAt(a);
                        httphead.setRequestHeader(httpHeader.getHeader(), httpHeader.getValue());
                    }
                    httphead.setFollowRedirects(Config.followRedirects);
                    int responceCode = httpclient.executeMethod(httphead);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Response code for head check = " + responceCode);
                    }
                    if (responceCode == 501 || responceCode == 400 || responceCode == 405) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(
                                    "Changing to GET only HEAD test returned 501(method no implmented) or a 400");
                        }
                        manager.setAuto(false);
                    }
                } catch (MalformedURLException e) {
                    LOG.debug("Malformed URL", e);
                } catch (IOException e) {
                    LOG.debug(e);
                }
            }

            d = new BufferedReader(new InputStreamReader(new FileInputStream(inputFile)));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Starting fuzz on " + firstPart + urlFuzzStart + "{dir}" + urlFuzzEnd);
            }

            int filesProcessed = 0;

            BaseCase baseCaseObj =
                    GenBaseCase.genURLFuzzBaseCase(manager, firstPart + urlFuzzStart, urlFuzzEnd);

            while ((line = d.readLine()) != null) {
                if (stopMe) {
                    return;
                }

                if (!line.startsWith("#")) {
                    String method;
                    if (manager.getAuto()
                            && !baseCaseObj.useContentAnalysisMode()
                            && !baseCaseObj.isUseRegexInstead()) {
                        method = "HEAD";
                    } else {
                        method = "GET";
                    }

                    // url encode all the items
                    line = URLEncoder.encode(line);

                    URL currentURL = new URL(firstPart + urlFuzzStart + line + urlFuzzEnd);
                    // BaseCase baseCaseObj = new BaseCase(currentURL, failcode, true, failurl,
                    // baseResponce);
                    // if the base case is null then we need to switch to content anylsis mode
                    workQueue.put(new WorkUnit(currentURL, true, method, baseCaseObj, line));
                }

                Thread.sleep(3);
            }
        } catch (InterruptedException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(ex.toString());
            }
        } catch (MalformedURLException ex) {
            LOG.warn("Failed to create the fuzzed URL:", ex);
        } catch (IOException ex) {
            LOG.warn("Failed to create the fuzzed URL:", ex);
        } finally {
            try {
                d.close();
                manager.setURLFuzzGenFinished(true);
            } catch (IOException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(ex.toString());
                }
            }
        }
    }

    private String makeItemsafe(String item) {
        // covert spaces
        item = item.replaceAll(" ", "%20");
        // remove "
        item = item.replaceAll("\"", "");
        // convert \ into /
        item = item.replaceAll("\\\\", "");

        // item = item.replaceAll("", "");
        // remove none valid URL encoding
        // item = item.replaceAll("%[^0-9A-Fa-f][^0-9A-Fa-f]", "");
        // TODO move to the database level
        // tempfix to deal with ASPX problem
        // item = item.replaceAll(".aspx", "");

        if (item.length() > 2) {
            // remove / from the end
            if (item.endsWith("/")) {
                item = item.substring(1, item.length() - 1);
            }
            // remove / from the front
            if (item.startsWith("/")) {
                item = item.substring(2, item.length());
            }
        } else {
            // change a single / for DirBuster -> this stops errors and recursive loops
            if (item.startsWith("/")) {
                item = "DirBuster";
            }
        }
        return item;
    }

    /** Method to stop the manager while it is working */
    public void stopMe() {
        stopMe = true;
    }

    public void skipCurrent() {
        skipCurrent = true;
    }
}
