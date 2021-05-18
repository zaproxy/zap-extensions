/*
 * Worker.java
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
package com.sittinglittleduck.DirBuster;

import com.sittinglittleduck.DirBuster.SimpleHttpClient.HttpMethod;
import java.io.IOException;
import java.net.URL;
import java.util.concurrent.BlockingQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** This class process workunit and determines if the link has been found or not */
public class Worker implements Runnable {

    private BlockingQueue<WorkUnit> queue;
    private URL url;
    private WorkUnit work;
    private final Manager manager;
    private boolean pleaseWait = false;
    private int threadId;
    private boolean working;
    private boolean stop = false;

    /* Logger object for the class */
    private static final Logger LOG = LogManager.getLogger(Worker.class);

    /**
     * Creates a new instance of Worker
     *
     * @param threadId Unique thread id for the worker
     * @param manager The manager class the worker thread reports to
     */
    public Worker(int threadId, Manager manager) {
        this.manager = manager;

        // get the work queue from, the manager
        queue = manager.workQueue;

        // set the thread id
        this.threadId = threadId;
    }

    /** Run method of the thread */
    @Override
    public void run() {

        queue = manager.workQueue;
        while (manager.hasWorkLeft()) {

            working = false;
            // code to make the worker pause, if the pause button has been presed

            // if the stop signal has been given stop the thread
            if (stop) {
                return;
            }

            // this pauses the thread
            synchronized (this) {
                while (pleaseWait) {
                    try {
                        wait();
                    } catch (InterruptedException e) {
                        return;
                    } catch (Exception e) {
                        LOG.debug(e);
                    }
                }
            }

            try {

                work = queue.take();
                working = true;
                url = work.getWork();

                String response = "";
                String rawResponse = "";

                HttpResponse httpResponse = makeRequest(work.getMethod(), url.toString());
                int code = httpResponse.getStatusCode();

                if (work.getMethod() == HttpMethod.GET) {

                    String rawHeader = httpResponse.getResponseHeader();
                    response = httpResponse.getResponseBody();

                    rawResponse = rawHeader + response;
                    // clean the response

                    if (Config.parseHTML && !work.getBaseCaseObj().isUseRegexInstead()) {
                        parseHtml(httpResponse, response);
                    }

                    response = FilterResponce.CleanResponce(response, work);

                    Thread.sleep(10);
                }

                // if we need to check the against the base case
                if (work.getMethod() == HttpMethod.GET
                        && work.getBaseCaseObj().useContentAnalysisMode()) {
                    if (code == HttpStatus.OK) {
                        verifyResponseForValidRequests(code, response, rawResponse);
                    } else if (code == HttpStatus.NOT_FOUND || code == HttpStatus.BAD_REQUEST) {
                        LOG.debug("Worker[{}]: {} for: {}", threadId, code, url);
                    } else {
                        notifyItemFound(
                                code, response, rawResponse, work.getBaseCaseObj().getBaseCase());
                    }
                }
                /*
                 * use the custom regex check instead
                 */
                else if (work.getBaseCaseObj().isUseRegexInstead()) {
                    Pattern regexFindFile = Pattern.compile(work.getBaseCaseObj().getRegex());

                    Matcher m = regexFindFile.matcher(rawResponse);

                    if (m.find()) {
                        // do nothing as we have a 404
                        LOG.debug("Worker[{}]: Regex matched 404 code. ({})", threadId, url);

                    } else {
                        if (Config.parseHTML) {
                            parseHtml(httpResponse, rawResponse);
                        }

                        notifyItemFound(
                                code, response, rawResponse, work.getBaseCaseObj().getBaseCase());
                    }

                }
                // just check the response code
                else {
                    // if is not the fail code, a 404 or a 400 then we have a possible
                    if (code != work.getBaseCaseObj().getFailCode() && verifyIfCodeIsValid(code)) {
                        if (work.getMethod() == HttpMethod.HEAD) {
                            httpResponse = makeRequest(HttpMethod.GET, url.toString());
                            int newCode = httpResponse.getStatusCode();

                            // in some cases the second get can return a different result, than the
                            // first head request!
                            if (newCode != code) {
                                manager.foundError(
                                        url,
                                        "Return code for first HEAD, is different to the second GET: "
                                                + code
                                                + " - "
                                                + newCode);
                            }

                            // build a string version of the headers
                            rawResponse = httpResponse.getResponseHeader();

                            String responseBodyAsString = httpResponse.getResponseBody();
                            rawResponse = rawResponse + responseBodyAsString;

                            if (Config.parseHTML) {
                                parseHtml(httpResponse, responseBodyAsString);
                            }
                        }

                        if (work.isDir()) {
                            manager.foundDir(url, code, rawResponse, work.getBaseCaseObj());
                        } else {
                            manager.foundFile(url, code, rawResponse, work.getBaseCaseObj());
                        }
                    }
                }

                manager.workDone();
                Thread.sleep(20);

            } catch (IOException e) {

                manager.foundError(url, e.getClass().getSimpleName() + " " + e.getMessage());
                manager.workDone();
            } catch (InterruptedException e) {
                // manager.foundError(url, "InterruptedException " + e.getMessage());
                manager.workDone();
                return;
            } catch (IllegalArgumentException e) {
                manager.foundError(url, "IllegalArgumentException " + e.getMessage());
                manager.workDone();
            }
        }
    }

    private HttpResponse makeRequest(HttpMethod method, String url)
            throws IOException, InterruptedException {
        LOG.debug("Worker[{}]: {} : {}", threadId, method, url);

        /*
         * this code is used to limit the number of request/sec
         */
        if (manager.isLimitRequests()) {
            while (manager.getTotalDone()
                            / ((System.currentTimeMillis() - manager.getTimestarted()) / 1000.0)
                    > manager.getLimitRequestsTo()) {
                Thread.sleep(100);
            }
        }

        HttpResponse response = manager.getHttpClient().send(method, url);

        LOG.debug("Worker[{}]: {} {}", threadId, response.getStatusCode(), url);
        return response;
    }

    private boolean verifyIfCodeIsValid(int code) {
        return code != HttpStatus.NOT_FOUND && code != 0 && code != HttpStatus.BAD_GATEWAY;
    }

    private void verifyResponseForValidRequests(int code, String response, String rawResponse) {
        LOG.debug("Worker[{}]: Base Case Check {}", threadId, url);

        // TODO move this option to the Adv options
        // if the response does not match the base case
        Pattern regexFindFile = Pattern.compile(".*file not found.*", Pattern.CASE_INSENSITIVE);

        Matcher m = regexFindFile.matcher(response);

        // need to clean the base case of the item we are looking for
        String basecase =
                FilterResponce.removeItemCheckedFor(
                        work.getBaseCaseObj().getBaseCase(), work.getItemToCheck());

        if (m.find()) {
            LOG.debug("Worker[{}]: 404 for: {}", threadId, url);
        } else if (!response.equalsIgnoreCase(basecase)) {
            notifyItemFound(code, response, rawResponse, basecase);
        }
    }

    private void notifyItemFound(
            int code, String response, String rawResponse, String basecase, String type) {
        if (work.isDir()) {
            LOG.debug("Worker[{}]: Found Dir ({}) {}", threadId, type, url);
            // we found a dir
            manager.foundDir(url, code, response, basecase, rawResponse, work.getBaseCaseObj());
        } else {
            // found a file
            LOG.debug("Worker[{}]: Found File ({}) {}", threadId, type, url);
            manager.foundFile(url, code, response, basecase, rawResponse, work.getBaseCaseObj());
        }
    }

    private void notifyItemFound(int code, String response, String rawResponse, String basecase) {
        notifyItemFound(code, response, rawResponse, basecase, "base case");
    }

    private void parseHtml(HttpResponse httpResponse, String response) {
        // parse the html of what we have found

        String contentType = httpResponse.getContentType();

        if (contentType != null && contentType.startsWith("text")) {
            manager.addHTMLToParseQueue(new HTMLparseWorkUnit(response, work));
        }
    }

    /** Method to call to pause the thread */
    public synchronized void pause() {
        pleaseWait = true;
    }

    /** Method to call to unpause the thread */
    public synchronized void unPause() {
        pleaseWait = false;
    }

    /**
     * Return a boolean based on if the thread is working
     *
     * @return boolean value about if the thread is working
     */
    public synchronized boolean isWorking() {
        return working;
    }

    /** Method to call to stop the thread */
    public synchronized void stopThread() {
        this.stop = true;
    }
}
