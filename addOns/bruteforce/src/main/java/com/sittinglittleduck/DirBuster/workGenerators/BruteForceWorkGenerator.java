/*
 * BruteForceWorkGenerator.java
 *
 *
 * Copyright 2006 James Fisher
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
import com.sittinglittleduck.DirBuster.DirToCheck;
import com.sittinglittleduck.DirBuster.ExtToCheck;
import com.sittinglittleduck.DirBuster.GenBaseCase;
import com.sittinglittleduck.DirBuster.HttpStatus;
import com.sittinglittleduck.DirBuster.Manager;
import com.sittinglittleduck.DirBuster.SimpleHttpClient.HttpMethod;
import com.sittinglittleduck.DirBuster.WorkUnit;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Vector;
import java.util.concurrent.BlockingQueue;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** @author James */
public class BruteForceWorkGenerator implements Runnable {
    private String[] list = {"a", "b", "c", "d"};
    private int[] listindex;

    private int minLen;
    private int maxLen;

    private final Manager manager;
    private BlockingQueue<WorkUnit> workQueue;
    private BlockingQueue<DirToCheck> dirQueue;

    private String firstPart;
    private String fileExtention;
    private String finished;
    private String started;

    // find bug UuF
    // private String failString = Config.failCaseString;

    private String currentDir = "/";
    Vector<ExtToCheck> extToCheck = new Vector<>(10, 5);
    private int failcode = 404;
    private boolean doingDirs = true;

    /* Logger object for the class */
    private static final Logger LOG = LogManager.getLogger(BruteForceWorkGenerator.class);

    // find bug UuF
    // HttpState initialState;

    /** Creates a new instance of BruteForceWorkGenerator */
    public BruteForceWorkGenerator(Manager manager) {
        this.manager = manager;

        this.maxLen = manager.getMaxLen();
        this.minLen = manager.getMinLen();
        this.list = manager.getCharSet();
        listindex = new int[list.length];
        calcTotalPerPass(list.length, minLen, maxLen);
        initIndex();

        workQueue = manager.workQueue;
        dirQueue = manager.dirQueue;
        fileExtention = manager.getFileExtention();
        firstPart = manager.getFirstPartOfURL();
    }

    @Override
    public void run() {
        boolean recursive = true;

        // checks if the server surports heads requests

        if (manager.getAuto()) {
            try {
                URL headurl = new URL(firstPart);

                int responceCode =
                        manager.getHttpClient()
                                .send(HttpMethod.HEAD, headurl.toString())
                                .getStatusCode();

                // if the responce code is method not implemented or fails
                if (responceCode == HttpStatus.NOT_IMPLEMENTED
                        || responceCode == HttpStatus.BAD_REQUEST) {
                    // switch the mode to just GET requests
                    manager.setAuto(false);
                }
            } catch (IOException e) {
                LOG.error(e);
            }
        }

        while ((!dirQueue.isEmpty() || !workQueue.isEmpty()) && recursive) {
            recursive = manager.isRecursive();
            // deal with the dirs
            try {
                // get item from  queue
                DirToCheck tempDirToCheck = dirQueue.take();
                // get dir name
                currentDir = tempDirToCheck.getName();
                // get any extention that need to be checked
                extToCheck = tempDirToCheck.getExts();
            } catch (InterruptedException e) {
                LOG.debug(e);
            }

            started = currentDir;

            if (manager.getDoDirs()) {
                doingDirs = true;
                String baseCase = null;
                // store for the basecase object set to null;
                BaseCase baseCaseObj = null;
                URL failurl = null;
                try {
                    // get fail responce code for a dir test

                    baseCaseObj =
                            GenBaseCase.genBaseCase(manager, firstPart + currentDir, true, null);

                } catch (IOException e) {
                    LOG.error(e);
                }

                // baseCaseObj = new BaseCase(null, failcode, true, failurl, baseCase);
                // call function to generate the brute force
                if (failcode != 200) {
                    makeList(minLen, maxLen, null, baseCaseObj);
                } else {
                    makeList(minLen, maxLen, baseCase, baseCaseObj);
                }
            } // end of doing the dirs

            // brute force files names
            if (manager.getDoFiles()) {
                doingDirs = false;
                String baseCase = null;
                BaseCase baseCaseObj = null;
                URL failurl = null;
                for (int b = 0; b < extToCheck.size(); b++) {
                    ExtToCheck tempExt = extToCheck.elementAt(b);
                    if (tempExt.toCheck()) {
                        fileExtention = "";
                        if (tempExt.getName().equals(ExtToCheck.BLANK_EXT)) {
                            fileExtention = "";
                        } else {
                            fileExtention = "." + tempExt.getName();
                        }

                        try {
                            // deal with the files

                            baseCaseObj =
                                    GenBaseCase.genBaseCase(
                                            manager, firstPart + currentDir, false, fileExtention);

                        } catch (IOException e) {
                            LOG.error(e);
                        }

                        // call function to generate the brute force
                        if (failcode != 200) {
                            makeList(minLen, maxLen, null, baseCaseObj);
                        } else {
                            makeList(minLen, maxLen, baseCase, baseCaseObj);
                        }
                    }
                }
            }

            finished = started;
        }
        manager.youAreFinished();
    }

    private void makeList(int minLen, int maxLen, String baseCase, BaseCase baseCaseObj) {
        for (int x = minLen; x <= maxLen; x++) {
            while (listindex[0] < list.length) {
                showString(x, baseCase, baseCaseObj);
                incrementCounter(x);
            }
            /* re-initialize the index */
            initIndex();
        }
    }

    private void showString(int len, String baseCase, BaseCase baseCaseObj) {
        int chrx, endchr;
        String temp = "";
        /* print the current index */
        StringBuffer buf = new StringBuffer();
        for (int x = 0; x < len; x++) {
            chrx = listindex[x];
            // printf("%c", charlist[chrx]);
            buf.append(list[chrx]);
            // temp = temp + list[chrx];
        }
        temp = buf.toString();
        // System.out.println(temp);
        try {

            HttpMethod method;
            if (manager.getAuto()
                    && !baseCaseObj.useContentAnalysisMode()
                    && !baseCaseObj.isUseRegexInstead()) {
                method = HttpMethod.HEAD;
            } else {
                method = HttpMethod.GET;
            }

            if (doingDirs) {
                URL currentURL = new URL(firstPart + currentDir + temp + "/");

                workQueue.put(new WorkUnit(currentURL, true, method, baseCaseObj, temp));

            } else {
                URL currentURL = new URL(firstPart + currentDir + temp + fileExtention);

                workQueue.put(new WorkUnit(currentURL, false, method, baseCaseObj, temp));
            }
        } catch (InterruptedException e) {
            LOG.debug(e);
        } catch (MalformedURLException e) {
            LOG.debug("Bad URL", e);
        }
    }

    private void incrementCounter(int len) {

        int x, z;
        int limit, last, check;

        /* nasty kludge */
        len--;

        limit = list.length;
        // printf("Limit is %d\n", limit);

        /* this sets the last octet of the index up by one */

        last = listindex[len];
        // printf("Last index was %d\n", last);
        last++;
        listindex[len] = last;
        // printf("set index to %d\n", chrindex[len]);

        /* this loop goes backwards through the index */
        /* each time determining if the char limit is reached */

        for (x = len; x > 0; x--) {
            // printf("Checking index %d of chrindex which is set to %d\n", x, chrindex[x]);
            if (listindex[x] == limit) {
                /* set this index to 0 */
                listindex[x] = 0;
                /* increment the next index */
                z = x - 1;
                listindex[z] = listindex[z] + 1;
                /* this loop should continue */
                // printf("Set index %d to 0 and incremented index %d by 1\n", x, z);
            }
        }
    }

    private void initIndex() {
        for (int a = 0; a < listindex.length; a++) {
            listindex[a] = 0;
        }
    }

    // calculates the total number of tries per pass
    private void calcTotalPerPass(int listLength, int minLen, int maxLen) {
        LOG.debug("listLen: {} minLen: {} maxLen: {}", listLength, minLen, maxLen);

        double total = 0;
        for (int a = minLen; a <= maxLen; a++) {
            total = total + Math.pow(listLength, a);
        }

        LOG.debug("Total for a pure brute force = {}", total);
        manager.setTotalPass(total);
    }
}
