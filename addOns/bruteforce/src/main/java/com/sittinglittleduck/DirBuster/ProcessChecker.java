/*
 * ProcessChecker.java
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

import java.util.TimerTask;
import java.util.Vector;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ProcessChecker extends TimerTask {

    private final Manager manager;
    private long timeStarted;
    private long lastTotal = 0L;
    private Vector<Long> lastTen = new Vector<>(10, 1);

    /* Logger object for the class */
    private static final Logger LOG = LogManager.getLogger(ProcessChecker.class);

    /** Creates a new instance of ProcessChecker */
    public interface ProcessUpdate {

        void isAlive();
    }

    public ProcessChecker(Manager manager) {
        this.manager = manager;
        timeStarted = System.currentTimeMillis();
    }

    @Override
    public void run() {
        long timePassed = (scheduledExecutionTime() - timeStarted) / 1000;
        if (timePassed > 0) {
            int totalDirs = 1;

            if (manager.isRecursive() && manager.getDoDirs()) {
                totalDirs = 1 + manager.getTotalDirsFound();
            }

            int doingFiles = 1;

            // only if we are doing both files and dirs do we need to times by 2
            if (manager.getDoFiles() && manager.getDoDirs()) {
                doingFiles = 1 + manager.getExtToUse().size();
            } else if ((manager.getDoFiles() && !manager.getDoDirs())) {
                doingFiles = manager.getExtToUse().size();
            }

            long totalToDo = ((long) manager.getTotalPass()) * totalDirs * doingFiles;

            // add the number of base cases and the frist inital request
            totalToDo = totalToDo + manager.getNumberOfBaseCasesProduced();

            // correct to deal with the intial dir we need to test
            if (manager.getDoDirs()) {
                totalToDo = totalToDo + 1;
            }

            // add the process parsed links
            totalToDo = totalToDo + manager.getParsedLinksProcessed();

            // correct the total to do but removing items we have skipped
            totalToDo = totalToDo - manager.getWorkAmountCorrection();

            // correct the total removing base cases that where not processed
            // totalToDo = totalToDo - manager.getBaseCaseCounterCorrection();

            // System.out.println("totalToDo = " + totalToDo + " = " + manager.getTotalPass() + " *
            // " + totalDirs + " * " + doingFiles + " + " + numberOfBaseCases);
            long currentTotal = manager.getTotalDone();
            long average = currentTotal / timePassed;
            long current = currentTotal - lastTotal;

            // store the last ten current speeds
            // used to calculate averages better
            if (lastTen.size() < 10) {
                lastTen.addElement(current);
            } else if (lastTen.size() == 10) {
                // remove the first item from the vector
                lastTen.removeElementAt(0);
                lastTen.addElement(current);
            } else {
                // should never get here
            }

            long lastTenTotal = 0;
            for (int a = 0; a < lastTen.size(); a++) {
                long temp = lastTen.elementAt(a);
                lastTenTotal = lastTenTotal + temp;
            }

            long averageLastTen = lastTenTotal / lastTen.size();

            String parseQueueLength = "N/A";

            if (Config.parseHTML) {
                parseQueueLength = String.valueOf(manager.parseQueue.size());
            }

            if (LOG.isDebugEnabled()) {
                if (average == 0 || lastTenTotal == 0 || averageLastTen == 0) {
                    LOG.debug(
                            "Current Speed: {} requests/sec\nAverage Speed: (T) {}, (C) {} requests/sec\nTotal Requests: {}/{}\nTime To Finish: ~{}",
                            current,
                            average,
                            averageLastTen,
                            currentTotal,
                            totalToDo,
                            parseQueueLength);

                } else {
                    long timeLeft = (totalToDo - currentTotal) / averageLastTen;
                    String timeToCompelete = convertSecsToTime(timeLeft);
                    lastTotal = currentTotal;
                    LOG.debug(
                            "Current speed: {} request/sec\nAverage Speed: (T) {}, (C) {} requests/sec\nTotal Requests: {}/{}\nTime To Finish: {}\n{}",
                            current,
                            average,
                            averageLastTen,
                            currentTotal,
                            totalToDo,
                            timeToCompelete,
                            parseQueueLength);
                }

                // System.out.println("workQ: " + manager.workQueue.size());
                LOG.debug("dirQ: {}", manager.dirQueue.size());
                // System.out.println("parseQ: " + manager.parseQueue.size());
                // manager.
            }
        }
    }

    private String convertSecsToTime(long secs) {
        // get the number of minuates
        if (secs < 10) {
            return "00:00:0" + secs;
        }

        if (secs < 60) {
            return "00:00:" + secs;
        }
        long mins = secs / 60;
        long secsleft = secs - (mins * 60);
        String addZeroSecs = "";
        if (secsleft < 10) {
            addZeroSecs = "0";
        }

        String addZeroMins = "";
        if (mins < 10) {
            addZeroMins = "0";
        }

        if (mins < 60) {
            return "00:" + addZeroMins + mins + ":" + addZeroSecs + secsleft;
        }
        long hours = mins / 60;
        long minsleft = mins - (hours * 60);
        if (minsleft < 10) {
            addZeroMins = "0";
        }
        if (hours > 24) {
            long days = hours / 24;
            if (days == 1) {
                return days + " Day";
            } else {
                return days + " Days";
            }
        }
        if (hours < 10) {
            return "0" + hours + ":" + addZeroMins + minsleft + ":" + addZeroSecs + secsleft;
        } else {
            return hours + ":" + addZeroMins + minsleft + ":" + addZeroSecs + secsleft;
        }
    }
}
