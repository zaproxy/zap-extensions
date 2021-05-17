/*
 * Manager.java
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

import com.sittinglittleduck.DirBuster.workGenerators.BruteForceURLFuzz;
import com.sittinglittleduck.DirBuster.workGenerators.BruteForceWorkGenerator;
import com.sittinglittleduck.DirBuster.workGenerators.WorkerGenerator;
import com.sittinglittleduck.DirBuster.workGenerators.WorkerGeneratorURLFuzz;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;
import java.util.Locale;
import java.util.Timer;
import java.util.Vector;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.prefs.Preferences;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Manager implements ProcessChecker.ProcessUpdate {

    int workerCount = 150;
    // the two work queues
    public BlockingQueue<WorkUnit> workQueue;
    public BlockingQueue<DirToCheck> dirQueue;
    public BlockingQueue<HTMLparseWorkUnit> parseQueue;
    private Thread workGenThread;
    private WorkerGenerator workGen;
    private BruteForceWorkGenerator workGenBrute;
    private WorkerGeneratorURLFuzz workGenFuzz;
    private BruteForceURLFuzz workGenBruteFuzz;
    private String inputFile;
    private String firstPartOfURL;
    private String extention;
    private Timer timer;
    private ProcessChecker task;
    private ProcessEnd task2;
    private String protocol;
    private String host;
    private int port;
    private String startPoint;
    private boolean doDirs, doFiles;
    private int totalDone = 0;
    private Vector<Worker> workers = new Vector<>(100, 10);
    private Vector<HTMLparse> parseWorkers = new Vector<>(100, 10);
    private String[] charSet;
    private int maxLen, minLen;
    boolean pureBrute = false;
    boolean urlFuzz = false;
    boolean pureBrutefuzz = false;
    boolean recursive = true;
    // flag for if we are auto switching between HEADS and GETS
    private boolean auto = true;
    // used for storing total numbers of trys per pass
    private double totalPass;
    // used to record the total number of dirs that have been found
    // set to 1 as we there must always at least 1
    private int totalDirsFound = 1;
    // setting for using a blank extention
    private boolean blankExt = false;
    // store of all extention that are to be tested
    private Vector<ExtToCheck> extToUse = new Vector<>(10, 5);
    private Vector<BaseCase> producedBasesCases = new Vector<>(10, 10);
    // used to store all the links that have parsed, will not contain a list a all items, processed
    // as this will consume to much memory.  There for there is a chance of some duplication.
    private Vector<String> processedLinks = new Vector<>(100, 100);
    // not all base case requests are processed so this will ensure the stats stay correct
    private int baseCaseCounterCorrection = 0;
    // used to store the value of items that will have been skipped
    private int workAmountCorrection = 0;
    // total number of links pasrsed from the HTML that have been added to the work queue
    private int parsedLinksProcessed = 0;
    // total number of basecases produced
    private int numberOfBaseCasesProduced = 0;
    // exts that are not to be added to the work queue if found by the HTML parser
    public Vector<String> extsToMiss = new Vector<>(10, 10);
    // Vector to store all the html elements that are to be parsed.
    public Vector<HTMLelementToParse> elementsToParse = new Vector<>(10, 10);
    // Used to store a string of what we are currently processing
    private String currentlyProcessing = "";
    // Variables to store information used for the URL fuzzing
    private String urlFuzzStart;
    private String urlFuzzEnd;
    // var to note when the fuzz generator has finished
    private boolean urlFuzzGenFinished = false;
    /*
     * time at which the fuzzing started
     */
    private long timestarted;
    /*
     * store of information about request limiting
     */
    private boolean limitRequests = false;
    private int limitRequestsTo = 50;
    /*
     * user pref object
     */
    Preferences userPrefs;
    /*
     * Date when the last check was performed
     */
    Date lastUpdateCheck;

    /*
     * stores the default number of threads to be used
     */
    private int defaultNoThreads;

    /*
     * stores the default list to use
     */
    private String defaultList;

    /*
     * stores the default exts to use
     */
    private String defaultExts;

    /*
     * this stores all the regexes that have been used when we get inconsistent base cases
     */
    private Vector<String> failCaseRegexes = new Vector<>(10, 10);
    /*
     * Vector to store results when we are running in headless mode
     */
    Vector<HeadlessResult> headlessResult = new Vector<>(100, 100);

    /*
     * stores of information used to transer data to the gui when started with console args
     *
     */
    private URL targetURL = null;
    private String fileLocation = null;
    private String reportLocation = null;
    private String fileExtentions = null;
    private String pointToStartFrom = null;

    // ZAP: Option to control whether only the dirs found under the startPoint should be
    // parsed/fetched.
    private boolean onlyUnderStartPoint = true;

    /* Logger object for the class */
    private static final Logger LOG = LogManager.getLogger(Manager.class);

    private final SimpleHttpClient httpClient;

    // ZAP: Changed to public to allow it to be extended
    public Manager(SimpleHttpClient httpClient) {
        elementsToParse.addElement(new HTMLelementToParse("a", "href"));
        elementsToParse.addElement(new HTMLelementToParse("img", "src"));
        elementsToParse.addElement(new HTMLelementToParse("form", "action"));
        elementsToParse.addElement(new HTMLelementToParse("script", "src"));
        elementsToParse.addElement(new HTMLelementToParse("iframe", "src"));
        elementsToParse.addElement(new HTMLelementToParse("div", "src"));
        elementsToParse.addElement(new HTMLelementToParse("frame", "src"));
        elementsToParse.addElement(new HTMLelementToParse("embed", "src"));

        /*
         * load the manager prefs
         */
        loadPrefs();

        this.httpClient = httpClient;
    }

    // set up dictionay based attack with normal start
    public void setupManager(
            String startPoint,
            String inputFile,
            String protocol,
            String host,
            int port,
            String extention,
            int ThreadNumber,
            boolean doDirs,
            boolean doFiles,
            boolean recursive,
            boolean blankExt,
            Vector<ExtToCheck> extToUse) {
        totalDone = 0;
        this.startPoint = startPoint;
        this.inputFile = inputFile;
        this.firstPartOfURL = protocol + "://" + host + ":" + port;
        this.extention = extention;
        this.protocol = protocol;
        this.host = host;
        this.port = port;
        workerCount = ThreadNumber;
        this.doFiles = doFiles;
        this.doDirs = doDirs;
        this.recursive = recursive;
        this.blankExt = blankExt;
        this.extToUse = extToUse;
        URL url;

        // add the start point to the running list
        // TODO change this so it sctually checks for it
        try {
            url = new URL(firstPartOfURL + startPoint);
            // gui.addResult(new ResultsTableObject("Dir", url.getPath(), "---", "Scanning",
            // url.toString(), "Start point of testing", null, null, this.recursive, null));
        } catch (MalformedURLException ex) {
            LOG.error("Bad URL", ex);
        }

        LOG.info("Starting dir/file list based brute forcing");

        createTheThreads();
        workGen = new WorkerGenerator(this);
    }

    public Vector<HeadlessResult> getHeadlessResult() {
        return headlessResult;
    }

    // setup for purebrute force with normal start
    public void setupManager(
            String startPoint,
            String[] charSet,
            int minLen,
            int maxLen,
            String protocol,
            String host,
            int port,
            String extention,
            int ThreadNumber,
            boolean doDirs,
            boolean doFiles,
            boolean recursive,
            boolean blankExt) {
        totalDone = 0;
        this.startPoint = startPoint;
        this.firstPartOfURL = protocol + "://" + host + ":" + port;
        this.extention = extention;
        this.protocol = protocol;
        this.host = host;
        this.port = port;
        workerCount = ThreadNumber;
        this.doFiles = doFiles;
        this.doDirs = doDirs;
        this.charSet = charSet;
        this.maxLen = maxLen;
        this.minLen = minLen;
        pureBrute = true;
        this.recursive = recursive;
        this.blankExt = blankExt;
        URL url;

        // add the start point to the running list
        try {
            url = new URL(firstPartOfURL + startPoint);
            // gui.addResult(new ResultsTableObject("Dir", url.getPath(), "---", "Scanning",
            // url.toString(), "Start point of testing", null, null, this.recursive, null));
        } catch (MalformedURLException ex) {
            LOG.error("Bad URL", ex);
        }

        LOG.info("Starting dir/file pure brute forcing");

        createTheThreads();
        workGenBrute = new BruteForceWorkGenerator(this);
    }

    /*
     * Used to setup the manager when we are URL fuzzing
     */
    public void setUpManager(
            String inputFile,
            String protocol,
            String host,
            int port,
            int ThreadNumber,
            String urlFuzzStart,
            String urlFuzzEnd) {
        totalDone = 0;
        this.inputFile = inputFile;
        this.firstPartOfURL = protocol + "://" + host + ":" + port;
        this.protocol = protocol;
        this.host = host;
        this.port = port;
        workerCount = ThreadNumber;
        this.urlFuzzStart = urlFuzzStart;
        this.urlFuzzEnd = urlFuzzEnd;

        urlFuzz = true;

        LOG.info("Starting URL fuzz");

        createTheThreads();
        workGenFuzz = new WorkerGeneratorURLFuzz(this);
    }

    /*
     * set up manager for bruteforce fuzzing
     */
    public void setUpManager(
            String[] charSet,
            int minLen,
            int maxLen,
            String protocol,
            String host,
            int port,
            int ThreadNumber,
            String urlFuzzStart,
            String urlFuzzEnd) {
        /*
         * arguments for the fuzzing
         */
        this.charSet = charSet;
        this.maxLen = maxLen;
        this.minLen = minLen;

        /*
         * test details
         */
        totalDone = 0;
        this.firstPartOfURL = protocol + "://" + host + ":" + port;
        this.protocol = protocol;
        this.host = host;
        this.port = port;
        workerCount = ThreadNumber;

        /*
         * fuzzing points
         */

        this.urlFuzzStart = urlFuzzStart;
        this.urlFuzzEnd = urlFuzzEnd;

        pureBrutefuzz = true;

        LOG.info("Starting URL fuzz");

        createTheThreads();
        workGenBruteFuzz = new BruteForceURLFuzz(this);
    }

    private void createTheThreads() {
        // workers = new Worker[workerCount];

        workers.removeAllElements();
        parseWorkers.removeAllElements();

        for (int i = 0; i < workerCount; i++) {
            workers.addElement(new Worker(i, this));
            // workers[i] = new Worker(this, i);
            // tpes.execute(workers[i]);
        }

        // create the htmlparse threads
        for (int i = 0; i < workerCount; i++) {
            parseWorkers.addElement(new HTMLparse(this));
        }
        // work queue
        workQueue = new ArrayBlockingQueue<>(workerCount * 3);

        // dir to be processed
        dirQueue = new ArrayBlockingQueue<>(100000);

        // queue to hold a list of items to parsed
        parseQueue = new ArrayBlockingQueue<>(200000);

        timer = new Timer();

        // add the fist string on to the queue
        try {
            Vector<ExtToCheck> tempext = extToUse;
            // extToUse.clone().
            dirQueue.put(new DirToCheck(startPoint, tempext));
        } catch (InterruptedException e) {
            LOG.debug(e);
        }
    }

    public void start() {
        try {
            timestarted = System.currentTimeMillis();

            totalDirsFound = 0;
            producedBasesCases.clear();
            numberOfBaseCasesProduced = 0;
            parsedLinksProcessed = 0;
            processedLinks.clear();

            task = new ProcessChecker(this);
            timer.scheduleAtFixedRate(task, 0L, 1000L);

            task2 = new ProcessEnd(this);
            timer.scheduleAtFixedRate(task2, 0L, 10000L);

            // start the pure brute force thread
            if (pureBrute) {
                // start the work generator
                workGenThread = new Thread(workGenBrute);
            }
            // start the
            else if (urlFuzz) {
                workGenThread = new Thread(workGenFuzz);

            } else if (pureBrutefuzz) {
                workGenThread = new Thread(workGenBruteFuzz);
            } else {
                // start the work generator
                workGenThread = new Thread(workGen);
            }

            workGenThread.setName("DirBuster-WorkerGenerator");
            workGenThread.start();

            // add the worker and parseWorker threads
            for (int i = 0; i < workers.size(); i++) {
                Thread workerThread = new Thread((workers.elementAt(i)));
                workerThread.setName("DirBuster-Worker");
                workerThread.start();
                parseWorkers.elementAt(i).start();
            }

        } catch (Exception e) {
            LOG.error(e);
        }
    }

    public boolean hasWorkLeft() {
        // TODO  finish
        return true;
    }

    public BlockingQueue<WorkUnit> getWorkQueue() {
        return workQueue;
    }

    public BlockingQueue<DirToCheck> getDirQueue() {
        return dirQueue;
    }

    public synchronized void foundDir(URL url, int statusCode, BaseCase baseCaseObj) {
        foundDir(url, statusCode, null, null, null, baseCaseObj);
    }

    public synchronized void foundDir(
            URL url, int statusCode, String Responce, BaseCase baseCaseObj) {
        foundDir(url, statusCode, Responce, null, Responce, baseCaseObj);
    }

    public synchronized void foundDir(
            URL url,
            int statusCode,
            String Responce,
            String BaseCase,
            String RawResponce,
            BaseCase baseCaseObj) {
        try {

            boolean isStartPoint;

            if (Config.caseInsensativeMode) {
                isStartPoint = url.getPath().equalsIgnoreCase(startPoint);

                /*
                 * loop through all the items in the queue
                 */

                /*
                 * convert to array
                 */
                boolean foundDir = false;
                DirToCheck[] dirArray = (DirToCheck[]) dirQueue.toArray();

                for (int a = 0; a < dirArray.length; a++) {
                    /*
                     * perform case in seneative check
                     */
                    if (url.getPath().equalsIgnoreCase(dirArray[a].getName())) {
                        foundDir = true;
                        break;
                    }
                }

                /*
                 * if the dir is not already there.
                 */
                if (!foundDir) {

                    // hack to prevent getting an instance of the main extToUse and its contents!

                    Vector<ExtToCheck> tempExtToUse = new Vector<>(10, 10);
                    // tempExtToUse = extToUse.clone();

                    for (int a = 0; a < extToUse.size(); a++) {
                        ExtToCheck oldExtToCheck = extToUse.elementAt(a);
                        ExtToCheck tempExtToCheck =
                                new ExtToCheck(oldExtToCheck.getName(), oldExtToCheck.toCheck());
                        tempExtToUse.addElement(tempExtToCheck);
                    }

                    boolean addToDirQueue = true;

                    if (onlyUnderStartPoint) {
                        addToDirQueue =
                                url.getPath()
                                        .toLowerCase(Locale.ENGLISH)
                                        .startsWith(startPoint.toLowerCase(Locale.ENGLISH));
                    }

                    if (addToDirQueue) {
                        dirQueue.put(new DirToCheck(url.getPath(), tempExtToUse));
                    }
                    totalDirsFound++;
                }

            }
            /*
             * normal case sensative search
             */
            else {
                isStartPoint = url.getPath().equals(startPoint);
                // check it is not already in the queue
                if (!dirQueue.contains(new DirToCheck(url.getPath(), extToUse))
                        && !isStartPoint
                        && isRecursive()) {
                    // Vector tempext = (Vector) extToUse.clone();

                    // hack to prevent getting an instance of the main extToUse and its contents!

                    Vector<ExtToCheck> tempExtToUse = new Vector<>(10, 10);
                    // tempExtToUse = extToUse.clone();

                    for (int a = 0; a < extToUse.size(); a++) {
                        ExtToCheck oldExtToCheck = extToUse.elementAt(a);
                        ExtToCheck tempExtToCheck =
                                new ExtToCheck(oldExtToCheck.getName(), oldExtToCheck.toCheck());
                        tempExtToUse.addElement(tempExtToCheck);
                    }

                    boolean addToDirQueue = true;

                    if (onlyUnderStartPoint) {
                        addToDirQueue = url.getPath().startsWith(startPoint);
                    }

                    if (addToDirQueue) {
                        dirQueue.put(new DirToCheck(url.getPath(), tempExtToUse));
                    }
                    totalDirsFound++;
                }
            }

            LOG.debug("Dir found: {} - {}", url.getFile(), statusCode);

            // add to list of items that have already processed
            addParsedLink(url.getPath());

            headlessResult.addElement(
                    new HeadlessResult(url.getFile(), statusCode, HeadlessResult.DIR));
        } catch (InterruptedException e) {
            LOG.debug(e);
            return;
        }
    }

    public synchronized void foundFile(URL url, int statusCode, BaseCase baseCaseObj) {
        foundFile(url, statusCode, null, null, null, baseCaseObj);
    }

    public synchronized void foundFile(
            URL url, int statusCode, String Responce, BaseCase baseCaseObj) {
        foundFile(url, statusCode, Responce, null, Responce, baseCaseObj);
    }

    public synchronized void foundFile(
            URL url,
            int statusCode,
            String Responce,
            String BaseCase,
            String rawResponce,
            BaseCase baseCaseObj) {

        LOG.debug("File found: {} - {}", url.getFile(), statusCode);

        addParsedLink(url.getPath());

        headlessResult.addElement(
                new HeadlessResult(url.getFile(), statusCode, HeadlessResult.FILE));
    }

    public synchronized void foundError(URL url, String reason) {
        headlessResult.addElement(
                new HeadlessResult(url.getFile() + ":" + reason, -1, HeadlessResult.ERROR));
        LOG.warn("{} - {}", url, reason);
    }

    public String getInputFile() {
        return inputFile;
    }

    public String getFirstPartOfURL() {
        return firstPartOfURL;
    }

    public String getFileExtention() {
        return extention;
    }

    @Override
    public void isAlive() {}

    public synchronized void workDone() {
        totalDone++;
    }

    public synchronized int getTotalDone() {
        return totalDone;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public boolean getDoDirs() {
        return doDirs;
    }

    public boolean getDoFiles() {
        return doFiles;
    }

    public void pause() {
        for (int a = 0; a < workers.size(); a++) {
            synchronized (workers.elementAt(a)) {
                workers.elementAt(a).pause();
            }
        }
    }

    public void unPause() {
        for (int a = 0; a < workers.size(); a++) {
            synchronized (workers.elementAt(a)) {
                workers.elementAt(a).unPause();
                workers.elementAt(a).notify();
            }
        }
    }

    public int getMinLen() {
        return minLen;
    }

    public int getMaxLen() {
        return maxLen;
    }

    public String[] getCharSet() {
        return charSet;
    }

    public boolean isRecursive() {
        return recursive;
    }

    // TODO: check how  youAreFinished() is called and when it is called
    public synchronized void youAreFinished() {

        // clear all the queue
        workQueue.clear();
        dirQueue.clear();
        parseQueue.clear();

        // reset counters
        totalDirsFound = 0;
        producedBasesCases.clear();
        numberOfBaseCasesProduced = 0;
        parsedLinksProcessed = 0;
        processedLinks.clear();
        workAmountCorrection = 0;

        // kill all the running threads
        task.cancel();
        task2.cancel();

        if (pureBrute) {
            // TODO
        } else if (urlFuzz) {
            workGenFuzz.stopMe();
        } else if (pureBrutefuzz) {
            // TODO
        } else {
            workGen.stopMe();
        }

        // stop all the workers;
        for (int a = 0; a < workers.size(); a++) {
            synchronized (workers.elementAt(a)) {
                workers.elementAt(a).stopThread();
            }
        }

        // stops all the parsers
        for (int a = 0; a < this.parseWorkers.size(); a++) {
            synchronized (parseWorkers.elementAt(a)) {
                parseWorkers.elementAt(a).stopWorking();
                parseWorkers.elementAt(a).notify();
            }
        }

        LOG.info("DirBuster Stopped");

        /*
         * reset the all the markers for what type of test we are doing
         */
        urlFuzz = false;
        pureBrute = false;
        pureBrutefuzz = false;
    }

    public synchronized double getTotalPass() {
        return totalPass;
    }

    public synchronized void setTotalPass(double totalPass) {
        this.totalPass = totalPass;
    }

    public synchronized int getTotalDirsFound() {
        return totalDirsFound;
    }

    public int getWorkerCount() {
        return workerCount;
    }

    public Vector<Worker> getWorkers() {
        return workers;
    }

    public boolean getAuto() {
        return auto;
    }

    public void setAuto(boolean b) {
        auto = b;
    }

    /*
     * used to add extra workers to the queue
     */
    public void addWrokers(int number) {
        int currentNumber = workers.size();
        for (int i = 0; i < number; i++) {
            int threadid = currentNumber + i;
            workers.addElement(new Worker(threadid, this));

            new Thread(workers.elementAt(threadid)).start();
        }
        workerCount = currentNumber + number;
    }

    /*
     * used to remove extra workers from the queue
     */
    public void removeWorkers(int number) {
        int currentNumber = workers.size();

        if (number >= currentNumber) {
            return;
        }

        for (int a = currentNumber - 1; a >= (currentNumber - number); a--) {
            workers.elementAt(a).stopThread();
            workers.remove(a);
        }
        workerCount = currentNumber - number;
    }

    // used to remove stuff from the work queue, as a result of the request from a user;
    public synchronized void removeFromDirQueue(String dir) {

        /*
         *Convert item queue to an array
         */
        Object[] tempArray = dirQueue.toArray();
        DirToCheck dirToCheck = null;

        for (int b = 0; b < tempArray.length; b++) {
            dirToCheck = (DirToCheck) tempArray[b];
            String processWork = dirToCheck.getName();

            /*
             * find the object of all the ones we wish to remove
             */
            if (processWork.equals(dir)) {
                /*
                 * remove the item
                 */
                if (dirQueue.remove(dirToCheck)) {

                    totalDirsFound--;
                } else {
                    LOG.warn("Failed to remove {} from dir queue", processWork);
                }
            }
        }
    }

    // used to re add stuff to the work as the reswult from a request from the work queue
    public synchronized void addToDirQueue(String dir) {
        // System.out.println("SBSB addToDirQueue " + dir);
        try {

            dirQueue.put(new DirToCheck(dir, extToUse));
            totalDirsFound++;
        } catch (InterruptedException ex) {
            LOG.debug(ex);
            return;
        }
    }

    public synchronized void addHTMLToParseQueue(HTMLparseWorkUnit parseWorkUnit) {
        if (onlyUnderStartPoint
                && !parseWorkUnit.getWorkUnit().getWork().getPath().startsWith(startPoint)) {
            return;
        }

        // System.out.println("SBSB addHTMLToParseQueue " + parseWorkUnit.toString());
        try {
            parseQueue.put(parseWorkUnit);
        } catch (InterruptedException ex) {
            LOG.debug(ex);
        }
    }

    public boolean isBlankExt() {
        return blankExt;
    }

    public void addExt(ExtToCheck ext) {
        extToUse.addElement(ext);
    }

    public Vector<ExtToCheck> getExtToUse() {
        return extToUse;
    }

    public synchronized BaseCase getBaseCase(String base, boolean isDir, String fileExt) {

        try {
            for (int a = 0; a < producedBasesCases.size(); a++) {
                BaseCase tempBaseCase = producedBasesCases.elementAt(a);

                if (tempBaseCase.getBaseCaseURL().equals(new URL(base))
                        && tempBaseCase.isDir() == isDir) {
                    if (!isDir) {
                        if (tempBaseCase.getFileExt().equals(fileExt)) {
                            return tempBaseCase;
                        }
                    } else {
                        return tempBaseCase;
                    }
                }
            }
        } catch (MalformedURLException ex) {
            // do nothing I dont care
        }

        return null;
    }

    public synchronized void addBaseCase(BaseCase baseCase) {
        if (!producedBasesCases.contains(baseCase)) {
            producedBasesCases.addElement(baseCase);
        }
    }

    public synchronized boolean hasLinkBeenDone(String link) {

        if (processedLinks.contains(link)) {
            return true;
        }

        return false;
    }

    public int getBaseCaseCounterCorrection() {
        return baseCaseCounterCorrection;
    }

    public synchronized int getParsedLinksProcessed() {
        return parsedLinksProcessed;
    }

    public synchronized boolean addParsedLink(String link) {
        // System.out.println("SBSB addParsedLink " + link);
        /*
         * case insenataive mode
         */
        if (Config.caseInsensativeMode) {

            for (int a = 0; a < processedLinks.size(); a++) {
                if (link.equalsIgnoreCase(processedLinks.elementAt(a))) {
                    return false;
                }
            }
            processedLinks.addElement(link);

            if (onlyUnderStartPoint
                    && !link.toLowerCase(Locale.ENGLISH)
                            .startsWith(startPoint.toLowerCase(Locale.ENGLISH))) {
                addParsedLinksProcessed();
                return false;
            }
        } else
        /*
         * case sensative mode
         */
        {
            if (!processedLinks.contains(link)) {
                processedLinks.addElement(link);
            }

            if (onlyUnderStartPoint && !link.startsWith(startPoint)) {
                addParsedLinksProcessed();
                return false;
            }
        }

        return true;
    }

    public synchronized void addParsedLinksProcessed() {
        parsedLinksProcessed++;
    }

    public synchronized int getNumberOfBaseCasesProduced() {
        return numberOfBaseCasesProduced;
    }

    // increments the correction counter
    public synchronized void addBaseCaseCounterCorrection() {
        baseCaseCounterCorrection++;
    }

    public Vector<HTMLelementToParse> getElementsToParse() {
        return elementsToParse;
    }

    public synchronized void addNumberOfBaseCasesProduced() {
        numberOfBaseCasesProduced++;
    }

    public Vector<HTMLparse> getParseWorkers() {
        return parseWorkers;
    }

    public void skipCurrentWork() {
        /*
         * while this is a case snsative comparie, it should not require to be done both ways
         */
        // stop work gen from adding more the the queue
        workGen.skipCurrent();

        // remove all items in the current work queue that are no loger required.
        Object[] tempArray = workQueue.toArray();
        WorkUnit work = null;
        int totalRemoved = 0;
        for (int b = 0; b < tempArray.length; b++) {
            work = (WorkUnit) tempArray[b];
            String processWork = work.getWork().getPath();
            if (processWork.startsWith(currentlyProcessing)) {
                workQueue.remove(work);
                totalRemoved++;
            }
        }
        addToWorkCorrection(totalRemoved);
    }

    public void setCurrentlyProcessing(String currentlyProcessing) {
        this.currentlyProcessing = currentlyProcessing;
    }

    public synchronized void addToWorkCorrection(int amount) {
        workAmountCorrection = workAmountCorrection + amount;
    }

    public synchronized int getWorkAmountCorrection() {
        return workAmountCorrection;
    }

    public String getUrlFuzzEnd() {
        return urlFuzzEnd;
    }

    public String getUrlFuzzStart() {
        return urlFuzzStart;
    }

    public boolean isURLFuzzGenFinished() {
        return urlFuzzGenFinished;
    }

    public void setURLFuzzGenFinished(boolean urlFuzzGenFinished) {
        this.urlFuzzGenFinished = urlFuzzGenFinished;
    }

    public long getTimestarted() {
        return timestarted;
    }

    public boolean isLimitRequests() {
        return limitRequests;
    }

    public void setLimitRequests(boolean limitRequests) {
        this.limitRequests = limitRequests;
    }

    public int getLimitRequestsTo() {
        return limitRequestsTo;
    }

    public void setLimitRequestsTo(int limitRequestsTo) {
        this.limitRequestsTo = limitRequestsTo;
    }

    public boolean areWorkersAlive() {
        for (int a = 0; a < workers.size(); a++) {
            if (workers.elementAt(a).isWorking()) {
                // there is a worker still working so break
                return true;
            }
        }
        return false;
    }

    /*
     * this loads the user prefs for set for DirBuster
     */
    public void loadPrefs() {
        userPrefs = Preferences.userNodeForPackage(Manager.class);
        lastUpdateCheck = new Date(userPrefs.getLong("LastUpdateCheck", 0L));
        defaultNoThreads = userPrefs.getInt("DefaultNoTreads", 10);
        defaultList = userPrefs.get("DefaultList", "");
        defaultExts = userPrefs.get("DefaultExts", "php");
    }

    /*
     * returns a vector of all the regexes we have already used
     */
    public Vector<String> getFailCaseRegexes() {
        return failCaseRegexes;
    }

    /*
     * adds a new regex fail case
     */
    public void addFailCaseRegex(String regex) {
        failCaseRegexes.addElement(regex);
    }

    public URL getTargetURL() {
        return targetURL;
    }

    public void setTargetURL(URL targetURL) {
        this.targetURL = targetURL;
    }

    public String getFileLocation() {
        return fileLocation;
    }

    public void setFileLocation(String fileLocation) {
        this.fileLocation = fileLocation;
    }

    public String getReportLocation() {
        return reportLocation;
    }

    public void setReportLocation(String reportLocation) {
        this.reportLocation = reportLocation;
    }

    public String getFileExtentions() {
        return fileExtentions;
    }

    public void setFileExtentions(String fileExtentions) {
        this.fileExtentions = fileExtentions;
    }

    public String getPointToStartFrom() {
        return pointToStartFrom;
    }

    public void setPointToStartFrom(String pointToStartFrom) {
        this.pointToStartFrom = pointToStartFrom;
    }

    public String getDefaultExts() {
        return defaultExts;
    }

    public void setDefaultExts(String defaultExts) {
        this.defaultExts = defaultExts;
        userPrefs.put("DefaultExts", defaultExts);
    }

    public String getDefaultList() {
        return defaultList;
    }

    public void setDefaultList(String defaultList) {
        this.defaultList = defaultList;
        userPrefs.put("DefaultList", defaultList);
    }

    public int getDefaultNoThreads() {
        return defaultNoThreads;
    }

    public void setDefaultNoThreads(int defaultNoThreads) {
        this.defaultNoThreads = defaultNoThreads;
        userPrefs.putInt("DefaultNoTreads", defaultNoThreads);
    }

    public void setOnlyUnderStartPoint(boolean onlyUnderStartPoint) {
        this.onlyUnderStartPoint = onlyUnderStartPoint;
    }

    public SimpleHttpClient getHttpClient() {
        return httpClient;
    }
}
