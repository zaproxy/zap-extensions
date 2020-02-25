/*
 * ReportWriter.java
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

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Date;
import java.util.Vector;
import org.apache.log4j.Logger;

public class ReportWriter {

    private static final Logger log = Logger.getLogger(ReportWriter.class);

    private final String fileToWriteTo;
    private final Manager manager;

    public ReportWriter(Manager manager, String fileToWriteTo) {
        this.fileToWriteTo = fileToWriteTo;
        this.manager = manager;
    }

    /*
     * writes the report when we are in headless mode.
     */
    public void writeReportHeadless() {
        Vector<HeadlessResult> data = manager.getHeadlessResult();

        Vector<HeadlessResult> dirs = new Vector<HeadlessResult>(100, 10);
        Vector<HeadlessResult> files = new Vector<HeadlessResult>(100, 10);
        Vector<HeadlessResult> errors = new Vector<HeadlessResult>(100, 10);

        Vector dirCodes = new Vector(100, 10);
        Vector fileCodes = new Vector(100, 10);

        for (int a = 0; a < data.size(); a++) {
            if (data.elementAt(a).getType() == HeadlessResult.FILE) {
                files.addElement(data.elementAt(a));
            } else if (data.elementAt(a).getType() == HeadlessResult.DIR) {
                dirs.addElement(data.elementAt(a));
            } else if (data.elementAt(a).getType() == HeadlessResult.ERROR) {
                errors.addElement(data.elementAt(a));
            }
        }

        // get responce codes for dirs
        for (int b = 0; b < dirs.size(); b++) {
            if (!dirCodes.contains(String.valueOf(dirs.elementAt(b).getResponceCode()))) {
                dirCodes.addElement(String.valueOf(dirs.elementAt(b).getResponceCode()));
            }
        }

        // get responce codes for files
        for (int b = 0; b < files.size(); b++) {
            if (!fileCodes.contains(String.valueOf(files.elementAt(b).getResponceCode()))) {
                fileCodes.addElement(String.valueOf(files.elementAt(b).getResponceCode()));
            }
        }

        BufferedWriter out;
        try {
            out = new BufferedWriter(new FileWriter(fileToWriteTo));
            /*
             * write the report header
             */
            writeReportHeader(out);

            /*
             * Write the found dirs
             */
            if (dirs.size() > 0) {
                out.write("Directories found during testing:");
                out.newLine();
                out.newLine();
                for (int a = 0; a < dirCodes.size(); a++) {
                    String foundCode = (String) dirCodes.elementAt(a);
                    int foundCodeInt = Integer.parseInt(foundCode);
                    out.write("Dirs found with a " + foundCode + " response:");
                    out.newLine();
                    out.newLine();
                    for (int b = 0; b < dirs.size(); b++) {

                        if (dirs.elementAt(b).getResponceCode() == foundCodeInt) {
                            out.write(dirs.elementAt(b).getFound());
                            out.newLine();
                        }
                    }
                    out.newLine();
                }
                out.newLine();
                out.write("--------------------------------");
                out.newLine();
            }

            /*
             * Write the files
             */

            if (files.size() > 0) {
                out.write("Files found during testing:");
                out.newLine();
                out.newLine();
                for (int a = 0; a < fileCodes.size(); a++) {
                    String foundCode = (String) fileCodes.elementAt(a);
                    int foundCodeInt = Integer.parseInt(foundCode);
                    out.write("Files found with a " + foundCode + " responce:");
                    out.newLine();
                    out.newLine();
                    for (int b = 0; b < files.size(); b++) {

                        if (files.elementAt(b).getResponceCode() == foundCodeInt) {
                            out.write(files.elementAt(b).getFound());
                            out.newLine();
                        }
                    }
                    out.newLine();
                }
                out.newLine();
            }
            out.write("--------------------------------");
            out.newLine();

            /*
             * write any error that were discovered
             */
            if (errors.size() > 0) {
                out.write("Errors encountered during testing:");
                out.newLine();
                out.newLine();

                for (int a = 0; a < errors.size(); a++) {
                    out.write(errors.elementAt(a).getFound());
                    out.newLine();
                }
                out.newLine();
            }

            out.flush();
            out.close();

        } catch (IOException ex) {
            log.error(ex);
        }
    }

    private void writeReportHeader(BufferedWriter out) throws IOException {

        out.write("DirBuster " + Config.version + " - Report");
        out.newLine();
        out.write("http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project");
        out.newLine();
        Date date = new Date(System.currentTimeMillis());
        out.write("Report produced on " + date);
        out.newLine();
        out.write("--------------------------------");
        out.newLine();
        out.newLine();

        out.write(manager.getProtocol() + "://" + manager.getHost() + ":" + manager.getPort());
        out.newLine();
        out.write("--------------------------------");
        out.newLine();
    }
}
