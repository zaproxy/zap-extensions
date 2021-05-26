This project contains the addon for a connection to the SQLMap API.

To use this addon a running instance of the SQLMap API must be provided.
SQLMap can be downloaded from https://sqlmap.org/

To start the SQLMap API you can use the following command:
![img.png](start%20sqlmap%20api.png)
In this example the API is hosted on localhost:9091

The addon functionality can be accessed via the rightclick message menu from an interceted HTTP request -> send to sqlmap menu option:
![img_3.png](rightclick%20message%20menu%20from%20httprequest.png)

which will lead the user to a GUI prefilled with data from said request:
![img_4.png](addon%20prefilled%20after%20rigthclick.png)

In the GUI the user can then define options for the scan on SQLMap:
SQLMap API IP:Port defines the IP and Port which your SQLMap instance is hosted on.

URL is the URL of the target to be attacked.

Post Data is the data from the intercepted POST request sent by the target.

Cookies hold information about session IDs used for user authentication.

Test Parameters can be supplied to restrict the SQLMap scan to a certain parameter.

HTTP Method option restricts which method should be scanned by SQLMap.

Level and Risk define the depth of the SQLMap Scan. Higher level and risk cause SQLMap to use more specific payloads and injection techniques the higher these options are set.

The next 6 options restrict which SQL injection techniques should be used and tested by SQLMap.
Available are boolean-based, error-based, UNION query-based, stacked queries, time-based and inline queries. More detailed information on those techniques an be found in https://github.com/sqlmapproject/sqlmap/wiki/Techniques

The Addon offers 7 scan options to be set to specify which attacks should be used against the target:

Param Pollution: uses HTTP parameter pollution attack on the target.

List Users: extracts all DBMS users from the target

Current User: retreives the current DBMS user

Current DB: retreives current DBMS database

Hostname: retreives DBMS server hostname

is DBA?: detects if the current user is a database admin

List DBS: enumerated DBMS databases

Threads: values bigger than 1 enable multithreading on SQLMap engine

Retries: specifies number of retries in case of a timeout

DBMS backend: user can supply information of the DBMS

Operating System: user can supply information of the OS

Buttons:
Cancel terminates the current addon instance
Reset resets all data entered into the GUI to defaul values
Start Scan start a scan on the SQLMap API

Running a scan:

To run a scan the user has to correctly specify the IP and port of the SQLMap API instance, and enter a URL to the target to be attacked.
All other data is optional but might still be required in most cases, like cookies for authentication.

After entering all relevant data into the GUI the scan can be started with the "Start Scan" button at the bottom of the GUI.
If executed currectly the API will relay some basic data about what is running like so:
![img_5.png](sqlmapapi%20create-options-start-get.png)

Once the scan is finished the addon create a report and will supply a path to said report in the Output pane:
![img_6.png](path%20to%20report%20output.png)

Currently only Windows Systems are supported for storing reports in path users\username\documents\

At the supplied file location a report file of the type .html can be found which summarises the findings from SQLMap.

![img_7.png](report%20example%20basic.png)

At the top the report again relays some basic information about the attacked target like URL and hostname. In the above example the hostname was not extracted and "null".

At the bottom part a summary of succesful SQL injections and used payloads can be found.

At the end of the document data about the application which was succesfully enumerated is listed. Here you can find data related to specific attacks used by SQLMap.

The addon functionality can also be accessed from the Tools -> sqlmap top menu option:

![img_1.png](sqlmap%20top%20menu.png)

which will lead the user to a GUI with minimal options data:
![img_2.png](addon%20default%20options.png)