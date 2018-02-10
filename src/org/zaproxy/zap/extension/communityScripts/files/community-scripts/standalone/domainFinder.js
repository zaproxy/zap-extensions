//REQUIRES: Java 8+
//
//Inspired partially by fierce domain scanner
//Partially addresses https://github.com/zaproxy/zaproxy/issues/562
//Author: kingthorin+owaspzap@gmail.com
//20160207: Initial release.

var DOMAIN=".example.org"; //Update this with the domain you want to do lookups on 

var System = Java.type("java.lang.System");
var Thread = Java.type("java.lang.Thread");
var TimeUnit = Java.type("java.util.concurrent.TimeUnit");
var ForkJoinPool = Java.type("java.util.concurrent.ForkJoinPool");
var ForkJoinTask = Java.type("java.util.concurrent.ForkJoinTask");
var RecursiveAction = Java.extend(Java.type("java.util.concurrent.RecursiveAction"));

//Prefixes based on http://ftp.isc.org/www/survey/reports/2015/01/first.txt
var prefixes = ["mail","www","ns2","ns1","server","smtp","mail2","gw","remote","ftp",
"host","ns","mail1","webmail","mx","mx1","ip1","cpe","vpn","router","mx2","gateway",
"web","exchange","lo0","server1","vps","mail3","secure","test","ns3","ip2","www2","email",
"mailhost","dev","dns1","host2","dns2","fw","static","broadcast","host1","eth0","o1","dns",
"db","net","portal","office","smtp2","e0","owa","proxy","network","admin","lwdc","mta",
"mail4","host3","adsl","pc1","bcast","web1","se400","mailgate","smtp1","gate","pc2","a",
"pc3","host4","ns4","pc4","pc5","server2","support","mx3","host5","relay","www1","pc6","e1",
"nmd","a1","stats","bc","backup","host6","b","sdtc","a0","ip3","mail01","a3","news","c1",
"a7","b1","firewall"];

var NUMBER_ELEMENTS = prefixes.length;
// Slice for each RecursiveAction
var ARRAY_SLICE = NUMBER_ELEMENTS / 2;
var pool = new ForkJoinPool();

var foundFwd = [];
var foundRev = [];
var found_ips = [];
// Do forward lookups (brute force names to IPs)
var fb = createRecursiveAction(prefixes, 0, prefixes.length, 'fwd');
start = startTime();
print('Running FWD lookups...');
pool.invoke(fb);
print('');
printElapsed(start);
print('Found: ' + foundFwd.length + ' via forward lookup.');
print('');
// Do reverse lookups (using the IPs from the FWDs check if there are other names)
fb = createRecursiveAction(found_ips, 0, found_ips.length, 'rev');
start2 = startTime();
print('Running REV lookups...');
pool.invoke(fb);
print('');
printElapsed(start2);
print('Found: ' + foundRev.length + ' via reverse lookup.');
// Final results
print('');
print('Found: '+(foundFwd.length+foundRev.length)+' domain names. Full list: \n');
print(foundFwd.toString().replaceAll(',','\n'));
print(foundRev.toString().replaceAll(',', '\n'));
print('\nThe list above may include CDNs, shared hosts, or 3rd party hosting. Please be careful how you proceed.');

function nslookup(lookupItem, type) {
  var host='';
  switch (type) {
    case 'rev':
      try {
        host = java.net.InetAddress.getByName(lookupItem).getCanonicalHostName();
        if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(host)) {
          printHost(host);
          foundRev.push(host);
        }
      } catch (e) { return }
      break; 
    case 'fwd':
      try { 
        host = java.net.InetAddress.getByName(lookupItem + DOMAIN);
        foundFwd.push(host.getHostName());
        printHost(host);
        new_ip=host.getHostAddress();
        found_ips.push(new_ip);
      } catch (e) { return }
  }
  return host;
}

function startTime() {
  return System.nanoTime();
}

function printElapsed(start) {
  var end = System.nanoTime();
  print("Took: " + TimeUnit.NANOSECONDS.toMillis(end - start) + " ms\t" + TimeUnit.NANOSECONDS.toSeconds(end-start) + " sec");
}

function printHost(host) {
  print(host.toString().replace('/',' / '));
}

function createRecursiveAction(data, start, length, type) {
  var task = new RecursiveAction() {
    computeDirectly: function () {
      var end = start + length;
      for (var i = start; i < end; i++) { 
        nslookup(data[i], type);
      }
    },

    compute: function () {
      if (length < ARRAY_SLICE) {
        this.computeDirectly();
        return;
      }

      var split = Math.floor(length / 2);
      var right = createRecursiveAction(data, start, split, type);
      var left = createRecursiveAction(data, start + split, length - split, type);
      ForkJoinTask.invokeAll(right, left);
    }
  }
  return task;
}
