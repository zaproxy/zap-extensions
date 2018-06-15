//@zaproxy-standalone

// This script will load example_library.js and a popular JS library from the Internet
// Docs: https://wiki.openjdk.java.net/display/Nashorn/Nashorn+extensions

print('loading scripts from: ' + java.lang.System.getProperty("user.dir"))

var number = 0 // This variable will be overwritten by the loading of example_library.js

// Load example_library.js
load("./example_library.js")

print(number)

print(customFunction('hello'))

// Load Loadash
load('https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.10/lodash.min.js')

print(_.last([1, 2, 3]))
