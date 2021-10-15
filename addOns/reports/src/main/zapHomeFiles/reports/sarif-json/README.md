# SARIF report

## Sarif 2.1.0
https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html

## WebRequest and WebResponse
A run object can contain "webRequests" and also "webResponses" as an array
A result object can contain "webRequest" and also "webResponse" objects

### Run object
#### 3.14.21 webRequests property
https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317505

A run object MAY contain a property named webRequests whose value is an array of zero or more unique (§3.7.3) webRequest objects (§3.46) representing HTTP requests that appear in result objects (§3.27) within theRun.

NOTE: This property is primarily useful to web analysis tools.


#### 3.14.22 webResponses property
A run object MAY contain a property named webResponses whose value is an array of zero or more unique (§3.7.3) webResponse objects (§3.47) representing HTTP responses that appear in result objects (§3.27) within theRun.

NOTE: This property is primarily useful to web analysis tools.


## Result object

#### 3.27.14 webRequest property

A result object MAY contain a property named webRequest whose value is a webRequest object (§3.46) that describes the HTTP request which led to this result.

NOTE: This property is primarily useful to web analysis tools.


#### 3.27.15 webResponse property

A result object MAY contain a property named webResponse whose value is a webResponse object (§3.47) that describes the response to the HTTP request which led to this result.

NOTE: This property is primarily useful to web analysis tools.


### WebRequest Object
https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317808
3.46.1 General
 
A webRequest object describes an HTTP request [RFC7230]. The response to the request is described by a webResponse object (§3.47).

NOTE 1: This object is primarily useful to web analysis tools.

A webRequest object does not need to represent a valid HTTP request.

NOTE 2: This allows an analysis tool that intentionally sends invalid HTTP requests to use the webRequest object

Here some important properties: (see former link for all)
- index
- protocol
- version
- **headers**
- **body**

### WebResponse Object
https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317818
3.47.1 General

A webResponse object describes the response to an HTTP request [RFC7230]. The request itself is described by a webRequest object (§3.46).

NOTE: This object is primarily useful to web analysis tools.

A webResponse object does not need to represent a valid HTTP response.

NOTE 2: This allows an analysis tool to describe a situation where a server produces an invalid response.

Here some important properties: (see former link for all)
- index
- protocol
- version
- **statusCode**
- **reasonPhrase**
- **headers**
- **body**

## Links
- Sarif V2.1.0 - official document https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html


