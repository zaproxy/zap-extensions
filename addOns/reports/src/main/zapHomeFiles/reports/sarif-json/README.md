# SARIF report
## General
This is a reference/documentation how the DAST content is available inside SARIF (which originally was only for static application testing)

## Sarif 2.1.0
https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html

### Example report with description about presenting ZAP data structure via SARIF format
The next example JSON is not 100% valid (it contains comments ...) - but is an explanation how the ZAP report data
has been mapped to SARIF 2.1.0:

```json
{
    "runs": [
        {
            "results": [
                {
                    "level": "error",
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": "https://localhost:8081/greeting?name=%3C%2Fp%3E%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E%3Cp%3E"
                                },
                                //  we use the region tag here. Will be identified by attack + body
                                "region": {
                                    "startLine": 10, // the line references to the webRequest.body line
                                    "snippet": {
                                        "text": "<p>XSS attackable parameter output: </p><script>alert(1);</script><p>!</p>"
                                    }
                                }
                            },
                            "properties": {
                                // the attack and evidence do not have to be the same
                                "attack": "</p><script>alert(1);</script><p>",
                                "evidence": "</p><script>alert(1);</script><p>"
                            }
                        }
                    ],
                    "message": {
                       // when alert.otherInfo is not empty or null text will contain this,
                       // otherwise the alert.description will be used as fallback
                       "text" : "A text from zap alert - either otherInfo or description"
                    },
                    // the pluginId of an alert is used as ruleId
                    // see: https://www.zaproxy.org/docs/alerts/
                    // example: https://www.zaproxy.org/docs/alerts/40012/
                    "ruleId": "40012",
                    "webRequest": {
                        "protocol": "HTTP",
                        "version": "1.1",
                        // in absolute form see: 5.3 in https://www.rfc-editor.org/rfc/rfc7230.txt
                        "target": "https://localhost:8081/greeting?name=%3C%2Fp%3E%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E%3Cp%3E",
                        // this is optional
                        "parameters": {
                            "name": "%3C%2Fp%3E%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E%3Cp%3E",
                            // or without the encoding
                            "name": "</p><script>alert(1);</script><p>"
                        },
                        "method": "GET",
                        "headers": {
                            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0",
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                            "Accept-Language": "en-US,en;q=0.5",
                            "Authorization": "Basic dGVzdHVzZXI6cGFzc3dvcmQtMTIzNDU=", // should probably be obfuscated
                            "Connection": "keep-alive",
                            "Referer": "https://localhost:8081/hello",
                            "Cookie": "locale=de; JSESSIONID=2327E9EBE8342769A6DB1322562DD850",
                            "Upgrade-Insecure-Requests": "1",
                            "Sec-Fetch-Dest": "document",
                            "Sec-Fetch-Mode": "navigate",
                            "Sec-Fetch-Site": "same-origin",
                            "Sec-Fetch-User": "?1",
                            "Content-Length": "0"
                        },
                        "body": {
                            //  only one of them - see https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317817
                            // when no body was sent, neither text nor binary will be set, just an empty body element is rendered
                            "text": "",
                            "binary": ""
                        }
                    },
                    "webResponse": {
                        "protocol": "HTTP",
                        "version": "1.1",
                        "statusCode": 200,
                        "reasonPhrase": "OK",
                        "headers": {
                            "Set-Cookie": "locale=de; HttpOnly; SameSite=strict",
                            "X-Content-Type-Options": "nosniff",
                            "X-XSS-Protection": "1; mode=block",
                            "Cache-Control": "no-cache, no-store, max-age=0, must-revalidate",
                            "Pragma": "no-cache",
                            "Expires": "0",
                            "Strict-Transport-Security": "max-age=31536000 ; includeSubDomains",
                            "X-Frame-Options": "DENY",
                            "Content-Security-Policy": "script-src 'self'",
                            "Referrer-Policy": "no-referrer",
                            "Content-Type": "text/html;charset=UTF-8",
                            "Content-Language": "en-US",
                            "Date": "Mon, 18 Oct 2021 07:25:32 GMT"
                        },
                        "body": {
                            //  https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317817
                            "text": "<!DOCTYPE HTML>
                            <html>
                            <head>
                                <title>Getting Started: Serving Web Content</title>
                                <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
                            </head>
                            <body>
                                <!-- unsecure text used (th:utext instead th:text)- to create vulnerability (XSS) -->
                                <!-- simple usage: http://localhost:8080/greeting?name=Test2</p><script>;alert("hallo")</script> -->
                                <p >XSS attackable parameter output: </p><script>alert(1);</script><p>!</p>
                            </body>
                            </html>",
                            "binary": ""
                        },
                        "noResponseReceived": false
                    }
                }
            ],
            
            "taxonomies": [
                {
                    "downloadUri": "https://cwe.mitre.org/data/xml/cwec_v4.4.xml.zip",
                    "guid": "f2856fc0-85b7-373f-83e7-6f8582243547",
                    "informationUri": "https://cwe.mitre.org/data/published/cwe_v4.4.pdf/",
                    "isComprehensive": true,
                    "language": "en",
                    "minimumRequiredLocalizedDataSemanticVersion": "4.4",
                    "name": "CWE",
                    "organization": "MITRE",
                    "releaseDateUtc": "2021-03-15",
                    "shortDescription": {
                        "text": "The MITRE Common Weakness Enumeration"
                    },
                    "taxa": [
                        {   
                            // we do not add descriptions here
                            // this would need to download taxa description from mitre website etc.
                            // helpURI, CWEId are enough information, people can open the website...
                            "guid": "1a37bf66-7c5a-3aa0-94bb-ffae58a9e01c",
                            "helpUri": "https://cwe.mitre.org/data/definitions/79.html",
                            "id": "79",
                        }
                    ],
                    "version": "4.4"
                }
            ],
            "tool": {
                "driver": {
                    "guid": "4d841334-0141-4e13-bdd0-53087266ebcd",
                    "informationUri": "https://www.zaproxy.org/",
                    "name": "ZAP",
                    "rules": [
                        {
                            // pluginId/alertRef -  we use pluginId
                            "id": "40012",
                            "defaultConfiguration": {
                                "level": "error"
                            },
                            // summary of plugin: https://www.zaproxy.org/docs/alerts/40012/
                            "fullDescription": {
                                //  alert.getFullDescription() - converted HTML to plain text only
                                "text": "Cross-site Scripting (XSS) is an attack technique that...."
                            },
                            // name
                            "name": "Cross Site Scripting (Reflected)",
                            // in the json format those are called reference and a list of links as <p> elements
                            "properties": {
                                "references": [
                                    "http://projects.webappsec.org/Cross-Site-Scripting",
                                    "https://owasp.org/www-community/attacks/xss/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                                    "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)"
                                ],
                                // solution
                                "solution": {
                                    "text": "Phase: Architecture and Design\nUse a vetted library or  ...more....</p>"
                                },
                                "confidence": "medium" // possible values (false-positive, low, medium, heigh, confirmed)
                            },
                            "relationships": [
                                {
                                    "kinds": [
                                        "superset"
                                    ],
                                    "target": {
                                        "guid": "6bd55435-166c-3594-bc06-5e0dea916067",
                                        "id": "89",
                                        "toolComponent": {
                                            "guid": "f2856fc0-85b7-373f-83e7-6f8582243547",
                                            "name": "CWE"
                                        }
                                    }
                                }
                            ],
                            // same as name
                            "shortDescription": {
                                "text": "Cross Site Scripting (Reflected)"
                            }
                        }
                    ],
                    "semanticVersion": "2.11.0",
                    "supportedTaxonomies": [
                        {
                            "guid": "f2856fc0-85b7-373f-83e7-6f8582243547",
                            "name": "CWE"
                        }
                    ],
                    "version": "2.11.0"
                }
            }
        }
    ],
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0"
}
```

## Links
- Sarif V2.1.0 - official document https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html


