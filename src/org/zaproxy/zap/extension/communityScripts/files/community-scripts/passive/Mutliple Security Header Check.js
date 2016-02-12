// Multiple Security Header checker by freakyclown@gmail.com


function scan(ps, msg, src) {
    url = msg.getRequestHeader().getURI().toString();
    body = msg.getResponseHeader().toString()
    alertRisk = [0, 1, 2, 3] //0=informational, 1=low, 2=medium, 3=high
    alertReliability = [0, 1, 2, 3, 4] //0=fp,1=low,2=medium,3=high,4=confirmed
    alertTitle = ["Strict Transport Security(STS) Header Not Set (script)",
        "Content-Security-Policy (script)",
        "Web Browser XSS Protection Not Enabled (script)",
        "X-Content-Type-Options Header Missing (script)",
        "X-Frame-Options Header Not Set (script)",
        ""
    ]
    alertDesc = ["HTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web server declares that complying user agents (such as a web browser) are to interact with it using only secure HTTPS  connections (i.e. HTTP layered over TLS/SSL). HSTS is an IETF standards track protocol and is specified in RFC 6797.",
        "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a standard HTTP header that allows website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.",
        "Web Browser XSS Protection is not enabled, or is disabled by the configuration of the 'X-XSS-Protection' HTTP response header on the web server",
        "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.",
        "X-Frame-Options header is not included in the HTTP response to protect against 'ClickJacking' attacks.",
        ""
    ]
    alertSolution = ["Ensure that your web server, application server, load balancer, etc. is configured to set Strict Transport Security headers.",
        "Ensure that your web server, application server, load balancer, etc. is configured to set Content Security Policy headers.",
        "Ensure that the web browser's XSS filter is enabled, by setting the X-XSS-Protection HTTP response header to '1'.",
        "Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages. If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.",
        "Most modern Web browsers support the X-Frame-Options HTTP header. Ensure it's set on all web pages returned by your site (if you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY.  ALLOW-FROM allows specific websites to frame the web page in supported web browsers).",
        ""
    ]
    cweId = [0, 1]
    wascId = [0, 1]

    // test sts
    if (msg.getRequestHeader().isSecure()) {
        if (msg.getResponseHeader().getHeaders("Strict-Transport-Security") == null)
            ps.raiseAlert(alertRisk[1], alertReliability[3], alertTitle[0], alertDesc[0], url, '', '', '', alertSolution[0], '', cweId[0], wascId[0], msg);
    }
    // test csp
    if (msg.getResponseHeader().getHeaders(("Content-Security-Policy" && "X-Content-Security-Policy" && "X-WebKit-CSP")) == null)
        ps.raiseAlert(alertRisk[1], alertReliability[3], alertTitle[1], alertDesc[1], url, '', '', '', alertSolution[1], '', cweId[0], wascId[0], msg);


    // test xxs protection
    re_xss = /(X\-XSS\-Protection\:.+1)/g
    if (!(re_xss.test(body))) //if its false
    {
        ps.raiseAlert(alertRisk[1], alertReliability[3], alertTitle[2], alertDesc[2], url, '', '', '', alertSolution[2], '', cweId[0], wascId[0], msg);
    }

    // test xcontent no sniff protection
    re_nosniff = /(X\-Content\-Type\-Options\:.*nosniff.*)/g
    if (!(re_nosniff.test(body))) //if its false
    {
        ps.raiseAlert(alertRisk[2], alertReliability[2], alertTitle[3], alertDesc[3], url, '', '', '', alertSolution[3], '', cweId[0], wascId[0], msg);
    }

    // test xcontent no sniff protection
    re_clickjack = /(X\-Frame\-Options\:.+[Dd][Ee][Nn][Yy])/g
    if (!(re_clickjack.test(body))) //if its false
    {
        ps.raiseAlert(alertRisk[1], alertReliability[3], alertTitle[4], alertDesc[4], url, '', '', '', alertSolution[4], '', cweId[0], wascId[0], msg);
    }



}
