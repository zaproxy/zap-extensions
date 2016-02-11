Proxy scripts
=============

Scripts which these run 'inline', can change every request and response that is proxied through ZAP and can be individually enabled. 
They can also trigger break points. 
They are not invoked for requests that originate from ZAP, for example from the active scanner or spiders.
To access requests that originate from ZAP use httpsender scripts.
