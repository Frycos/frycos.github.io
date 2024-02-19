---
layout: post
title:  "Tableau Server - There Ain't No Vulns"
date:   2024-02-19 01:00:00 +0200
categories: vulns4free
---

> Tableau Server - Governed self-service analytics at scale

Recently, I began a code audit on the software product **Tableau Server** which turned out to be prone to several vulnerabilities in its latest version. All attacks were conducted on a test trial environment against the Tableau Cloud during January 2024. The vulnerabilities found were only exploitable *within an authenticated context* and I rated them of *medium severity*. Due to the challenging system requirements, I was only able to show the first vulnerability (SSRF) against their live cloud environment based on Linux. But let the code speak for itself. I also stopped my code audit after my first submission, because you know: motivation issues. The Salesforce Security team spoke about lacking evidence, proof-of-concept exploitability and step-by-step descriptions. They only referred me to their submission guideslines, so I thought: let's dump my original report on my blog instead.


# Server-Side Request Forgery (SSRF)

An API call implemented in `com.tableau.loom.rest.resources.VizportalApiResource` allows for a **Server-Side Request Forgery (SSRF)** attack. This endpoint could e.g. be reached at the web application deployed through `flow-processor.war`. According to its `MANIFEST.MF` descriptor file, the `Start-Class` is defined as `com.tableau.loom.rest.spring.LoomSpringApp`. The Spring annotation `@ComponentScan` contains the namespace of the beforementioned class.

The URL prefix `/flow-editor` can be found in `floweditor.20233.23.1017.0948.json`, connecting the same with the `flow-processor` microservice:

```json
"microservices": {
    "flow_editor": "${root}/floweditor/flow-processor.war"
},
"microserviceOptions": {
    "flow_editor": {
    "urlprefix": "flow-editor"
    }
},
```

This API might be reachable through other microservices as well. I didn't check for additional `@ComponentScan` entries.
The vulnerable endpoint in `VizportalApiResource` is therefore callable by sending a GET request to `flow-editor/api/vizportalApi/checkCompatibility`. The method `com.tableau.loom.rest.resources.VizportalApiResource#checkCompatibility` takes a request parameter named `serverHost`.

Following the call hierarchy further is shown in the following listing.

```
com.tableau.loom.vizportal.VizportalAdaptor#getVizportalCompatibilityInfo
-> com.tableau.loom.vizportal.VizportalAdaptor#getVizportalCompatibilityInfo_aroundBody18
--> com.tableau.loom.vizportal.VizportalAdaptor#getVizportalDocumentVersion
---> com.tableau.loom.vizportal.VizportalAdaptor#getVizportalDocumentVersion_aroundBody16
----> com.tableau.maestro.vizportal.clientXmlApi.util.ClientXmlApiClient#getVizportalDocumentVersion(java.lang.String)
```

The `serverHost` variable is wrapped into a `java.net.URI` object and passed to `com.tableau.maestro.vizportal.clientXmlApi.util.ClientXmlApiClient#getVizportalDocumentVersion(java.net.URI)`. The method `com.tableau.maestro.vizportal.clientXmlApi.util.ClientXmlApiUrlBuilder#getServerAuthInfoRequestUrl` adds the path `/auth` and the corresponding query parameter `format=xml` to the URI. Again, following the call chain further

```
com.tableau.maestro.vizportal.clientXmlApi.util.ClientXmlApiClient#getDocumentVersion
-> com.tableau.maestro.vizportal.clientXmlApi.util.ClientXmlApiClient#issueGetRequestForUrlAndReadXmlResponse
--> com.tableau.maestro.vizportal.clientXmlApi.util.ClientXmlApiClient#issueGetRequestForUrl
---> com.tableau.maestro.vizportal.HttpRequestor#get
```
finally uses the **Jersey Client library** to then request the resource. As indicated by the parametrization of the method `com.tableau.maestro.vizportal.HttpRequestor#get`, a `Map<String, Object> properties` variable is passed as well. This `Map` is built via `com.tableau.maestro.vizportal.clientXmlApi.util.ClientXmlApiClient#constructBaseRequestProperties` and the property `jersey.config.client.followRedirects` set to `true` (which is enabled by default anyway!). This is a relevant setting from an exploitability point of view since the SSRF would otherwise be restricted to `baseUrl` injection. Every forged request would have included the `/auth?format=xml` path and query parameter which would have lowered the impact of this vulnerability class. Nevertheless, since redirects are automatically followed, another host controlled by the attacker could be leveraged to deliver arbitrary URLs for another Jersey client request (i.e. with full control of `baseUrl`, path and query parameters).

A proof-of-concept exploitation in the **Tableau Cloud (trial test account)** is shown next.

{:refdef: style="text-align: center;"}
![Request against Tableau server](/assets/images/tableau/ssrf_request.png)
{: refdef}

{:refdef: style="text-align: center;"}
![Python redirector fetching the request and providing a 302 response with Location header](/assets/images/tableau/python_redirector.png)
{: refdef}

{:refdef: style="text-align: center;"}
![Incoming Jersey client call from Tableau server after following redirect with full host, path and query parameter control](/assets/images/tableau/jersey_client.png)
{: refdef}

The Python redirector script basically contains
```python
import SimpleHTTPServer
import SocketServer
PORT = 8443

def do_GET(self):
    self.send_response(302)
    self.send_header('Location', 'http://[TARGETED_HOST|LOCALHOST]/anypath/iwant?withquery=params')
    self.end_headers()

Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
Handler.do_GET = do_GET
httpd = SocketServer.TCPServer(("", PORT), Handler)
httpd.serve_forever()
```

This vulnerability could be abused in various ways, e.g.:

* Target other servers with the Tableau server as attacker source
* Target internal AWS APIs
* Target "trusted" API calls on Tableau server itself, supposedly originating from loopback or internal IP addresses belonging to the AWS VPC

# NetNTLM Leaks

The method `com.tableau.loom.lang.api.utils.LoomFileUtils#getDirectory` is reused in several places across the Tableau server code base. This includes externally reachable API calls such as `com.tableau.loom.rest.desktop.resources.LoomDocValidationResource#validateLoomDoc`. Sending a POST request to the "Loom Doc Validation API" endpoint processes the following code.

```java
@Operation(summary="validateLoomDoc", operationId="validateLoomDoc")
@RequestMapping(method={RequestMethod.POST})
@Instrumented(value="validateLoomDoc")
public LoomDocValidationResponse validateLoomDoc(@Parameter(description="docValidationRequest") @RequestBody LoomDocValidationRequest loomDocValidationRequest, HttpServletRequest request) throws LoomException {
    if (loomDocValidationRequest != null) {
    if (loomDocValidationRequest.getParameterOverrides() != null) {
    loomDocValidationRequest.getLoomDoc().getParameters().setCurrentValues(loomDocValidationRequest.getParameterOverrides());
    }
    MaestroDocumentSanitizer.sanitize(loomDocValidationRequest.getLoomDoc());
    }
    DisplayProps displayProps = new DisplayProps();
    String localFileName = loomDocValidationRequest.getFilePath();
    if (StringUtils.isEmpty(localFileName)) {
    localFileName = ".";
    }
    File loomDir = LoomFileUtils.getDirectory(localFileName); <--
	...
```

The `<--` marked line shows the call to `com.tableau.loom.lang.api.utils.LoomFileUtils#getDirectory`. The variable `localFileName` is directly user-controlled as part of the request body containing a `com.tableau.loom.rest.api.loomDocValidation.LoomDocValidationRequest` object. `com.tableau.loom.rest.api.loomDocValidation.LoomDocValidationRequest#getFilePath` simply reads the property `filePath` without any further sanitization before `getDirectory` gets called.

Unfortunately, the Tableau Cloud trial instance was based on the Linux operating system. This attack vector is only feasible on Windows instances. Here, an attacker could provide a network UNC path in the `filePath` variable. If `getDirectory` gets called, access to the network share is tried for, starting with an authentication handshake based on the NTLM protocol. NetNTLM hashes could be abused in e.g. "relay attacks", often used by threat actors lately. See e.g. [this blog post on techniques involved](https://trustedsec.com/blog/a-comprehensive-guide-on-relaying-anno-2022).

To be able to show exploitability, a proof-of-concept (PoC) Java program was written, basically copying the code of `com.tableau.loom.lang.api.utils.LoomFileUtils#getDirectory`.

{:refdef: style="text-align: center;"}
![PoC Java source code + Execution with a network UNC path](/assets/images/tableau/java_poc.png)
{: refdef}

{:refdef: style="text-align: center;"}
![Observing authentication request with NetNTLM hash on another Linux machine](/assets/images/tableau/ntlm_auth.png)
{: refdef}


## Recommendations
* To lower the risk of SSRF exploitation primitives, consult resources such as the [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html). In this specific case, enforcing the context path and (query) parameters would already reduce the attack's applicability significantly.
* Check if meaningful restrictions to user-controlled file path parameters are applicable. Then implement an allow list approach with e.g. regular expressions to check the rules accordingly. Make sure that always the absolute path is calculated first before further decision-making.