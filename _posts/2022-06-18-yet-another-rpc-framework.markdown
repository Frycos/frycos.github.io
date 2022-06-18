---
layout: post
title:  "SmarterStats - Yet Another RPC Framework"
date:   2022-06-18 23:00:09 +0200
categories: vulns4free
---
First of all, the SmarterTools team is pretty cool, a vendor I practice responsible disclosure with pleasure. I also needed some positive vendor vibes after my last experiences. I already worked with them successfully in the past. They provide a bunch of software products, one of them called [SmarterStats](https://www.smartertools.com/smarterstats/website-analytics): a web log analytics suite measuring the popularity of your websites given certain metrics. The installation of a trial version is straight forward and the code based on ASP .NET. The web interface can be reached at TCP port `9999`. According to [Censys.io](https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=SmarterStats) there exist **a few thousand instances** on the public internet with **several hundreds** also exposing TCP port `50003` (this will become relevant later). For our code audit we installed the latest version **Build 8011 (Dec 7, 2021)** available at that time. The patched version was published a few days ago (June 9th 2022) as **Build 8195**.

![Login](/assets/images/smarterstats/SmarterStatsBlog1.png)

First, I usually check the IIS manager `inetmgr` for the deployment structure, web root directories etc.

![Deployment structure](/assets/images/smarterstats/SmarterStatsBlog2.png)

Second, the `inetmgr` lists the **HTTP handlers** for which we're especially interested in *custom* handlers.

![HTTP Handlers](/assets/images/smarterstats/SmarterStatsBlog3.png)

Even more interesting are **HTTP modules** because according to the ASP .NET workflow, these are usually called *before any authentication checks* trigger. A nice example for this kind of entry-point leading to Pre-Auth Remote Code Execution (RCE) was shown by my colleague [in this blog on Citrix ShareFile](https://codewhitesec.blogspot.com/2021/09/citrix-sharefile-rce-cve-2021-22941.html). Unfortunately, no custom HTTP modules can be identified for SmarterStats.

![HTTP Modules](/assets/images/smarterstats/SmarterStatsBlog4.png)

Next, we check for all `.aspx`, `.ascx` and `.asmx`  files in `C:\Program Files (x86)\SmarterTools\SmarterStats\MRS` for potential vulnerabilities. As you might notice, most of these files contain references to C# code base such as 

```
<%@ WebService Language="C#" CodeBehind="UserAdmin.asmx.cs" Class="SSWeb.Services.UserAdmin" %>
```

So, you search for the proper IIS worker process `w3wp.exe` serving your SmarterStats application and load it into *dnSpy*. Then load all the modules related to the process and sort the .NET assemblies for a first overview. I like to sort them because it's a quick visual check for *custom vs. .NET framework assemblies* by name.

![Assemblies](/assets/images/smarterstats/SmarterStatsBlog5.png)

Remember to browse the application before attaching to the IIS worker process. Otherwise, you might not see all the "cryptic" `Asp_Web_junk` modules with their corresponding .NET code.

![ASP Assemblies](/assets/images/smarterstats/SmarterStatsBlog6.png)

After digging through some code, I realize that our ultimate goal **"Pre-Auth RCE"** is at risk. But we only checked the web-interface at TCP port `9999` so far. Back in 2020 I reported another Pre-Auth RCE for SmarterStats affecting a service available at TCP port `50003`. This was fixed in [Build 7422 (Apr 27, 2020)](https://www.smartertools.com/smarterstats/release-notes/current). Back then, the RCE was based on the fact that they used **.NET Remoting**. So, let's check if this port is still used by a SmarterStats process **by default** after a fresh installation. *Sysinternals TCPView* says "yes".

![Port 50003](/assets/images/smarterstats/SmarterStatsBlog7.png)

Loading the process `SSSvc.exe` into *dnSpy* again, let's investigate how this works under the hood. It quickly becomes clear that .NET Remoting *is not used anymore* which is good, right?

The module name shown in TCPView was called `SSCollect` so we search for this module in the code base. We find `SStatSvc.SSCollect` extending `System.ServiceProcess.ServiceBase`. The `ServiceBase.OnStart(string[] args)` method is overridden by `SSCollect`.

![Service Start](/assets/images/smarterstats/SmarterStatsBlog8.png)

Let's follow the `ServiceWorker.StartService()` which calls `ServiceWorker._serviceLifetimeThread = new Thread(new ThreadStart(ServiceWorker.ServiceLifetimeFunction))` ending in a `ServiceWorker.Start()`.

![Service Thread Start](/assets/images/smarterstats/SmarterStatsBlog9.png)

Here, things are getting more specific and interesting. During this initialization procedure we find a call to `GrpcManager.StartGrpc()` which nicely matches with a set of assemblies we spotted after loading all modules used by the `SSSvc.exe` process: `Grpc.Core.dll` and `Grpc.Core.Api.dll`.

![Start Grpc](/assets/images/smarterstats/SmarterStatsBlog10.png)

We have some classes with namespace prefix `SmarterStats.Config.Protos` calling `BindService` methods with distinct implementation classes. We also spot the TCP port `50003` and another interesting fact giving us confidence for another Pre-Auth chance: [`ServerCredentials.Insecure`](https://grpc.io/docs/guides/auth/).

I already heard about **gRPC and protocol buffers** before but honestly didn't look into programmatic approaches too much. So what to do first? Reading documentation like a beginner. I start with [this](https://grpc.io/docs/what-is-grpc/introduction/), telling me something about **remote method invocation**. From a security research perspective, this topic is often related to Java (RMI), .NET (Remoting) and more. gRPC uses so called protocol buffers by default to send serialized data over the wire. But *this is not as dangerous as you might think*. Data structures for automatically generated client stubs and server service skeletons are derived from `.proto` files.

Unfortunately, we don't have these files…so let's look into the server code again. Starting with the first gRPC type `SmarterStats.Config.Protos.Query` we see something interesting.

![Query Type](/assets/images/smarterstats/SmarterStatsBlog11.png)

There is a class named `SmarterStats.Config.Protos.QueryClient`. Hooray! We try to find the implementation now through all these `virtual, abstract, override` function definitions. We start again in `SmarterStats.Config.Protos.Query` where the method `BindService(ServiceBinderBase serviceBinder, Query.QueryBase serviceImpl)` is implemented.

![BindService](/assets/images/smarterstats/SmarterStatsBlog12.png)

Choosing one random function of this specific service, virtual functions such as `Task<GetAvailableQueriesWithInputsReply> GetAvailableQueriesWithInputs(GetAvailableQueriesWithInputsRequest request, ServerCallContext context)` bring us a step further to the real business code.

In `SStatSvc.Communication.QueryServiceImplementation` this function is overridden

![QueriesWithInput](/assets/images/smarterstats/SmarterStatsBlog13.png)

and we finally reach the business code

![Business Code](/assets/images/smarterstats/SmarterStatsBlog14.png)

The request input class `SmarterStats.Config.Protos.GetAvailableQueriesWithInputsRequest` seems to be pretty empty, i.e. no obvious user-controllable attributes exist. But this is somehow expected since the remote method name `GetAvailableQueries` indicates that probably no further input is needed. Fine, now how do we get a working client running?

The documentation ["A basic tutorial introduction to gRPC in C#"](https://grpc.io/docs/languages/csharp/basics/) sounds like a good starting point. We clone the example project [RoutingGuide](https://github.com/grpc/grpc/tree/v1.45.0/examples/csharp/RouteGuide) and try to understand the project structure and code within. Also I'm **really lazy** which means… simply reuse the code to create a SmarterStats client.

We directly switch to the *RouteGuideClient* part of the Visual Studio solution. gRPC assemblies are already set up for us so only the **SmarterStats types** are needed. Checking with dnSpy again, we then add the reference `C:\Program Files (x86)\SmarterTools\SmarterStats\Service\SmarterStats.Config.dll` to our solution.

Let's write some really dumm code (I'm allowed to do this because I worked as a software developer years ago (⌐ ͡■ ͜ʖ ͡■)).

![Client Code](/assets/images/smarterstats/SmarterStatsBlog15.png)

Running our "meaningless" `RouteGuideClient.exe` works!

![Running Query Client](/assets/images/smarterstats/SmarterStatsBlog16.png)

Now, let's hunt for some **Pre-Auth RCE bugs!** We go through all binding service implementations step by step and stop at `SStatSvc.Communication.ServiceOperationsServiceImplementation` because it contains a lot of interestingly sounding methods. The method `GetExportedLogsForSite(GetExportedLogsForSiteRequest request, IServerStreamWriter<GetExportedLogsForSiteResponse> responseStream, ServerCallContext context)` e.g. has the word "Export" in it.

![Export Logs Code](/assets/images/smarterstats/SmarterStatsBlog17.png)

The call `Path.Combine(Constants.ServiceTemporaryDirectory, this.request.FileToDownload)` already tells us everything we want to know: **user-controlled file name + path traversal** opportunity?! Let's test this with our new gRPC knowledge.

![Export Logs Client](/assets/images/smarterstats/SmarterStatsBlog18.png)

And indeed, we can read the configuration file with credentials and a bunch of sensitive information.

![Run Export Logs Client](/assets/images/smarterstats/SmarterStatsBlog19.png)

What `Path.Combine` can do for you (in different flavors), have a look at my previous blog on [3CX Pwnage](https://medium.com/p/pwning-3cx-phone-management-backends-from-the-internet-d0096339dd88). **Pre-Auth Arbitrary File Read** as `NT AUTHORITY\SYSTEM` achieved.

So what would be a good method candidate for Remote Code Execution then? `SaveFileTo(SaveFileToRequest request, ServerCallContext context)` sounds promising.

![SaveFileTo Code](/assets/images/smarterstats/SmarterStatsBlog20.png)

But the **"Unauthorized to copy"** could become a problem. Let's see if it really is. The authorization check consists of taking a request parameter `this.request.Auth` and puts it into a "crypto check" `cryptographyHelper.DecodeFromBase64` method. The result has to match our user-controlled value `this.request.Filename`. The `DecodeFromBase64` method indeed decodes the value from a Base64 format and operates with some crypto on the result.

![Decode and Crypto](/assets/images/smarterstats/SmarterStatsBlog21.png)

But did you also spot the `cryptographyHelper.SetKey(creationTime.ToString("MMddyyyy") + " ksghsfkgjh", null)`? Yes, `creationTime` comes from `this.request.CreationDate.ToDateTime()` which **we control as well**. Does this mean we control the crypto key and initialization vector? Let's write some more ugly code.

![SaveToFile Client Code](/assets/images/smarterstats/SmarterStatsBlog24.png)

Execute the modified client

![Run SaveToFile Client](/assets/images/smarterstats/SmarterStatsBlog22.png)

and we have written a file

![Shell Written](/assets/images/smarterstats/SmarterStatsBlog23.png)

which can be called

![Web Shell](/assets/images/smarterstats/SmarterStatsBlog25.png)

giving us **Pre-Auth Remote Code Execution** again. At the end of the day, we found a second Pre-Auth RCE for the service at TCP port `50003` (2020, 2022).

P.S.: I didn't check all the other gRPC binding implementations but rather told the vendor to check the others for similar flaws themselves. Maybe you can find others! What I *did* see was a small opportunity for another Pre-Auth RCE in the patched version. Can you spot it as well?