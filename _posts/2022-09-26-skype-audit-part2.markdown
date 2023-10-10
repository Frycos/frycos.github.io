---
layout: post
title:  "Skype for Business Audit Part 2 - SKYPErimeterleak"
date:   2022-09-26 23:00:00 +0200
categories: vulns4free
---

> Update 2023-10-10: After a year, Microsoft decided to provide a patch for this - [CVE-2023-41763](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2023-41763)

In my last [blog post](https://frycos.github.io/vulns4free/2022/09/22/skype-audit-part1.html) we talked about a new *persistence technique* in **Skype for Business 2019 (SfB)** found during my code audit. Now, I give a short code walk-through
about an **Pre-Auth Server-side Request Forgery (SSRF)** vulnerability which could easily lead to an internet perimeter breach.
But let's start from the beginning.


We still have the same setup, i.e. an Active Directory (AD) `CONTOSO.COM` with a SfB installation on a system `SKYPE01`.
But this time, we're looking for a vulnerability instead of a persistence technique for Red Teams.
Since the [MSRC](https://www.microsoft.com/en-us/msrc) rejected my submission for this vulnerability with a "not meeting the bar" argument, I told them to publish a blog post instead.

We look again with `InetMgr.exe` at the Application Pool and URI path configurations.

![InetMgr](/assets/images/skypethings/skype_inetmgr.png)

Since we mentioned the term "internet perimeter breach" above, the focus will again be on the "External Web Site" configurations.
The target we chose was the URI path `/lwa` which stands for **Lync Web App**. The corresponding App Pool is named `LyncExtFeature`.
The file system location of interest can usally be found at `C:\Program Files\Skype for Business Server 2019\Web Components\LWA\Ext`.

In the `Web.config` file the following declaration is made:

```xml
<defaultDocument>
    <files>
    <clear/>
    <add value="LwaClient.aspx"/>
    </files>
</defaultDocument>
```

The ASPX file mentioned is located at `C:\Program Files\Skype for Business Server 2019\Web Components\LWA\Ext\WebPages`
and the first line reads:

```xml
<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="LwaClient.aspx.cs" Inherits="Lync.Client.PreAuth.LwaClient" Async="true" %>
```

Browsing to this ASPX file is indeed possible without further authentication needed as also indicated by the `PreAuth` key word being part of the namespace.

![LWA_ASPX](/assets/images/skypethings/skype_lwaaspx.png)

We attach *dnSpy* to our `w3wp.exe` process with the App Pool `LyncExtFeature` and load all .NET assemblies/modules into the debugger.
Looking into the class `Lync.Client.PreAuth.LwaClient` reveals that it inherits from `System.Web.UI.Page` so we can usually expect several methods like `Page_Init` and/or `Page_Load` being implemented (see any blog on "ASP.NET Page Life Cycle").

But the most interesting implementation is an asynchronous one called `PageLoadInternal()`. Several user-controlled
parameter are easily spotted in the first lines of code *[1], [2]*.

```csharp
...
if (base.Request.QueryString.Count != 0)
{
		this.LwaLocale = HttpUtility.UrlDecode(base.Request.QueryString["reachLocale"]); //[1]
		string joinXml = LwaClient.Base64DecodeString(base.Request.QueryString["xml"]); //[2]
		...
```

If no query parameter `xml` is provided, the following if-statement turns out to be `true` *[3]*.

```csharp
...
if (string.IsNullOrEmpty(joinXml)) //[3]
{
			if (Wpp.tracer.Level >= 5 && (Wpp.tracer.Flags & 1) != 0)
			{
				WPP_2897018b9080d7ca34b73bbf6c519b5b.WPP_p(3, 10, (IntPtr)this.GetHashCode());
			}
			try
			{
				string meetUrl = LwaClient.Base64DecodeString(base.Request.QueryString["meeturl"]); //[4]
			...
```

The query parameter `meeturl` now get evaluated at *[4]* and we're almost there, looking at the SSRF.

```csharp
...
if (this.CmsLWAValidateMeetUrlFlag)
{
					this.ValidateMeetUrl(meetUrl); //[5]
}
HttpWebRequest request = (HttpWebRequest)WebRequest.Create(meetUrl); //[6]
request.Accept = "Application/vnd.microsoft.lync.meeting+xml";
request.UserAgent = "LCS-Server";
using (HttpWebResponse response = (HttpWebResponse)(await request.GetResponseAsync())) //[7]
{
	using (StreamReader reader = new StreamReader(response.GetResponseStream()))
	{
		joinXml = await reader.ReadToEndAsync();
		reader.Close();
	}
	response.Close();
}
...
```

Some kind of *validation* in *[5]* seems to take place. We'll look into this in a minute.
If the validation turns out to be successful, an `HttpWebRequest` object is created *[6]* and fires *[7]*
in an asynchronous manner. If we could inject an arbitrary URL with **full control including query parameters** etc.,
a powerful SSRF would have been born (a *blind* one though). Thanks to the Base64 encoding, one doesn't even
have to take care (a lot) on weird characters etc.

But let's investigate the `ValidateMeetUrl` *[5]* method first.

```csharp
private void ValidateMeetUrl(string meetUrl)
{
		if (Wpp.tracer.Level >= 4 && (Wpp.tracer.Flags & 1) != 0)
		{
			WPP_2897018b9080d7ca34b73bbf6c519b5b.WPP_p(3, 15, (IntPtr)this.GetHashCode());
		}
		string pattern = "(https?:\\/\\/(www\\.)|(www\\.))?.*(\\.\\w{2,4})\\/.*\\/[a-zA-Z0-9]*\\/?$"; //[8]
		bool flag = Regex.IsMatch(meetUrl, pattern);
		if (flag)
		{
			return;
		}
		string pattern2 = "^(https?:\\/\\/(www\\.)|(www\\.))?.*(\\.\\w{2,4})\\/Meet\\/\\?.*\\/?$"; //[9]
		if (!Regex.IsMatch(meetUrl, pattern2))
		...
```

It basically breaks down to defeat the regular expressions *[8]* or *[9]*. Intuitively, I chose the first one at *[8]* (but does it matter? :-P). For this kind of regex testing, there are tons of online [regex testers](https://www.regextester.com/) available to play with expressions.

So it looks like the "idea" of this validation by the code author *could* be based on the following thoughts (I'm just guessing here!). We do not differentiate between optional match groups for this interpretation.

1. Could be a valid domain name starting with `http` or `https` (you're stuck in the `WebRequest` cast indeed)
2. Could contain a `www` prefix
3. Domain could end with an TLD of length between `2` and `4`, e.g. `de, com, army`
4. Last segment could contain an alpha-numeric sequence and we need another slash in there

So things like this should work.

![Regex1](/assets/images/skypethings/skype_regex1.png)

What about IP addresses? Since `www` is optional but constraint *3.* exists: the fourth octet cannot be a single digit.
Alright, this constraint is not too hard. Enough IP addresses left to do something evil.

![Regex2](/assets/images/skypethings/skype_regex2.png)

A bit later, I realized that this could also become optional. But see the difference between `https://10.0.0.1/whatever/iwant` vs. `https://10.0.0.10/whatever/iwant`? Sometimes, your mind is playing tricks on you. :-P

What about queries? Exploiting a third-party system at least should take into account arbitrary query parameters.
Yes, works also fine since most web apps from my experience simply ignore additional undefined query parameters.

![Regex3](/assets/images/skypethings/skype_regex3.png)

Of course, if you already know the Windows Domain name (e.g. obtained from one of the Skype endpoints talking NTLM),
common hostname prefixes like `jira.contoso.com` are also possible. If you need some inspiration for *Exploiting Blind SSRF*, I highly recommend [some](https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/) [resources](https://github.com/assetnote/blind-ssrf-chains) by Assetnote.

After I showed this vulnerability to my teammates [@codewhitesec](https://twitter.com/codewhitesec), a result in discussion with [Markus](https://twitter.com/mwulftange) ended in an even more beautiful regex breaker (of course the previous examples might work for most cases of exploitation cases as well).

![Regex4](/assets/images/skypethings/skype_regex4.png)

With this, we could basically control everything as needed. And since there are tons of vulnerable systems
(especially in intranet corporate networks), such as routers, Jenkins, or lately VMware Workspace ONE Access (exploitable with a single GET request), this *Pre-Auth Blind SSRF* should indeed be seen as an *internet perimeter leak* threat.

Finally, what's missing? Right, **PoC\|\|GTFO**.
Our Skype server `SKYPE01` has the IP address `10.137.0.27` (right). A second machine at `10.137.0.26` (left) sends the SSRF payload `https://skype01.contoso.com/lwa/Webpages/LwaClient.aspx?meeturl=aHR0cDovLzEwLjEzNy4wLjI2Lz9pZD1QT0MlMjV7MTMzNyoxMzM3fSMueHgvLw==` and also provides an HTTP service so we're able to receive HTTP requests and investigate the related log files.

For me it seemed easier to provide a nice screenshot with only two machines such that the attacker and victim machine
happens to be the same at `10.137.0.26` but it doesn't really matter. A well-known Struts2 RCE payload (CVE-2019-0230) was sent
but any payload deliverable with a GET request is exploitable.

![PoC](/assets/images/skypethings/skype_poc.png)
