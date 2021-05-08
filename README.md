
# cpsula

A bare-bones Project Gemini server which serves Lua-generated content using `libevent` and
`openssl`.

## Overview

[Project Gemini](https://portal.mozz.us/gemini/gemini.circumlunar.space/docs/faq.gmi) is a minimal,
application-level internet protocol with a focus on privacy and security. Its
[specification](https://portal.mozz.us/gemini/gemini.circumlunar.space/docs/specification.gmi) is
simple enough to fit in your head, and comes with an equally minimal
[markup](https://portal.mozz.us/gemini/gemini.circumlunar.space/docs/gemtext.gmi) specification.

Following this theme of minimalism, `cpsula` is a Gemini server which feeds all requests through a
single Lua function, aiming to do so with as little code/dependency overhead as possible. While
existing servers predominantly host static content (albeit with the addition of CGI), `cpsula`
leverages the simplicity and flexibility of Lua to generate dynamic content to your heart's content.

`cpsula` is short for cápsula, Portuguese for capsule.

## Features

### Simple interface

All of the connection management & server configuration details are hidden from Lua. Thanks to the
simplicity of the Gemini protocol, request handlers have only 4 arguments! See
[contrib/main.lua](contrib/main.lua) for an example request handler.

### Security

Per standard web-hosting procedure, `cpsula` switches to a less-privileged user after initializing
its SSL context, and refuses to run as root thereafter. Requests are pre-validated before Lua sees
them, and certain errors are handled automatically. `libevent` takes care of the TLS handshake and
connection management.

### Internationalized Resource Identifiers

Building on the Gemini specification, `cpsula` accepts [IRIs](https://tools.ietf.org/html/rfc3987)
in client request headers. This is done for two reasons: 1) the use of UTF-8 is highly encouraged by
the Gemini specification for all textual formats, and 2) request URLs are already specified as being
UTF-8 encoded. The use of unescaped UTF-8 characters in gemtext links is plainly more accessible than
having to percent-encode them, and accepting IRIs at the server level is a simple extension of this.

While any server which advertises resources via IRI will inevitably receive escaped URI requests as
per the Gemini specification, the two are ultimately equivalent. For example, according to the
fine-grained definitions in [RFC3986](https://tools.ietf.org/html/rfc3986), the ASCII-US encoded URI
`gemini://foo.bar/%C3%A4` refers to a set of two characters, `0xC3` and `0xA4`. For all intents and
purposes, these characters denote the single character `ä`, just as the IRI `gemini://foo.bar/ä`
would. In the context of Lua (and I believe Gemini at large), there is no a practical distinction to
be made here. The use of IRIs should not cause incompatibility issues, provided clients do not
reject them altogether.

### Zero-Configuration Certificate Generation

Soon™, the server will allow for automatic generation of self-signed certificates.

## Instructions for Use

I'm working on getting a package on the AUR. Until then, the following steps will have to suffice.

The project is simple enough that if you have `libevent`, `openssl`, and `lua` installed, `make` should
compile things without much hassle. The server binary, `cpsula`, is the default makefile target.

The first argument to `cpsula` is a config file (see `contrib/cpsula.conf`) which tells the server
what to do. You'll want to create a config file which lets you start the server from the current
directory. For example, this is the configuration I use to test things locally, called
`cpsula.conf.local`:

    certificate-file=./ssl/cert
    certificate-key-file=./ssl/pkey
    user=<some-user>
    group=<some-group>
    socket-address=
    socket-port=1965
    root-directory=./
    lua-main=./contrib/main.lua

Next, because Gemini mandates TLS, you will need to generate a certificate and private key. For example:

    $ openssl genrsa -out pkey 2048
    $ openssl req -new -key pkey -out cert.req
    $ openssl x509 -req -days 365 -in cert.req -signkey pkey -out cert

All fields for the certificate request (second command) can be left blank. However, when prompted
for a CN (Common Name), enter "localhost" if you plan on hosting & connecting locally. Otherwise,
enter the server's hostname. As indicated by the above configuration, the resulting `pkey` and
`cert` files should be placed in `./ssl`. (Normally they would be owned by root, but it's not
strictly required in this example.)

After reading `pkey` and `cert`, the server will immediately switch user/group to the those
specified in the config file. Changing user/group will only work if `cpsula` is run as root, or if
`<some-user>` and `<some-group>` match the user/group of the user that starts the server. In any
case, the server will refuse to continue if running as root by this point.

If all goes well, you should see something like this:

    # ./cpsula cpsula.conf.local
    20:55:49 Reading configuration from cpsula.conf.local
    20:55:49 Server running (user: <some-user>)

To see the server in action, you'll need to get a Gemini browser. I use a terminal-based client
called [amfora](https://github.com/makeworld-the-better-one/amfora).

You can find the code that generates Gemini pages in 'contrib/main.lua'. There's more
documentation in that file that goes over specifically how pages are generated.

