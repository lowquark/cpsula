
# cpsula

A bare-bones Project Gemini server which serves arbitrary, Lua-generated content using `libevent`
and `openssl`.

## Overview

[Project Gemini](https://portal.mozz.us/gemini/gemini.circumlunar.space/docs/faq.gmi) is a minimal,
application-level internet protocol with a focus on privacy and security. Its
[specification](https://portal.mozz.us/gemini/gemini.circumlunar.space/docs/specification.gmi) is
simple enough to fit in your head, and comes with an equally minimal
[markup](https://portal.mozz.us/gemini/gemini.circumlunar.space/docs/gemtext.gmi) specification.

Following Gemini's theme of minimalism, `cpsula` is a Gemini server which feeds all requests through
a single Lua function, and it aims to do so with as little code/dependency overhead as possible.
While existing servers predominantly host static content (albeit with the addition of CGI), `cpsula`
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

### Automatic Key & Certificate Generation

The server supports the automatic generation of SSL keys / certificates. The only required
configuration from the user is the hostname; if a private key / certificate associated with the
given hostname does not exist, `cpsula` will generate one automatically. Currently, ECC secp384r1 is
used to generate keys, and the generated X509 certificates are valid for 20 years or so. 

### Internationalized Resource Identifiers

Building on the Gemini specification, `cpsula` accepts [IRIs](https://tools.ietf.org/html/rfc3987)
in client request headers. This is done for two reasons: 1) the use of UTF-8 is highly encouraged by
the Gemini specification for all textual formats, and 2) request URLs are already specified as being
UTF-8 encoded. The use of unescaped UTF-8 characters in gemtext links is plainly more accessible than
having to percent-encode them, and accepting IRIs at the server level is a simple extension of this.

While any server which advertises resources via IRI will inevitably receive escaped URI requests as
per the Gemini specification, the IRI and its escaped URI are ultimately equivalent. For example,
according to the fine-grained definitions in [RFC3986](https://tools.ietf.org/html/rfc3986), the
ASCII-US encoded URI `gemini://foo.bar/%C3%A4` technically refers to a set of two characters, `0xC3`
and `0xA4`. For all intents and purposes, these "two" characters denote the single character `ä`,
just as the IRI `gemini://foo.bar/ä` would. In the context of Lua (and I believe Gemini at large),
there is no a practical distinction to be made here. Thus, the use of IRIs by a server should not
cause incompatibility issues, provided clients do not ignore them altogether.

## Instructions for Use

### Compiling

A [package](https://aur.archlinux.org/packages/cpsula-git/) exists for Arch Linux, but the project
is simple enough that if you have `libevent`, `openssl`, and `lua` installed, `make` should compile
things without much hassle. The server binary, `cpsula`, is the default makefile target. See the
`install` rule for a basic installation.

For those who are (rightly) skeptical to run joe internet's code as root, the server can be
configured to run in a local directory. `CFG_SHARE_DIRECTORY` and `CFG_ETC_DIRECTORY` just need to
be pointed to a relative path when compiling, as do the paths specified in the config file. Of
course, it works just fine in a Docker image too.

### Configuration

Server configuration can be found in `/etc/cpsula/cpsula.conf`, or specified as a single argument to
`cpsula`, e.g. `cpsula local_config.conf`.

By default, the server is configured to generate a key and self-signed certificate for `localhost`.
This is fine for local testing, but in order to access your capsule from the internet, you'll want
to change the value for `<certificate_hostname>` to your server's public domain name. A key and
certificate will be generated for that domain automatically when the server is started next.
Generated keys / certificates can be found in
`/usr/share/cpsula/ssl/<certificate_hostname>.(pkey|cert)` and won't be deleted or overwritten.

Alternatively, you can specify an existing key or certificate to use with the `<private_key_file>`
and `<certificate_file>` fields. Files at these locations will not be generated or overwritten.

Next, by default, `cpsula` will attempt to switch user/group to `gemini-data` after initializing
SSL, and before starting the server. Either create this user and group or change `<user>` and
`<group>` to something else. If not running `cpsula` as root, then these must match the user and
group of the user who started cpsula. (Note that this runs the risk of leaking the private key!)

Finally, a suitable location to keep capsule data needs to be created and configured. This location
is specified by `<root_directory>` in the config file, and the default is `/var/gemini`. This is
also where a main file should be placed; the default in the config file is `main.lua`. See
[contrib/main.lua](contrib/main.lua) for an example. Both of these should be accessible to `<user>`.

### Running

If all goes well, you should see something similar to the following:

    # cpsula
    12:27:47 Reading configuration from /etc/cpsula/cpsula.conf
    12:27:47 Read private key from /usr/share/cpsula/ssl/xxxxxxxx.pkey
    12:27:47 Read certificate from /usr/share/cpsula/ssl/xxxxxxxx.cert
    12:27:47 Server listening on *:1965

To see the server in action, you'll need to get a Gemini browser. I use a terminal-based client
called [amfora](https://github.com/makeworld-the-better-one/amfora).

### Development

You can find documentation for how requests are handled in [contrib/main.lua](contrib/main.lua).
The main file is run in a standard Lua environment, so external packages can be `require`'d just
like normal. The only difference is, your script is run in a persistent sandbox directory, and all
of the details of hosting a Gemini server have already been taken care of. What you create from here
is up to you!

