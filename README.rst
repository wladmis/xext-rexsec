===========
XEXT-ALTSEC
===========

Xext-altsec or altsec or alternative X11 security module.

Altsec (alternative X11 security module) is an implementation of X11
client security isolation for X.org server and EWMH-compliant Window
managers. It aims to be practical and not to be general-purpose, so it
is not very flexible.  It is supposed to just work and requires a zero
or a very little configuration.

It aims to protect only the X11 resources of the clients and does not
handle other entities like filesystem access, etc. So for more complete
application isolation it should be used in conjunction with other
security mechanisms like UID-based separation, AppArmor, SELinux,
firejail, etc.

For installation and configuration please refer to the `BUILD AND
INSTALL`_ and `CONFIGURATION`_ sections.

.. contents:: **Table of contents**

DESIGN
======

(A bunch of hacks and workaround).

The idea of altsec is to have two types of X11 applications (clients in
terms of X11): trusted and confined. Trusted clients can do whatever
they want, while confined clients are restricted to their own resources
and a relatively safe set of operations, which are enough for modern
applications to run.  It may sound like a classical XSecurity extension,
but it is very different in details.  And these days, when this project
is written, XSecurity is absolutely unusable. The rules altsec is using
to mark clients as trusted or confined are described at `TRUSTED
CLIENTS`_ section.

Originally, I wrote it to address the following problems:

* Protecting the clipboard from being stolen by malicious clients.
* Preventing X11 clients and their environment from unauthorized
  screenshots.
* Safeguarding X11 client resources against theft or tampering by
  malicious clients.
* Shielding the environment from keyloggers and unauthorized event
  sending.

HOW IT WORKS
------------

This file provides a high level overview of how it works. To get more
specifics, please read the source code.

Originally altsec did X11 client separation based on their UIDs (user
identifier, specifically *effective UID*), where clients with one UID
could do almost anything with other clients with the same UID, but now
it implements an even more strict mode (policy), where confined clients
only can operate only with their own resources and have a limited
read-only access to some other resources.

All clients are divided into trusted and confined clients. See `TRUSTED
CLIENTS`_.

Altsec's lifetime modes are divided into several stages. When X starts,
altsec runs in the *insecure mode*, all clients started in this mode are
marked as *trusted*. This mode lasts until some Window Manager started.
After that altsec switches to the *secure mode*, and all clients started
in this mode are marked as *confined* by default.

Take a look to the following ``.xinitrc`` example::

    #/bin/sh

    # insecure mode
    xrdb ~/.Xresources
    xsetroot -gray
    xrandr -dpi 96

    eval $(ssh-agent)

    # Window manager (transition to secure mode after this command)
    somewm

There ``somewm`` is some window manager.

CONSIDERATIONS AND LIMITATIONS
------------------------------

It **does not** make X11 completely secure or X11 clients fully isolated!
It only makes them less transparent.

For now there is no way to temporarily allow confined clients to take a
screenshot or record a screen or do any other staff that only trusted
clients can do.

It is still in an **alpha** state, but nevertheless I use it every day,
so I consider it stable at least for my use-case.  To transfer its
status to at least **beta** I need to get some feedback, that means at
least to get one issue report and resolve it.

TRUSTED CLIENTS
---------------

The *trusted* clients--like regular X11 clients--can do almost anything.
Altsec marks a client as trusted in the following cases:

* the client was started during insecure mode;
* the client is a Window Manager;
* the client executable name was defined in the list of trusted clients
  (see `CONFIGURATION`_) and there are no other conditions why altsec
  should mark it as confined (see below);
* if ``strict mode`` is disabled (see `CONFIGURATION`_), and the client
  runs with the same EUID as the Window Manager's EUID (UID-based
  separation).

All other clients are marked as *confined*.

Also all clients are *always* marked as ``confined`` and **never** as
``trusted`` in the following cases:

* its EUID != EUID of the WM;
* its process runs on a remote host;
* its process runs inside a chroot (Linux-only for now);
* its process runs inside a non-initial user namespace (Linux-only).

CONFINED CLIENTS
----------------

*Confined clients* have full access only to their own resources, i.e.
windows, properties, etc. When a *confined client* creates a resource,
the resource is marked by altsec as belonging to the client. The client
can modify and destroy its own resources, and cannot do this to others
resources.

*Confined clients* also have read-only access to publicly available
resources. Generally, these resources are properties created by a Window
Manager that describe its behavior and available protocols.

Also *confined clients* can communicate with a Window Manager in order
to exercise their basic functionality: set their name, icon, wanted
windows size, hints, etc.

*Confined clients* have access to some relatively safe X11 protocol
extensions, but they can only get some non-sensitive information like
screen size (assume that it is not a secret), and cannot change X11
behavior or properties. No, *confined clients* **cannot** keylog user
input with help of XInputExtension.

There are also cases that are handled separately: refer to `CLIPBOARD
PROTECTION`_, `SELECTIONS HANDLING`_ and `SCREEN SHARING AND SCREEN
CASTING`_ for more information.

CLIPBOARD PROTECTION
--------------------

Altsec protects both primary selection and clipboard. Only those
confined clients whose window is in focus at the moment can read and
write to the clipboards. This is quite a simple technique but still it
can protect from some abuses.

Trusted clients have unlimited access to both primary selection and
clipboard.

If you want to use a clipboard manager, start it in insecure mode to
make it trusted, or add it to the list of trusted clients (see
`CONFIGURATION`_).

SELECTIONS HANDLING
-------------------

Not to be confused with clipboard selections, X11 selections is a
general X11 mechanism for inter-client communication. There are two
predefined selections in X11: primary and clipboard, altsec handles
those separately, please refer to `CLIPBOARD PROTECTION`_ for that.

The rest of selections are just allowed to all clients: I don't know
that to handle it properly, but on the other hand handling it wrong
could break many things, and I do not see any serious threats in
allowing them (I haven't meant to write a completely secure solution
anyway), given that the actual clients communication is done via
properties, not via the selection itself (see `PROPERTIES HANDLING`_).

PROPERTIES HANDLING
-------------------

With Altsec, the properties that are described by EWMH can be handled only
by a Window Manager or the window owner client, depending on the property.
To get more information please refer to the source code.

Any other properties are considered to be for selection usage (see
`SELECTIONS HANDLING`_), and the following rules apply:

* Any client can create and write a non-protected property to any other
  window of any other client (this action is considered safe, as it does
  not affect behavior).
* Only a window's owner and a client that created a property on that
  window can read or destroy the property (which provides confidentiality
  of inter-client communication).

SCREEN SHARING AND SCREEN CASTING
---------------------------------

Altsec makes client resources non-transparent for other clients, but
sometimes it can be a desired behavior, for example for a screen sharing
use case. For that, altsec provides an option that is called SpyMode
(disabled by default, see `CONFIGURATION`_) that temporarily gives a
client read-only access to all resources. If this option is enabled, you
can give the focused client that ability by pressing `CTRL-ALT-=`, and
revoke it by pressing `CTRL-ALT-SHIFT-=`.

BUILD AND INSTALL
=================

To build it you need to have a C99-compliant compiler (I'm sure you have
one), GNU Make, xorg-server's and libXext's development files. To build,
run the following command:

   $ make

And then run as root to install it:

   # make install

CONFIGURATION
=============

The module **will not be** loaded automatically, so you should create a
config file and at least put a ``Load "altsec"`` directive to load it.

Here is an example of 90-altsec.conf file, which should reside in
/etc/X11/xorg.conf.d/::

    Section "Module"
        Load "altsec"

        SubSection "altsec"
            # A list of clients that should be considered trusted when
            # started after secured phase.
            Option "TrustedClients" "dmenu:nm-applet:xkill:xlockmore:xrandr:xscreensaver:xsetroot:/usr/lib64/misc/ssh-askpass:/usr/libexec/at-spi2-registryd:/usr/libexec/gsd-power:/usr/libexec/gsd-xsettings"
            # Increase log level
            Option "LogLevel" "1"
        EndSubSection
    EndSection

All available options are described in the next subsection.

To ensure that the module is loading and running check the following
line in the Xorg.${DISPLAY#:}.log::

    Initializing extension ALTSecurity

AVAILABLE OPTIONS
-----------------

Here is a brief description of the available options:

================ ======================================================= =============
OPTION           DESCRIPTION                                             DEFAULT VALUE
================ ======================================================= =============
AllowedExts      A colon-separated list of extra allowed extensions      *None*
                 beyond defaults.

                 By default altsec allows to use a lot of relatively
                 safe extensions for all the clients to make modern
                 applications and toolkits work, but still not abuse the
                 rest of X11.

                 You probably do not need to change it.

LogLevel         Log level: 0: default, 1: INFO, 2: DEBUG, 3: TRACE      ``0``

Permanent        If false, altsec stops to work until a new WM starts.   ``True``

                 By default, altsec starts working in the secure mode
                 after a WM is started, and then works forever until an
                 X11 session ends.  In case if the WM was stopped or
                 crashed, there is no way to start a new WM again within
                 the current session.

                 You can disable this behavior, then in case the WM was
                 stopped or crashed altsec will allow to start a new WM.

SharedProps      A colon-separated list of shared properties.            *None*

                 By default, only clients who own the property and
                 trusted clients can manipulate it. Shared properties
                 are not handled by altsec, and any clients (trusted and
                 confined) can manipulate them.

                 Check ``Xorg.${DISPLAY#:}.log`` if you really need to
                 add them.

Strict           If false, a UID-based separation is used instead of     ``True``
                 client-based.

                 This is deprecated, option and will be deleted in the
                 future (i.e., it will be always ``True``).

TrustedClients   A colon-separated list of executables whose clients     *None*
                 should be marked as trusted.

                 By default, only clients that started at insecure phase
                 are marked as trusted. In the real usage you might need
                 to add some clients here. Please note that it is on you
                 to ensure that confined clients can not start trusted
                 clients as their children to abuse. The easiest way to
                 achieve this is to run all confined clients under user
                 namespace, i.e. confined via Flatpak, or firejail, etc.

                 You can provide a fullpath to an executable or a
                 relative path, resided in the ``$PATH`` of ``X`` server
                 process.

                 On Linux, every relative executable pathname provided
                 in the list is looked up in ``$PATH`` of ``X`` server
                 process, so that it can't be abused by creating a
                 malicious program with the same name. Every symlink is
                 also dereferenced when reading the configuration and
                 before matching.  If an executable does not start with
                 a *slash symbol* ``/``, then altsec looks up it in the
                 ``X`` server process ``$PATH``. If it does not reside
                 in the ``$PATH``, you should provide a full pathname to
                 the executable.

                 Linux-only for now.

TrustSUID        Treat set-uid processes as trusted. Disable it if you   ``True``
                 do not want such behavior, but for now there is no
                 other way to make set-uid application trusted.

                 Linux-only.

TrustSGID        The same as TrustSGID, but for set-gid application.     ``True``

                 Linux-only.

SpyMode          When enabled, allow to temporarily grant a client an    ``False``
                 ability to read other clients properties (but not to
                 change them) via following keypress combination:
                 ``Control-Alt-Equal (=)``. To revoke the ability, use
                 ``Control-Alt-Shift-Equal (=)``.
                 It can be useful for screen sharing.
                 There can be only one client in the SpyMode at a time.
================ ======================================================= =============

NOTE
====

AltSec **does not** handle operating system process execution tree, in
case of usage of trusted client list you have to make sure by yourself
that confined clients cannot run clients from the trusted client list.
The easiest way to achieve this is to run all confined client under user
namespace confinement (either via firejail, Flatpak, etc) or restrict
executables they can run with AppArmor/SELinux for example.

PERFORMANCE IMPACT
==================

I did not measure it.

FUTURE DEVELOPMENT
==================

I guess the future is for Wayland. This module is an attempt to make X11
less transparent and all-permissive for X11 clients and restrict them,
and I hope it can be useful for users who cannot switch to Wayland
for some reason.

I also have a couple of ideas for its improvement, like to make it able
to allow screenshots or screencasts in certain conditions for confined
clients (which is necessary for online video calls or streaming, for
example), or system tray handling.

Beside these, only code cleanup, refactoring, bug fixes and resolving
runtime issues with different WMs and workflows are expected.

BUGS
====

If you have found one, please report.

This module might break something. Feel free to open an issue or a PR,
or send me an email directly.

Some of the features are currently not available for systems other than
Linux.

It is intended to be used with simple WMs. It probably won't work with
big and complex DEs.

It probably does not cover some specific use-cases, so some things might
break.  If you are interested to use it and catch some problem, do not
hesitate to send me a message or help me with the code.

It is probably bypassable.

.. vim:filetype=rst textwidth=72:
