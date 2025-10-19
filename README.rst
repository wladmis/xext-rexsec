===========
XEXT-ALTSEC
===========

Xext-altsec or altsec or alternative X11 security module.

Altsec (alternative X11 security module) is an implementation of X11
client security isolation for X.org server and EWMH-compilant Window
managers. It aims to be practical and not to be general-purpose, so it
is not very flexible.  It is supposed to just work and requires a zero
or a very little configuration.

It aims to protect only clients X11 resources and does not handle other
entities like filesystem access, etc. So for more complete application
isolation it should be used in conjunction with other security
mechanisms like UID-based separation, AppArmor, SELinux, firejail, etc.

DESIGN
======

(A bunch of hacks and workaround).

The idea of altsec is to have two types of X11 applications (clients in
term of X11): trusted and confined. Trusted clients can do whatever they
want, while confined clients are restricted with its own resources and
a relatevely safe set of operations enough for modern applications to run.
It may sounds like a classical XSecurity extension, but it is very
different in details. And at these days when this project is written
XSecurity is absolutely unusable. The rules altsec is using to mark
clients as trusted or confined are described at `TRUSTED CLIENTS`_
section.

Altsec also protect both primary selection and clipboard in some manner
(see `CLIPBOARD PROTECTION`_) without any additional configuration.

HOW IT WORKS
------------

Originally altsec did X11 client separation based on their UIDs (user
identifier, specifically *effective UID*) where clients with one UID can
do almost anything with other clients with the same UID, but now there
is even more strict mode (policy) where confined clients only can do
anything with resources they own.

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

CONSIDIRATIONS AND LIMITATIONS
------------------------------

It **does not** make X11 completely secure or X11 clients fully isolated!
It only makes them less transparent.

For now there is no way to temporary allow confined clients to take a
screenshot or record a screen or do any other staff that only trusted
clients can do.

It is still in an **alpha** state, but nevertheless I use it every day,
so I consider it stable at least for my use-case.  To transfer its
status to at least **beta** I need to get some feedback, that means at
least to get one issue report and resolve it.

TRUSTED CLIENTS
---------------

The *trusted* cliens can do almost anything, like regular X11 clients do.
Altsec marks a client as trusted in the following cases:

* the client was started during insecure mode;
* the client is a Window Manager;
* the client executable name was defined in the list of trusted clients (see `CONFIGURATION`_) and there are no other conditions why altsec should mark it as confined (see below);
* if ``strict mode`` is disabled (see `CONFIGURATION`_), and the client runs with the same EUID as the Window Manager's EUID (UID-based separation).

All other clients are marked as *confined*.

Also all clients are *always* marked as ``confined`` and **never** as
``trusted`` in the following cases:

* its EUID != EUID of the WM;
* its process run on the remote host;
* its process run inside of chroot (Linux-only for now);
* its process run inside of non-initial user namespace (Linux-only).

CLIPBOARD PROTECTION
--------------------

Altsec protects both primary selection and clipboard. Only those
confined clients which window is in focus at the moment can read and
write to the clipboards. This is quite a simple technic but still it can
protect from some abuses.

Trusted clients have unlimited access to both primary selection and
clipboard.

If you want to use a clipboard manager, start it in insecure mode to
make it trusted.

BUILD AND INSTALL
=================

To build it you need to have a compiler that supported GNU99 extensions,
GNU Make, xorg-server's and libXext's development files.  To build, run
the following command:

   $ make

And then run as root to install it:

   # make install

CONFIGURATION
=============

The module will not be loaded automatically, so you should create a config
file and at least put a ``Load "altsec"`` directive to load it.

Here is an examplee of 90-altsec.conf file, which should reside in
/etc/X11/xorg.conf.d/::

    Section "Module"
        Load "altsec"

        SubSection "altsec"
            # This makes system tray work if you need it
            Option "SharedSelections" "_NET_SYSTEM_TRAY_S0"
            # A list of clients that should be considered trusted when
            # started after secured phase.
            Option "TrustedClients" "dmenu:xrandr:xsetroot:/usr/lib64/misc/ssh-askpass"
            # Increase log level
            Option "LogLevel" "1"
        EndSubSection
    EndSection

All available options are described in the next subsection.

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

Permanent        If false, altsec stops to work until a new WM started.  ``True``

                 By default, altsec starts working in the secure mode
                 after a WM is started, and then works forever until an
                 X11 session ends.  In case if the WM was stopped or
                 crushed, there is no way to start a new WM again within
                 a current session.

                 You can disable this behavior, then in case the WM was
                 stopped or crushed altsec will allow to start a new WM.

SharedProps      A colon-separated list of shared properties.            *None*

                 By default, only clients who owns the property and
                 trusted clients can manipulate it. Shared properties
                 are not handled by altsec and any clients (trusted and
                 confined) can manipulate them.

                 Check ``Xorg.${DISPLAY#:}.log`` if you really need to
                 add them.

SharedSelections A colon-separated list of shared selections.            *None*

                 The same as SharedProps, but for selections.
                 Do not confuse this with primary selection and
                 clipboard as altsec handles them separately.

Strict           If false, a UID-based separation is used instead of     ``True``
                 client-based.

TrustedClients   A colon-separated list of executables which clients     *None*
                 should be marked as trusted.

                 By default, only clients that started at insecure phase
                 are marked as trusted. In the real usage you might need
                 to add some clients here. Please note that it is on you
                 to ensure that confined clients could not start to
                 abuse trusted client as its children. The easiest way
                 to achieve this to run all confined clients under user
                 namespace, i.e. confined via Flatpak, or firejail, etc.

                 You can provide a fullpath to an executable or a
                 relative path (Linux-only), resided in the ``$PATH`` of
                 ``X`` server process.
                 On Linux, every relative executable pathname provided
                 in the list is looked up in ``$PATH`` of ``X`` server
                 process, that it can't be abused with creating a
                 malicious program with the similar name. On Linux,
                 every symlink  is also deferred before matching.
                 On Linux system, if an executable does not start with
                 a *slash symbol* ``/``, then altsec looks up it in the
                 ``X`` server process ``$PATH``. If it does not reside
                 in the ``$PATH``, you should add a full pathname to the
                 executable.

                 On non-Linux systems you should provide only full
                 pathname to the executable, any others will be ignored.
================ ======================================================= =============

NOTE
====

AltSec **does not** handle process tree execution, in case of usage of
trusted client list you have to make sure by yourself that confined
clients cannot run clients from the trusted client list. The easiest way
to achieve this to run all confined client under user namespace
confinement (either via firejail, Flatpak, etc) or restrict executables
they can run with AppArmor/SELinux for example.

PERFORMANCE IMPACT
==================

I did not measure it.

FUTURE DEVELOPMENT
==================

I guess the future is for Wayland. This module is an attempt to make X11
less transparent and all-permissive for X11 clients and restrict them,
and I hope it could be useful for users who cannot switch to Wayland
for some reason.

I have also a couple ideas for its improvement, like make it able to
allow screenshots or screencasts in certain conditions for confined
clients (which is necessary for online video calls or streaming, for
example), or system tray handling.

Beside these, only code cleanup, refactoring, bug fixes and resolving
runtime issues with different WMs and workflows are expected.

BUGS
====

If you found one, please report.

It might break something. Feel free to open an issue or a PR, or send me
an email directly.

Some of features are currently not available for systems other than
Linux.

It is intended to be used with simple WMs. It probably won't work with
big and complex DEs.

It probably does not cover some specific use-cases, so some things might
break.  If you are interested to use it and catch some problem, do not
hesitate to send me a message or help me with code.

It is probably bypassable.

.. vim:filetype=rst textwidth=72:
