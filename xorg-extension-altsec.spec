Name: xorg-extension-altsec
Version: 0.0.1
Release: alt1

Summary: ALT X11 security extension

License: MIT/X11
Group: Other
#Url: 

Source: %name-%version.tar

BuildRequires(pre): xorg-sdk xorg-util-macros
BuildRequires: libXext-devel xorg-proto-devel

%description
%summary.

%prep
%setup

%build
make

%install
install -m644 altsec.so -D %buildroot%_x11modulesdir/extensions/altsec.so

%files
%_x11modulesdir/extensions/altsec.so

%changelog
