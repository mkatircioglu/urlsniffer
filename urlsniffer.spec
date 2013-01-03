%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}
%define name urlsniffer
%define version 0.0.3
%define release 1

Summary: Url sniffing daemon
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{version}.tar.gz
License: GNU GPL2
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Vendor: Mete Alpaslan Katircioglu <mete@katircioglu.net>
Url: http://mkatircioglu.github.com
BuildRequires:  python-devel python-setuptools
BuildRequires:  pcapy, pcapy
Requires:       python

%description
Url sniffing daemon

%prep
%setup -q -n %{name}-%{version}

%build
%{__python} setup.py build

%install
rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install \
        -O1 --skip-build \
        --root=$RPM_BUILD_ROOT \
        --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)
%{_bindir}/urlsniffer
%{_sysconfdir}/%{name}.conf
%{python_sitelib}/urlsniffer

%changelog
* Thu Sep 01 2013 Mete Alpaslan Katircioglu <mete@katircioglu.net> - UrlSniffer1.0.3
  - Multi-processing support and python 2.6 version dependency removed.
  - Pcapy dependency added.
