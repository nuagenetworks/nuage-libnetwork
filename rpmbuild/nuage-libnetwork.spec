%define libnetwork_nuage_binary   nuage-libnetwork
%define libnetwork_nuage_service  nuage-libnetwork.service
%define libnetwork_nuage_yaml   nuage-libnetwork.yaml
%define libnetwork_nuage_service_file scripts/nuage-libnetwork.service
%undefine _missing_build_ids_terminate_build

Name: nuage-libnetwork
Version: %{version}
Release: 1%{?dist}
Summary: Nuage Libnetwork Plugin
Group: System Environments/Daemons  
License: ALU EULA and ASL 2.0   
Source0: nuage-libnetwork-%{version}.tar.gz

BuildRequires:  %{?go_compiler:compiler(go_compiler)}%{!?go_compiler:golang}

%description
%{summary}

%prep
%setup -q

%build

%pre
if [ "$1" = "2" ]; then
    cp $RPM_BUILD_ROOT/etc/default/%{libnetwork_nuage_yaml} $RPM_BUILD_ROOT/etc/default/%{libnetwork_nuage_yaml}.orig
fi

%install
install --directory $RPM_BUILD_ROOT/usr/bin
install --directory $RPM_BUILD_ROOT/etc/default
install --directory $RPM_BUILD_ROOT/etc/systemd/system

install -m 755 %{libnetwork_nuage_binary} $RPM_BUILD_ROOT/usr/bin
install -m 755 %{libnetwork_nuage_service_file} $RPM_BUILD_ROOT/etc/systemd/system/%{libnetwork_nuage_service}
install -m 644 %{libnetwork_nuage_yaml}.template $RPM_BUILD_ROOT/etc/default/%{libnetwork_nuage_yaml}

%post
if [ "$1" = "2" ]; then
    mv $RPM_BUILD_ROOT/etc/default/%{libnetwork_nuage_yaml}.orig $RPM_BUILD_ROOT/etc/default/%{libnetwork_nuage_yaml}
fi
systemctl enable %{libnetwork_nuage_binary}

%preun
if [ "$1" = "0" ]; then
    systemctl stop %{libnetwork_nuage_binary}
    systemctl disable %{libnetwork_nuage_binary}
fi

%clean
rm -rf $RPM_BUILD_ROOT

%files

/usr/bin/%{libnetwork_nuage_binary}
/etc/systemd/system/%{libnetwork_nuage_service}
%attr(644, root, nobody) /etc/default/%{libnetwork_nuage_yaml} 
%doc

%changelog
