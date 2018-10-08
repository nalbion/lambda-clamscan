#!/bin/bash

set -e

pushd /tmp
echo http_proxy=http://zsproxysw.internal.justice.nsw.gov.au:80 >> /etc/yum.conf
echo proxy=http://zsproxysw.internal.justice.nsw.gov.au:80 >> /etc/yum.conf
echo sslverify=false >> /etc/yum.conf
#yum install -y pcre.x86_64
rpm --httpproxy=http://zsproxysw.internal.justice.nsw.gov.au:80 -Uvha http://download.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm
sed -i 's/^\(enabled\s*=\s*\).*$/\10/' /etc/yum.repos.d/epel.repo
yum install -y yum-utils
yumdownloader -x \*i686 --archlist=x86_64 --enablerepo=epel clamav clamav-lib clamav-update
echo "downloaded:"
ls -al
rpm2cpio clamav-0*.rpm | cpio -idmv
#rpm2cpio clamav-lib*.rpm | cpio -idmv
#rpm2cpio clamav-update*.rpm | cpio -idmv
echo "extracted:"
ls -al /tmp/usr/bin/
ls -al /tmp/usr/lib64/
popd
#mkdir -p bin
echo "copying libs..."
cp /tmp/usr/bin/clamscan /tmp/usr/bin/freshclam /tmp/usr/lib64/* lib

#yum install -y --enablerepo=epel pcre clamav clamav-lib clamav-update
#ls -al /usr/lib
#echo "copying libs........."
#cp /usr/lib/libclamav.so.7 lib
#cp /lib/x86_64-linux-gnu/libcrypto.so.1.0.0 lib
#cp /usr/lib/x86_64-linux-gnu/libmspack.so.0 lib
#cp /lib/x86_64-linux-gnu/libbz2.so.1.0 lib
#cp /usr/lib/x86_64-linux-gnu/libLLVM-3.6.so.1 lib
#cp /lib/x86_64-linux-gnu/libssl.so.1.0.0 lib
#cp /lib/x86_64-linux-gnu/libjson-c.so.2 lib
#cp /lib/x86_64-linux-gnu/libpcre.so.3 lib
#cp /usr/lib/x86_64-linux-gnu/libedit.so.2 lib
#cp /lib/x86_64-linux-gnu/libbsd.so.0 lib
#ls -al lib
#echo "DatabaseMirror database.clamav.net" > bin/freshclam.conf
