#!/bin/bash
VERSION=$(cat ./VERSION)
VER="${VERSION}_$(date '+%Y%m%d%H%M%S')"
RELEASE="release-${VERSION}"
X="-X github.com/snail007/shadowtunnel/core.VERSION=$VER"
TRIMPATH1="/Users/snail/go/src/github.com/snail007"
TRIMPATH=$(dirname ~/go/src/github.com/snail007)/snail007
if [ -d "$TRIMPATH1" ];then
	TRIMPATH=$TRIMPATH1
fi
OPTS="-gcflags=-trimpath=$TRIMPATH -asmflags=-trimpath=$TRIMPATH"

rm -rf ${RELEASE}
mkdir ${RELEASE}

#linux
CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-386.tar.gz" shadowtunnel
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-amd64.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-arm-v6.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOARM=6 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-arm64-v6.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-arm-v7.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOARM=7 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-arm64-v7.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-arm-v5.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOARM=5 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-arm64-v5.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-arm64-v8.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=linux GOARCH=arm go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-arm-v8.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=linux GOARCH=mips go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-mips.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=linux GOARCH=mips64 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-mips64.tar.gz" shadowtunnel
CGO_ENABLED=0 GOOS=linux GOARCH=mips64le go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-mips64le.tar.gz" shadowtunnel
CGO_ENABLED=0 GOOS=linux GOARCH=mipsle go build -o shadowtunnel $OPTS -ldflags "-s -w $X"  && tar zcfv "${RELEASE}/shadowtunnel-linux-mipsle.tar.gz" shadowtunnel
CGO_ENABLED=0 GOOS=linux GOARCH=mips GOMIPS=softfloat go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-mips-softfloat.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=linux GOARCH=mips64 GOMIPS=softfloat go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-mips64-softfloat.tar.gz" shadowtunnel
CGO_ENABLED=0 GOOS=linux GOARCH=mips64le GOMIPS=softfloat go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-mips64le-softfloat.tar.gz" shadowtunnel
CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-mipsle-softfloat.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=linux GOARCH=ppc64 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-ppc64.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=linux GOARCH=ppc64le go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-ppc64le.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=linux GOARCH=s390x go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-linux-s390x.tar.gz" shadowtunnel 
#android
CGO_ENABLED=0 GOOS=android GOARCH=386 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-android-386.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=android GOARCH=amd64 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-android-amd64.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=android GOARCH=arm go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-android-arm.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-android-arm64.tar.gz" shadowtunnel 
#darwin
CGO_ENABLED=0 GOOS=darwin GOARCH=386 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-darwin-386.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-darwin-amd64.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=darwin GOARCH=arm go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-darwin-arm.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-darwin-arm64.tar.gz" shadowtunnel 
#dragonfly
CGO_ENABLED=0 GOOS=dragonfly GOARCH=amd64 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-dragonfly-amd64.tar.gz" shadowtunnel 
#freebsd
CGO_ENABLED=0 GOOS=freebsd GOARCH=386 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-freebsd-386.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-freebsd-amd64.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=freebsd GOARCH=arm go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-freebsd-arm.tar.gz" shadowtunnel 
#nacl
CGO_ENABLED=0 GOOS=nacl GOARCH=386 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-nacl-386.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=nacl GOARCH=amd64p32 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-nacl-amd64p32.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=nacl GOARCH=arm go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-nacl-arm.tar.gz" shadowtunnel 
#netbsd
CGO_ENABLED=0 GOOS=netbsd GOARCH=386 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-netbsd-386.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=netbsd GOARCH=amd64 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-netbsd-amd64.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=netbsd GOARCH=arm go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-netbsd-arm.tar.gz" shadowtunnel 
#openbsd
CGO_ENABLED=0 GOOS=openbsd GOARCH=386 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-openbsd-386.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=openbsd GOARCH=amd64 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-openbsd-amd64.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=openbsd GOARCH=arm go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-openbsd-arm.tar.gz" shadowtunnel 
#plan9
CGO_ENABLED=0 GOOS=plan9 GOARCH=386 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-plan9-386.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=plan9 GOARCH=amd64 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-plan9-amd64.tar.gz" shadowtunnel 
CGO_ENABLED=0 GOOS=plan9 GOARCH=arm go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-plan9-arm.tar.gz" shadowtunnel 
#solaris
CGO_ENABLED=0 GOOS=solaris GOARCH=amd64 go build -o shadowtunnel $OPTS -ldflags "-s -w $X" && tar zcfv "${RELEASE}/shadowtunnel-solaris-amd64.tar.gz" shadowtunnel 
#windows
CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -o shadowtunnel-noconsole.exe
CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -o shadowtunnel.exe && tar zcfv "${RELEASE}/shadowtunnel-windows-386.tar.gz" shadowtunnel.exe shadowtunnel-noconsole.exe
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o shadowtunnel-noconsole.exe
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o shadowtunnel.exe && tar zcfv "${RELEASE}/shadowtunnel-windows-amd64.tar.gz" shadowtunnel.exe shadowtunnel-noconsole.exe

rm -rf shadowtunnel shadowtunnel.exe shadowtunnel-noconsole.exe

