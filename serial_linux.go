//go:build linux

package main

import "golang.org/x/sys/unix"

var serialPatterns = []string{"/dev/ttyACM*", "/dev/ttyUSB*"}

const (
	ioctlGetTermios = unix.TCGETS
	ioctlSetTermios = unix.TCSETS
)

func makeRaw115200(t *unix.Termios) {
	t.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON | unix.IXOFF | unix.IXANY
	t.Oflag &^= unix.OPOST
	t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	t.Cflag &^= unix.CSIZE | unix.PARENB | unix.CSTOPB | unix.CRTSCTS | unix.CBAUD
	t.Cflag |= unix.CS8 | unix.CREAD | unix.CLOCAL | unix.B115200
	t.Cc[unix.VMIN] = 1
	t.Cc[unix.VTIME] = 0
	t.Ispeed = unix.B115200
	t.Ospeed = unix.B115200
}
