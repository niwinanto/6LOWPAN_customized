#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <assert.h>

#define READ(i) if(read(fd,str,i)<0)fputs("read() failed!\n",stderr)
#define MAX_SIZE 88
/*dispatch header fields*/
#define NALP 0xc0
#define UC_IPv6 0x41
#define LOWPAN_HC1 0x42
#define LOWPAN_BC0 0x50
#define ESC 0x7f
#define MESH 0x80
#define FRAG1 0xc0
#define FRAGN 0xe0

/*HC1_encoding header fields*/
#define HC1_PIIC_s 0x40
#define HC1_PCII_s 0x80
#define HC1_PCIC_s 0xc0
#define HC1_PIIC_d 0x10
#define HC1_PCII_d 0x20
#define HC1_PCIC_d 0x30
#define HC1_Tclass 0x08
#define HC1_UDP 0x02
#define HC1_ICMP 0x04
#define HC1_TCP 0x06
#define HC1_HC2EN 0x01

/*HC_UDP header fields*/
#define HC_UDP_s 0x80
#define HC_UDP_d 0x40
#define HC_UDP_len 0x20


int open_port(void)
{
    int fd;
    fd = open("/dev/ttyUSB0", O_RDWR | O_NOCTTY | O_NDELAY);
    if(fd == -1)
        perror("open_port: Unable to open /dev/ttyUSB0  ");

    else
        fcntl(fd, F_SETFL, 0);

    return (fd);
}


int read_port(int fd){
    char *str;
    char buffer[MAX_SIZE];
    int n=0;

    while(1){

        READ(1);
        buffer[n++]=*str;
        assert(!(*str & NALP));
        if(*str & LOWPAN_HC1){
            /*It is a HC1 compressed packet*/
            READ(1);
            buffer[n++]=*str;
        }
        else{
            /*It is a HC1 uncompressed packet*/
        }

    }
    return 1;
}

int main(int argc, char *argv[]){
    int y,x;
    x=open_port();
    y=read_port(x);
}
