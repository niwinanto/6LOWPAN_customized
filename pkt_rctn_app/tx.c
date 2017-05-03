#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/ioctl.h>
int open_port(void)
{
    int fd;
    fd = open("/dev/ttyUSB1", O_RDWR | O_NOCTTY | O_NDELAY);
    if(fd == -1)
        perror("open_port: Unable to open /dev/ttyS0 − ");

    else
        fcntl(fd, F_SETFL, 0);
    return (fd);

}
int write_port(int fd){
    int n;
    char c[80];
    c[0]=0x8e;c[1]=0xb0; c[2]=0xb0; c[3]=0xb0; c[4]=0xb0;
    c[5]=0xc0;c[6]=0x05; c[7]=0xb0; c[8]=0xb0; c[9]=0x00;
    c[10]=0x42;c[11]=0xfb; c[12]=0xb0; c[13]=0xe0; c[14]=0xb0;
    c[15]=0xb0;c[16]=0xb0; c[17]=0xb0; c[18]=0xb0; c[19]=0xb0;
    c[20]=0xb0;c[21]=0x00; c[22]=0x00;c[23] = 0xb0; c[24]=0xb0; c[25]=0xb0;
    c[26]=0xb0;c[27]=0xb0; c[28]=0xb0; c[29]=0xb0; c[30]=0xb0;
    c[31]=0xb0;c[32]=0xb0; c[33]=0xb0; c[34]=0xb0; c[35]=0xb0;
    c[36]=0xb0;c[37]=0xb0; c[38]=0xb0; c[39]=0xb0; c[40]=0xb0;
    int i;
    for(i=0;i<23;i++){
    //sleep(1);

        n = write(fd,c+i,1);
        printf("%x\n",c[i]);
    if(n<0)
        fputs("write() of 4 bytes failed!\n", stderr);

    }
    return 1;

}

int main(int argc, char *argv[]){
    int y,x=open_port();
        y=write_port(x);
    }
