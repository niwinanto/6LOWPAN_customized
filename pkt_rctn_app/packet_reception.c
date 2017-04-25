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

struct lowpan_hdr{
    char *mtype,*m_saddr,*m_daddr;
    char *ftype,*data_size,*data_tag,*data_offst;
    char *dispatch;
    char *hc1;
    char *hope;
    char *hc2;
    char *udp_src,*udp_dst,*udp_len,*udp_cksm;

}hdr;
/*dispatch header fields*/
#define NALP 0xc0
#define UC_IPv6 0x41
#define LOWPAN_HC1 0x42
#define LOWPAN_BC0 0x50
#define ESC 0x7f
#define MESH 0x80
#define FRAG1 0xc0
#define FRAGN 0xe0
#define HC 0x40
#define FRAG 0xc0
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
    char *str,c;
    char buffer[MAX_SIZE];
    int n=0,i;

    while(1){

        READ(1);
        buffer[n++]=*str;
        assert(!(*str & NALP));

        if((c=(*str & MESH)) == MESH){
            hdr.mtype = buffer + n - 1;
            READ(1);
            buffer[n++]=*str; //8bit mesh encoded header
            hdr.m_saddr = buffer + n - 1;
            if(*hdr.mtype & 0x20){
                READ(1);
                buffer[n++]=*str;
            }
            else{
                for(i=0;i<7;i++){
                    READ(1);
                    buffer[n++]=*str;
                }
            }
            READ(1);
            buffer[n++]=*str; //8bit mesh encoded header
            hdr.m_daddr = buffer + n - 1;
            if(*hdr.mtype & 0x10){
                READ(1);
                buffer[n++]=*str;
            }
            else{
                for(i=0;i<7;i++){
                    READ(1);
                    buffer[n++]=*str;
                }
            }
            READ(1);
            buffer[n++]=*str;
        }
        if((c=(*str & FRAG)) == FRAG){
            hdr.ftype = buffer + n - 1;
            READ(1);
            buffer[n++]=*str; //11bit datagram size
            hdr.data_size = buffer + n - 1;
            READ(1);
            buffer[n++]=*str; //16bit datagram tag-1
            hdr.data_tag = buffer + n - 1;
            READ(1);
            buffer[n++]=*str; //16bit datagram tag-2
            READ(1);
            buffer[n++]=*str; //8bit datagram offset
            hdr.data_offst = buffer + n - 1;
            READ(1);
            buffer[n++]=*str;
        }
        if((c = (*str & HC)) == HC){
            hdr.dispatch = buffer + n - 1;
        }


        if(*hdr.dispatch & LOWPAN_HC1){
            /*It is a HC1 compressed packet*/
            READ(1);
            buffer[n++]=*str; //8bit HC1 encoded header
            hdr.hc1 = buffer + n - 1;

            READ(1);
            buffer[n++]=*str; //8bit hope  header
            hdr.hope = buffer + n - 1;

            if(*hdr.hc1 & HC1_HC2EN){
                /*HC2 compressed packet*/

                /////////////////////////
                if((c=(*hdr.hc1 & HC1_TCP)) == HC1_TCP ){
                    /*8bit HC2_TCP encoded header*/
                }
                else if((c=(*hdr.hc1 & HC1_UDP)) == HC1_UDP ){
                    /*8bit HC2_UDP encoded header*/
                    READ(1);
                    buffer[n++]=*str; //8bit HC2 encoded header
                    hdr.hc2 = buffer + n - 1;
                    if(*hdr.hc2 & HC_UDP_s){
                        READ(1);
                        buffer[n++]=*str; //4bit UDP source addr
                        hdr.udp_src = buffer + n - 1;
                    }
                    else{
                        READ(1);
                        buffer[n++]=*str; //16bit UDP source addr-1
                        hdr.udp_src = buffer + n - 1;
                        READ(1);
                        buffer[n++]=*str; //16bit UDP source addr-2
                    }
                    if(*hdr.hc2 & HC_UDP_d){
                        READ(1);
                        buffer[n++]=*str; //4bit UDP source addr
                        hdr.udp_dst = buffer + n - 1;
                    }
                    else{
                        READ(1);
                        buffer[n++]=*str; //16bit UDP destination addr-1
                        hdr.udp_dst = buffer + n - 1;
                        READ(1);
                        buffer[n++]=*str; //16bit UDP destination addr-2
                    }
                    if(!(*hdr.hc2 & HC_UDP_len)){
                        READ(1);
                        buffer[n++]=*str; //16bit UDP length -1
                        hdr.udp_len = buffer + n - 1;
                        READ(1);
                        buffer[n++]=*str; //16bit UDP length -2
                    }
                    READ(1);
                    buffer[n++]=*str; //16bit UDP checksum -1
                    hdr.udp_cksm = buffer + n - 1;
                    READ(1);
                    buffer[n++]=*str; //16bit UDP checksum -2
                }
                else if((c=(*hdr.hc1 & HC1_ICMP)) == HC1_ICMP){
                    /*8bit HC2_*/
                }
                else{
                    /*reserved */
                }
                //////////////////////////
            }
            else{
                /*HC2 uncompressed packet*/
            }
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
