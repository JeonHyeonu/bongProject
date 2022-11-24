#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// SQL
#include <my_global.h>
#include <mysql.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
//#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <time.h>
#include <math.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <netdb.h>

#define SUPPORT_OUTPUT


//----------------------------------------------------
// 이더넷, IP, TCP포트의 구조체들 선언 
#define ETHER_ADDR_LEN   6
/* 이더넷 헤더의 정보를 담을 구조체 */
struct sniff_ethernet {
   u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
   u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
   u_short ether_type; /* IP? ARP? RARP? etc */
};


/* IP 헤더의 정보를 담을 구조체  */
struct sniff_ip {
   u_char ip_vhl;      /* version << 4 | header length >> 2 */
   u_char ip_tos;      /* type of service */
   u_short ip_len;      /* total length */
   u_short ip_id;      /* identification */
   u_short ip_off;      /* fragment offset field */
#define IP_RF 0x8000      /* reserved fragment flag */
#define IP_DF 0x4000      /* don't fragment flag */
#define IP_MF 0x2000      /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
   u_char ip_ttl;      /* time to live */
   u_char ip_p;      /* protocol */
   u_short ip_sum;      /* checksum */
   struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)      (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)      (((ip)->ip_vhl) >> 4)


/* TCP포트 헤더의 정보를 담을 구조체 */
typedef u_int tcp_seq;

struct sniff_tcp {
   u_short th_sport;   /* source port */
   u_short th_dport;   /* destination port */
   tcp_seq th_seq;      /* sequence number */
   tcp_seq th_ack;      /* acknowledgement number */
   u_char th_offx2;   /* data offset, rsvd */
#define TH_OFF(th)   (((th)->th_offx2 & 0xf0) > 4)
   u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
   u_short th_win;      /* window */
   u_short th_sum;      /* checksum */
   u_short th_urp;      /* urgent pointer */
};



struct pseudohdr {
        u_int32_t   saddr;
        u_int32_t   daddr;
        u_int8_t    useless;
        u_int8_t    protocol;
        u_int16_t   tcplength;
};


struct struct_bong_pkdb{ //구조체 형태로 내가 만든 DB데이터의 정보를담을 변수를 선언
   int id;
   char Created_at[100];
   char Source[100];
   char Destination[100];
   char Domain[256];
};


struct struct_blk_site{
   int id;
   char Created_at[100];
   char Domain[256];
   char Comment[100];
};


//전역 변수
MYSQL *con;

//char if_bind_global[] = "enp0s3" ;
char if_bind_global[] = "lo" ;
//int if_bind_global_len = 6 ;
int if_bind_global_len = 2 ;

int sendraw_mode = 1;

struct struct_bong_pkdb *bong_pkdb;
struct struct_blk_site *blk_site;
int bong_pkdb_cnt, blk_site_cnt;


//본격적이 패킷잡는 함수 선언
void packet_catch(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int print_chars(char print_char, int nums);

void
print_payload(const u_char *payload, int len);

void
print_payload_right(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_hex_ascii_line_right(const u_char *payload, int len, int offset);

unsigned short in_cksum(u_short *addr, int len);

int sendraw ( u_char* pre_packet, int mode );


int main(int argc,char *argv[])
{
   
   pcap_t *handle;                
   char * dev;                   
   char errbuf[PCAP_ERRBUF_SIZE];       
   struct bpf_program fp;            
   char filter_exp[] = "dst port 80";      
   bpf_u_int32 my_net;               
   bpf_u_int32 my_mask;            
   struct pcap_pkthdr;               
   const u_char *packet;             
   
   
   MYSQL_RES *res_bong; 
   MYSQL_ROW row_bong;
   
   int ret_bong;
   
   con = mysql_init(NULL);
   
   
   if(mysql_real_connect(con,"127.0.0.1","bongbong","1128","BONG_PACKET_DB",3306,NULL,0) == NULL)
   {
      printf("ERROR : SQL 연동에 문제가 발생했습니다.\n");
      printf("%s\n", mysql_error(con));
      exit(1);
   }
   
   printf("SQL 연결에 성공하였습니다!\n");
   
   
   
   ret_bong = mysql_query(con, "SELECT COUNT(*) FROM Block_site;");
   if ( ret_bong != 0 ) {
      printf("에러 발생: query가 갯수를 조회하지 않았습니다!!!");
   }
   
   res_bong = mysql_store_result(con);
   row_bong = mysql_fetch_row(res_bong);
   blk_site_cnt = atoi(row_bong[0]);
   

   ret_bong = mysql_query(con, "SELECT * FROM Block_site;");
   if ( ret_bong != 0 ) {
      printf("에러 발생: query가 테이블을 조회하지 않았습니다!!!");
   }
   
   res_bong = mysql_store_result(con);
   
   
      blk_site = malloc(sizeof(struct struct_blk_site) * blk_site_cnt);
     if ( blk_site == NULL ) {
        printf("ERROR : Block_site 메모리를 초기화 하지못했습니다!(cnt=%d)\n", blk_site_cnt);
        exit(1);
     } else {
        printf("INFO: Block_site 메모리 초기화를 성공했습니다 (cnt=%d)\n", blk_site_cnt);
     }
     
   
     int j=0;
     
     while ( row_bong = mysql_fetch_row(res_bong) )
     {
      printf("  등록 시간: Created_at = %s\n" , row_bong[1]);
        printf("  도메인 정보: Domain = %s\n" , row_bong[2]);
        printf("  사이트 정보: Comment = %s\n\n" , row_bong[3]);
        
        //blk_site[j].id = atoi(row_bong[0]);
        
        //strcpy( blk_site[j].Created_at , row_bong[1] );
        
        strcpy( blk_site[j].Domain , row_bong[2] );
        
        
        j++;
     }
   
   
   dev = pcap_lookupdev(errbuf); 
   if(dev == NULL){
      fprintf(stderr, "디바이스 정보를 찾을 수 없습니다 : %s\n",errbuf);
      return 2;
   }
   
   strcpy(dev , "lo");
   
   if(pcap_lookupnet(dev, &my_net, &my_mask, errbuf) == -1) {
      fprintf(stderr, "ip주소 및 서브넷 마스크 주소를 찾을 수 없습니다. : %s\n",errbuf);
      return 2;
   }
   
   

   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if(handle == NULL){
      fprintf(stderr, "디바이스를 열 수 없습니다 %s : %s\n",dev,errbuf);
      return 2;
   }
   

   if(pcap_compile(handle, &fp, filter_exp, 0, errbuf) == -1) {
      fprintf(stderr, "필터 %s를 구간을 분석 할 수 없습니다 : %s\n", filter_exp, pcap_geterr(handle));
      return 2;
   }
   


   if (pcap_setfilter(handle, &fp) == -1) {
      fprintf(stderr, "필터를 설치 할 수 없습니다 %s: %s\n",filter_exp, pcap_geterr(handle));
      return 2;
   }

   printf("스니핑 작업을 시작합니다 \n");

   pcap_loop(handle, 0, packet_catch, NULL);
   
   
   pcap_close(handle); 
   handle = NULL;
   
   if(handle != NULL){
      printf("INFO : 핸들이 종료되지 않았습니다!\n");
      pcap_close(handle);
   } else 
      printf("WARN : 핸들이 정상 종료 되었습니다.\n");
      
   mysql_close(con);
   con = NULL;
   
   if(con !=NULL){
      printf("INFO : SQL핸들이 종료되지 않았습니다!\n");
      mysql_close(con);
   } else
      printf("WARN : SQL핸들이 정상 종료 되었습니다.\n");
      
   return 0;
}



void packet_catch(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
   
#define SIZE_ETHERNET 14 


   const struct sniff_ethernet *ethernet; 
   const struct sniff_ip *ip; 
   const struct sniff_tcp *tcp; 
   const char *payload; 


   u_int size_ip;
   u_int size_tcp;


   ethernet = (struct sniff_ethernet*)(packet); 
   
   
   ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
   size_ip = IP_HL(ip)*4;
   if (size_ip < 20) { 
      printf("   * Invalid IP header length: %u bytes\n", size_ip);
      return;
   }
   

   tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
   
   size_tcp = 20;
   if (size_tcp < 20) {
      printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
      return;
   }
   char ip_dst[100];
   memset(&ip_dst,0,100);
   strcpy(ip_dst,inet_ntoa(ip->ip_dst));
   
   payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
   
   
   
   char* line_data; 
   char* line_start; 
   char* line_end; 
   int line_len = 0; 
   int while_con1 = 1; 
   char domain[256];
   int target;
   int ret = 0;
   
   line_start = payload; 
   
   line_data = malloc(1000); 
   
   while ( while_con1 > 0 ) {
      line_end = strstr(line_start , "\x0d\x0a"); 
      if ( line_end == NULL ) {
         while_con1 = 0;
      } else {
         line_len = line_end - line_start ;
         
         memset(line_data , 0x00 , 1000 );
         
         strncpy(line_data , line_start , line_len); 
         
               
         if ( strncmp( line_data , "Host: " , 6 ) == 0 ) {
            printf("NOTICE: Host http header found .\n");
            memset(&domain, 0, 256);
            strcpy(domain,line_data + 6 );
            printf("찾은 도메인 : domain = %s \n",domain);
            
            
            int matched_cnt = 0; //도메인의 일치 결과를 확인하려고 만든변수
            for (int k = 0; k < blk_site_cnt; k++ ) {
            
               if (strcmp( domain , blk_site[k].Domain ) == 0 ){
               
               matched_cnt++; 
               }
            }
            
         
            if ( matched_cnt > 0 ) {
         
               printf("INFO: 유해 사이트가 감지 되었습니다!!!\n");
               printf("INFO: 차단 패킷을 생성합니다. \n");
               
               int sendraw_result = 0;
               
               sendraw_result = sendraw(packet, 1);
               if ( sendraw_result == 1 ) {
                  printf("INFO: 차단 패킷을 생성을 완료했습니다 (%d) .\n", sendraw_result);
               } else {
                  printf("ERROR: sendraw의 값에 문제가 생겼습니다!!!(%d) \n", sendraw_result);
               }
               
            } else {
               printf("INFO: 문제가 발견 되지 않았습니다.\n");
            
            }
            
            
         
            char insert_query[10240];
            memset(&insert_query, 0x00 , 10240);
            sprintf (&insert_query, "INSERT INTO paket_log "
             " ( Source, Destination, Domain )  values ('%s','%s','%s')",
             inet_ntoa(ip->ip_src),ip_dst,domain);
            ret = mysql_query(con, insert_query);
            
            if (ret != 0) {
               printf("ERROR: SQL query 실행되지 않았습니다.. (%s).\n",
                  mysql_error(con));
            } else {
               printf("INFO: 해당 패킷 로그를 저장했습니다.\n\n");
            }
            
         }
         line_start = line_end + 2 ;
      }
   }
   
   free(line_data);
}


int sendraw( u_char* pre_packet, int mode)
{
      const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */

      u_char packet[1600];
        int raw_socket, recv_socket;
        int on=1, len ;
        char recv_packet[100], compare[100];
        struct iphdr *iphdr;
        struct tcphdr *tcphdr;
        struct in_addr source_address, dest_address;
        struct sockaddr_in address, target_addr;
        struct pseudohdr *pseudo_header;
        struct in_addr ip;
        struct hostent *target;
        int port;
        int loop1=0;
        int loop2=0;
        int pre_payload_size = 0 ;
      u_char *payload = NULL ;
      int size_vlan = 0 ;
      int size_vlan_apply = 0 ;
      int size_payload = 0 ;
        int post_payload_size = 0 ;
        int sendto_result = 0 ;
       int rc = 0 ;
       //struct ifreq ifr ;
      char * if_bind ;
      int if_bind_len = 0 ;
      int setsockopt_result = 0 ;
      int prt_sendto_payload = 0 ;
      char* ipaddr_str_ptr ;

      int warning_page = 1 ;
      int vlan_tag_disabled = 0 ;

      int ret = 0 ;
//#ifdef : 조건식인데 만약 ~이 정의가 되었냐를 묻는 조건식
//SUPPORT_OUTPUT이 정의가 되었다면 해당 문구를 실행합니다.
      #ifdef SUPPORT_OUTPUT 
      print_chars('\t',6);
      printf( "\n[raw socket sendto]\t[start]\n\n" );

      if (size_payload > 0 || 1) {
         print_chars('\t',6);
         printf("   pre_packet whole(L2-packet-data) (%d bytes only):\n", 100);
         print_payload_right(pre_packet, 100);
      }
      //m-debug
      printf("DEBUG: (u_char*)packet_dmp ( in sendraw func ) == 0x%p\n", pre_packet);
      #endif

        for( port=80; port<81; port++ ) {
         #ifdef SUPPORT_OUTPUT
         print_chars('\t',6);
         printf("onetime\n");
         #endif
         // raw socket 생성
         raw_socket = socket( AF_INET, SOCK_RAW, IPPROTO_RAW );
         if ( raw_socket < 0 ) {
            print_chars('\t',6);
            fprintf(stderr,"Error in socket() creation - %s\n", strerror(errno));
            fprintf(stderr,"Error in socket() creation - %s\n", strerror(errno));
            return -2;
         }

         setsockopt( raw_socket, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on));

         if ( if_bind_global != NULL ) {
            setsockopt_result = setsockopt( raw_socket, SOL_SOCKET, SO_BINDTODEVICE, if_bind_global, if_bind_global_len );

            if( setsockopt_result == -1 ) {
               print_chars('\t',6);
               fprintf(stderr,"ERROR: setsockopt() - %s\n", strerror(errno));
               return -2;
            }
            #ifdef SUPPORT_OUTPUT
            else {
               print_chars('\t',6);
               fprintf(stdout,"OK: setsockopt(%s)(%d) - %s\n", if_bind_global, setsockopt_result, strerror(errno));
            }
            #endif

         }

         ethernet = (struct sniff_ethernet*)(pre_packet);
         if ( ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x81\x00" ) {
            #ifdef SUPPORT_OUTPUT
            printf("vlan packet\n");
            #endif
            size_vlan = 4;
            memcpy(packet, pre_packet, size_vlan);
         } else if (ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x08\x00" ) {
            #ifdef SUPPORT_OUTPUT
            printf("normal packet\n");
            #endif
            size_vlan = 0;
         } else {
            fprintf(stderr,"NOTICE: ether_type diagnostics failed .......... \n");
         }

         vlan_tag_disabled = 1 ;
         if ( vlan_tag_disabled == 1 ) {
            size_vlan_apply = 0 ;
            memset (packet, 0x00, 4) ;
         } else {
            size_vlan_apply = size_vlan ;
         }
                // TCP, IP 헤더 초기화
                iphdr = (struct iphdr *)(packet + size_vlan_apply) ;
                memset( iphdr, 0, 20 );
                tcphdr = (struct tcphdr *)(packet + size_vlan_apply + 20);
                memset( tcphdr, 0, 20 );

            #ifdef SUPPORT_OUTPUT
                // TCP 헤더 제작
                tcphdr->source = htons( 777 );
                tcphdr->dest = htons( port );
                tcphdr->seq = htonl( 92929292 );
                tcphdr->ack_seq = htonl( 12121212 );
            #endif

            source_address.s_addr = 
            ((struct iphdr *)(pre_packet + size_vlan + 14))->daddr ;
            // twist s and d address
            dest_address.s_addr = ((struct iphdr *)(pre_packet + size_vlan + 14))->saddr ;      // for return response
            iphdr->id = ((struct iphdr *)(pre_packet + size_vlan + 14))->id ;
            int pre_tcp_header_size = 0;
            char pre_tcp_header_size_char = 0x0;
            pre_tcp_header_size = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->doff ;
            pre_payload_size = ntohs( ((struct iphdr *)(pre_packet + size_vlan + 14))->tot_len ) - ( 20 + pre_tcp_header_size * 4 ) ;

            tcphdr->source = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->dest ;      // twist s and d port
            tcphdr->dest = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->source ;      // for return response
            tcphdr->seq = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->ack_seq ;
            tcphdr->ack_seq = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->seq  + htonl(pre_payload_size - 20)  ;
            tcphdr->window = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->window ;

                tcphdr->doff = 5;

                tcphdr->ack = 1;
                tcphdr->psh = 1;

                tcphdr->fin = 1;
                // 가상 헤더 생성.
                pseudo_header = (struct pseudohdr *)((char*)tcphdr-sizeof(struct pseudohdr));
                pseudo_header->saddr = source_address.s_addr;
                pseudo_header->daddr = dest_address.s_addr;
                pseudo_header->useless = (u_int8_t) 0;
                pseudo_header->protocol = IPPROTO_TCP;
                pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);

            #ifdef SUPPORT_OUTPUT
            // m-debug
            printf("DEBUG: &packet == \t\t %p \n" , &packet);
            printf("DEBUG: pseudo_header == \t %p \n" , pseudo_header);
            printf("DEBUG: iphdr == \t\t\t %p \n" , iphdr);
            printf("DEBUG: tcphdr == \t\t\t %p \n" , tcphdr);
            #endif

            #ifdef SUPPORT_OUTPUT
                strcpy( (char*)packet + 40, "HAHAHAHAHOHOHOHO\x0" );
            #endif

            // choose output content
            warning_page = 5;
            if ( warning_page == 5 ){
               // write post_payload ( redirecting data 2 )
               //post_payload_size = 201 + 67  ;   // Content-Length: header is changed so post_payload_size is increased.
               post_payload_size = 226 + 65  ;   // Content-Length: header is changed so post_payload_size is increased.
                    //memcpy ( (char*)packet + 40, "HTTP/1.1 200 OK" + 0x0d0a + "Content-Length: 1" + 0x0d0a + "Content-Type: text/plain" + 0x0d0a0d0a + "a" , post_payload_size ) ;
               memcpy ( (char*)packet + 40, "HTTP/1.1 200 OK\x0d\x0a"
                     "Content-Length: 226\x0d\x0a"
                     "Content-Type: text/html"
                     "\x0d\x0a\x0d\x0a"
                     "<html>\r\n"
                     "<head>\r\n"
                     "<meta charset=\"UTF-8\">\r\n"
                     "<title>\r\n"
                     "CroCheck - WARNING - PAGE\r\n"
                          "SITE BLOCKED - WARNING - \r\n"
                     "</title>\r\n"
                     "</head>\r\n"
                     "<body>\r\n"
                     "<center>\r\n"
      "<img src=\"http://127.0.0.1:80/warning.png\" alter=\"*WARNING*\">\r\n"
        "<h1>SITE BLOCKED</h1>\r\n"
                     "</center>\r\n"
                     "</body>\r\n"
                     "</html>", post_payload_size ) ;
                }
            pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);

                tcphdr->check = in_cksum( (u_short *)pseudo_header,
                                sizeof(struct pseudohdr) + sizeof(struct tcphdr) + post_payload_size);

                iphdr->version = 4;
                iphdr->ihl = 5;
                iphdr->protocol = IPPROTO_TCP;
                //iphdr->tot_len = 40;
                iphdr->tot_len = htons(40 + post_payload_size);

            #ifdef SUPPORT_OUTPUT
            //m-debug
            printf("DEBUG: iphdr->tot_len = %d\n", ntohs(iphdr->tot_len));
            #endif

            iphdr->id = ((struct iphdr *)(pre_packet + size_vlan + 14))->id + htons(1);

            memset( (char*)iphdr + 6 , 0x40 , 1 );

                iphdr->ttl = 60;
                iphdr->saddr = source_address.s_addr;
                iphdr->daddr = dest_address.s_addr;
                // IP 체크섬 계산.
                iphdr->check = in_cksum( (u_short *)iphdr, sizeof(struct iphdr));

                address.sin_family = AF_INET;

            address.sin_port = tcphdr->dest ;
            address.sin_addr.s_addr = dest_address.s_addr;

            prt_sendto_payload = 0;
            #ifdef SUPPORT_OUTPUT
            prt_sendto_payload = 1 ;
            #endif

            if( prt_sendto_payload == 1 ) {

            print_chars('\t',6);
            printf("sendto Packet data :\n");

            print_chars('\t',6);
            printf("       From: %s(%hhu.%hhu.%hhu.%hhu)\n",
                        inet_ntoa( source_address ),
                        ((char*)&source_address.s_addr)[0],
                        ((char*)&source_address.s_addr)[1],
                        ((char*)&source_address.s_addr)[2],
                        ((char*)&source_address.s_addr)[3]
                  );
            print_chars('\t',6);
            printf("         To: %s(%hhu.%hhu.%hhu.%hhu)\n",
                        inet_ntoa( dest_address ),
                        ((char*)&dest_address.s_addr)[0],
                        ((char*)&dest_address.s_addr)[1],
                        ((char*)&dest_address.s_addr)[2],
                        ((char*)&dest_address.s_addr)[3]
                  );

            switch(iphdr->protocol) {
               case IPPROTO_TCP:
                  print_chars('\t',6);
                  printf("   Protocol: TCP\n");
                  break;
               case IPPROTO_UDP:
                  print_chars('\t',6);
                  printf("   Protocol: UDP\n");
                  return -1;
               case IPPROTO_ICMP:
                  print_chars('\t',6);
                  printf("   Protocol: ICMP\n");
                  return -1;
               case IPPROTO_IP:
                  print_chars('\t',6);
                  printf("   Protocol: IP\n");
                  return -1;
               case IPPROTO_IGMP:
                  print_chars('\t',6);
                  printf("   Protocol: IGMP\n");
                  return -1;
               default:
                  print_chars('\t',6);
                  printf("   Protocol: unknown\n");
                  //free(packet_dmp);
                  return -2;
            }

            print_chars('\t',6);
            printf("   Src port: %d\n", ntohs(tcphdr->source));
            print_chars('\t',6);
            printf("   Dst port: %d\n", ntohs(tcphdr->dest));

            payload = (u_char *)(packet + sizeof(struct iphdr) + tcphdr->doff * 4 );

            size_payload = ntohs(iphdr->tot_len) - ( sizeof(struct iphdr) + tcphdr->doff * 4 );

            printf("DEBUG: sizeof(struct iphdr) == %lu \t , \t tcphdr->doff * 4 == %hu \n",
                        sizeof(struct iphdr) , tcphdr->doff * 4);

            if (size_payload > 0 || 1) {
               print_chars('\t',6);
               printf("   PACKET-HEADER(try1) (%d bytes):\n", ntohs(iphdr->tot_len) - size_payload);
               //print_payload(payload, size_payload);
               print_payload_right((const u_char*)&packet, ntohs(iphdr->tot_len) - size_payload);
            }

            if (size_payload > 0 || 1) {
               print_chars('\t',6);
               printf("   PACKET-HEADER(try2) (%d bytes):\n", 40);
               //print_payload(payload, size_payload);
               print_payload_right((const u_char*)&packet, 40);
            }

            if (size_payload > 0) {
               print_chars('\t',6);
               printf("   Payload (%d bytes):\n", size_payload);
               //print_payload(payload, size_payload);
               print_payload_right(payload, size_payload);
            }
         } // end -- if -- prt_sendto_payload = 1 ;
            if ( mode == 1 ) {
                    sendto_result = sendto( raw_socket, &packet, ntohs(iphdr->tot_len), 0x0,
                                            (struct sockaddr *)&address, sizeof(address) ) ;
               if ( sendto_result != ntohs(iphdr->tot_len) ) {
                  fprintf ( stderr,"ERROR: sendto() - %s\n", strerror(errno) ) ;
                  ret = -10 ;
               } else {
                  ret = 1 ;
               }
              } // end if(mode)
                //} // end for loop

            if ( (unsigned int)iphdr->daddr == (unsigned int)*(unsigned int*)"\xCB\xF6\x53\x2C" ) {
               printf("##########################################################################################################################\n");
               printf("##########################################################################################################################\n");
               printf("##########################################################################################################################\n");
               printf("##########################################################################################################################\n");
               printf("##########################################################################################################################\n");
               printf("##########################################################################################################################\n");
               printf("##########################################################################################################################\n");
               printf( "address1 == %hhu.%hhu.%hhu.%hhu\taddress2 == %X\taddress3 == %X\n",
                     *(char*)((char*)&source_address.s_addr + 0),*(char*)((char*)&source_address.s_addr + 1),
                     *(char*)((char*)&source_address.s_addr + 2),*(char*)((char*)&source_address.s_addr + 3),
                     source_address.s_addr,   (unsigned int)*(unsigned int*)"\xCB\xF6\x53\x2C" );
            }
                close( raw_socket );
                
        } // end for loop
      #ifdef SUPPORT_OUTPUT
        printf( "\n[차단 완료]  \n\n" );
      #endif
      //return 0;
      return ret ;
}

unsigned short in_cksum(u_short *addr, int len)
{
        int         sum=0;
        int         nleft=len;
        u_short     *w=addr;
        u_short     answer=0;
        while (nleft > 1){
            sum += *w++;
            nleft -= 2;
        }

        if (nleft == 1){
            *(u_char *)(&answer) = *(u_char *)w ;
            sum += answer;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return(answer);
}

int print_chars(char print_char, int nums)
{
   int i = 0;
   for ( i ; i < nums ; i++) {
      printf("%c",print_char);
   }
   return i;
}

void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

   int i;
   int gap;
   const u_char *ch;

   /* offset */
   printf("%05d   ", offset);

   /* hex */
   ch = payload;
   for(i = 0; i < len; i++) {
      printf("%02x ", *ch);
      ch++;
      /* print extra space after 8th byte for visual aid */
      if (i == 7)
         printf(" ");
   }
   /* print space to handle line less than 8 bytes */
   if (len < 8)
      printf(" ");

   /* fill hex gap with spaces if not full line */
   if (len < 16) {
      gap = 16 - len;
      for (i = 0; i < gap; i++) {
         printf("   ");
      }
   }
   printf("   ");

   /* ascii (if printable) */
   ch = payload;
   for(i = 0; i < len; i++) {
      if (isprint(*ch))
         printf("%c", *ch);
      else
         printf(".");
      ch++;
   }

   printf("\n");

    return;
}

void
print_hex_ascii_line_right(const u_char *payload, int len, int offset)
{

   int i;
   int gap;
   const u_char *ch;
   int tabs_cnt = 6 ;  // default at now , afterward receive from function caller

   /* print 10 tabs for output to right area   */
   for ( i = 0 ; i < tabs_cnt ; i++ ) {
      printf("\t");
   }

   /* offset */
   printf("%05d   ", offset);

   /* hex */
   ch = payload;
   for(i = 0; i < len; i++) {
      printf("%02x ", *ch);
      ch++;
      /* print extra space after 8th byte for visual aid */
      if (i == 7)
         printf(" ");
   }
   /* print space to handle line less than 8 bytes */
   if (len < 8)
      printf(" ");

   /* fill hex gap with spaces if not full line */
   if (len < 16) {
      gap = 16 - len;
      for (i = 0; i < gap; i++) {
         printf("   ");
      }
   }
   printf("   ");

   /* ascii (if printable) */
   ch = payload;
   for(i = 0; i < len; i++) {
      if (isprint(*ch))
         printf("%c", *ch);
      else
         printf(".");
      ch++;
   }

   printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

   int len_rem = len;
   int line_width = 16;         /* number of bytes per line */
   int line_len;
   int offset = 0;               /* zero-based offset counter */
   const u_char *ch = payload;

   if (len <= 0)
      return;

   /* data fits on one line */
   if (len <= line_width) {
      print_hex_ascii_line(ch, len, offset);
      return;
   }

   /* data spans multiple lines */
   for ( ;; ) {
      /* compute current line length */
      line_len = line_width % len_rem;
      /* print line */
      print_hex_ascii_line(ch, line_len, offset);
      /* compute total remaining */
      len_rem = len_rem - line_len;
      /* shift pointer to remaining bytes to print */
      ch = ch + line_len;
      /* add offset */
      offset = offset + line_width;
      /* check if we have line width chars or less */
      if (len_rem <= line_width) {
         /* print last line and get out */
         print_hex_ascii_line(ch, len_rem, offset);
         break;
      }
   }

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload_right(const u_char *payload, int len)
{

   int len_rem = len;
   int line_width = 16;         /* number of bytes per line */
   int line_len;
   int offset = 0;               /* zero-based offset counter */
   const u_char *ch = payload;


   if (len <= 0)
      return;

   /* data fits on one line */
   if (len <= line_width) {
      print_hex_ascii_line_right(ch, len, offset);
      return;
   }

   /* data spans multiple lines */
   for ( ;; ) {
      /* compute current line length */
      line_len = line_width % len_rem;
      /* print line */
      print_hex_ascii_line_right(ch, line_len, offset);
      /* compute total remaining */
      len_rem = len_rem - line_len;
      /* shift pointer to remaining bytes to print */
      ch = ch + line_len;
      /* add offset */
      offset = offset + line_width;
      /* check if we have line width chars or less */
      if (len_rem <= line_width) {
         /* print last line and get out */
         print_hex_ascii_line_right(ch, len_rem, offset);
         break;
      }
      //m-debug
      if ( offset > 600 ) {
         print_chars('\t',6);
         printf("INFO: ..........    payload too long (print_payload_right func) \n");
         break;
      }
   }

    return;
}
