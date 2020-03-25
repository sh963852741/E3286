#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include"pcap.h"
#include"Packet32.h"
#include<stdio.h>
#include<conio.h>
#include<ntddndis.h>
#include<string.h>


typedef struct ip_adress {
	u_char first;
	u_char second;
	u_char third;
	u_char forth;
}ip_d;


typedef struct mac_add {
	u_char first;
	u_char second;
	u_char third;
	u_char forth;
	u_char fifth;
	u_char sixth;
}mac_d;


typedef struct mac_header {
	mac_d dadder;//目标MAC
	mac_d sadder;//源MAC
	u_char type[2];
}mac_header;


typedef struct tcp_header{
	u_short sport;//源地址端口号
	u_short dsport;//目的地址端口号
	u_int seq;//数据序号
	u_int arc;//确认号
	u_char ihl;//高四位为头部长度 单位四字节
	u_char frame;//第六位为各个标志位
	u_short wsize;//窗口大小
	u_short cre;//crc校验和
	u_short urg;//紧急指针
}tcp_header;

typedef struct ip_header {
	u_char version;  //版本
	u_char tos;
	u_short tlen;           // 总长(Total length) 
	u_short identification; // 标识(Identification)
	u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
	u_char  ttl;            // 存活时间(Time to live)
	u_char  proto;          // 协议(Protocol)
	u_short crc;            // 首部校验和(Header checksum)
	ip_d  saddr;      // 源地址(Source address)
	ip_d  daddr;      // 目的地址(Destination address)
	u_int   op_pad;         // 选项与填充(Option + Padding)
}ip_h;


typedef struct udp_h {
	u_short sport;
	u_short dport;
	u_short len;
	u_short crc;
}udp_h;

/* 回调函数原型 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


char name[30];//用户名
char pass[30];//密码

int main()
{
	pcap_if_t *allports;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "port 21";//ftp默认端口号

	struct bpf_program fcode;


	if (pcap_findalldevs(&allports, errbuf) == -1)
	{
		fprintf(stderr, "Erron in pcap_findalldevs:%s\n", errbuf);
		exit(1);
	}

	for (d = allports;d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces be founded");
		return -1;
	}

	printf("Enter the interface number(1-%d)", i);
	scanf("%d", &inum);

	if (inum<1 || inum>i)
	{
		printf("\nThis number is illegal\n");
		pcap_freealldevs(allports);
		return -1;
	}
	i = inum;

	/*转到已选设备*/
	for (d = allports; i > 1; d = d->next, i--);

 	
     /*打开适配器*/
	if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL)
	{

		fprintf(stderr, "\nCannot open the adapter.\n");
		pcap_freealldevs(allports);
		return -1;
	}


	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr,"\nOnly can work on Enthernet networks\n");
		pcap_freealldevs(allports);
		return -1;
	}

	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;


	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(allports);
		return -1;
	}


	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(allports);
		return -1;
	}

	pcap_freealldevs(allports);

	pcap_loop(adhandle, 0, packet_handler, NULL);
	return 0;
}


void out(ip_h*ih,mac_header*mh, const struct pcap_pkthdr *header, char user[], char pass[],int issuccessed)
{
	if (user[0] == '\0')
		return;
	/*输出时间*/
	struct tm *ltime;
	time_t local_tv_sec;
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	printf("%d-%d-%d %d:%d:%d,", ltime->tm_year + 1900, ltime->tm_mon + 1, ltime->tm_mday, ltime->tm_hour, ltime->tm_min, ltime->tm_sec);

	/*输出主机mac地址和ip*/
	printf("%02x-%02x-%02x-%02x-%02x-%02x,", mh->dadder.first, mh->dadder.second, mh->dadder.third, mh->dadder.forth, mh->dadder.fifth, mh->dadder.sixth);
	printf("%d.%d.%d.%d,",
		ih->daddr.first,
		ih->daddr.second,
		ih->daddr.third,
		ih->daddr.forth
	);
	/*输出ftp mac地址和ip*/
	printf("%02x-%02x-%02x-%02x-%02x-%02x,", mh->sadder.first, mh->sadder.second, mh->sadder.third, mh->sadder.forth, mh->sadder.fifth, mh->sadder.sixth);
	printf("%d.%d.%d.%d,",
		ih->saddr.first,
		ih->saddr.second,
		ih->saddr.third,
		ih->saddr.forth
	);
	/*输出用户名和密码*/
	printf("%s,%s,", user, pass);//账号密码

	/*输出*/
	if (issuccessed) {
		printf("SUCCEED\n");
	}
	else {
		printf("FAILED\n");
	}

	/*输入文件*/
	FILE* fp = fopen("log.csv", "a+");

	fprintf(fp,"%d-%d-%d %d:%d:%d,", ltime->tm_year + 1900, ltime->tm_mon + 1, ltime->tm_mday, ltime->tm_hour, ltime->tm_min, ltime->tm_sec);

	fprintf(fp,"%02x-%02x-%02x-%02x-%02x-%02x,", mh->dadder.first, mh->dadder.second, mh->dadder.third, mh->dadder.forth, mh->dadder.fifth, mh->dadder.sixth);
	fprintf(fp,"%d.%d.%d.%d,",
		ih->daddr.first,
		ih->daddr.second,
		ih->daddr.third,
		ih->daddr.forth
	);

	fprintf(fp,"%02x-%02x-%02x-%02x-%02x-%02x,", mh->sadder.first, mh->sadder.second, mh->sadder.third, mh->sadder.forth, mh->sadder.fifth, mh->sadder.sixth);
	fprintf(fp,"%d.%d.%d.%d,",
		ih->saddr.first,
		ih->saddr.second,
		ih->saddr.third,
		ih->saddr.forth
	);

	fprintf(fp,"%s,%s,", user, pass);//账号密码


	if (issuccessed) {
		fprintf(fp,"SUCCEED\n");
	}
	else {
		fprintf(fp,"FAILED\n");
	}

	fclose(fp);
	user[0] = 0;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{


	ip_h *ih;
	mac_header *mh;
	u_int i = 0;



	int length = sizeof(mac_header) + sizeof(ip_h);
	ih = (ip_h *)(pkt_data + 14);
	mh = (mac_header*)pkt_data;
	int name_point = 0;
	int pass_point = 0;
	int tmp;
	for (int i = 0; i < ih->tlen - 40; i++) {
		if (*(pkt_data + i) == 'U'&&*(pkt_data + i + 1) == 'S'&&*(pkt_data + i + 2) == 'E'&&*(pkt_data + i + 3) == 'R') {
			name_point = i + 5;

	
			int j = 0;
			while (!(*(pkt_data + name_point) == 13 && *(pkt_data + name_point + 1) == 10)) {
				name[j] = *(pkt_data + name_point);//存储账号
				j++;
				++name_point;
			}
			name[j] = '\0';
			break;

		}

		if (*(pkt_data + i) == 'P' && *(pkt_data + i + 1) == 'A' && *(pkt_data + i + 2) == 'S' && *(pkt_data + i + 3) == 'S') {
			pass_point = i + 5;
			tmp = pass_point;

	
			int k = 0;
			while (!(*(pkt_data + pass_point) == 13 && *(pkt_data + pass_point + 1) == 10)) {
				pass[k] = *(pkt_data + pass_point);//存储密码
				k++;
				++pass_point;

			}
			pass[k] = '\0';

			for (;; tmp++) {
				if (*(pkt_data + tmp) == '2'&&*(pkt_data + tmp + 1) == '3'&&*(pkt_data + tmp + 2) == '0') {
					out(ih, mh, header, (char *)name, (char *)pass, 1);
					break;
				}
				else if (*(pkt_data + tmp) == '5'&&*(pkt_data + tmp + 1) == '3'&&*(pkt_data + tmp + 2) == '0') {
					out(ih, mh, header, (char *)name, (char *)pass, 0);
					break;
				}
			}
			break;
		}
	}
	
	
}


