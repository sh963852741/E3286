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
	mac_d dadder;//Ŀ��MAC
	mac_d sadder;//ԴMAC
}mac_header;


typedef struct ip_header {
	u_char version;  //�汾
	u_char tos;
	u_short tlen;           // �ܳ�(Total length) 
	u_short identification; // ��ʶ(Identification)
	u_short flags_fo;       // ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)
	u_char  ttl;            // ���ʱ��(Time to live)
	u_char  proto;          // Э��(Protocol)
	u_short crc;            // �ײ�У���(Header checksum)
	ip_d  saddr;      // Դ��ַ(Source address)
	ip_d  daddr;      // Ŀ�ĵ�ַ(Destination address)
	u_int   op_pad;         // ѡ�������(Option + Padding)
}ip_h;


typedef struct udp_h {
	u_short sport;
	u_short dport;
	u_short len;
	u_short crc;
}udp_h;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int macCmp(mac_d a, mac_d b);
#define Max_Num_Adapter 10
char		AdapterList[Max_Num_Adapter][1024];
long long int allmac[3][1000] = {0};
mac_d maclist[1000];
int macnum;
mac_d ownmac;
u_int get;
u_int sent;
u_int multi;
u_int broad;
time_t t1;
int minute;
int main()
{
	pcap_if_t *allports;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;

	LPADAPTER	lpAdapter = 0;
	int			j;
	DWORD		dwErrorCode;
	char		AdapterName[8192];
	char		*temp, *temp1;
	int			AdapterNum = 0, Open;
	ULONG		AdapterLength;
	PPACKET_OID_DATA  OidData;
	BOOLEAN		Status;

	AdapterLength = sizeof(AdapterName);
	PacketGetAdapterNames(AdapterName, &AdapterLength);

	temp = AdapterName;
	temp1 = AdapterName;
	j = 0;
	while ((*temp != '\0') || (*(temp - 1) != '\0'))
	{
		if (*temp == '\0')
		{
			memcpy(AdapterList[j], temp1, temp - temp1);
			temp1 = temp + 1;
			j++;
		}
		temp++;
	}
	AdapterNum = j;


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
	for (d = allports; i > 1; d = d->next, i--);

	for (int m = 0; m < AdapterNum; m++)
	{
		if (strcmp(d->name ,AdapterList[m])==0)
		{
			Open = m;
			break;
		}
	}

	lpAdapter = PacketOpenAdapter(AdapterList[Open ]);

	OidData = malloc(6 + sizeof(PACKET_OID_DATA));
	OidData->Oid = OID_802_3_CURRENT_ADDRESS;
	OidData->Length = 6;
	ZeroMemory(OidData->Data, 6);
	Status = PacketRequest(lpAdapter, FALSE, OidData);
	if (Status)
	{
		ownmac.first = OidData->Data[0];
		ownmac.second = OidData->Data[1];
		ownmac.third = OidData->Data[2];
		ownmac.forth = OidData->Data[3];
		ownmac.fifth = OidData->Data[4];
		ownmac.sixth = OidData->Data[5];
	}

	free(OidData);

	PacketCloseAdapter(lpAdapter);

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
	pcap_freealldevs(allports);
	t1 = time(0);
	FILE *p = fopen("data.txt", "w+");
	fclose(p);
	FILE *q = fopen("record.txt", "w+");
	fclose(q);	
	minute = 0;
	macnum = 0;
	pcap_loop(adhandle, 0, packet_handler, NULL);
	return 0;
}

int macCmp(mac_d a, mac_d b)
{
	if (a.first == b.first&&
		a.second == b.second&&
		a.third == b.third&&
		a.forth == b.forth&&
		a.fifth == b.fifth&&
		a.sixth == b.sixth)
		return 1;
	else
		return 0;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	FILE *p = fopen("data.txt", "a+");
	struct tm *ltime;
	time_t t2 = time(0);
	char timestr[16];
	ip_h *ih;
	mac_header *mh;
	udp_h *uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	(VOID)(param);

	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	fprintf(p,"%d-%d-%d %d:%d:%d,", ltime->tm_year + 1900, ltime->tm_mon + 1, ltime->tm_mday, ltime->tm_hour, ltime->tm_min, ltime->tm_sec);
	printf("%d-%d-%d %d:%d:%d,", ltime->tm_year + 1900, ltime->tm_mon + 1, ltime->tm_mday, ltime->tm_hour, ltime->tm_min, ltime->tm_sec);



	ih = (ip_h *)(pkt_data + 14);
	mh = (mac_header*)pkt_data;
	fprintf(p,"%02x-%02x-%02x-%02x-%02x-%02x,", mh->sadder.first, mh->sadder.second, mh->sadder.third, mh->sadder.forth, mh->sadder.fifth, mh->sadder.sixth);
	fprintf(p,"%d.%d.%d.%d,",
		ih->saddr.first,
		ih->saddr.second,
		ih->saddr.third,
		ih->saddr.forth
	);
	fprintf(p,"%02x-%02x-%02x-%02x-%02x-%02x,", mh->dadder.first, mh->dadder.second, mh->dadder.third, mh->dadder.forth, mh->dadder.fifth, mh->dadder.sixth);
	fprintf(p,"%d.%d.%d.%d,",
		ih->daddr.first,
		ih->daddr.second,
		ih->daddr.third,
		ih->daddr.forth
	);
	fprintf(p,"%d\n", header->len);

	printf("%02x-%02x-%02x-%02x-%02x-%02x,", mh->sadder.first, mh->sadder.second, mh->sadder.third,mh->sadder.forth, mh->sadder.fifth, mh->sadder.sixth);
	printf("%d.%d.%d.%d,",
		ih->saddr.first,
		ih->saddr.second,
		ih->saddr.third,
		ih->saddr.forth
	);
	printf("%02x-%02x-%02x-%02x-%02x-%02x,", mh->dadder.first, mh->dadder.second, mh->dadder.third, mh->dadder.forth, mh->dadder.fifth, mh->dadder.sixth);
	printf("%d.%d.%d.%d,",
		ih->daddr.first,
		ih->daddr.second,
		ih->daddr.third,
		ih->daddr.forth
	);
	printf("%d\n",header->len);
	
	if (macCmp(mh->sadder, ownmac))//Դ��ַ
	{
		int number;
		sent += header->len;
		long long int s = 0;
		s += mh->dadder.first;
		s = s << 8;
		s += mh->dadder.second;
		s = s << 8;
		s += mh->dadder.third;
		s = s << 8;
		s += mh->dadder.forth;
		s = s << 8;
		s += mh->dadder.fifth;
		s = s << 8;
		s += mh->dadder.sixth;
		for (number = 0; number < macnum; number++)
		{
			if (s == allmac[0][number])
			{
				break;
			}
		}
		if (number == macnum)
		{
			allmac[0][macnum] = s;
			
			allmac[1][macnum] += header->len;
			maclist[macnum].first= mh->dadder.first;
			maclist[macnum].second = mh->dadder.second;
			maclist[macnum].third= mh->dadder.third;
			maclist[macnum].forth = mh->dadder.forth;
			maclist[macnum].fifth = mh->dadder.fifth;
			maclist[macnum].sixth = mh->dadder.sixth;
			macnum++;
		}
		else if (number < macnum)
		{
			allmac[1][number] += header->len;
		}
	}
	else
	{
		if (macCmp(mh->dadder, ownmac))//Ŀ�ĵ�ַ
		{
			long long int s = 0;
			s += mh->sadder.first;
			s = s << 8;
			s += mh->sadder.second;
			s = s << 8;
			s += mh->sadder.third;
			s = s << 8;
			s += mh->sadder.forth;
			s = s << 8;
			s += mh->sadder.fifth;
			s = s << 8;
			s += mh->sadder.sixth;
			int number;
			for (number = 0; number < macnum; number++)
			{
				if (s == allmac[0][number])
				{
					break;
				}
			}
			if (number == macnum)
			{
				allmac[0][macnum] = s;
				allmac[2][macnum] += header->len;
				maclist[macnum].first = mh->sadder.first;
				maclist[macnum].second = mh->sadder.second;
				maclist[macnum].third = mh->sadder.third;
				maclist[macnum].forth = mh->sadder.forth;
				maclist[macnum].fifth = mh->sadder.fifth;
				maclist[macnum].sixth = mh->sadder.sixth;
				macnum++;
			}
			else if (number < macnum)
			{
				allmac[2][number] += header->len;
			}
			get += header->len;
		}
		else if (mh->dadder.first == 255 &&
			mh->dadder.second == 255 &&
			mh->dadder.third == 255 &&
			mh->dadder.forth == 255 &&
			mh->dadder.fifth == 255 &&
			mh->dadder.sixth == 255)
		  {
			 long long int s = 0;
			 s += mh->sadder.first;
			 s = s << 8;
			 s += mh->sadder.second;
			 s = s << 8;
			 s += mh->sadder.third;
			 s = s << 8;
			 s += mh->sadder.forth;
			 s = s << 8;
			 s += mh->sadder.fifth;
			 s=s << 8;
			 s += mh->sadder.sixth;
			 int number;
			 for (number = 0; number < macnum; number++)
			 {
				if (s == allmac[0][number])
				{
					break;
				}
			 }
			 if (number == macnum)
			 {
				allmac[0][macnum] = s;
			
			 	allmac[2][macnum] += header->len;
				maclist[macnum].first = mh->sadder.first;
				maclist[macnum].second = mh->sadder.second;
				maclist[macnum].third = mh->sadder.third;
				maclist[macnum].forth = mh->sadder.forth;
				maclist[macnum].fifth = mh->sadder.fifth;
				maclist[macnum].sixth = mh->sadder.sixth;
				macnum++;
			 }
			 else if (number < macnum)
			 {
				allmac[2][number] += header->len;
			 }
			 get += header->len;
			 broad += header->len;
		}
		else if ((mh->dadder.first & 0x01) == 1)
		{
			long long int s = 0;
			s += mh->sadder.first;
			s=s << 8;
			s += mh->sadder.second;
			s=s << 8;
			s += mh->sadder.third;
			s=s << 8;
			s += mh->sadder.forth;
			s=s << 8;
			s += mh->sadder.fifth;
			s=s << 8;
			s += mh->sadder.sixth;
			int number;
			for (number = 0; number < macnum; number++)
			{
				if (s == allmac[0][number])
				{
					break;
				}
			}
			if (number == macnum)
			{
				allmac[0][macnum] = s;
		
				allmac[2][macnum] += header->len;
				maclist[macnum].first = mh->sadder.first;
				maclist[macnum].second = mh->sadder.second;
				maclist[macnum].third = mh->sadder.third;
				maclist[macnum].forth = mh->sadder.forth;
				maclist[macnum].fifth = mh->sadder.fifth;
				maclist[macnum].sixth = mh->sadder.sixth;
				macnum++;
			}
			else if (number < macnum)
			{
				allmac[2][number] += header->len;
			}
			multi += header->len;
			get += header->len;
		}
	}


	if (t2 - t1 > 5)
	{
		minute++;
		FILE* q = fopen("record.txt", "a+");
		printf("��%d����\n", minute);
		printf("�յ���������Ϊ��%d\n", get);
		printf("�յ��Ķಥ������Ϊ��%d\n", multi);
		printf("�յ��Ĺ㲥������Ϊ��%d\n", broad);
		printf("����������Ϊ��%d\n", sent);
		fprintf(q,"��%d����\n", minute);
		fprintf(q,"�յ���������Ϊ��%d\n", get);
		fprintf(q,"�յ��Ķಥ������Ϊ��%d\n", multi);
		fprintf(q,"�յ��Ĺ㲥������Ϊ��%d\n", broad);
		fprintf(q,"����������Ϊ��%d\n", sent);

		for (int i = 0; i < macnum; i++)
		{

			fprintf(q, "�����ַ��");
			fprintf(q, "%02x-%02x-%02x-%02x-%02x-%02x,", maclist[i].first, maclist[i].second, maclist[i].third, maclist[i].forth, maclist[i].fifth, maclist[i].sixth);
			fprintf(q, "���͵��˵�ַ��%d", allmac[1][i]);
			fprintf(q, " �Ӵ˵�ַ���ܣ�%d", allmac[2][i]);
			if (allmac[1][i] > 1048576 || allmac[2][i] > 1048576)
			{
				fprintf(q, " �˵�ַ�����̴ﵽ��ֵ����ע��");
			}
			else
			{
				fprintf(q, " �˵�ַ������δ�ﵽ��ֵ");
			}
			fprintf(q, "\n");
			allmac[0][i] = 0;
			allmac[1][i] = 0;
			allmac[2][i] = 0;
		}
		macnum = 0;
		t1 = t2;
		get = 0;
		sent = 0;
		multi = 0;
		broad = 0;
		fclose(q);
	}
	fclose(p);
}


