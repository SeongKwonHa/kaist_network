/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{
	
}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet){
	Packet* mypacket = this->clonePacket(packet);
	uint32_t source[1];
	packet->readData(14+12, source, 4);
	uint32_t dest[1];
	packet->readData(14+16, dest, 4);
	uint16_t s_port[1];
	packet->readData(14+20, s_port, 2);
	uint16_t d_port[1];
	packet->readData(14+22, d_port, 2);
	uint32_t seq[1];
	packet->readData(14+24, seq, 4);
	uint32_t ack_seq[1];
	packet->readData(14+28, ack_seq, 4);
	uint8_t flag[1];
	packet->readData(14+33, flag, 1);

	uint8_t msg_seq[4];
	msg_seq[0]=0;
	msg_seq[1]=1;
	msg_seq[2]=2;
	msg_seq[3]=3;
	
	struct Sockmeta * mysocket;
	int result=0;
	struct Connection *connect_info = new struct Connection;
	//printf("packetarrive enter\n");
	switch(*flag){
		case 0x002:
			//syn only
			//printf("packetarrive syn enter\n");
			seq[0] = ntohl(htonl(seq[0])+1);
			flag[0] = 0x012;
			mypacket->writeData(14+12, dest, 4);
			mypacket->writeData(14+16, source, 4);
			mypacket->writeData(14+20, d_port, 2);
			mypacket->writeData(14+22, s_port, 2);
			mypacket->writeData(14+24, msg_seq, 4);
			mypacket->writeData(14+28, seq, 4);
			mypacket->writeData(14+33, flag, 1);

			uint16_t initzero[1];
			initzero[0] = 0;
			mypacket->writeData(14+36, initzero, 2);
			uint8_t tempsum[20];
			mypacket->readData(14+20, tempsum, 20);
			uint16_t checksum[1];
			checksum[0] = htons((~E::NetworkUtil::tcp_sum(dest[0], source[0], (uint8_t *)tempsum, 20)));
			//printf("checksum : %x\n", checksum[0]);
			mypacket->writeData(14+36, checksum, 2);

			
			for(int i=0;i<socketlist.size();i++){
				/*
				printf("socketlist port : %x\n",socketlist[i]->port);
				printf("socketlist ipaddr : %x\n",socketlist[i]->ip.s_addr);
				printf("packet port : %x\n",d_port[0]);
				printf("packet ipaddr : %x\n",dest[0]);
				*/
				if((socketlist[i]->port == d_port[0] && socketlist[i]->ip.s_addr == dest[0])||(socketlist[i]->port == d_port[0] && socketlist[i]->ip.s_addr == INADDR_ANY)){
					mysocket = socketlist[i];
					result = 1;
					break;
				}
			}
			if(result==0){
				this->freePacket(packet);
				break;
			}
			mysocket->state = State::SYN_RCVD;
			
			connect_info->dest[0] = dest[0];
			connect_info->source[0] = source[0];
			connect_info->d_port[0] = d_port[0];
			connect_info->s_port[0] = s_port[0];
			if(mysocket->waitingqueue.size()==mysocket->backlog){
				this->freePacket(packet);
			}else{
				mysocket->waitingqueue.push(connect_info);
				this->sendPacket(fromModule.c_str(),mypacket);
				this->freePacket(packet);
			}
			
			break;

		case 0x012:
		//syn+ack
		//printf("packetarrive syn+ack enter\n");
			seq[0] = ntohl(htonl(seq[0])+1);
			flag[0] = 0x010;
			mypacket->writeData(14+12, dest, 4);
			mypacket->writeData(14+16, source, 4);
			mypacket->writeData(14+20, d_port, 2);
			mypacket->writeData(14+22, s_port, 2);
			mypacket->writeData(14+24, msg_seq, 4);
			mypacket->writeData(14+28, seq, 4);
			mypacket->writeData(14+33, flag, 1);

			for(int i=0;i<socketlist.size();i++){
				if((socketlist[i]->port == d_port[0] && socketlist[i]->ip.s_addr == dest[0])||(socketlist[i]->port == d_port[0] && socketlist[i]->ip.s_addr == INADDR_ANY)){
					mysocket = socketlist[i];
					result = 1;
					break;
				}
			}
			if(result==0){
				this->freePacket(packet);
				break;
			}
			mysocket->state = State::ESTAB;
			this->sendPacket(fromModule,mypacket);
			this->freePacket(packet);
			break;

		case 0x010:
		//ack
			printf("packetarrive ack enter\n");
			for(int i=0;i<socketlist.size();i++){
				if((socketlist[i]->port == d_port[0] && socketlist[i]->ip.s_addr == dest[0])||(socketlist[i]->port == d_port[0] && socketlist[i]->ip.s_addr == INADDR_ANY)){
					mysocket = socketlist[i];
					result = 1;
					break;
				}
			}
			if(result==0){
				this->freePacket(packet);
				break;
			}
			mysocket->state = State::ESTAB;
			struct Connection * myconnect;
			myconnect = mysocket->waitingqueue.front();
			mysocket->waitingqueue.pop();
			mysocket->estabqueue.push(myconnect);

			if(!mysocket->acceptqueue.empty()){
				printf("enter here\n");
				struct Connection *tempconnect = mysocket->estabqueue.front();
				mysocket->estabqueue.pop();
				struct Sockmeta * getsocket = mysocket->acceptqueue.front();
				mysocket->acceptqueue.pop();
				struct sockaddr_in * myaddr_in = (struct sockaddr_in *) getsocket->accept_addr;
				getsocket->connection = tempconnect;
				getsocket->sin_family = mysocket->sin_family;
				getsocket->ip.s_addr = mysocket->ip.s_addr;
				getsocket->port = mysocket->port;
				getsocket->addrlen = mysocket->addrlen;
				mysocket->state = State::LISTEN;
				myaddr_in->sin_family = mysocket->sin_family;
				myaddr_in->sin_port = mysocket->port;
				myaddr_in->sin_addr = mysocket->ip;
				*(getsocket->accept_addrlen) = mysocket->addrlen;
				returnSystemCall(getsocket->syscallUUID, getsocket->fd);
			}

			//struct Sockmeta *tempsocket;
			//tempsocket = mysocket->acceptqueue.front();
			//mysocket->acceptqueue.pop();
			//tempsocket->connection = myconnect;
			this->freePacket(packet);
		
			//socket 찾아서 ESTAB로 바꾼다.
			break;
	
	}
	/*
	printf("source: ");
	for(int i=0; i<4;i++){
		printf("%x", *(source+i));
	}
	printf("\n");
	printf("dest: ");
	for(int i=0; i<4;i++){
		printf("%x", *(dest+i));
	}
	printf("\n");
	printf("seq: ");
	for(int i=0; i<4;i++){
		printf("%x", *(seq+i));
	}
	printf("\n");
	printf("ack_seq: ");
	for(int i=0; i<4;i++){
		printf("%x", *(ack_seq+i));
	}
	printf("\n");

	for(int i=0;i<1;i++){
		printf("flag: %x\n", *(flag+i));
	}
	printf("string : %s\n", fromModule.c_str());
	*/

	

}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type){
	int fd =createFileDescriptor(pid);
	if(pid<0){
		returnSystemCall(syscallUUID, -1);
	}
	else{
		Sockmeta* sockmeta = new Sockmeta;
		sockmeta->pid = pid;
		sockmeta->fd = fd;
		sockmeta->sin_family = 0;//bind 된적 있는지 없는지 체크
		sockmeta->ip.s_addr = 0;
		sockmeta->port = 0;
		sockmeta->addrlen = 0;
		sockmeta->state = State::CLOSED;
		socketlist.push_back(sockmeta);
		returnSystemCall(syscallUUID, fd);
		//printf("syscall_socket fd : %d\n", fd);
		//소켓을 만들고 어디 테이블에 넣어야할듯 - socketlist
	}

}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd){
	//어디 테이블에서 pid에 알맞는 소켓을 찾아 없애야할듯
	struct Sockmeta * mysocket;
	int result = 0;
	int index = 0;
	for(int i=0;socketlist.size();i++){
		if(socketlist[i]->fd==sockfd&&socketlist[i]->pid==pid){
			mysocket = socketlist[i];
			index = i;
			result = 1;
			break;
		}
	}
	if(result==0){
		returnSystemCall(syscallUUID, -1);
	}
	else{
		//여기는 일반적인 경우.
		delete mysocket;
		socketlist.erase(socketlist.begin()+index);
		removeFileDescriptor(pid, sockfd);
		returnSystemCall(syscallUUID, 0);
		//여기부터 close connection?
		//TODO
		//printf("syscall_close fd : %d\n", sockfd);
	}
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *myaddr, socklen_t addrlen){
	//AF_INET인지 시스템 내에서 통신하는 AF_UNIX에 따라서 달라짐.
	//AF_INET의 경우 sockaddr을 인터넷에서 사용하는 sockaddr_in으로 들어온다.
	printf("**syscall_bind fd : %d\n", sockfd);
	//printf("**syscall_bind addreln : %d\n", addrlen);
	//printf("**syscall_bind sa_family : %d\n", myaddr->sa_family);

	if(myaddr->sa_family==AF_INET){
		struct sockaddr_in * myaddr_in=(struct sockaddr_in *) myaddr;
		sa_family_t	sin_family = myaddr_in->sin_family; 
		unsigned short int port = myaddr_in->sin_port;
		struct in_addr ip = myaddr_in->sin_addr;
		printf("**syscall_bind port : %d\n", port);
		printf("**syscall_bind ip : %d\n", ip.s_addr);
		printf("**syscall_bind pid: %d\n",pid);

		//이미 있는 socket들 중에서 bind rule을 점검
		//testcase에서는 1)같은 fd에 두번 bind하는 것 하나과 2)다른 fd지만 overlap 조건
		for(int i=0;i<socketlist.size();i++){
			//printf("size : %d\n", socketlist.size());
			//printf("compare fd : %d\n", socketlist[i]->fd);
			//printf("port_test :%d, input port:%d, listport:%d\n", (port == socketlist[i]->port), port, socketlist[i]->port);
			//printf("ip_test: %d, input ip:%d, listip:%d\n", (socketlist[i]->ip.s_addr == INADDR_ANY), ip.s_addr, socketlist[i]->ip.s_addr);
			if((port == socketlist[i]->port)&&(socketlist[i]->ip.s_addr == INADDR_ANY)){
				//2)조건
				//printf("pass1\n");
				returnSystemCall(syscallUUID, -1);
				return;
			}
			if((port == socketlist[i]->port)&&(ip.s_addr == INADDR_ANY)){
				//2)조건
				//printf("pass2\n");
				returnSystemCall(syscallUUID, -1);
				return;
			}
			if((port == socketlist[i]->port)&&(ip.s_addr == socketlist[i]->ip.s_addr)){
				//2)조건
				//printf("pass3\n");
				returnSystemCall(syscallUUID, -1);
				return;
			}
			if((socketlist[i]->fd==sockfd)&&(socketlist[i]->sin_family != 0)&&(socketlist[i]->pid==pid)){
				//1)조건
				//printf("pass4\n");
				returnSystemCall(syscallUUID, -1);
				return;
			}
		}

		//overlap 점검 통과 후
		int result = 0;
		for(int i=0;i<socketlist.size();i++){
			if(socketlist[i]->fd==sockfd&&socketlist[i]->pid==pid){
				socketlist[i]->pid == pid;
				socketlist[i]->sin_family = sin_family;
				socketlist[i]->port = port;
				socketlist[i]->ip.s_addr = ip.s_addr;
				socketlist[i]->addrlen = addrlen;
				result = 1;
				break;
			}
		}
		if(result==0){
			returnSystemCall(syscallUUID, -1);
		}
		else{
			returnSystemCall(syscallUUID, 0);
		}
	}else{
		//내부(AF_UNIX)일때는 모르겟음. 일단 test1은 전부 AF_INET으로 나온다.
		//fd를 찾아서 리턴값만 맞춰준다.
		int result = 0;
		for(int i=0;socketlist.size();i++){
			if(socketlist[i]->fd==sockfd){
				result = 1;
				break;
			}
		}
		if(result==0){
			returnSystemCall(syscallUUID, -1);
			printf("**syscall_bind fail\n");
		}
		else{
			returnSystemCall(syscallUUID, 0);
			printf("**syscall_bind success\n");
		}
	}
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr * myaddr , socklen_t * addrlen){
	//구분이 불가능해서 AF_INET이라고 가정하고 getsockname한다.
	struct sockaddr_in * myaddr_in=(struct sockaddr_in *) myaddr;
	int result = 0;
	for(int i=0;socketlist.size();i++){
		if(socketlist[i]->fd==sockfd&&socketlist[i]->pid==pid){
			myaddr_in->sin_family = socketlist[i]->sin_family;
			myaddr_in->sin_port = socketlist[i]->port;
			myaddr_in->sin_addr = socketlist[i]->ip;
			*addrlen = socketlist[i]->addrlen;
			result = 1;
			//printf("**syscall_getsockname sa_family : %d\n", myaddr_in->sin_family);
			//printf("**syscall_getsockname port : %d\n", myaddr_in->sin_port);
			//printf("**syscall_getsockname ip : %d\n", myaddr_in->sin_addr.s_addr);
			break;
		}
	}
	if(result==0){
		returnSystemCall(syscallUUID, -1);
		printf("**syscall_getsockname fail\n");
	}
	else{
		returnSystemCall(syscallUUID, 0);
		printf("**syscall_getsockname success\n");
	}
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog){
	int result = 0;
	for(int i=0;socketlist.size();i++){
		if(socketlist[i]->fd==sockfd&&socketlist[i]->pid==pid){
			socketlist[i]->state=State::LISTEN;
			socketlist[i]->backlog = backlog;
			result = 1;
			break;
		}
	}
	printf("listen enter\n");
	printf("listen backlog %d\n", backlog);
	if(result==0){
		returnSystemCall(syscallUUID, -1);
	}
	else{
		returnSystemCall(syscallUUID, 0);
	}

}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	struct Sockmeta * mysocket;
	struct sockaddr_in * myaddr_in=(struct sockaddr_in *) addr;
	for(int i=0;i<socketlist.size();i++){
		if(socketlist[i]->fd == sockfd&&socketlist[i]->pid==pid){
			mysocket= socketlist[i];
			break;
		}
	}
	printf("accept enter\n");
	int fd =createFileDescriptor(pid);
        if(pid<0){
        	returnSystemCall(syscallUUID, -1);
        }
	
        struct Sockmeta * newsocket = new struct Sockmeta;
        newsocket->pid = pid;
        newsocket->fd = fd;
        newsocket->sin_family = 0;
        newsocket->ip.s_addr = 0;
        newsocket->port = 0;
        newsocket->addrlen = 0;
		newsocket->state = State::CLOSED;
		newsocket->accept_addr = addr;
		newsocket->accept_addrlen = addrlen;
		newsocket->syscallUUID = syscallUUID;
        socketlist.push_back(newsocket);
        mysocket->acceptqueue.push(newsocket);
	
	if (!mysocket->estabqueue.empty()) {
		struct Connection *tempconnect = mysocket->estabqueue.front();
        mysocket->estabqueue.pop();
        struct Sockmeta * getsocket = mysocket->acceptqueue.front();
        mysocket->acceptqueue.pop();
        getsocket->connection = tempconnect;
        getsocket->sin_family = mysocket->sin_family;
        getsocket->ip.s_addr = mysocket->ip.s_addr;
        getsocket->port = mysocket->port;
        getsocket->addrlen = mysocket->addrlen;
        mysocket->state = State::LISTEN;
        myaddr_in->sin_family = mysocket->sin_family;
        myaddr_in->sin_port = mysocket->port;
        myaddr_in->sin_addr = mysocket->ip;
        *addrlen = mysocket->addrlen;
        returnSystemCall(syscallUUID, getsocket->fd);
                //estabqueu에서 꺼내온??
	}
	/*if(mysocket->acceptqueue.empty()){
		int fd =createFileDescriptor(pid);
		if(pid<0){
			returnSystemCall(syscallUUID, -1);
		}
		struct Sockmeta * newsocket = new struct Sockmeta;
		newsocket->pid = pid;
		newsocket->fd = fd;
		newsocket->sin_family = 0;
		newsocket->ip.s_addr = 0;
		newsocket->port = 0;
		newsocket->addrlen = 0;
		newsocket->state = State::CLOSED;
		socketlist.push_back(newsocket);
		mysocket->acceptqueue.push(newsocket);
		//새로운 큐를 만들고
		//block
		printf("accept empty enter\n");
	}
	else{
		struct Connection *tempconnect = mysocket->estabqueue.front();
		mysocket->estabqueue.pop();
		struct Sockmeta * getsocket = mysocket->acceptqueue.front();
		mysocket->acceptqueue.pop();
		getsocket->connection = tempconnect;
		getsocket->sin_family = mysocket->sin_family;
		getsocket->ip.s_addr = mysocket->ip.s_addr;
		getsocket->port = mysocket->port;
		getsocket->addrlen = mysocket->addrlen;
		mysocket->state = State::LISTEN;
		myaddr_in->sin_family = mysocket->sin_family;
		myaddr_in->sin_port = mysocket->port;
		myaddr_in->sin_addr = mysocket->ip;
		*addrlen = mysocket->addrlen;
		printf("accept empty else\n");
		returnSystemCall(syscallUUID, getsocket->fd);
		//estabqueu에서 꺼내온??
	}*/
	printf("accept end\n");
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen){
	printf("connect enter\n");
	struct Sockmeta * mysocket;
	struct sockaddr_in * myaddr_in=(struct sockaddr_in *) addr;
	int result = 0;
	for(int i=0;socketlist.size();i++){
		if(socketlist[i]->fd==sockfd&&socketlist[i]->pid==pid){
			mysocket = socketlist[i];
			result = 1;
			break;
		}
	}
	if(result==0){
		returnSystemCall(syscallUUID, -1);
		printf("**syscall_getpeername fail\n");
	}
	else{
		returnSystemCall(syscallUUID, 0);
		printf("**syscall_getpeername success\n");
	}
	//소켓 다시 보내야함.
	//bind에 대해 체크해야한다는데, 어떻게??
	//(socketlist[i]->sin_family != 0)이거 바인드 했는지 체크인데 이걸로 할수있으면하면된다.
	//이걸로 안되면 바인드한거 모으는 리스트를 따로 만들어야할듯!
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	printf("getpeername enter\n");
	struct sockaddr_in * myaddr_in=(struct sockaddr_in *) addr;
	int result = 0;
	for(int i=0;socketlist.size();i++){
		if(socketlist[i]->fd==sockfd&&socketlist[i]->pid==pid){
			myaddr_in->sin_addr.s_addr = socketlist[i]->ip.s_addr;
			myaddr_in->sin_port = socketlist[i]->port;
			myaddr_in->sin_family = socketlist[i]->sin_family;
			*addrlen = socketlist[i]->addrlen;
			result = 1;
			break;
		}
	}
	if(result==0){
		returnSystemCall(syscallUUID, -1);
		printf("**syscall_getpeername fail\n");
	}
	else{
		returnSystemCall(syscallUUID, 0);
		printf("**syscall_getpeername success\n");
	}
}


void TCPAssignment::timerCallback(void* payload)
{

}


}
