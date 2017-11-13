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

#define MAX(a,b) \  
({ __typeof__ (a) _a = (a); \  
__typeof__ (b) _b = (b); \  
_a > _b ? _a : _b; })  
  
#define MIN(a,b) \  
({ __typeof__ (a) _a = (a); \  
__typeof__ (b) _b = (b); \  
_a < _b ? _a : _b; })  

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
		this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
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

	uint8_t tempsum[packet->getSize()-34];
	packet->readData(14+20, tempsum, packet->getSize()-34);
	if (0 != htons(~E::NetworkUtil::tcp_sum(source[0], dest[0], (uint8_t *)tempsum, packet->getSize()-34))) {
		this->freePacket(packet);
		return;
	}

	uint32_t msg_seq[1];

	struct Sockmeta * mysocket;
	int result=0;
	int index= 0;
	switch(*flag){
		case 0x001:
			{
				//printf("packetarrived fin enter\n");
				for(int i=0;i<socketlist.size();i++){
					if((socketlist[i]->port == d_port[0] && socketlist[i]->ip.s_addr == dest[0] && socketlist[i]->d_port == s_port[0] && socketlist[i]->d_ip.s_addr == source[0])||(socketlist[i]->port == d_port[0] && socketlist[i]->ip.s_addr == INADDR_ANY && socketlist[i]->d_port == s_port[0] && socketlist[i]->d_ip.s_addr == source[0])){
						mysocket = socketlist[i];
						index = i;
						result = 1;
						break;
					}
				}

				if(result==0){
					//printf("no socket\n");
					this->freePacket(packet);
					break;
				}


				if(mysocket->state == State::ESTAB){		
					mysocket->state = State::CLOSE_WAIT;
					msg_seq[0] = htonl(mysocket->seqnum);
					seq[0] = ntohl(htonl(seq[0])+1);
					flag[0] = 0x010;
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
					mypacket->writeData(14+36, checksum, 2);

					this->sendPacket(fromModule.c_str(),mypacket);
					this->freePacket(packet);
					break;

				} else if(mysocket->state == State::FIN_WAIT_2 || mysocket->state == State::FIN_WAIT_1) {
					if (mysocket->state == State::FIN_WAIT_1) {
						mysocket->seqnum = mysocket->seqnum+1;
					}

					if (mysocket->timer != 0) E::TimerModule::cancelTimer(mysocket->timer);
					//printf("timer cancel: %d\n", mysocket->timer);
			
					mysocket->timer = 0;


					mysocket->state = State::TIMED_WAIT;	
					msg_seq[0]= htonl(mysocket->seqnum);
					seq[0] = ntohl(htonl(seq[0])+1);
					flag[0] = 0x010;
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
					mypacket->writeData(14+36, checksum, 2);

					this->sendPacket(fromModule.c_str(),mypacket);
					this->freePacket(packet);
					break;
				}
				this->freePacket(packet);
				break;
			}
		case 0x002:
			{
				//syn only
				//printf("packetarrive syn enter\n");

				for(int i=0;i<socketlist.size();i++){

					if((socketlist[i]->port == d_port[0] && socketlist[i]->ip.s_addr == dest[0])||(socketlist[i]->port == d_port[0] && socketlist[i]->ip.s_addr == INADDR_ANY)){
						mysocket = socketlist[i];
						result = 1;
						break;
					}
				}

				if(result==0){
					//printf("no socket\n");
					this->freePacket(packet);
					break;
				}
				msg_seq[0]= htonl(mysocket->seqnum);
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
				mypacket->writeData(14+36, checksum, 2);

				mysocket->state = State::SYN_RCVD;
				if(mysocket->waitingqueue.size() >=mysocket->backlog){
					//printf("no enough queue\n");
					this->freePacket(packet);
				}else{
					struct Sockmeta * newsocket = new struct Sockmeta;
					newsocket->pid = -1;
					newsocket->fd = -1;
					newsocket->sin_family = mysocket->sin_family;
					newsocket->ip.s_addr = dest[0];
					newsocket->port = mysocket->port;
					newsocket->addrlen = mysocket->addrlen;
					newsocket->d_ip.s_addr = source[0];
					newsocket->d_port = s_port[0];
					newsocket->state = State::CLOSED;
					newsocket->backlog = 1;
					newsocket->syscallUUID = -1;
					newsocket->read_buffer_pointer = 0;
					newsocket->readInfo = (struct ReadInfo *)malloc(sizeof(struct ReadInfo));
					newsocket->readInfo->count = 0;
					newsocket->readInfo->read_buffer = 0;
					newsocket->bind_connect = 0;	
					newsocket->slowstart = mysocket->slowstart;
					newsocket->real_wsize = 0;
					newsocket->callindex = mysocket->callindex;
					newsocket->first = 0;
					newsocket->retranscall = 0;
					newsocket->write_buffer_size = 0;
					socketlist.push_back(newsocket);

					mysocket->waitingqueue.push(newsocket);

					struct TimerInfo * timerInfo = (struct TimerInfo *)malloc(sizeof(struct TimerInfo));
					timerInfo->fd = mysocket->fd;
					timerInfo->pid = mysocket->pid;
					timerInfo->life = 0;
					timerInfo->seqnum = 0;
					timerInfo->packet_data = (uint8_t *)malloc(mypacket->getSize());
					mypacket->readData(0, timerInfo->packet_data, (size_t)mypacket->getSize());
					timerInfo->packet_length = mypacket->getSize();
					UUID timer = E::TimerModule::addTimer((void *) timerInfo,100000000);
					this->sendPacket(fromModule.c_str(),mypacket);
					if (mysocket->timer != 0) E::TimerModule::cancelTimer(mysocket->timer);
					printf("timer create: %d\n", timer);
					printf("timer cancel: %d\n", mysocket->timer);	
					mysocket->timer = timer;
					this->freePacket(packet);
				}

				break;
			}
		case 0x012:
			{
				//syn+ack
				//printf("packetarrive syn+ack enter\n");


				for(int i=0;i<socketlist.size();i++){
					if((socketlist[i]->port == d_port[0] && socketlist[i]->ip.s_addr == dest[0])||(socketlist[i]->port == d_port[0] && socketlist[i]->ip.s_addr == INADDR_ANY)){
						mysocket = socketlist[i];
						result = 1;
						break;
					}
				}

				if(result==0){
					//printf("no socket\n");
					this->freePacket(packet);
					break;
				}

				uint16_t window_size[1];
				packet->readData(14+34,window_size,2);
				window_size[0] = ntohs(window_size[0]);	
				mysocket->peer_window_size = window_size[0];

				E::TimerModule::cancelTimer(mysocket->timer);
				//printf("timer cancel: %d", mysocket->timer);
				mysocket->timer = 0;
				seq[0] = ntohl(htonl(seq[0])+1);
				flag[0] = 0x010;
				mypacket->writeData(14+12, dest, 4);
				mypacket->writeData(14+16, source, 4);
				mypacket->writeData(14+20, d_port, 2);
				mypacket->writeData(14+22, s_port, 2);
				mypacket->writeData(14+24, ack_seq, 4);
				mypacket->writeData(14+28, seq, 4);
				mypacket->writeData(14+33, flag, 1);

				uint16_t initzero[1];
				initzero[0] = 0;
				mypacket->writeData(14+36, initzero, 2);
				uint8_t tempsum[20];
				mypacket->readData(14+20, tempsum, 20);
				uint16_t checksum[1];
				checksum[0] = htons((~E::NetworkUtil::tcp_sum(dest[0], source[0], (uint8_t *)tempsum, 20)));
				mypacket->writeData(14+36, checksum, 2);

				mysocket->seqnum = ntohl(ack_seq[0]);
				mysocket->ack_seqnum = ntohl(seq[0]);
				mysocket->state = State::ESTAB;

				returnSystemCall(mysocket->syscallUUID,0);


				this->sendPacket(fromModule.c_str(),mypacket);
				this->freePacket(packet);
				break;
			}
		case 0x010:
			{
				//ack
				//ack 3handshaking
				//printf("packetarrive ack enter\n");
				for(int i=0;i<socketlist.size();i++){
					if((socketlist[i]->port == d_port[0] && socketlist[i]->ip.s_addr == dest[0])||(socketlist[i]->port == d_port[0] && socketlist[i]->ip.s_addr == INADDR_ANY)){
						mysocket = socketlist[i];
						index = i;
						result = 1;
						break;					
					}
				}

				if (result != 0) {
					if (mysocket->state != State::SYN_RCVD) {
						for(int i=0;i<socketlist.size();i++) {
							if((socketlist[i]->port == d_port[0] && socketlist[i]->ip.s_addr == dest[0] && socketlist[i]->d_port == s_port[0] && socketlist[i]->d_ip.s_addr == source[0])||(socketlist[i]->port == d_port[0] && socketlist[i]->ip.s_addr == INADDR_ANY && socketlist[i]->d_port == s_port[0] && socketlist[i]->d_ip.s_addr == source[0])){
								if (socketlist[i]->state != 9) {
									mysocket = socketlist[i];
									index = i;
									break;
								}		
							}
						}
					}
				}

				if(result==0){
					//printf("no socket\n");
					this->freePacket(packet);
					break;
				}


				if (mysocket->timer != 0) {
					E::TimerModule::cancelTimer(mysocket->timer);
					//printf("timer cancel: %d\n", mysocket->timer);
					mysocket->timer = 0;
				}

				if(mysocket->state == State::FIN_WAIT_1 && mysocket->seqnum+1 == ntohl(ack_seq[0])){
					//E::TimerModule::cancelTimer(mysocket->timer);
					//mysocket->timer = 0;

					//printf("finwait_1 to 2\n");
					//printf("seqnum: %x\n",mysocket->seqnum);
					if (mysocket->seqnum != ntohl(ack_seq[0])) {
						mysocket->state = State::FIN_WAIT_2;
					}
					mysocket->seqnum = ntohl(ack_seq[0]);
					this->freePacket(packet);
					break;
				} else if (mysocket->state == State::TIMED_WAIT) {
					//	if (mysocket->timer != 0) E::TimerModule::cancelTimer(mysocket->timer);
					//	mysocket->timer = 0;

					this->freePacket(packet);

					mysocket->seqnum = ntohl(ack_seq[0]);
					//this->timerCallback(0);
					struct TimerInfo * timerInfo = (struct TimerInfo *)malloc(sizeof(struct TimerInfo));
					timerInfo->fd = mysocket->fd;
					timerInfo->pid = mysocket->pid;
					timerInfo->seqnum =0;
					timerInfo->life =0;
					UUID timer = E::TimerModule::addTimer((void *)timerInfo, 60000000000);
					//printf("time wait timer create: %d\n", timer);
			
					//기다리기

					break;
				}
				else if(mysocket->state == State::LAST_ACK){
					//E::TimerModule::cancelTimer(mysocket->timer);
					//mysocket->timer = 0;

					mysocket->seqnum = ntohl(ack_seq[0]);
					mysocket->state = State::CLOSED;
					delete mysocket;
					socketlist.erase(socketlist.begin()+index);
					removeFileDescriptor(socketlist[index]->pid, socketlist[index]->fd);
					returnSystemCall(socketlist[index]->syscallUUID, 0);
					break;
				}
				else if(mysocket->state == State::SYN_RCVD){	
					mysocket->seqnum = ntohl(ack_seq[0]);
					if (mysocket->bind_connect != 0) {
						returnSystemCall(mysocket->syscallUUID, 0);
						mysocket->state = State::ESTAB;
						return;
					}
					if (mysocket->waitingqueue.size()==1) {
						mysocket->state = State::LISTEN;
						//mysocket->state = State::ESTAB;
					}
					//E::TimerModule::cancelTimer(mysocket->timer);
					//mysocket->timer = 0;


					struct Sockmeta * estabsocket;
					estabsocket = mysocket->waitingqueue.front();
					estabsocket->state = State::ESTAB;
					mysocket->waitingqueue.pop();
					mysocket->estabqueue.push(estabsocket);

					if(!mysocket->acceptqueue.empty()){
						struct Sockmeta * newsocket = mysocket->estabqueue.front();
						mysocket->estabqueue.pop();
						struct AcceptInfo * acceptinfo = mysocket->acceptqueue.front();
						mysocket->acceptqueue.pop();

						uint16_t window_size[1];
						packet->readData(14+34,window_size,2);
						window_size[0] = ntohs(window_size[0]);	
						newsocket->peer_window_size = window_size[0];


						newsocket->fd = acceptinfo->fd;
						newsocket->pid = acceptinfo->pid;
						newsocket->syscallUUID = acceptinfo->syscallUUID;
						newsocket->seqnum = 0;
						newsocket->seqnum = ntohl(ack_seq[0]);
						newsocket->ack_seqnum = ntohl(seq[0]);
						mysocket->state = State::LISTEN;
						struct sockaddr_in * myaddr_in = (struct sockaddr_in *) acceptinfo->addr;
						myaddr_in->sin_family = mysocket->sin_family;
						myaddr_in->sin_port = mysocket->port;
						myaddr_in->sin_addr = mysocket->ip;
						*(acceptinfo->addrlen) = mysocket->addrlen;

						returnSystemCall(newsocket->syscallUUID, newsocket->fd);
						//printf("return no~~1\n");


						//printf("0x010 getsocket:%d\n",newsocket->fd);
					} else {
						struct Sockmeta * newsocket = mysocket->estabqueue.back();
						newsocket->seqnum = ntohl(ack_seq[0]);
						uint16_t window_size[1];
						packet->readData(14+34,window_size,2);
						window_size[0] = ntohs(window_size[0]);	
						newsocket->peer_window_size = window_size[0];
						newsocket->ack_seqnum = ntohl(seq[0]);
						//printf("no acceptqueue\n");
					}
					this->freePacket(packet);
					break;
				} else if(mysocket->state == State::ESTAB || mysocket->state == State::FIN_WAIT_1){
					//printf("packet enter, count : %d, packetsize : %d\n",mysocket->readInfo->count, packet->getSize());	
					//printf("pass here 1\n");
					if (packet->getSize()-54 == 0) {
						//printf("pass here 2\n");
						uint16_t window_size[1];
						packet->readData(14+34,window_size,2);
						window_size[0] = ntohs(window_size[0]);
						if (mysocket->save_seqnum == ntohl(ack_seq[0]) && mysocket->seqnum > ntohl(ack_seq[0]) && mysocket->peer_window_size != window_size[0]) {
							printf("mysocket->seqnum: %d\n",mysocket->seqnum);
							printf("ack_seq[0]: %d", ntohl(ack_seq[0]));
							mysocket->fast_retransmit++;
						} else {
							mysocket->fast_retransmit = 0;
						}
						mysocket->save_seqnum = ntohl(ack_seq[0]);
						if (mysocket->fast_retransmit==2) {
							mysocket->retranscall = 1;
							printf("retransmit\n");
							int buffer_size = 0;
							for(int i=0;i<mysocket->write_buffer.size();i++) {
								if (mysocket->write_buffer[i]->seqnum >= ntohl(ack_seq[0]) && buffer_size < 512*((mysocket->slowstart*4)/4)) {
									Packet* mypacket = this->allocatePacket(mysocket->write_buffer[i]->packet_length);
									mypacket->writeData(0, mysocket->write_buffer[i]->packet_data, mysocket->write_buffer[i]->packet_length);
									this->sendPacket("IPv4",mypacket);	
									buffer_size += (mysocket->write_buffer[i]->packet_length-54);	
								}
							}
							mysocket->slowstart = ((mysocket->slowstart*2)/4);
							//mysocket->callindex = 0;

						}

						mysocket->peer_window_size = window_size[0];
						for(int i=0;i<mysocket->write_buffer.size();i++) {
							if (mysocket->write_buffer[i]->seqnum == ntohl(ack_seq[0])) {
								if (mysocket->write_buffer_size<=MIN(mysocket->peer_window_size, mysocket->slowstart*512)) {
									
									if (mysocket->seqnum == ntohl(ack_seq[0])) {
										//printf("delete\n");
										if (mysocket->timer != 0) E::TimerModule::cancelTimer(mysocket->timer);
										//printf("timer cancel: %d\n", mysocket->timer);
										mysocket->timer = 0;
									} 
									for (int j=0;j<=i;j++) {
										
										mysocket->write_buffer_size -= (mysocket->write_buffer[0]->packet_length-54);
										mysocket->write_buffer.erase(mysocket->write_buffer.begin());
									}
								}
								else if (mysocket->write_buffer_size>MIN(mysocket->peer_window_size, mysocket->slowstart*512)) {
									
									//printf("over window size\n");
									if (mysocket->seqnum == ntohl(ack_seq[0])) {
										if (mysocket->timer != 0) E::TimerModule::cancelTimer(mysocket->timer);
										//printf("timer cancel: %d\n", mysocket->timer);
										mysocket->timer = 0;
									} 
									for (int j=0;j<=i;j++) {
										
										mysocket->write_buffer_size -= (mysocket->write_buffer[0]->packet_length-54);
										mysocket->write_buffer.erase(mysocket->write_buffer.begin());
									}
									if(mysocket->write_buffer.size()>0){
									struct TimerInfo * timerInfo = mysocket->write_buffer[mysocket->write_buffer.size()-1];
										//printf("length : %d\n",timerInfo->packet_length);
										//printf("life: %d\n", timerInfo->life);
										Packet* mypacket = this->allocatePacket(timerInfo->packet_length);
										mypacket->writeData(0, timerInfo->packet_data, timerInfo->packet_length);
										this->sendPacket("IPv4",mypacket);	
										UUID timer = E::TimerModule::addTimer((void *) timerInfo, 100000000);		
										if (mysocket->timer != 0) E::TimerModule::cancelTimer(mysocket->timer);
										//printf("timer create: %d\n", timer);
										//printf("timer cancel: %d\n", mysocket->timer);
										mysocket->timer = timer;

										mysocket->seqnum += (timerInfo->packet_length-54);
										returnSystemCall(timerInfo->syscallUUID,timerInfo->packet_length-54);

										if(mysocket->retranscall==1||((mysocket->write_buffer_size >= mysocket->real_wsize)&&(mysocket->peer_window_size>mysocket->slowstart*512)&&(mysocket->callindex==mysocket->slowstart))){
											printf("**pass2-1\n");
											if((mysocket->slowstart < 64)&&(mysocket->retranscall ==0)){
												mysocket->slowstart = (mysocket->slowstart)*2;
											}
											else{
												if(mysocket->slowstart == 64){

												}
												else{
													mysocket->slowstart = (mysocket->slowstart)+1;
												}
												
											}
										}
										
									}
									//printf("!!!return :%d\n",timerInfo->packet_length-54);	
								}
								break;
							 }
						}
						//mysocket->timer = 0;
						return;
					}
					if (mysocket->readInfo->count>0) {
						mysocket->seqnum = ntohl(ack_seq[0]);
						int data_length = MIN((packet->getSize()-54), mysocket->readInfo->count);
						uint8_t * tempdata = (uint8_t* )malloc(sizeof(uint8_t)*data_length);
						//printf("first / data_length : %d\n", data_length);
						packet->readData(14+40, tempdata, data_length);
						//printf("data[0] : %02x\n", tempdata[0]);
						//printf("buf addr : %p\n", mysocket->readInfo->read_buffer);
						memcpy(mysocket->readInfo->read_buffer, tempdata, data_length);

						Packet* mypacket = this->allocatePacket(54);
						seq[0] = ntohl(htonl(seq[0])+packet->getSize()-54);
						uint8_t header_length[1];
						header_length[0] = 80;
						uint16_t window_size[1];
						window_size[0]= htons(51200);

						flag[0] = 0x010;
						mypacket->writeData(14+12, dest, 4);
						mypacket->writeData(14+16, source, 4);
						mypacket->writeData(14+20, d_port, 2);
						mypacket->writeData(14+22, s_port, 2);
						mypacket->writeData(14+24, ack_seq, 4);
						mypacket->writeData(14+28, seq, 4);
						mypacket->writeData(14+33, flag, 1);
						mypacket->writeData(14+32, header_length, 1);
						mypacket->writeData(14+34, window_size, 2);
						uint16_t initzero[1];
						initzero[0] = 0;
						mypacket->writeData(14+36, initzero, 2);
						uint8_t tempsum[20];
						mypacket->readData(14+20, tempsum, 20);
						uint16_t checksum[1];
						checksum[0] = htons((~E::NetworkUtil::tcp_sum(dest[0], source[0], (uint8_t *)tempsum, 20)));
						mypacket->writeData(14+36, checksum, 2);

						this->sendPacket("IPv4",mypacket);

						if (packet->getSize()-54>data_length) {
							int rest_data_length = packet->getSize()-54-data_length;
							uint8_t * restdata = (uint8_t* )malloc(sizeof(uint8_t)*rest_data_length);
							packet->readData(14+40+data_length, restdata, rest_data_length);
							memcpy(&(mysocket->read_buffer[mysocket->read_buffer_pointer]),restdata, rest_data_length);
							mysocket->read_buffer_pointer += rest_data_length;
						}
						returnSystemCall(mysocket->syscallUUID, data_length);
						//printf("return no~~2\n");
					} else { 
						int data_length = packet->getSize();
						uint8_t data[data_length];
						packet->readData(14+40, data, data_length);
						memcpy(&(mysocket->read_buffer[mysocket->read_buffer_pointer]),data,data_length);
						mysocket->read_buffer_pointer += data_length;
						//printf("psss11\n");
						//printf("readbuffpointer : %d\n", mysocket->read_buffer_pointer);
					}
					this->freePacket(packet);
					break;
				}
			}
	}
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type){
	int fd =createFileDescriptor(pid);
	if(pid<0){
		returnSystemCall(syscallUUID, -1);
		//printf("return no~~3\n");
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
		sockmeta->seqnum = pid << 16;
		sockmeta->seqnum += fd;
		sockmeta->backlog = 1;
		sockmeta->syscallUUID = -1;
		sockmeta->read_buffer_pointer = 0;
		sockmeta->readInfo = (struct ReadInfo *)malloc(sizeof(struct ReadInfo));
		sockmeta->readInfo->count = 0;
		sockmeta->readInfo->read_buffer = 0;
		socketlist.push_back(sockmeta);
		sockmeta->bind_connect = 0;
		sockmeta->slowstart = 1;
		sockmeta->real_wsize = 0;
		sockmeta->callindex = 0;
		sockmeta->first = 0;
		sockmeta->retranscall = 0;
		sockmeta->write_buffer_size = 0;
		returnSystemCall(syscallUUID, fd);
		
		//printf("syscall_socket fd : %d\n", fd);
		//소켓을 만들고 어디 테이블에 넣어야할듯 - socketlist
	}

}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd){
	//어디 테이블에서 pid에 알맞는 소켓을 찾아 없애야할듯
	//printf("close enter\n");
	struct Sockmeta * mysocket;
	int result = 0;
	int index = 0;
	for(int i=0;i<socketlist.size();i++){
		if(socketlist[i]->fd==sockfd&&socketlist[i]->pid==pid){
			mysocket = socketlist[i];
			index = i;
			result = 1;
			break;
		}
	}
	if(result==0){
		//printf("no socket\n");
		returnSystemCall(syscallUUID, -1);
		//printf("return no~~4\n");
	}
	else{
		if(mysocket->state == State::ESTAB){
			//printf("close estab enter\n");
			Packet* mypacket = this->allocatePacket(54);
			mysocket->state = State::FIN_WAIT_1;
			mysocket->syscallUUID = syscallUUID;

			/*int interface_index = 0;
			  uint8_t temp_addr[4];
			  uint32_t d_ip_addr = mysocket->d_ip.s_addr;
			  for (int i=0; i<4; i++) {
			  temp_addr[3-i] = d_ip_addr & 0xff;
			  d_ip_addr >>= 8;
			  }
			  interface_index = this->getHost()->getRoutingTable(temp_addr);
			  uint8_t ip_buffer[4];
			  bool routing_result = this->getHost()->getIPAddr(ip_buffer, interface_index);
			  uint32_t ip;
			  ip = ip_buffer[0] << 24;
			  ip += ip_buffer[1] << 16;
			  ip += ip_buffer[2] << 8;
			  ip += ip_buffer[3] << 0;*/

			//printf("source_ip: %x\n", mysocket->ip.s_addr);
			uint32_t source[1];
			source[0] = mysocket->ip.s_addr;
			//source[0] = htonl(ip);
			uint32_t dest[1];
			dest[0] = mysocket->d_ip.s_addr;
			uint16_t s_port[1];
			s_port[0] = mysocket->port;
			uint16_t d_port[1];
			d_port[0] = mysocket->d_port;
			uint32_t ack_seq[1];
			ack_seq[0] = 0;
			uint8_t flag[1];
			flag[0] = 0x001;
			uint8_t header_length[1];
			header_length[0] = 80;
			uint16_t window_size[1];
			window_size[0]= htons(51200);


			uint32_t msg_seq[1];
			msg_seq[0]= htonl(mysocket->seqnum);

			mypacket->writeData(14+12, source, 4);
			mypacket->writeData(14+16, dest, 4);
			mypacket->writeData(14+20, s_port, 2);
			mypacket->writeData(14+22, d_port, 2);
			mypacket->writeData(14+24, msg_seq, 4);
			mypacket->writeData(14+28, ack_seq, 4);
			mypacket->writeData(14+32, header_length, 1);
			mypacket->writeData(14+33, flag, 1);
			mypacket->writeData(14+34, window_size, 2);
			uint16_t initzero[1];
			initzero[0] = 0;
			mypacket->writeData(14+36, initzero, 2);
			uint8_t tempsum[20];
			mypacket->readData(14+20, tempsum, 20);
			uint16_t checksum[1];
			checksum[0] = htons((~E::NetworkUtil::tcp_sum(dest[0], source[0], (uint8_t *)tempsum, 20)));
			mypacket->writeData(14+36, checksum, 2);

			struct TimerInfo * timerInfo = (struct TimerInfo *)malloc(sizeof(struct TimerInfo));
			timerInfo->fd = sockfd;
			timerInfo->pid = pid;
			timerInfo->life = 0;	
			timerInfo->seqnum = 0;
			timerInfo->packet_data = (uint8_t *)malloc(mypacket->getSize());
			mypacket->readData(0, timerInfo->packet_data, (size_t)mypacket->getSize());
			timerInfo->packet_length = mypacket->getSize();
			UUID timer = E::TimerModule::addTimer((void *) timerInfo,100000000);
			this->sendPacket("IPv4",mypacket);
			if (mysocket->timer != 0) E::TimerModule::cancelTimer(mysocket->timer);
			//printf("timer create: %d\n", timer);
			//printf("timer cancel: %d\n", mysocket->timer);
			mysocket->timer = timer;

		} else if(mysocket->state == State::CLOSE_WAIT){
			//printf("close wait endter\n");
			Packet* mypacket = this->allocatePacket(54);
			mysocket->state = State::LAST_ACK;
			mysocket->syscallUUID = syscallUUID;

			/*int interface_index = 0;
			  uint8_t temp_addr[4];
			  uint32_t d_ip_addr = mysocket->d_ip.s_addr;
			  for (int i=0; i<4; i++) {
			  temp_addr[3-i] = d_ip_addr & 0xff;
			  d_ip_addr >>= 8;
			  }
			  interface_index = this->getHost()->getRoutingTable(temp_addr);
			  printf("d_ip.s_addr: %d", d_ip_addr);
			  printf("interface_index: %d\n", interface_index);
			  uint8_t ip_buffer[4];
			  bool routing_result = this->getHost()->getIPAddr(ip_buffer, interface_index);
			  uint32_t ip;
			  ip = ip_buffer[0] << 24;
			  ip += ip_buffer[1] << 16;
			  ip += ip_buffer[2] << 8;
			  ip += ip_buffer[3] << 0;*/

			uint32_t source[1];
			source[0] = mysocket->ip.s_addr;
			//source[0] = htonl(ip);
			uint32_t dest[1];
			dest[0] = mysocket->d_ip.s_addr;
			uint16_t s_port[1];
			s_port[0] = mysocket->port;
			uint16_t d_port[1];
			d_port[0] = mysocket->d_port;
			uint32_t ack_seq[1];
			ack_seq[0] = 0;
			uint8_t flag[1];	
			flag[0] = 0x001;
			uint8_t header_length[1];
			header_length[0] = 80;
			uint16_t window_size[1];
			window_size[0]= htons(51200);

			uint32_t msg_seq[1];
			msg_seq[0] = ntohl(mysocket->seqnum);

			mypacket->writeData(14+12, source, 4);
			mypacket->writeData(14+16, dest, 4);
			mypacket->writeData(14+20, s_port, 2);
			mypacket->writeData(14+22, d_port, 2);
			mypacket->writeData(14+24, msg_seq, 4);
			mypacket->writeData(14+28, ack_seq, 4);
			mypacket->writeData(14+32, header_length, 1);
			mypacket->writeData(14+33, flag, 1);
			mypacket->writeData(14+34, window_size, 2);
			uint16_t initzero[1];
			initzero[0] = 0;
			mypacket->writeData(14+36, initzero, 2);
			uint8_t tempsum[20];
			mypacket->readData(14+20, tempsum, 20);
			uint16_t checksum[1];
			checksum[0] = htons((~E::NetworkUtil::tcp_sum(dest[0], source[0], (uint8_t *)tempsum, 20)));
			mypacket->writeData(14+36, checksum, 2);

			struct TimerInfo * timerInfo = (struct TimerInfo *)malloc(sizeof(struct TimerInfo));
			timerInfo->fd = sockfd;
			timerInfo->pid = pid;
			timerInfo->life = 0;
			timerInfo->seqnum = 0;
			timerInfo->packet_data = (uint8_t *)malloc(mypacket->getSize());
			mypacket->readData(0, timerInfo->packet_data, (size_t)mypacket->getSize());
			timerInfo->packet_length = mypacket->getSize();
			UUID timer = E::TimerModule::addTimer((void *) timerInfo,100000000);
			this->sendPacket("IPv4",mypacket);
			if (mysocket->timer != 0) E::TimerModule::cancelTimer(mysocket->timer);
			//printf("timer create: %d\n", timer);
			//printf("timer cancel: %d\n", mysocket->timer);
			mysocket->timer = timer;

		}
		else{
			delete mysocket;
			socketlist.erase(socketlist.begin()+index);
			removeFileDescriptor(pid, sockfd);
			returnSystemCall(syscallUUID, 0);
		}

	}
	//printf("close end\n");
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *myaddr, socklen_t addrlen){
	//AF_INET인지 시스템 내에서 통신하는 AF_UNIX에 따라서 달라짐.
	//AF_INET의 경우 sockaddr을 인터넷에서 사용하는 sockaddr_in으로 들어온다.
	//printf("**syscall_bind fd : %d\n", sockfd);

	if(myaddr->sa_family==AF_INET){
		struct sockaddr_in * myaddr_in=(struct sockaddr_in *) myaddr;
		sa_family_t	sin_family = myaddr_in->sin_family; 
		unsigned short int port = myaddr_in->sin_port;
		struct in_addr ip = myaddr_in->sin_addr;
		//printf("**syscall_bind port : %d\n", port);
		//printf("**syscall_bind ip : %d\n", ip.s_addr);
		//printf("**syscall_bind pid: %d\n",pid);

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
				//printf("return no~~5\n");
				return;
			}
			if((port == socketlist[i]->port)&&(ip.s_addr == INADDR_ANY)){
				//2)조건
				//printf("pass2\n");
				returnSystemCall(syscallUUID, -1);
				//printf("return no~~6\n");
				return;
			}
			if((port == socketlist[i]->port)&&(ip.s_addr == socketlist[i]->ip.s_addr)){
				//2)조건
				//printf("pass3\n");
				returnSystemCall(syscallUUID, -1);
				//printf("return no~~7\n");
				return;
			}
			if((socketlist[i]->fd==sockfd)&&(socketlist[i]->sin_family != 0)&&(socketlist[i]->pid==pid)){
				//1)조건
				//printf("pass4\n");
				returnSystemCall(syscallUUID, -1);
				//printf("return no~~8\n");
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
			//printf("return no~~9\n");
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
			//printf("return no~~10\n");
			//printf("**syscall_bind fail\n");
		}
		else{
			returnSystemCall(syscallUUID, 0);
			//printf("**syscall_bind success\n");
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
			break;
		}
	}
	if(result==0){
		returnSystemCall(syscallUUID, -1);
		//printf("return no~~11\n");
		//printf("**syscall_getsockname fail\n");
	}
	else{
		returnSystemCall(syscallUUID, 0);
		//printf("**syscall_getsockname success\n");
	}
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog){
	int result = 0;
	for(int i=0;i<socketlist.size();i++){
		if(socketlist[i]->fd==sockfd&&socketlist[i]->pid==pid){
			socketlist[i]->state=State::LISTEN;
			socketlist[i]->backlog = backlog;
			result = 1;
			break;
		}
	}
	//printf("listen enter\n");
	//printf("listen backlog %d\n", backlog);
	if(result==0){
		returnSystemCall(syscallUUID, -1);
		//printf("return no~~12\n");
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
	//printf("accept enter\n");
	int fd =createFileDescriptor(pid);
	if(pid<0){
		returnSystemCall(syscallUUID, -1);
		//printf("return no~~13\n");
	}

	struct AcceptInfo * acceptinfo = new struct AcceptInfo;
	acceptinfo->pid = pid;
	acceptinfo->fd = fd;	
	acceptinfo->addr = addr;
	acceptinfo->addrlen = addrlen;
	acceptinfo->syscallUUID = syscallUUID;
	mysocket->acceptqueue.push(acceptinfo);

	if (!mysocket->estabqueue.empty()) {

		struct Sockmeta * newsocket = mysocket->estabqueue.front();
		mysocket->estabqueue.pop();
		struct AcceptInfo * acceptinfo = mysocket->acceptqueue.front();
		mysocket->acceptqueue.pop();

		newsocket->fd = acceptinfo->fd;
		newsocket->pid = acceptinfo->pid;
		newsocket->syscallUUID = acceptinfo->syscallUUID;		

		//mysocket->state = State::ESTAB;

		struct sockaddr_in * myaddr_in = (struct sockaddr_in *) acceptinfo->addr;
		myaddr_in->sin_family = mysocket->sin_family;
		myaddr_in->sin_port = mysocket->port;
		myaddr_in->sin_addr = mysocket->ip;
		*(acceptinfo->addrlen) = mysocket->addrlen;

		returnSystemCall(syscallUUID, newsocket->fd);
		//estabqueu에서 꺼내온??

		//printf("accept accept\n");
	}

	//printf("accept end\n");
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen){
	struct Sockmeta * mysocket;
	struct sockaddr_in * myaddr_in=(struct sockaddr_in *) addr;
	int result = 0;
	for(int i=0;i<socketlist.size();i++){
		if(socketlist[i]->fd==sockfd&&socketlist[i]->pid==pid){
			mysocket = socketlist[i];
			result = 1;
			break;
		}
	}

	if(mysocket->sin_family == 0) {
		int interface_index = 0;
		uint8_t temp_addr[4];
		uint32_t d_ip_addr = myaddr_in->sin_addr.s_addr;
		for (int i=0; i<4; i++) {
			temp_addr[3-i] = d_ip_addr & 0xff;
			d_ip_addr >>= 8;
		}

		interface_index = this->getHost()->getRoutingTable(temp_addr);
		uint8_t ip_buffer[4];

		bool routing_result = false;
		routing_result = this->getHost()->getIPAddr(ip_buffer, interface_index);
		uint32_t ip;
		ip = ip_buffer[0] << 24;
		ip += ip_buffer[1] << 16;
		ip += ip_buffer[2] << 8;
		ip += ip_buffer[3] << 0;
		int result = 0;
		uint16_t port = 0;
		while (result == 0) {
			int not_same = 0;
			port = rand() % 16384 + 49152;
			for(int i=0;i<socketlist.size();i++){
				if (port == socketlist[i]->port) {
					not_same = 1;
				}
			}
			if (not_same == 0) {
				result = 1;
			}
		}
		mysocket->pid = pid; 
		mysocket->sin_family = AF_INET;
		mysocket->port = htons(port);
		mysocket->ip.s_addr = htonl(ip);
		mysocket->addrlen = sizeof(struct sockaddr_in);
	} else {
		sa_family_t sin_family = myaddr_in->sin_family;
		unsigned short int port = myaddr_in->sin_port;
		struct in_addr ip = myaddr_in->sin_addr;

		mysocket->syscallUUID = syscallUUID;
		mysocket->d_sin_family = sin_family;
		mysocket->d_port = port;
		mysocket->d_ip.s_addr = ip.s_addr;
		mysocket->d_addrlen = addrlen;
		mysocket->bind_connect = 1;		
		//returnSystemCall(mysocket->syscallUUID,0);
		return;
	}

	sa_family_t sin_family = myaddr_in->sin_family;
	unsigned short int port = myaddr_in->sin_port;
	struct in_addr ip = myaddr_in->sin_addr;

	mysocket->syscallUUID = syscallUUID;
	mysocket->state = State::SYN_SENT;
	mysocket->d_sin_family = sin_family;
	mysocket->d_port = port;
	mysocket->d_ip.s_addr = ip.s_addr;
	mysocket->d_addrlen = addrlen;

	Packet* mypacket = this->allocatePacket(54);
	uint32_t source[1];
	source[0] = mysocket->ip.s_addr;
	uint32_t dest[1];
	dest[0] = ip.s_addr;
	uint16_t d_port[1];
	d_port[0] = port;
	uint16_t s_port[1];
	s_port[0] = mysocket->port;
	uint32_t seq[1];
	seq[0]= htonl(mysocket->seqnum);
	uint32_t ack_seq[1];
	ack_seq[0] = 0;
	uint8_t flag[1];
	flag[0] = 0x002;
	uint8_t header_length[1];
	header_length[0] = 80;
	uint16_t window_size[1];
	window_size[0]= htons(51200);
	mypacket->writeData(14+12, source, 4);
	mypacket->writeData(14+16, dest, 4);
	mypacket->writeData(14+20, s_port, 2);
	mypacket->writeData(14+22, d_port, 2);
	mypacket->writeData(14+24, seq, 4);
	mypacket->writeData(14+28, ack_seq, 4);
	mypacket->writeData(14+32, header_length, 1);
	mypacket->writeData(14+33, flag, 1);
	mypacket->writeData(14+34, window_size, 2);

	uint16_t initzero[1];
	initzero[0] = 0;
	mypacket->writeData(14+36, initzero, 2);
	uint8_t tempsum[20];
	mypacket->readData(14+20, tempsum, 20);
	uint16_t checksum[1];
	checksum[0] = htons((~E::NetworkUtil::tcp_sum(source[0], dest[0], (uint8_t *)tempsum, 20)));
	mypacket->writeData(14+36, checksum, 2);

	struct TimerInfo * timerInfo = (struct TimerInfo *)malloc(sizeof(struct TimerInfo));
	timerInfo->fd = sockfd;
	timerInfo->pid = pid;
	timerInfo->life = 0;
	timerInfo->seqnum = 0;
	timerInfo->packet_data = (uint8_t *)malloc(mypacket->getSize());
	mypacket->readData(0, timerInfo->packet_data, (size_t)mypacket->getSize());
	timerInfo->packet_length = mypacket->getSize();
	UUID timer = E::TimerModule::addTimer((void *) timerInfo,100000000);
	this->sendPacket("IPv4",mypacket);
	if (mysocket->timer != 0) E::TimerModule::cancelTimer(mysocket->timer);
			//printf("timer create: %d\n", timer);
		//printf("timer cancel: %d\n", mysocket->timer);
	mysocket->timer = timer;

	//printf("timer create UUID: %d\n", mysocket->timer);
	//printf("abs time: %d\n", this->getHost()->getSystem()->getCurrentTime());

	//printf("connect packet send success\n");

	//소켓 다시 보내야함.
	//bind에 대해 체크해야한다는데, 어떻게??
	//(socketlist[i]->sin_family != 0)이거 바인드 했는지 체크인데 이걸로 할수있으면하면된다.
	//이걸로 안되면 바인드한거 모으는 리스트를 따로 만들어야할듯!
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	//printf("getpeername enter\n");
	struct sockaddr_in * myaddr_in=(struct sockaddr_in *) addr;
	int result = 0;
	for(int i=0;i<socketlist.size();i++){
		if(socketlist[i]->fd==sockfd&&socketlist[i]->pid==pid){
			myaddr_in->sin_addr.s_addr = socketlist[i]->d_ip.s_addr;
			myaddr_in->sin_port = socketlist[i]->d_port;
			myaddr_in->sin_family = socketlist[i]->d_sin_family;
			*addrlen = socketlist[i]->d_addrlen;
			result = 1;
			break;
		}
	}
	if(result==0){
		returnSystemCall(syscallUUID, -1);
		//printf("return no~~14\n");
		//printf("**syscall_getpeername fail\n");
	}
	else{
		returnSystemCall(syscallUUID, 0);
		//printf("**syscall_getpeername success\n");
	}
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid,  int fd, void *buf, size_t count){		
	struct Sockmeta * mysocket;
	int result = 0;
	for(int i=0;i<socketlist.size();i++){
		if(socketlist[i]->fd==fd&&socketlist[i]->pid==pid){
			mysocket = socketlist[i];
			result = 1;
			break;
		}
	}
		
	if (result == 0) {
		return;
	}
	
	//printf("enter read\n");
	if (mysocket->read_buffer_pointer>0) {
		//printf("pass 1\n");
		//printf("pointer: %d\n", mysocket->read_buffer_pointer);
		int data_length = MIN(mysocket->read_buffer_pointer, count);
		memcpy(buf,&(mysocket->read_buffer[0]),data_length);
		memcpy(mysocket->read_buffer,&(mysocket->read_buffer[data_length]),mysocket->read_buffer_pointer-data_length);
		memset(&(mysocket->read_buffer[mysocket->read_buffer_pointer-data_length]),0,data_length);
		mysocket->read_buffer_pointer = mysocket->read_buffer_pointer-data_length;		
		returnSystemCall(syscallUUID, data_length);
		//printf("return no~~15\n");
	} else {
		//printf("pass 2\n");
		mysocket->syscallUUID = syscallUUID;
		struct ReadInfo * tempInfo = (struct ReadInfo *)malloc(sizeof(struct ReadInfo));
		tempInfo->read_buffer = buf;
		tempInfo->count = count;
		mysocket->readInfo = tempInfo;
		//mysocket->readInfo->read_buffer = tempInfo->read_buffer;
		//mysocket->readInfo->count = tempInfo->count;		
	}
}


void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, const void *buf, size_t count){
	//printf("enter Wrint\n");
	struct Sockmeta * mysocket;
	int result = 0;
	for(int i=0;i<socketlist.size();i++){
		if(socketlist[i]->fd==fd&&socketlist[i]->pid==pid){
			mysocket = socketlist[i];
			result = 1;
			break;
		}
	}
	
	int data_length = MIN(512, count);
	Packet* mypacket = this->allocatePacket(54+data_length);
	mysocket->syscallUUID=syscallUUID;
	int interface_index = 0;
	uint8_t temp_addr[4];
	uint32_t d_ip_addr = mysocket->d_ip.s_addr;
	for (int i=0; i<4; i++) {
		temp_addr[3-i] = d_ip_addr & 0xff;
		d_ip_addr >>= 8;
	}
	interface_index = this->getHost()->getRoutingTable(temp_addr);
	uint8_t ip_buffer[4];
	bool routing_result = this->getHost()->getIPAddr(ip_buffer, interface_index);
	uint32_t ip;
	ip = ip_buffer[0] << 24;
	ip += ip_buffer[1] << 16;
	ip += ip_buffer[2] << 8;
	ip += ip_buffer[3] << 0;
				
	//printf("source_ip: %x\n", mysocket->ip.s_addr);
	uint32_t source[1];
	source[0] = htonl(ip);
	uint32_t dest[1];
	dest[0] = mysocket->d_ip.s_addr;
	uint16_t s_port[1];
	s_port[0] = mysocket->port;
	uint16_t d_port[1];
	d_port[0] = mysocket->d_port;
	uint32_t ack_seq[1];
	ack_seq[0] = htonl(mysocket->ack_seqnum);
	uint8_t flag[1];
	flag[0] = 0x010;
	uint8_t header_length[1];
        header_length[0] = 80;
        uint16_t window_size[1];
        window_size[0]= htons(51200);
	uint8_t data[data_length];
	memcpy(data, buf, data_length);

	uint32_t msg_seq[1];
	msg_seq[0]= htonl(mysocket->seqnum);
			
	mypacket->writeData(14+12, source, 4);
	mypacket->writeData(14+16, dest, 4);
	mypacket->writeData(14+20, s_port, 2);
	mypacket->writeData(14+22, d_port, 2);
	mypacket->writeData(14+24, msg_seq, 4);
	mypacket->writeData(14+28, ack_seq, 4);
        mypacket->writeData(14+32, header_length, 1);
	mypacket->writeData(14+33, flag, 1);
        mypacket->writeData(14+34, window_size, 2);
	mypacket->writeData(14+40, data, data_length);
	uint16_t initzero[1];
	initzero[0] = 0;
	mypacket->writeData(14+36, initzero, 2);
	uint8_t tempsum[20+data_length];
	mypacket->readData(14+20, tempsum, 20+data_length);
	uint16_t checksum[1];
	checksum[0] = htons((~E::NetworkUtil::tcp_sum(dest[0], source[0], (uint8_t *)tempsum, 20+data_length)));
	mypacket->writeData(14+36, checksum, 2);
	
	mysocket->real_wsize = MIN(mysocket->peer_window_size, mysocket->slowstart*512);
	printf("call: %d, write: %d, pwz: %d, slow: %d, real: %d\n",mysocket->callindex*512, mysocket->write_buffer_size, mysocket->peer_window_size, mysocket->slowstart*512, mysocket->real_wsize);


	if (((mysocket->write_buffer_size<mysocket->real_wsize)||(mysocket->first==0))&&((mysocket->peer_window_size<mysocket->slowstart*512)||!(mysocket->write_buffer_size==mysocket->slowstart*512&&mysocket->callindex<mysocket->slowstart))){
		printf("**pass1\n");
		struct TimerInfo * timerInfo = (struct TimerInfo *)malloc(sizeof(struct TimerInfo));
		timerInfo->fd = fd;
		timerInfo->pid = pid;
		timerInfo->life = 0;
		timerInfo->syscallUUID = syscallUUID;
		timerInfo->seqnum = mysocket->seqnum+data_length;
		timerInfo->packet_data = (uint8_t *)malloc(mypacket->getSize());
		mypacket->readData(0, timerInfo->packet_data, (size_t)mypacket->getSize());
		timerInfo->packet_length = mypacket->getSize();
		UUID timer = E::TimerModule::addTimer((void *) timerInfo,100000000);
		this->sendPacket("IPv4",mypacket);
		if (mysocket->timer != 0) E::TimerModule::cancelTimer(mysocket->timer);
		//printf("timer create: %d\n", timer);
		//printf("timer cancel: %d\n", mysocket->timer);
		mysocket->timer = timer;
		mysocket->write_buffer.push_back(timerInfo);
		mysocket->write_buffer_size += data_length;
		mysocket->seqnum += data_length;
		returnSystemCall(syscallUUID, data_length);
		mysocket->first = 1;
		
		//printf("!!!return :%d\n",data_length);
	} else {	
		printf("**pass2\n");
		if(mysocket->callindex*512 != 65536){
			mysocket->callindex += 1;
		}
		struct TimerInfo * timerInfo = (struct TimerInfo *)malloc(sizeof(struct TimerInfo));
		timerInfo->fd = fd;
		timerInfo->pid = pid;
		timerInfo->life = 0;
		timerInfo->syscallUUID = syscallUUID;
		timerInfo->seqnum = mysocket->seqnum+data_length;
		timerInfo->packet_data = (uint8_t *)malloc(mypacket->getSize());
		mypacket->readData(0, timerInfo->packet_data, (size_t)mypacket->getSize());
		timerInfo->packet_length = mypacket->getSize();
		mysocket->write_buffer.push_back(timerInfo);
		mysocket->write_buffer_size += data_length;
		
		
	}
}


void TCPAssignment::timerCallback(void* payload)
{
	printf("timercallback\n");
	if (payload != 0) {
		struct TimerInfo * timerInfo = (struct TimerInfo *)payload;
		//printf("timer life %d\n", timerInfo->life);
		//printf("packet_length: %d\n", timerInfo->packet_length);
		if (timerInfo->life > 5) return;
		timerInfo->life++;
		int sockfd = timerInfo->fd;
		int pid = timerInfo->pid;
		int result = 0;
		int index = 0;
		Sockmeta * mysocket;
		for(int i=0;i<socketlist.size();i++){
			if(socketlist[i]->fd==sockfd&&socketlist[i]->pid==pid){
				mysocket = socketlist[i];
				index = i;
				result = 1;
				break;
			}
		}
		if (result == 0) {
			printf("no socket\n");
			return;
		}
		if (mysocket->state == State::TIMED_WAIT) {
			mysocket->state = State::CLOSED;
                        delete mysocket;
                        socketlist.erase(socketlist.begin()+index);
                        removeFileDescriptor(socketlist[index]->pid, socketlist[index]->fd);
                        returnSystemCall(socketlist[index]->syscallUUID, 0);	
		} else if (timerInfo->seqnum == 0) {
			//printf("seqnum\n");
			Packet* mypacket = this->allocatePacket(timerInfo->packet_length);
			mypacket->writeData(0, timerInfo->packet_data, timerInfo->packet_length);
			this->sendPacket("IPv4",mypacket);	
			UUID timer = E::TimerModule::addTimer((void *) timerInfo, 100000000);	
			//printf("timer create: %d\n", timer);
			//printf("timer cancel: %d\n", mysocket->timer);
			mysocket->timer = timer;
		} else {
			for(int i=0;i<mysocket->write_buffer.size();i++) {
				if (mysocket->write_buffer[i]->seqnum < timerInfo->seqnum) {
					Packet* mypacket = this->allocatePacket(mysocket->write_buffer[i]->packet_length);
					mypacket->writeData(0, mysocket->write_buffer[i]->packet_data, mysocket->write_buffer[i]->packet_length);
					this->sendPacket("IPv4",mypacket);	
				} else {
					//printf("timercallback resend\n");
					Packet* mypacket = this->allocatePacket(timerInfo->packet_length);
					mypacket->writeData(0, timerInfo->packet_data, timerInfo->packet_length);
					this->sendPacket("IPv4",mypacket);	
					UUID timer = E::TimerModule::addTimer((void *) timerInfo, 100000000);	
					//printf("timer create: %d\n", timer);
					//printf("timer cancel: %d\n", mysocket->timer);
					mysocket->timer = timer;
					break;
				}
			}
			mysocket->retranscall = 1;

			mysocket->slowstart = 1;
			//mysocket->callindex = 0;
		}
	}
}


}
