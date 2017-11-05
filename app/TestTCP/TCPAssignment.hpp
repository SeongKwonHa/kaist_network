/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>

namespace E
{
/*struct Connection{
	uint32_t source[1];
	uint32_t dest[1];
	uint16_t s_port[1];
	uint16_t d_port[1];
};*/

struct AcceptInfo{
	int pid;
	int fd;
	struct sockaddr * addr;
	socklen_t * addrlen;
	UUID syscallUUID;
};

enum State{
	LISTEN,
	CLOSED,
	SYN_SENT,
	SYN_RCVD,
	ESTAB,//5
	CLOSE_WAIT, //6
	LAST_ACK, //7
	FIN_WAIT_1, //8
	FIN_WAIT_2, //9
	TIMED_WAIT
};

struct Sockmeta{
	int pid;
	int fd;
	sa_family_t sin_family; 
	unsigned short int port;
	struct in_addr ip;
	socklen_t addrlen;
	sa_family_t d_sin_family;
	unsigned short int d_port;
	struct in_addr d_ip;
	socklen_t d_addrlen;
	enum State state;
	//struct Connection * connection;
	int backlog;
	uint32_t seqnum;
	UUID syscallUUID;
	//struct sockaddr * accept_addr;
	//socklen_t * accept_addrlen;
	std::queue<Sockmeta *> waitingqueue;
	std::queue<Sockmeta *> estabqueue;
	std::queue<AcceptInfo *> acceptqueue;
};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
	//add
	std::vector<Sockmeta*> socketlist;
	virtual void syscall_socket(UUID syscallUUID, int pid, int domain, int type);
	virtual void syscall_close(UUID syscallUUID, int pid, int sockfd);
	virtual void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *myaddr, socklen_t addrlen);
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr * name , socklen_t * namelen);
	virtual void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
	virtual void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	virtual void syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	virtual void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	virtual void syscall_read(UUID syscallUUID, int pid, int fd, void *buf, size_t count);
	virtual void syscall_write(UUID syscallUUID, int pid, int fd, const void *buf, size_t count);


};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
