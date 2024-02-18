#pragma once
#include "Alyssa.h"

typedef struct requestInfo {
	string RequestPath = "",
		host = "", // "Host" header
		cookies = "", auth = "",
		payload = "",//HTTP POST/PUT Payload
		qStr = "",//URL Query string.
		LastLine = "", // Last incomplete header line.
		Origin = "",
		DateCondition = ""; // Used for "If-Range" Date checking.
	bool close = 0, // Connection: close parameter
		hasEncoding = 0;
	unsigned short flags = 0;
	size_t rstart = 0, rend = 0; // Range request integers.
	int8_t method = 0; short VHostNum = 0;
	unsigned int CrcCondition = 0; // Used for "If-Not-Match" and "If-Range" ETag Checking.
	unsigned short ContentLength = 0; // Length of HTTP POST/PUT payload to be received from client.
	std::filesystem::path _RequestPath;

	FILE* f = NULL; size_t sz = 0; int stream = 0;
	_clientInfo* parent;
} requestInfo;

typedef struct _clientInfo {
	WOLFSSL* ssl;
	pollfd* pf;
	std::deque<requestInfo> streams;
	string ip;
	char flags, type;
} _clientInfo;

struct thread {
	std::thread thr;
	std::atomic_bool lk;
	unsigned int* shared;
	char* buf;
};

//extern std::deque<std::thread> thrArray;
//extern std::deque<std::atomic_bool> thrLk;
//extern std::deque<unsigned int*> thrShared;
//extern std::deque<char*> thrBuffer;
extern std::deque<thread> thrArray;
extern std::vector<pollfd> pollArray;
extern std::deque<_clientInfo> clArray;
extern short srvSocks;//amount of server listening sockets.

namespace pAlyssaHTTP {
	extern void ServerHeaders(HeaderParameters* h, requestInfo* r);
	extern void ServerHeadersM(requestInfo* r, unsigned short statusCode, const string& param = "");
	extern char parseHeader(requestInfo* r, char* buf, int sz);
	extern void Get(requestInfo* r);

}