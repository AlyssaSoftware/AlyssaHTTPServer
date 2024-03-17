#include "Alyssa.h"
#include "PollenTemporary.h"

void AlyssaThread(int num) {
	char* buf = thrArray[num].buf;
	int handled = 0, ret = 0;
#define cl clArray[thrArray[num].shared[0]]
#define type thrArray[num].shared[1]
	while (true) {
		// Check if there is a new client.
threadBeginning:
		if (threadLock[num]) {
			// Handle the new client
			cl.t = &thrArray[num];
			switch (type) {
			case 1:
				if (cl.flags & 16) {}
				else {
					switch (pAlyssaHTTP::parseHeader(&cl.streams[0], buf, thrArray[num].shared[2])) {
						case -7: pAlyssaHTTP::ServerHeadersM(&cl.streams[0], 414); cl.streams[0].clear(); break; // URI Too Long
						case -6: closesocket(cl.pf->fd); break; // Close the connection. Perhaps it's a non-HTTP
						case -5: pAlyssaHTTP::ServerHeadersM(&cl.streams[0], 501); cl.streams[0].clear(); break; // Not implemented
	#ifdef Compile_WolfSSL
						case -4: ServerHeadersM(&cl, 302, ((SSLport[0] == 80) ? "https://" + cl.host : "https://" + cl.host + ":" + std::to_string(SSLport[0]))); goto ccReturn; // HSTS is enabled but client doesn't use SSL.
	#endif // Compile_WolfSSL
						case -3: cl.streams[0].clear(); break; // Parsing is done and response is sent already, just clear the clientInfo.
						case -2: pAlyssaHTTP::ServerHeadersM(&cl.streams[0], 403); cl.streams[0].clear(); break; // Bad request but send 403.
						case -1: pAlyssaHTTP::ServerHeadersM(&cl.streams[0], 400); cl.streams[0].clear(); break; // Bad request.
						case  0: break; // Parsing is not done yet, do nothing.
						case  1: pAlyssaHTTP::Get(&cl.streams[0]); cl.streams[0].clear(); break;
	#ifdef Compile_CustomActions
						case  2: Post(&cl); cl.clear(); break;
						case  3: Post(&cl); cl.clear(); break;
						case  4: { HeaderParameters h; h.StatusCode = 200; h.CustomHeaders.emplace_back("Allow: GET,POST,PUT,OPTIONS,HEAD");
							ServerHeaders(&h, &cl); cl.clear(); break; }
	#else
						case  4: { HeaderParameters h; h.StatusCode = 200; h.CustomHeaders.emplace_back("Allow: GET,OPTIONS,HEAD");
							pAlyssaHTTP::ServerHeaders(&h, &cl.streams[0]); cl.streams[0].clear();  break; }
	#endif // Compile_CustomActions
						case  5: pAlyssaHTTP::Get(&cl.streams[0]); cl.streams[0].clear(); break;
					}
				} break;
			case 2:
				//if (cl.flags & 16) {
				//	/*for (size_t i = 0; i < cl.streams.size(); i++) {
				//
				//	}*/
				//}
				//else {
				//	fread(buf, (cl.streams[0].sz > 32768) ? 32768 : cl.streams[0].sz, 1, cl.streams[0].f);
				//	if (cl.flags & 128) {}
				//	else send(cl.pf->fd, buf, (cl.streams[0].sz > 32768) ? 32768 : cl.streams[0].sz, 0);
				//	if (cl.streams[0].sz > 32768) { cl.streams[0].sz -= 32768; cl.pf->events = POLLOUT; }
				//	else { //end of stream
				//		fclose(cl.streams[0].f); cl.streams[0].clear(); cl.pf->events = POLLIN;
				//	}
				//} break;
			case 3:

			default: break;

			}
			cl.t = NULL; threadLock[num] = 0;
		}
		
		// Send portion of data to clients that belongs to this thread.
		if (!thrArray[num].sz) { Sleep(50); goto threadBeginning; } // Nothing to do or send, go back to beginning.

		int i = 0;
		for (; i < thrArray[num].sz; i++) {
#undef cl
#define cl clArray[i + thrArray[num].offset]
			if (threadLock[num]) goto threadBeginning;
			if (cl.pf->fd == bastardizedSocket) continue; //skip closed socket
			if(cl.flags & 16) {} //if h2
			else {
				if (cl.streams[0].sz > 32768) {
					fread(thrArray[num].buf, 32768, 1, cl.streams[0].f); 
					ret = send(cl.pf->fd, thrArray[num].buf, 32768, 0);
					if (ret < 1) {// Connection lost.
						shutdown(cl.pf->fd, 2); closesocket(cl.pf->fd); cl.pf->fd = bastardizedSocket;
						fclose(cl.streams[0].f); cl.streams[0].sz = 0; handled++; continue;
					}
					cl.streams[0].sz -= 32768; handled++;
				}
				else if (cl.streams[0].sz) {// if false, there's no stream so do nothing.
					fread(thrArray[num].buf, cl.streams[0].sz, 1, cl.streams[0].f); 
					ret = send(cl.pf->fd, thrArray[num].buf, cl.streams[0].sz, 0);
					if (ret < 1) {// Connection lost.
						shutdown(cl.pf->fd, 2); closesocket(cl.pf->fd); cl.pf->fd = bastardizedSocket;
						fclose(cl.streams[0].f); cl.streams[0].sz = 0;  handled++; continue;
					}
					cl.streams[0].sz = 0; fclose(cl.streams[0].f); handled++; 
					if (cl.streams[0].close) { shutdown(cl.pf->fd, 2); closesocket(cl.pf->fd); cl.pf->fd = bastardizedSocket; }
					cl.streams[0].clear(); cl.streams[0].f = NULL; cl.pf->events = POLLIN;
				}
			}
		}
		Sleep(50 - handled); handled = 0; i = 0;
	}
}

void AlyssaInitThreads() {
	thread t;
	for (size_t i = 0; i < 4; i++) {
		t.buf = new char[32768]; memset(t.buf, 0, 32768);
		t.shared = new unsigned int[3]; memset(t.buf, 0, 3 * 4);
		thrArray.emplace_back(t); _thrArray.emplace_back(AlyssaThread, i);
		threadLock.emplace_back(0);
	}
}