#include "PollenTemporary.h"

std::deque<thread> thrArray;
std::vector<pollfd> pollArray;
std::deque<unsigned char> sockType;
std::deque<std::thread> _thrArray;
std::deque<std::atomic_bool> threadLock;
std::deque<_clientInfo> clArray;
short srvSocks;//amount of server listening sockets.
bool srvRunning = 1;//if server is running, it's shutting down if false.
unsigned int pollcnt;//amount of total sockets.
SOCKET bastardizedSocket;

namespace pAlyssaHTTP {
	void ServerHeaders(HeaderParameters* h, requestInfo* r) {
		std::string ret = "HTTP/1.1 "; ret.reserve(512);
		switch (h->StatusCode) {
			case 200:	ret += "200 OK\r\n"; break;
			case 206:	ret += "206 Partial Content\r\n"
				"Content-Range: bytes " + std::to_string(r->rstart) + "-" + std::to_string(r->rend) + "/" + std::to_string(h->ContentLength) + "\r\n";
				break;
			case 302:	ret += "302 Found\r\n"
				"Location: " + h->AddParamStr + "\r\n";
				break;
			case 304:	ret += "304 Not Modified\r\n"; break;
			case 400:	ret += "400 Bad Request\r\n"; break;
			case 401:	ret += "401 Unauthorized\r\nWWW-Authenticate: Basic\r\n"; break;
			case 402:	ret += "402 Precondition Failed\r\n"; break;
			case 403:	ret += "403 Forbidden\r\nWWW-Authenticate: Basic\r\n"; break;
			case 404:	ret += "404 Not Found\r\n"; break;
			case 414:	ret += "414 URI Too Long\r\n"; break;
			case 416:	ret += "416 Range Not Satisfiable\r\n"; break;
			case 418:	ret += "418 I'm a teapot\r\n"; break;
			case 500:	ret += "500 Internal Server Error\r\n"; break;
			case 501:	ret += "501 Not Implemented\r\n"; break;
			default:	ret += "501 Not Implemented\r\n"; break;
		}
#ifdef Compile_zlib
		if (h->hasEncoding) {
			ret += "Content-Encoding: deflate\r\n"
				"Transfer-Encoding: chunked\r\n"
				"Vary: Content-Encoding\r\n";
		}
		else
#endif 
			if (h->StatusCode != 206)
				ret += "Content-Length: " + std::to_string(h->ContentLength) + "\r\n";
			else {
				ret += "Content-Length: " + std::to_string(r->rend - r->rstart + 1) + "\r\n";
			}
		if (h->HasRange) ret += "Accept-Ranges: bytes\r\n";
		if (h->MimeType != "") ret += "Content-Type: " + h->MimeType + "\r\n";
		if (h->hasAuth) ret += "WWW-Authenticate: basic\r\n";
		if (h->_Crc) ret += "ETag: \"" + std::to_string(h->_Crc) + "\"\r\n";
		if (h->LastModified != "") ret += "Last-Modified: " + h->LastModified + "\r\n";
		ret += "Date: " + currentTime() + "\r\n";
		for (size_t i = 0; i < h->CustomHeaders.size(); i++) {
			ret += h->CustomHeaders[i] + "\r\n";
		}
		if (corsEnabled) {
			if (r->Origin != "") {
				for (unsigned char i = 0; i < ACAOList.size(); i++) {
					if (ACAOList[i] == r->Origin) {
						ret += "Access-Control-Allow-Origin: " + r->Origin + "\r\n"; break;
					}
				}
			}
		}

		ret += PredefinedHeaders;
		ret += "\r\n"; Send(&ret, r->parent->pf->fd, r->parent->ssl, 1);
#ifndef AlyssaTesting
		//r->clear();
#endif
		return;
	}

	void ServerHeadersM(requestInfo* r, unsigned short statusCode, const string& param) {
		std::string ret = "HTTP/1.1 "; ret.reserve(512);
		switch (statusCode) {
			case 200:	ret += "200 OK\r\n"; break;
				//case 206:	ret += "206 Partial Content\r\n"
				//	"Content-Range: bytes " + std::to_string(c->rstart) + "-" + std::to_string(c->rend) + "/" + std::to_string(h->ContentLength) + "\r\n"; break;
			case 302:	ret += "302 Found\r\n"
				"Location: " + param + "\r\n";
				break;
			case 304:	ret += "304 Not Modified\r\n"; break;
			case 400:	ret += "400 Bad Request\r\n"; break;
			case 401:	ret += "401 Unauthorized\r\nWWW-Authenticate: Basic\r\n"; break;
			case 402:	ret += "402 Precondition Failed\r\n"; break;
			case 403:	ret += "403 Forbidden\r\n"; break;
			case 404:	ret += "404 Not Found\r\n"; break;
			case 414:	ret += "414 URI Too Long\r\n"; break;
			case 416:	ret += "416 Range Not Satisfiable\r\n"; break;
			case 418:	ret += "418 I'm a teapot\r\n"; break;
			case 500:	ret += "500 Internal Server Error\r\n"; break;
			case 501:	ret += "501 Not Implemented\r\n"; break;
			default:	ret += "501 Not Implemented\r\n"; break;
		}
		ret += "Date: " + currentTime() + "\r\n";
		if (corsEnabled) {
			if (r->Origin != "") {
				for (unsigned char i = 0; i < ACAOList.size(); i++) {
					if (ACAOList[i] == r->Origin) {
						ret += "Access-Control-Allow-Origin: " + r->Origin + "\r\n";
					}
				}
			}
		}
		ret += PredefinedHeaders;
		ret += "\r\n"; Send(&ret, r->parent->pf->fd, r->parent->ssl, 1);
	}

	char parseHeader(requestInfo* r, char* buf, int sz) {
		unsigned short pos = 0;//Position of EOL

		if (!(r->flags & (1 << 0))) {// First line is not parsed yet.
			if (strnlen(buf, 4097) != sz) return -6;//Not a text.
			for (; pos < sz + 1; pos++)
				if (buf[pos] < 32) {
					if (buf[pos] > 0) {
						unsigned short _pos = 0;
						if (!strncmp(buf, "GET", 3)) {
							r->method = 1; _pos = 4;
						}
						else if (!strncmp(buf, "POST", 4)) {
							r->method = 2; _pos = 5;
						}
						else if (!strncmp(buf, "PUT", 3)) {
							r->method = 3; _pos = 4;
						}
						else if (!strncmp(buf, "OPTIONS", 7)) {
							r->method = 4; _pos = 8;
						}
						else if (!strncmp(buf, "HEAD", 4)) {
							r->method = 5; _pos = 5;
						}
						// 2.5: Added the methods that is specified on HTTP/1.1 specification
						// but is not implemented on Alyssa HTTP Server. They will be responded with 501.
						// Any other thing will be treated as non-HTTP and will be terminated.
						else if (!strncmp(buf, "DELETE", 6)) {
							r->method = -5; r->flags |= 3; _pos = 7;
						}
						else if (!strncmp(buf, "CONNECT", 7)) {
							r->method = -5; r->flags |= 3; _pos = 8;
						}
						else if (!strncmp(buf, "TRACE", 5)) {
							r->method = -5; r->flags |= 3; _pos = 6;
						}
						else if (!strncmp(buf, "MODIFY", 6)) {
							r->method = -5; r->flags |= 3; _pos = 7;
						}
						else {
							return -6;
						}
						r->RequestPath.resize(pos - _pos - 9); memcpy(&r->RequestPath[0], &buf[_pos], pos - _pos - 9); r->RequestPath[pos - _pos - 9] = 0;
						if (r->RequestPath.size() > 32768) {
							r->method = -7; r->flags |= 3; goto ExitParse;
						}
						// Decode percents
						_pos = r->RequestPath.size(); // Reusing _pos for not calling size() again and again.
						if (_pos == 0) { r->method = -1; r->flags |= 3; goto ExitParse; }
						for (char t = 0; t < _pos; t++) {
							if (r->RequestPath[t] == '%') {
								try {
									r->RequestPath[t] = hexconv(&r->RequestPath[t + 1]);
								}
								catch (const std::invalid_argument&) {
									r->flags |= 3; r->method = -1; break;
								}
								memmove(&r->RequestPath[t + 1], &r->RequestPath[t + 3], _pos - t); _pos -= 2;
							}
						}
						r->RequestPath.resize(_pos);
						// Sanity checks
						_pos = r->RequestPath.find('?');// Query string
						if (_pos != 65535) {
							unsigned char _sz = r->RequestPath.size();
							r->qStr.resize(_sz - _pos); memcpy(r->qStr.data(), &r->RequestPath[_pos + 1], _sz - _pos - 1);
							r->RequestPath.resize(_pos);
						}
						else _pos = r->RequestPath.size();
						if (!(r->flags & (1 << 1))) {// You can't remove that if scope else you can't goto.
							if ((int)r->RequestPath.find(".alyssa") >= 0) { r->method = -2; r->flags |= 3; goto ExitParse; }
							char level = 0; char t = 1; while (r->RequestPath[t] == '/') t++;
							// Check for level client tries to access.
							for (; t < _pos;) {
								if (r->RequestPath[t] == '/') {
									level++; t++;
									while (r->RequestPath[t] == '/') t++;
								}
								else if (r->RequestPath[t] == '.') {
									t++; if (r->RequestPath[t] == '.') level--;  // Parent directory, decrease.
									//else if (r->RequestPath[t] == '/') t++; // Current directory. don't increase.
									t++; while (r->RequestPath[t] == '/') t++;
								}
								else t++;
							}
							if (level < 0) { r->method = -2; r->flags |= 3; goto ExitParse; } //Client tried to access above htroot
							// Check for version
							if (!strncmp(&buf[pos - 8], "HTTP/1.", 7)) {
								r->flags |= 1;
								if (buf[pos - 1] == '0') {// HTTP/1.0 client
									r->close = 1;
								}
							}
							else { r->method = -1; r->flags |= 3; goto ExitParse; }
						}
						else { r->method = -1; r->flags |= 3; }
					ExitParse:
						pos++; if (buf[pos] < 31) pos++; // line delimiters are CRLF, iterate pos one more.
						break;
					}
					else {
						if (sz < r->LastLine.max_size()) {// If false, size is larger than we can ever hold. Discard the line
							try
							{
								r->LastLine.resize(sz);
							}
							catch (const std::bad_alloc a)
							{
								std::wcout << L"MIH DEDİN YARRAĞI YEDİN: " << a.what(); std::terminate();
							}
							memcpy(&r->LastLine[0], buf, sz);
						}
						goto ParseReturn;
					}
				}
		}
		else if (r->flags & (1 << 2)) {// Client sent data despite headers are parsed, which means there's payload to receive.
			if (!(r->flags & (1 << 1))) {
				if (sz > r->payload.size()) sz = r->payload.size();
				memcpy(&r->payload[r->payload.size() - r->ContentLength], buf, sz);
			}
			r->ContentLength -= sz; pos = sz;
			if (!r->ContentLength) { // If nothing more left to receive, request is done.
			EndRequest:
				// Virtual host stuff
				if (r->host == "") { r->flags |= 2; return -1; } // No host, bad request.
				if (HasVHost) {
					for (int i = 1; i < VirtualHosts.size(); i++) {
						if (VirtualHosts[i].Hostname == r->host) {
							r->VHostNum = i;
							if (VirtualHosts[i].Type == 0) // Standard virtual host
								r->_RequestPath = VirtualHosts[i].Location;
							else if (VirtualHosts[i].Type == 1) { // Redirecting virtual host
								ServerHeadersM(r, 302, VirtualHosts[i].Location); return -3;
							}
							else if (VirtualHosts[i].Type == 2) { // Forbidden virtual host
								ServerHeadersM(r, 403); return -3;
							}
							else if (VirtualHosts[i].Type == 3) { // "Hang-up" virtual host
								closesocket(r->parent->pf->fd);
								if (logging) AlyssaLogging::literal(r->parent->ip + " -> " + VirtualHosts[i].Hostname + r->RequestPath + " rejected and hung-up.", 'C');
								return -3;// No clean shutdown or anything, we just say fuck off to client.
							}
							break;
						}
					}
					if (r->_RequestPath == "") { // _RequestPath is empty, which means we havent got into a virtual host, inherit from default.
						// Same as above.
						if (VirtualHosts[0].Type == 0)
							r->_RequestPath = VirtualHosts[0].Location;
						else if (VirtualHosts[0].Type == 1) {
							ServerHeadersM(r, 302, VirtualHosts[0].Location); return -3;
						}
						else if (VirtualHosts[0].Type == 2) {
							ServerHeadersM(r, 403); return -3;
						}
						else if (VirtualHosts[0].Type == 3) {
							closesocket(r->parent->pf->fd);
							if (logging) AlyssaLogging::literal(r->parent->ip + " -> " + r->host + r->RequestPath + " rejected and hung-up.", 'C');
							return -3;
						}
					}
					r->_RequestPath += std::filesystem::u8path(r->RequestPath);
				}
				else {
					r->_RequestPath = std::filesystem::u8path(htroot + r->RequestPath);
				}
				// Check if client connects with SSL or not if HSTS is enabled
#ifdef Compile_WolfSSL
				if (HSTS && !r->parent->ssl) return -4; // client doesn't use SSL.
#endif

				return r->method;
			}
		}

		// Parse the lines
		for (unsigned short i = pos; i < sz; i++) {
			if (buf[i] > 31) continue;
			if (pos - i == 0) {// End of headers
				if (buf[pos] < 32) pos++; //CRLF
				r->flags |= 4;
				if (r->ContentLength) {// There is payload to receive.
					if (buf[pos] < 31) pos++; // line delimiters are CRLF, iterate pos one more.
					if (!(r->flags & (1 << 1))) {
						if (sz - pos > r->payload.size()) sz = pos + r->payload.size();
						memcpy(&r->payload[r->payload.size() - r->ContentLength], &buf[pos], sz - pos);
					}
					r->ContentLength -= sz - pos; pos = sz;
				}
				if (!r->ContentLength) { // If nothing more left to receive, request is done.
					goto EndRequest;
				}
			}
			else if (!strncmp(&buf[pos], "Content-Length", 14)) {
				try {
					r->ContentLength = std::atoi(&buf[pos + 16]);
					if (!(r->flags & (1 << 1)))
						r->payload.resize(r->ContentLength);
				}
				catch (const std::invalid_argument&) {
					r->method = -1; r->flags |= 2;
				}
			}
			else if (!(r->flags & (1 << 1))) { // Don't parse headers if bad request EXCEPT Content-Length.
				switch (buf[pos]) {// Narrow the range to strcmp by looking at first letter.
				case 'a':
				case 'A':
#ifdef Compile_CustomActions
					if (!strncmp(&buf[pos + 1], "uthorization", 12)) {
						if (strncmp(&buf[pos + 15], "Basic", 5)) { r->method = -1; r->flags |= 2; continue; } // Either auth is not basic or header is invalid as a whole. 
						pos += 21; r->auth.resize(i - pos); memcpy(&r->auth[0], &buf[pos], i - pos); r->auth = base64_decode(r->auth);
					}
#endif
#ifdef Compile_zlib
					else if (!strncmp(&buf[pos + 1], "ccept-", 6)) {
						if (buf[pos + 3] > 96) buf[pos + 3] -= 32;//97 is 'a', values > 96 are lowercase;

						if (!strncmp(&buf[pos + 7], "Encoding", 8)) {
							if (deflateEnabled) {
								//if (std::find(&buf[pos + 17], &buf[i], "deflate")) r->hasEncoding = 1; doesn't work
								buf[i] = 0; //strstr only works on null-terminates strings and no way I'm going to implement another one
								if (strstr(&buf[pos + 17], "deflate")) {
									r->hasEncoding = 1;
								}
							}
						}
					}
#endif //Compile_zlib
					break;
				case 'c':
				case 'C':
					if (!strncmp(&buf[pos + 1], "onnection", 9)) {
						if (!strncmp(&buf[pos + 12], "close", 5)) r->close = 1;
						else r->close = 0;
					}
					break;
				case 'h':
				case 'H':
					if (!strncmp(&buf[pos + 1], "ost", 3)) {// Headers will be parsed that way, you got the point. + offsets also includes the ": ".
						r->host.resize(i - pos - 6);
						memcpy(&r->host[0], &buf[pos + 6], i - pos - 6);
					}
					break;
				case 'o':
				case 'O':
					if (!strncmp(&buf[pos + 1], "rigin", 5)) {
						if (corsEnabled) {
							r->Origin.resize(i - pos - 8);
							memcpy(&r->Origin[0], &buf[pos + 8], i - pos - 8);
						}
					}
					break;
				case 'r':
				case 'R':
					if (!strncmp(&buf[pos + 1], "ange", 4)) {
						pos += 7; if (strncmp(&buf[pos], "bytes=", 6)) { r->method = -1; r->flags |= 2; continue; } // Either unit is not bytes or value is invalid as a whole.
						pos += 6;
						if (buf[pos] != '-') {
							try {
								r->rstart = std::atoll(&buf[pos]);
							}
							catch (const std::invalid_argument&) {
								r->method = -1; r->flags |= 2;
							}
							while (buf[pos] >= 48) pos++;
						}
						else { // No beginning value, read last n bytes.
							r->rstart = -1;
						}
						pos++;
						if (buf[pos] > 32) {
							try {
								r->rend = std::atoll(&buf[pos]);
							}
							catch (const std::invalid_argument&) {
								r->method = -1; r->flags |= 2;
							}
						}
						else { // No end value, read till the end.
							r->rend = -1;
						}
					}
					break;
				case 'i':
				case 'I':
					// Headers starting with 'i' are often "If-*" ones, which are the ones we only care about.
					// Check for that first, and then the trivial part is they are always more than 1 word, 
					// which means we should check for upper/lower cases too.
					if (buf[pos + 1] != 'f' && buf[pos + 2] != '-') break;// Not a "If-*" header.
					if (buf[pos + 3] > 96) buf[pos + 3] -= 32;//97 is 'a', values > 96 are lowercase;

					if (!strncmp(&buf[pos + 3], "Range", 5)) {
						pos += 10;
						if (buf[pos] == '"') {//ETag
							pos++;
							try {
								char* _endPtr = NULL;
								r->CrcCondition = strtoul(&buf[pos], &_endPtr, 10);
							}
							catch (const std::invalid_argument&) { r->CrcCondition = 0; }
						}
						else if (i - pos == 29) {//Date
							r->DateCondition.resize(29); memcpy(r->DateCondition.data(), &buf[pos], 29);
						}
					}
					else if (!strncmp(&buf[pos + 3], "None-", 5)) {
						if (buf[pos + 8] > 96) buf[pos + 8] -= 32;
						if (!strncmp(&buf[pos + 8], "Match", 5)) {
							pos += 16;
							try {
								char* _endPtr = NULL;
								r->CrcCondition = strtoul(&buf[pos], &_endPtr, 10);
							}
							catch (const std::invalid_argument&) { r->CrcCondition = 0; }
						}
					}
					break;
				default:
					break;
				}

			}
			pos = i + 1;
			if (buf[pos] < 31) { pos++; i++; } // line delimiters are CRLF, iterate pos one more.
		}
		// All complete lines are parsed, check if there's a incomplete remainder
		if (pos < sz) {
			r->LastLine.resize(sz - pos); memcpy(&r->LastLine[0], &buf[pos], sz - pos);
		}
	ParseReturn:
		return 0;
	}
	void Get(requestInfo* r) {
		HeaderParameters h;

		if (!strncmp(&r->RequestPath[0], &htrespath[0], htrespath.size())) {//Resource, set path to respath and also skip custom actions
			r->_RequestPath = respath + Substring(&r->RequestPath[0], 0, htrespath.size());
		}
#ifdef _DEBUG
		//else if (!strncmp(&r->RequestPath[0], "/Debug/", 7) && debugFeaturesEnabled) {
		//	DebugNode(r); if (r->close) shutdown(r->parent->pf->fd, 2); return;
		//}
#endif // _DEBUG

#ifdef Compile_CustomActions
		else if (CAEnabled) {
			switch (CustomActions::CAMain((char*)r->RequestPath.c_str(), r)) {
			case 0:  if (r->close) shutdown(r->parent->pf->fd, 2); return;
			case -1: h.StatusCode = 500; ServerHeaders(&h, r); if (r->close) shutdown(r->parent->pf->fd, 2); return;
			case -3: if (r->close) shutdown(r->parent->pf->fd, 2); return;
			default: break;
			}
		}
#endif

		if (std::filesystem::is_directory(r->_RequestPath)) {
			if (std::filesystem::exists(r->_RequestPath.u8string() + "/index.html")) {
				r->RequestPath += "/index.html";
				r->_RequestPath += "/index.html";
			}
#ifdef Compile_DirIndex
			else if (foldermode) {
				string asd = DirectoryIndex::DirMain(r->_RequestPath, r->RequestPath);
				h.StatusCode = 200; h.ContentLength = asd.size(); h.MimeType = "text/html";
				ServerHeaders(&h, r);
				if (r->method != 5)
					Send(&asd, r->parent->pf->fd, r->parent->ssl, 1);
				return;
			}
#endif
			else {
				h.StatusCode = 404;
				if (errorpages) {
					string ep = ErrorPage(404); h.ContentLength = ep.size();
					ServerHeaders(&h, r);
					if (ep != "") Send(&ep, r->parent->pf->fd, r->parent->ssl, 1);
				}
				else
					ServerHeaders(&h, r);
				return;
			}
		}

		FILE* file = NULL; size_t filesize = 0;
#ifndef _WIN32
		file = fopen(&r->_RequestPath.u8string()[0], "rb");
#else //WinAPI accepts ANSI for standard fopen, unlike sane operating systems which accepts UTF-8 instead. 
		//Because of that we need to convert path to wide string first and then use wide version of fopen (_wfopen)
		std::wstring RequestPathW;
		RequestPathW.resize(r->_RequestPath.u8string().size());
		MultiByteToWideChar(CP_UTF8, 0, r->_RequestPath.u8string().c_str(), RequestPathW.size(), &RequestPathW[0], RequestPathW.size());
		file = _wfopen(RequestPathW.c_str(), L"rb");
#endif

		if (file) {
			filesize = std::filesystem::file_size(r->_RequestPath); h.MimeType = fileMime(r->RequestPath);
			h.ContentLength = filesize; h.LastModified = LastModify(r->_RequestPath); h.HasRange = 1;

			h._Crc = FileCRC(file, filesize, r->parent->t->buf, 32768);

			if (r->rstart || r->rend) { // Range request
				// Check if file client requests is same as one we have.
				if (r->CrcCondition) {
					if (r->CrcCondition != h._Crc) {// Check by ETag failed.
						h.StatusCode = 402; ServerHeaders(&h, r); if (r->close) shutdown(r->parent->pf->fd, 2); return;
					}
				}
				else if (r->DateCondition != "") {
					if (r->DateCondition != h.LastModified) {// Check by date failed.
						h.StatusCode = 402; ServerHeaders(&h, r); if (r->close) shutdown(r->parent->pf->fd, 2); return;
					}
				}
				// Check done.
				h.StatusCode = 206;
				if (r->rend == -1) r->rend = filesize - 1;
				if (r->rstart == -1) {
					fseek(file, filesize - r->rend, 0); r->rstart = filesize - r->rend;
					size_t tempsize = filesize; filesize = r->rend; r->rend = tempsize - 1;
				}
				else {
					fseek(file, r->rstart, 0); filesize = r->rend + 1 - r->rstart;
				}

			}
			else {
			NoRange:
				if (h._Crc == r->CrcCondition) {// No content.
					h.StatusCode = 304; h.ContentLength = 0;
					r->method = 5;// Setting this for making the if above true, as it does what we need (closing file and returning without sending any payload.)
				}
				else {
					h.StatusCode = 200; rewind(file);
				}
			}
#ifdef Compile_zlib
			if (filesize < 2048) r->hasEncoding = 0; // Deflating really small things will actually inflate it beyond original size, don't compress if file is smaller than 2048b
			h.hasEncoding = r->hasEncoding;
#endif //Compile_zlib

			ServerHeaders(&h, r);
			if (r->method == 5) {// if head request (or 304)
				fclose(file); if (r->close) shutdown(r->parent->pf->fd, 2); return;
			}
			else {
				r->f = file; r->parent->pf->events = 0; r->sz = filesize;
			}
		}
		else {//File open failed.
			h.StatusCode = 404;
			if (errorpages) {
				string ep = ErrorPage(404); h.ContentLength = ep.size();
				ServerHeaders(&h, r);
				if (ep != "") Send(&ep, r->parent->pf->fd, r->parent->ssl, 1);
			}
			else
				ServerHeaders(&h, r);
		}

		/*if (r->close) {
			shutdown(r->parent->pf->fd, 2);
		}*/
	}
}