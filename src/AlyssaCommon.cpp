#ifndef AlyssaHeader
#include "Alyssa.h"
#endif // !AlyssaHeader

void Send(string* payload, SOCKET sock, WOLFSSL* ssl, bool isText) {
	size_t size = 0;
	if (isText)
		size = strlen(&payload->at(0));
	else size = payload->size();
#ifdef Compile_WolfSSL
	if (ssl != NULL) {
		SSL_send(ssl, payload->c_str(), size);
	}
	else { send(sock, payload->c_str(), size, 0); }
#else
	send(sock, payload->c_str(), size, 0);
#endif // Compile_WolfSSL
}
int Send(char* payload, SOCKET sock, WOLFSSL* ssl, size_t size) {
#ifdef Compile_WolfSSL
	if (ssl != NULL) {
		return SSL_send(ssl, payload, size);
	}
	else { return send(sock, payload, size, 0); }
#else
	return send(sock, payload, size, 0);
#endif // Compile_WolfSSL
}
string fileMime(string& filename) {//This function returns the MIME type from file extension.
	char ExtOffset = 0;
	for (size_t i = filename.size() - 1; i > 0; i--) {
		if (filename[i] == '.') {
			ExtOffset = i + 1; break;
		}
	}
	if(!ExtOffset) return "application/octet-stream";
	char start,end;
    // Okay, you may say WTF when you see that switch, its just for limiting which periods of
    // MIME types array will be searched because comparing with whole array is waste of time
    // (i.e. if our extension is PNG we don't need to compare other extensions that doesn't
    // start with P). I don't know if compiler does a smilar thing, or this isn't really
    // improves performance. If so, or some reason numbers are incorrrect for some reason,
    // please kindly inform me, do a pull request. Thank you.
    switch (filename[ExtOffset]) {
        case 'a': start=0; end=5; break;
        case 'b': start=6; end=9; break;
        case 'c': start=10; end=13; break;
        case 'd': start=14; end=15; break;
        case 'e': start=16; end=17; break;
        case 'g': start=18; end=19; break;
        case 'h': start=20; end=21; break;
        case 'i': start=22; end=23; break;
        case 'j': start=24; end=29; break;
        case 'm': start=30; end=36; break;
        case 'o': start=37; end=44; break;
        case 'p': start=45; end=49; break;
        case 'r': start=50; end=51; break;
        case 's': start=52; end=53; break;
        case 't': start=54; end=59; break;
        case 'v': start=60; end=60; break;
        case 'w': start=61; end=66; break;
        case 'x': start=67; end=71; break;
        case 'z': start=72; end=72; break;
        case '1': start=73; end=75; break;
        default: return "application/octet-stream";
    }
    for (; start <= end; start++) {
        if (!strcmp(&filename[ExtOffset],extensions[start])) return mimes[start];
	}
	return "application/octet-stream";
}
string currentTime() {
	std::ostringstream x;
	std::time_t tt = time(0);
	std::tm* gmt = std::gmtime(&tt);
	x << std::put_time(gmt, "%a, %d %b %Y %H:%M:%S GMT");
	return x.str();
}
std::string Substring(void* str, unsigned int size, unsigned int startPoint) {
	string x; if (size == 0) { size = strlen(&static_cast<char*>(str)[startPoint]); }
	x.resize(size);
	memcpy(&x[0], &static_cast<char*>(str)[startPoint], size);
	return x;
}
std::string ToLower(string str) {
	string x = ""; x.reserve(str.size());
	for (size_t i = 0; i < str.size(); i++) {
		if (str[i] < 91 && str[i] > 64) {
			str[i] += 32;
		}
		x += str[i];
	}
	return x;
}
void ToLower(char* c, int l) {
	for (int var = 0; var < l; ++var) {
		if (c[var] < 91 && c[var] > 64) {
			c[var] += 32;
		}
	}
}
size_t btoull(string str, int size) {
	size_t out = 0;
	for (int i = str.size(); size >= 0; i--) {
		if (str[i] == '1') {
			out += pow(2, size);
		}
		size--;
	}
	return out;
}
unsigned int Convert24to32(unsigned char* Source) {
	return (
		(Source[0] << 24)
		| (Source[1] << 16)
		| (Source[2] << 8)
		) >> 8;
}
size_t Append(void* Source, void* Destination, size_t Position, size_t Size) {
	if (Size == 0) { Size = strlen((const char*)Source); }
	memcpy(Destination, &static_cast<char*>(Source)[Position], Size);
	return Size + Position;
}
void Logging(clientInfo* cl) {
	if (!Log.is_open()) {
		std::terminate();
	}
	// A very basic logging implementation
	// This implementation gets the clientInfo and logs the IP address of client, the path where it requested and a timestamp.
	logMutex.lock();
	Log << "[" << currentTime() << "] " << cl->Sr->clhostname << " - " << cl->RequestPath;
	//if (cl->RequestType != "GET") Log << " (" << cl->RequestType << ")";
	Log << std::endl;
	logMutex.unlock();
 }
 // Log a predefined message instead of reading from clientInfo, for things like error logging.
void LogString(const char* s) {
	logMutex.lock(); Log << s; logMutex.unlock();
}
void LogString(string s) {
	logMutex.lock(); Log << s; logMutex.unlock();
}
void SetPredefinedHeaders() {
	std::string ret;
#ifdef Compile_WolfSSL
	if (HSTS) ret += "Strict-Transport-Security: max-age=31536000\r\n";
#endif // Compile_WolfSSL
	if (corsEnabled) {
		ret += "Access-Control-Allow-Origin: " + defaultCorsAllowOrigin + "\r\n";
	}
	if (CSPEnabled) {
		ret += "Content-Security-Policy: connect-src " + CSPConnectSrc + "\r\n";
	}
	ret += "Server: Alyssa/" + version + "\r\n"; PredefinedHeaders = ret; ret.clear();
#ifdef Compile_WolfSSL
	if (EnableH2) {
		if (HSTS) {
			ret += 64 | 56; ret += sizeof "max-age=31536000"; ret += "max-age=31536000";
		}
		if (corsEnabled) {
			ret += 64 | 20; ret += (char)defaultCorsAllowOrigin.size(); ret += defaultCorsAllowOrigin;
		}
		if (CSPEnabled) {
			ret += '\0'; ret += sizeof "content-security-policy" - 1; ret += "content-security-policy";
			ret += CSPConnectSrc.size() + sizeof "connect-src"; ret += "connect-src " + CSPConnectSrc;
		}
		ret += 64 | 54; ret += sizeof"Alyssa/" + version.size() - 1; ret += "Alyssa/" + version;
		PredefinedHeadersH2 = ret; PredefinedHeadersH2Size = ret.size();
	}
#endif // Compile_WolfSSL
	 return;
}
#ifdef _WIN32
char MsgColors[] = { 12,14,11,15,0 };
void AlyssaNtSetConsole() {
	 CONSOLE_SCREEN_BUFFER_INFO cbInfo;
	 GetConsoleScreenBufferInfo(hConsole, &cbInfo); // Get the original text color
	 MsgColors[4] = cbInfo.wAttributes;
}
#endif // _WIN32

void ConsoleMsg(int8_t MsgType, const char* UnitName, const char* Msg) {// Function for color output on console
																		 // Ex: "Error: Custom actions: Redirect requires an argument" MsgType: Error, UnitName: "Custom actions", Msg is the latter.
																		 // Note that this function can be abused in the future for outputting various things. 
	 if (MsgType > 2) std::terminate(); std::lock_guard<std::mutex> lock(ConsoleMutex);
	 if (ColorOut){
#ifndef _WIN32 // Color output on unix platforms is easy since terminals usually support ANSI escape characters.
		 std::cout << MsgColors[MsgType] << MsgTypeStr[MsgType] << MsgColors[3] << UnitName << MsgColors[4] << Msg << std::endl;
#else // Windows command prompt doesn't support these, instead we have WinAPI calls for changing color.
		 SetConsoleTextAttribute(hConsole, MsgColors[MsgType]); std::cout << MsgTypeStr[MsgType];
		 SetConsoleTextAttribute(hConsole, MsgColors[3]); std::cout << UnitName;
		 SetConsoleTextAttribute(hConsole, MsgColors[4]); std::cout << Msg << std::endl;
#endif // !_WIN32
	 }
	 else {
		 std::cout << MsgTypeStr[MsgType] << UnitName << Msg << std::endl;
	 }
	 return;
}
void ConsoleMsgM(int8_t MsgType, const char* UnitName) {// Just like the one above but this one only prints msgtype and unit name in color, and then resets color for manual output such as printf.
	 if (MsgType > 2) std::terminate();
	 if (ColorOut) {
#ifndef _WIN32 
		 std::cout << MsgColors[MsgType] << MsgTypeStr[MsgType] << MsgColors[3] << UnitName << MsgColors[4];
#else
		 SetConsoleTextAttribute(hConsole, MsgColors[MsgType]); std::cout << MsgTypeStr[MsgType];
		 SetConsoleTextAttribute(hConsole, MsgColors[3]); std::cout << UnitName; SetConsoleTextAttribute(hConsole, MsgColors[4]);
#endif // !_WIN32
	 }
	 else {
		 std::cout << MsgTypeStr[MsgType] << UnitName;
	 }
	 return;
 }
uint32_t FileCRC(FILE* f, size_t s, char* buf, size_t _Beginning=0) {
	 uint32_t ret = 0;
	 while (s) {
		 if (s >= 32768) {
			 fread(buf, 32768, 1, f);
			 ret = crc32_fast(buf, 32768, ret); s -= 32768;
		 }
		 else {
			 fread(buf, s, 1, f);
			 ret = crc32_fast(buf, s, ret); break;
		 }
	 }
	 fseek(f, _Beginning, 0); return ret;
}

std::string ErrorPage(unsigned short ErrorCode) {
	std::string ret;
	if (errorpages==2) {// True : custom error pages 
		FILE* f;
		if ((f = fopen(std::string(respath + "/" + std::to_string(ErrorCode) + ".html").c_str(), "r"))!=NULL) {
			ret.resize(std::filesystem::file_size(respath + "/" + std::to_string(ErrorCode) + ".html"));
			fread(&ret[0], ret.size(), 1, f); fclose(f); return ret;
		}
	}
	// Synthetic error pages
	ret = "<!DOCTYPE html><html><head><style>html{font-family:sans-serif;background:black;color:white;text-align:center;font-size:140%}</style><title>";
	switch (ErrorCode) {
	case 400:	ret += "400 Bad Request"; break;
	case 401:	ret += "401 Unauthorized"; break;
	case 403:	ret += "403 Forbidden"; break;
	case 404:	ret += "404 Not Found"; break;
	case 416:	ret += "416 Range Not Satisfiable"; break;
	case 418:	ret += "418 I'm a teapot"; break;
	case 500:	ret += "500 Internal Server Error"; break;
	case 501:	ret += "501 Not Implemented"; break;
	default:	ret += "501 Not Implemented"; break;
	}
	ret += "</title></head><body><h1>";
	switch (ErrorCode) {
	case 400:	ret += "400 Bad Request</h1><p>You've made an invalid request."; break;
	case 401:	ret += "401 Unauthorized</h1><p>You haven't provided any credentials."; break;
	case 403:	ret += "403 Forbidden</h1><p>You're not authorized to view this document."; break;
	case 404:	ret += "404 Not Found</h1><p>Requested documented is not found on server."; break;
	case 416:	ret += "416 Range Not Satisfiable</h1><p>Requested range is invalid (i.e. beyond the size of document)."; break;
	case 418:	ret += "418 I'm a teapot</h1><p>Wanna some tea?"; break;
	case 500:	ret += "500 Internal Server Error</h1><p>An error occurred in our side."; break;
	case 501:	ret += "501 Not Implemented</h1><p>Request type is not supported at that moment."; break;
	default:	ret += "501 Not Implemented</h1><p>Request type is not supported at that moment."; break;
	}
	ret += "</p><hr><pre>Alyssa HTTP Server " + version + "</pre></body></html>";
	return ret;
}