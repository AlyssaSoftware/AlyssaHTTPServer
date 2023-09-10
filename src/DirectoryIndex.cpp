#ifndef AlyssaHeader
#include "Alyssa.h"
#endif

#ifdef Compile_DirIndex

template <typename TP>
std::time_t to_time_t(TP tp)
{
	using namespace std::chrono;
	auto sctp = time_point_cast<system_clock::duration>(tp - TP::clock::now()
		+ system_clock::now());
	return system_clock::to_time_t(sctp);
}

std::deque<IndexEntry> DirectoryIndex::GetDirectory(std::filesystem::path p) {
	std::deque<IndexEntry> ret; IndexEntry NewEntry; int8_t DirCount=0;
	for (auto x : std::filesystem::directory_iterator(p)) {
		if (x.path().extension() == "alyssa" || x.path().filename()==".alyssa")
			continue;
		NewEntry.FileName = x.path().filename().u8string();
		NewEntry.isDirectory = x.is_directory();
		std::time_t tt = to_time_t(x.last_write_time());
		std::tm* gmt = std::gmtime(&tt);
		std::stringstream timebuf; timebuf << std::put_time(gmt, "%d %b %Y %H:%M");
		NewEntry.ModifyDate = timebuf.str();
		if (!NewEntry.isDirectory) {
			NewEntry.FileSize = x.file_size();
			ret.emplace_back(NewEntry);
		}
		else {
			NewEntry.FileSize = 0; ret.emplace(ret.begin() + DirCount, NewEntry); DirCount++;
		}
	}
	return ret;
}

string DirectoryIndex::DirMain(std::filesystem::path p, std::string& RelPath) {
	std::deque<IndexEntry> Array = GetDirectory(p);
	string ret; uint8_t DirCnt = 0; ret.reserve(4096);
	ret = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><style>body{font-family:sans-serif;tab-size:135;}pre{display:inline;font-family:sans-serif;}img{height:12px;width:15px;}</style>"
		"<title>Index of " + RelPath + "</title></head><body><h1>Index of " + RelPath + "</h1><hr><div>";
	if (RelPath != "/")
		ret += "<pre><img src=\"" + htrespath + "/directory.png\"><a href=\"../\">../</a>	-	-</pre><br>";
	for (uint8_t i = 0; i < Array.size(); i++) {
		if (Array[i].isDirectory) {
			ret += "<pre><img src=\"" + htrespath + "/directory.png\"><a href=\"" + Array[i].FileName + "/\">" + Array[i].FileName + "/</a>	" + Array[i].ModifyDate + "	-</pre><br>"; DirCnt++;
		}
		else {
			ret += "<pre><img src=\"" + htrespath + "/file.png\"><a href=\"" + Array[i].FileName + "\">" + Array[i].FileName + "</a>	" + Array[i].ModifyDate + "	[" + std::to_string(Array[i].FileSize) + "]</pre><br>";
		}
	}
	ret += "</div><hr>";
	if (DirCnt) {
		ret += std::to_string(DirCnt)+" director";
		if (DirCnt > 1)
			ret += "ies";
		else
			ret += "y";
		if (Array.size() - DirCnt)
			ret += " and ";
	}
	if (Array.size() - DirCnt) {
		ret += std::to_string(Array.size() - DirCnt) + " file";
		if (Array.size() - DirCnt > 1)
			ret += "s";
	}
	ret += "<br>Alyssa HTTP Server " + version + "</body></html>";
	return ret;
}


#endif