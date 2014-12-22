#pragma once
#ifndef WINVER			// Specifies that the minimum required platform is Windows XP.
#define WINVER 0x0501
#endif

#ifndef _WIN32_WINNT	// Specifies that the minimum required platform is Windows XP.
#define _WIN32_WINNT 0x0501
#endif
//#define _WIN32_WINNT 0x0601
#define PSAPI_VERSION 1
#include "stdafx.h"
#include "Nanolib.h"
#include <exception>
#define	_CRT_SECURE_NO_DEPRECATE
#define		MAXPAT  256

BOOL IsDLL = TRUE;					// Residual debug flag from when this module was an exe
const DWORD TF_BIT = 0x100;			// Trap Flag
BOOL FirstException = TRUE;			// The first exception needs to be handled
BOOL FirstWFDE = TRUE;				// WFDE = WaitForDebugEvent
BOOL StartedNanomites = FALSE;		// Whether the target process is ready to deal with Nanomites or not
BOOL ThreadsPatched = FALSE;		// Whether Get/SetThreadContext has been hooked
SIZE_T sbuf = 0;						// Temporary buffer
char dbuf[256]={0};					// Temporary buffer
std::string FileName("");			// Name of the target file
std::string DirName("");			// Name of the target file directory
STARTUPINFO sInfo={0};
PROCESS_INFORMATION pInfo={0};
BOOL running = TRUE;				// When running == false, the DLL returns control to ArmInline.exe
DEBUG_EVENT DBE={0};
BOOL NeedToContinue = FALSE;		// If a ContinueDebugEvent fails, this value will ensure that it is later 
									// called successfully before the debug script resumes
CONTEXT		Context={0};
LDT_ENTRY	sel={0};
DWORD ContinueCode = DBG_EXCEPTION_NOT_HANDLED;
LPVOID pRemoteDBE = 0;				// Pointer in the debugged process address space to the DEBUGEVENT structure
DEBUG_EVENT RemoteDBE={0};				// Local copy of the remote structure
DEBUG_EVENT TemplateDBE={0};			// Stored copy of the DEBUGEVENT structure pertaining to a Nanomite exception
LPVOID pRemoteContext = 0;			// " with the CONTEXT structure
CONTEXT RemoteContext={0};
LPVOID ReturnAddress = 0;			// Address to which a hooked function should return
SIZE_T CNano = 0;						// Index of the current Nanomite being tested
CONTEXT PreContext={0};					// CONTEXT structure before Armadillo deals with the Nanomite (in GetThreadContext)
CONTEXT PostContext={0};				// CONTEXT structure after Armadillo deals with the Nanomite (in SetThreadContext)
DWORD ConditionTable[64];			// Used to brute-force process each Nanomite. One entry per (relevant) combination of EFlags
SHORT CTIndex = 0;					// Which index of ConditionTable is being worked on
SIZE_T ConsecutiveGTCs = 0;			// Number of GetThreadContexts called consecutively without a SetThreadContext
									// This is used to determine whether Armadillo thinks it sees a Nanomite or some other INT3
SIZE_T FalseCCs = 0;					// The count of INT3s processed that turned out not to be Nanomites
SIZE_T lTimer = 0;					// Used with GetTickCount to time certain events.
SIZE_T LastUpdate = 0;				// As lTimer
BOOL Inconsistent = FALSE;			// Is set TRUE if a Nanomite produces a ConditionTable that contradicts the possible conditional jumps.
Nanomite *pFinalTable = 0;			// The result table that is passed to ArmInline.exe, containing all the (actual) Nanomites' summaries.
UpdateReport UR={0};
typedef void (__stdcall *FNPTR)(UpdateReport *pUR);	
FNPTR VBCallback = 0;				// Callback to Armageddon.exe to keep track of the progress				
SIZE_T	NumNanos = 0;					// Number of potential Nanomites
std::vector<Nanomite> Nano;			// Contains the data of all the potential Nanomites
typedef std::set<DWORD> SNano;		// unique/sorted logged nanomites address table
SNano		LNano;
SNano::iterator it;
std::vector<LogNano> LSNano;
LogNano		LVNano={0};
SIZE_T		LogNanos=0;
PVOID		Address = 0;
PVOID		LogAddress = 0;
PVOID		SaveAddress = 0;
BOOL		RunLogNanos=FALSE;		// Used to determine type run
UpdateLog	UL={0};
typedef void (__stdcall *LNPTR)(UpdateLog *pUL);
LNPTR VBCalllog = 0;				// Callback to Armageddon.exe to keep track of the progress				
HMODULE hKernel32 = 0;				// Addresses of API functions needing to be hooked or patched
PVOID AddIsDebuggerPresent = 0;
PVOID AddDebugActiveProcess = 0;
PVOID AddGetThreadContextR = 0;
PVOID AddSetThreadContextR = 0;
PVOID AddWaitForDebugEvent = 0;
PVOID AddWaitForDebugEventR = 0;
PVOID AddContinueDebugEvent = 0;
PVOID PseudoSingleStep = 0;
PVOID SWBPExceptionAddress[2] = { 0x00000000, 0x00000000 };
BYTE STARTRBYTE = 0xED;
BYTE BPBDAP = 0;
BYTE BPBWFDE = 0;
BYTE BPBWFDER = 0;
BYTE BPBCDE = 0;

// Used for fast search
typedef struct {
	int plen;
	unsigned char pp[MAXPAT+1];
	unsigned char pw[1];
	int skip[MAXPAT+1];
} FINDSTRUCT, FAR *LPFIND;
typedef HANDLE HFIND;
FINDSTRUCT		fs={0};
unsigned char *ss = 0;
unsigned char *sf = 0;
HFIND 		hfind = 0;
LPFIND 		lpfind = 0;
// Search related variables
unsigned char *p=0;
unsigned char *end=0;
unsigned char *pamiec=0;
int 		hexFind_size=0;
int 		selected_begin=0;
int 		selected_end=0;
int 		hexFind_from=0;
int			i,j,k,n=0;
int			sstrlen=0;
unsigned char	*ustring=0;
unsigned char	intext[MAXPAT+1]={0};
unsigned char	outtext[MAXPAT+1]={0};
unsigned char	hextext[MAXPAT+1]={0};
char		wildchar[1] = {'?'};	// default wildcard char
unsigned char   *wstring=0;
//******* SEARCH STRING ARRAYS *********//
//SWBP'S ON API RETN INSTRUCTION
//Note: hex "3F" denotes wildcard string "?"
char		*hexapiretn[1]={"C23F00"};
SIZE_T		dwAPISize=500;
SIZE_T		dwFileSize=0;
PVOID 		dwAddress=0;
PVOID		PEdwAddress=0;
SIZE_T		dwOffset=0;
BOOL		bWildcard=FALSE;
DWORD		DwordRead = 0;
SIZE_T		dwRead = 0;
SIZE_T		dwWritten=0;
DWORD		dwCalcAddress=0;
PVOID		dwsecurityVMAddress=0;
SIZE_T		dwsecurityVMOffset=0;
SIZE_T		dwsecurityVMSize=0;
HANDLE		childhThread=0;
HANDLE		childhProcess=0;
PVOID		StartAddress = 0;
BYTE		StartByte = 0;
BOOL        logfirsttime = TRUE;
BYTE        logbyte = 0;
MEMORY_BASIC_INFORMATION	mbi={0};

	PBYTE 	g_pMappedFileBase = 0;				// Pointer to Virtual Memory Address of Base Module
	PIMAGE_DOS_HEADER 		dosHeader;
	PIMAGE_FILE_HEADER 		pImgFileHdr;
  	PIMAGE_OPTIONAL_HEADER 	pImgOptHdr;
  	PIMAGE_SECTION_HEADER 	pImgSectHdr;
	PIMAGE_SECTION_HEADER 	pImgLSectHdr;
	#define IMAGE_SR_SIGNATURE                  0x5253  // SR
	#define IMAGE_SR_NOSIGNATURE                0x0000
	#define SIZE_OF_NT_SIGNATURE		(SIZE_T)sizeof(DWORD)
	/* global macros to define header offsets into file */
	/* offset to PE file signature                                 */
	#define NTSIGNATURE(a) ((LPVOID)((BYTE *)a		     +	\
			((PIMAGE_DOS_HEADER)a)->e_lfanew))
	/* Files protected with Armadillo are stamped with the */
	/*characters 'SR' (Silicon Realms) at this offset. */
	#define SRSIGNATURE(a) ((LPVOID)((BYTE *)a		     +	\
	((PIMAGE_DOS_HEADER)a)->e_lfanew + 26))

	/* DOS header identifies the NT PEFile signature dword
	the PEFILE header exists just after that dword              */
	#define PEFHDROFFSET(a) ((LPVOID)((BYTE *)a		     +	\
			 ((PIMAGE_DOS_HEADER)a)->e_lfanew    +	\
			 SIZE_OF_NT_SIGNATURE))

	/* PE optional header is immediately after PEFile header       */
	#define OPTHDROFFSET(a) ((LPVOID)((BYTE *)a		     +	\
			 ((PIMAGE_DOS_HEADER)a)->e_lfanew    +	\
			 SIZE_OF_NT_SIGNATURE		     +	\
			 (SIZE_T)sizeof (IMAGE_FILE_HEADER)))
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	// Directory Entries [INDEX] BELOW:
	#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
	#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
	#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
	#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
	#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
	#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
	#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
	//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
	#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
	#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
	#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
	#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
	#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
	#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
	#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
	#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

	/* section headers are immediately after PE optional header    */
	#define SECHDROFFSET(a) ((LPVOID)((BYTE *)a		     +	\
			 ((PIMAGE_DOS_HEADER)a)->e_lfanew    +	\
			 SIZE_OF_NT_SIGNATURE		     +	\
			 (SIZE_T)sizeof (IMAGE_FILE_HEADER)	     +	\
			 (SIZE_T)sizeof (IMAGE_OPTIONAL_HEADER)))

void Report(LPCSTR Msg)
{
	if (!IsDLL) return;
	//std::cout << Msg;
	//OutputDebugStringA(Msg);
	return;
} // Wrapper for OutputDebugStringA

/*-----------------------------------------------------------------------------
    func:   SetFindPattern
    desc:   initialize the pattern to be matched and generate skip table
    pass:   lpszPattern = pattern string
    rtrn:   HFIND - the find handle for further text search
-----------------------------------------------------------------------------*/
HFIND SetFindPattern( unsigned char *lpszPattern )
{
    hfind = GlobalAlloc(GHND, (SIZE_T)sizeof(FINDSTRUCT));
    if (!(lpfind = (LPFIND)GlobalLock(hfind)))
        return NULL;

	memset(&fs,0,(SIZE_T)sizeof(fs));
	lpfind->plen = sstrlen;

    if (lpfind->plen > MAXPAT)
        lpfind->plen = MAXPAT;

	ZeroMemory( &lpfind->pp, (SIZE_T)sizeof(lpfind->pp) );
	ZeroMemory( &lpfind->skip, (SIZE_T)sizeof(lpfind->skip) );

	memcpy(lpfind->pp, (unsigned char *) lpszPattern, lpfind->plen);
	// Wildcard related default "?" is used hex "3F"
	if ((unsigned char *) wstring)
	{
		memcpy(lpfind->pw, (unsigned char *)wstring, strlen((const char *)wstring));
	}
	else
	{
		lpfind->pw[0] = '0';
	}
	for (j=0; j<256; j++)
    {
		lpfind->skip[j] = lpfind->plen;
    }

   	for (j=0; j<lpfind->plen; j++)
   	{
		lpfind->skip[lpfind->pp[j]] = lpfind->plen - j - 1;
	}
    GlobalUnlock(hfind);
    return (hfind);
}

/*-----------------------------------------------------------------------------
    func:   FreeFindPattern
    desc:   free the memory occupied by SetFindPattern
    pass:   hfind - the find handle
    rtrn:   nothing
-----------------------------------------------------------------------------*/
void FreeFindPattern( HFIND hfind )
{
    GlobalFree(hfind);
	hfind=0;
}

/*-----------------------------------------------------------------------------
    func:   Find
    desc:   match a pattern defined in SetFindPattern against search space
			in forward manner
    pass:   hfind = the find handle created by SetFindPattern
    rtrn:   NULL = match fail
            else = pointer in search space where match 1st byte pattern found
-----------------------------------------------------------------------------*/
unsigned char * Find( HFIND hfind )
{
    unsigned char *lpresult=0;

	if (!(lpfind = (LPFIND)GlobalLock(hfind)))
    	return (NULL);
	// pointer to memory space
	pamiec = (unsigned char *)dwAddress;
	// start of search space
	p = pamiec + hexFind_from + lpfind->plen - 1;
	end = (unsigned char *)((unsigned char *)dwAddress + dwFileSize);
	__try
	{
		for(j = lpfind->plen - 1; j >= 0; j--, p--)
			while(*p != lpfind->pp[j] && lpfind->pp[j] != lpfind->pw[0])
        {
			if (bWildcard)
			{
				n = 1;
			}
			else
			{
				n = lpfind->skip[*p];
			}
            if(lpfind->plen - j > n)
            	p += lpfind->plen - j;
            else
                p += n;
            if(p>=end)
			{
				GlobalUnlock(hfind);
                return NULL;
			}
            j = lpfind->plen - 1;
        }
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		lpresult = NULL;
		goto FIND;
	}
    p++;
    selected_begin = p - pamiec;
    selected_end = selected_begin + lpfind->plen - 1;
   	hexFind_from = selected_begin + lpfind->plen;
	lpresult = p;
	FIND:
    GlobalUnlock(hfind);
    return (lpresult);
}

unsigned char DecryptHex(unsigned char znak)
{
    switch(znak)
    {
		case '0': return 0;
        case '1': return 1;
        case '2': return 2;
        case '3': return 3;
        case '4': return 4;
        case '5': return 5;
        case '6': return 6;
        case '7': return 7;
        case '8': return 8;
        case '9': return 9;
        case 'a': case 'A': return 0xA;
        case 'b': case 'B': return 0xB;
        case 'c': case 'C': return 0xC;
        case 'd': case 'D': return 0xD;
        case 'e': case 'E': return 0xE;
        case 'f': case 'F': return 0xF;
    }
	return 0;
}

// Convert hex to text
void HexToText(unsigned char* dest, char* src, int size)
{
	for(i = 0; i < size; i++)
    {
		dest[i] &= 0x0F;
       	dest[i] |= (DecryptHex(src[i << 1]) << 4);

       	dest[i] &= 0xF0;
       	dest[i] |= DecryptHex(src[(i << 1) + 1]);
    }
	return;
}

void DoNext(void)
{
	sf = Find(hfind);
	return;
}

void DoFind(void)
{
	sf = 0;
	ss = (unsigned char *)dwAddress;
	hexFind_from = 0;
	DoNext();
	return;
}

void DoSearch(int type, int which)
{
	if (hfind)
	{
		FreeFindPattern(hfind);
	}
	ZeroMemory( &intext, (SIZE_T)sizeof(intext) );
	ZeroMemory( &outtext, (SIZE_T)sizeof(outtext) );
	//***** SEARCH *****//
	// type: '0' = API hexapiretn RETN address hex strings
	// type: '1' = Armadillo code hexarmcode hex strings
	// type: '2' = Armadillo dynamic code hex string
	if (type == 0)
	{
		std::string strapi = (hexapiretn[which]);
		memcpy(outtext, (unsigned char *) hexapiretn[which], strapi.size());
		strapi.clear();
	}
	else if (type == 2)
	{
		std::string strhex = ((char *)hextext);
		memcpy(outtext, (unsigned char *) hextext, strhex.size());
		strhex.clear();
	}
	else
	{
		Report("DoSearch function: Unknown type");
		running = false;
		return;
	}
	std::string strout = ((char *)outtext);
	sstrlen = strout.size() / 2;
	strout.clear();
	hexFind_size = sstrlen;
    HexToText(intext, (char *)outtext, hexFind_size);
	ustring = (unsigned char *)intext;
	if (bWildcard)
	{
		wstring = (unsigned char *)wildchar;
	}
	else
	{
		wstring = 0;
	}
	hfind = SetFindPattern(ustring);
	DoFind();
	return;
}

void DoUpdate() 
{
	if (IsDLL) 
	{
		UR.CurrentNano = CNano;
		UR.NumNanos = NumNanos;
		if (Inconsistent) 
		{
			UR.Inconsistency = true;
		}
		else 
		{
			UR.Inconsistency = false;
		}
		UR.NumDuf = FalseCCs;
		VBCallback(&UR);
	}
	return;
} // Callback to Armageddon.exe to keep track of the progress

void DoUpdateLog() 
{
	if (IsDLL) 
	{
		UL.LogNanos = LogNanos;
		VBCalllog(&UL);
	}
	return;
} // Callback to Armageddon.exe to keep track of the progress

// Free PE related memory
void FreePEMemory(void)
{
	if (PEdwAddress)
	{
		VirtualFree(
			PEdwAddress,
			0,
			MEM_RELEASE
			);
		PEdwAddress=0;
	}
	return;
}

// Free the memory
void FreeVirtualMemory(void)
{
	if (dwAddress)
	{
		VirtualFree(
			dwAddress,
			0,
			MEM_RELEASE
			);
		dwAddress=0;
	}
	return;
}

/* Hardware breakpoint debug registers */
BOOL SetSingleStep(HANDLE thisThread)
{
	Context.ContextFlags = CONTEXT_FULL;
	if(!GetThreadContext(thisThread, &Context))
	{
		return FALSE;
	}
	Context.EFlags |= 0x100;	// set the "trap" flag for single step
	if(!SetThreadContext(thisThread, &Context))
	{
		return FALSE;
	}
	return TRUE;
}

void GetAddresses()
{
	hKernel32 = GetModuleHandle("Kernel32");
	AddIsDebuggerPresent = (PVOID)GetProcAddress(hKernel32, "IsDebuggerPresent");
	AddDebugActiveProcess = (PVOID)GetProcAddress(hKernel32, "DebugActiveProcess");
	AddWaitForDebugEventR = (PVOID)GetProcAddress(hKernel32, "WaitForDebugEvent");
	AddContinueDebugEvent = (PVOID)GetProcAddress(hKernel32, "ContinueDebugEvent");
	AddGetThreadContextR = (PVOID)GetProcAddress(hKernel32, "GetThreadContext");
	AddSetThreadContextR = (PVOID)GetProcAddress(hKernel32, "SetThreadContext");

	//Search for the RETN address in this API
	dwFileSize = dwAPISize;     //Size of search space
	dwAddress = (LPVOID)AddWaitForDebugEventR; //Search begin address
	// Using wildcards
	bWildcard = TRUE;
	DoSearch(0,0);
	// Search String not found! 
	if (!sf)
	{
		Report("Failed to find end of WaitForDebugEvent.\n");
		running = false;
	}
	else
	{
		dwOffset = ((DWORD)((HPSTR)sf - (HPSTR)ss));
		AddWaitForDebugEvent = (PVOID)((DWORD)AddWaitForDebugEventR + dwOffset);
	}
	//Search for the RETN address in this API
	dwFileSize = dwAPISize;     //Size of search space
	dwAddress = (LPVOID)AddSetThreadContextR; //Search begin address
	// Using wildcards
	bWildcard = TRUE;
	DoSearch(0,0);
	// Search String not found! 
	if (!sf)
	{
		Report("Failed to find end of SetThreadContext.\n");
		running = false;
	}
	else
	{
		dwOffset = ((DWORD)((HPSTR)sf - (HPSTR)ss));
		AddSetThreadContextR = (PVOID)((DWORD)AddSetThreadContextR + dwOffset);
	}
	//Search for the RETN address in this API
	dwFileSize = dwAPISize;     //Size of search space
	dwAddress = (LPVOID)AddGetThreadContextR; //Search begin address
	// Using wildcards
	bWildcard = TRUE;
	DoSearch(0,0);
	// Search String not found! 
	if (!sf)
	{
		Report("Failed to find end of GetThreadContext.\n");
		running = false;
	}
	else
	{
		dwOffset = ((DWORD)((HPSTR)sf - (HPSTR)ss));
		AddGetThreadContextR = (PVOID)((DWORD)AddGetThreadContextR + dwOffset);
	}
	//Search for the RETN address in this API
	dwFileSize = dwAPISize;     //Size of search space
	dwAddress = (LPVOID)AddDebugActiveProcess; //Search begin address
	// Using wildcards
	bWildcard = TRUE;
	DoSearch(0,0);
	// Search String not found! 
	if (!sf)
	{
		Report("Failed to find end of AddDebugActiveProcess.\n");
		running = false;
	}
	else
	{
		dwOffset = ((DWORD)((HPSTR)sf - (HPSTR)ss));
		AddDebugActiveProcess = (PVOID)((DWORD)AddDebugActiveProcess + dwOffset);
	}
	ReadProcessMemory(pInfo.hProcess, (LPCVOID) AddDebugActiveProcess, &BPBDAP, 1, &sbuf);
	ReadProcessMemory(pInfo.hProcess, (LPCVOID) AddWaitForDebugEvent, &BPBWFDE, 1, &sbuf);
	ReadProcessMemory(pInfo.hProcess, (LPCVOID) AddWaitForDebugEventR, &BPBWFDER, 1, &sbuf);
	ReadProcessMemory(pInfo.hProcess, (LPCVOID) AddContinueDebugEvent, &BPBCDE, 1, &sbuf);
	return;
} // Fills the values of all the Address holding variables. It is assumed that these APIs will reside at the same
  // RVA in the this process and the debugged one

int LoadSeDebugPrivilege(void)
{
	HANDLE hToken=0;
	LUID Val;
	TOKEN_PRIVILEGES tp;

	if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES
		| TOKEN_QUERY, &hToken))
		return(GetLastError());

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Val))
		return(GetLastError());

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = Val;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp,
		(SIZE_T)sizeof (tp), NULL, NULL))
		return(GetLastError());

	CloseHandle(hToken);
	return 1;
}

/* hide debugger */
BOOL HideDebugger(HANDLE thisProcess, HANDLE thisThread)
{
	DWORD		RVApeb=0;
	DWORD		fsbase=0;
	DWORD		numread=0;
	WORD		beingDebugged=0;

	// Get Thread context
	Context.ContextFlags = CONTEXT_SEGMENTS;
	GetThreadContext(thisThread,&Context);
	if (!GetThreadSelectorEntry(thisThread, Context.SegFs, &sel))
	{
		return FALSE;
	}
	fsbase = (sel.HighWord.Bytes.BaseHi << 8| sel.HighWord.Bytes.BaseMid) << 16|
		sel.BaseLow;
	if (!ReadProcessMemory(thisProcess, (LPCVOID)(fsbase + 0x30), &RVApeb, 4, &numread) ||
		numread != 4)
	{
		return FALSE;
	}
	if (!ReadProcessMemory(thisProcess, (LPCVOID)(RVApeb + 2), &beingDebugged, 2, &numread) ||
		numread != 2)
	{
		return FALSE;
	}
	beingDebugged = 0;
	if (!WriteProcessMemory(thisProcess, (LPVOID)(RVApeb + 2), &beingDebugged, 2, &numread) ||
		numread != 2)
	{
		return FALSE;
	}
	return TRUE;
}

void PatchDebugActiveProcess()
{
//	byte P = 0xCC;
	byte P = 0xED;
	WriteProcessMemory(pInfo.hProcess, (LPVOID) AddDebugActiveProcess, &P, 1, NULL);
	return;
} // Sets a breakpoint on DebugActiveProcess

void PatchThreadContext()
{
//	DWORD P = 0x0008C2CC;
//	WriteProcessMemory(pInfo.hProcess, (LPVOID) AddGetThreadContextR, &P, 4, NULL);
//	WriteProcessMemory(pInfo.hProcess, (LPVOID) AddSetThreadContextR, &P, 4, NULL);
	BYTE P = 0xED;
	WriteProcessMemory(pInfo.hProcess, (LPVOID)AddGetThreadContextR, &P, 1, NULL);
	WriteProcessMemory(pInfo.hProcess, (LPVOID)AddSetThreadContextR, &P, 1, NULL);
//	Command 
//	XOR EAX, EAX
//	INC EAX
//	RETN 0C
	BYTE CDE[6] = {0x33, 0xC0, 0x40, 0xC2, 0x0C, 0x00};
	WriteProcessMemory(pInfo.hProcess, (LPVOID) AddContinueDebugEvent, CDE, 6, NULL);
	return;
} //  Sets a breakpoint on Get/SetThreadContext, patches ContinueDebugEvent 
//so it does nothing but returns true

void DecrementEIP()
{
	Context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pInfo.hThread, &Context);
	Context.Eip--;
	SetThreadContext(pInfo.hThread, &Context);
	return;
} // For use when removing breakpoints

void IncrementEIP()
{
	Context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pInfo.hThread, &Context);
	Context.Eip++;
	SetThreadContext(pInfo.hThread, &Context);
	return;
} // For use when stepping past 2 byte (MOV EDI, EDI) breakpoint

void SpoofDebugEvent()
{
	Context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pInfo.hThread, &Context);
	ReadProcessMemory(pInfo.hProcess, (LPCVOID) (Context.Esp + 4), &pRemoteDBE, 4, NULL);
	if (StartedNanomites) 
	{
		if (!ThreadsPatched) 
		{
			PatchThreadContext();
			ThreadsPatched = TRUE;
		}
		memcpy(&RemoteDBE, &TemplateDBE, (SIZE_T)sizeof(DEBUG_EVENT));
		RemoteDBE.u.Exception.ExceptionRecord.ExceptionAddress = (PVOID)Nano[CNano].Address;
		WriteProcessMemory(pInfo.hProcess, pRemoteDBE, &RemoteDBE, (SIZE_T)sizeof(DEBUG_EVENT), NULL);
		ReadProcessMemory(pInfo.hProcess, (LPCVOID) Context.Esp, &ReturnAddress, 4, NULL);
		Context.Eax = 1;
		Context.Esp += 0x0C;
		Context.Eip = (DWORD) ReturnAddress;
		Context.ContextFlags = CONTEXT_FULL;
		SetThreadContext(pInfo.hThread, &Context);
		return;
	}
	ReadProcessMemory(pInfo.hProcess, pRemoteDBE, &RemoteDBE, (SIZE_T)sizeof(DEBUG_EVENT), NULL);
	if (RemoteDBE.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
	{
		if (RemoteDBE.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) 
		{
			if ((DWORD) RemoteDBE.u.Exception.ExceptionRecord.ExceptionAddress < 0x70000000) 
			{
				memcpy(&TemplateDBE, &RemoteDBE, (SIZE_T)sizeof(DEBUG_EVENT));
				DWORD dwOne = 1;
				memcpy((BYTE*)(&TemplateDBE) + 0x50, &dwOne, 4);
				StartedNanomites = TRUE;
				lTimer = GetTickCount();
			}
		}
	}
	// Continue Execution (WaitForDebugEvent):
//	BYTE BPCC = 0xCC;
	BYTE BPCC = 0xED;
	WriteProcessMemory(pInfo.hProcess, (LPVOID) AddWaitForDebugEvent, &BPBWFDE, 1, &sbuf);
	Context.EFlags |= TF_BIT;
//	Context.Eip--;
	SetThreadContext(pInfo.hThread, &Context);
	ContinueDebugEvent(DBE.dwProcessId, DBE.dwThreadId, DBG_CONTINUE);
	WaitForDebugEvent(&DBE, 1000);
	AddWaitForDebugEvent = AddWaitForDebugEventR;
	BPBWFDE = BPBWFDER;
	WriteProcessMemory(pInfo.hProcess, (LPVOID) AddWaitForDebugEvent, &BPCC, 1, &sbuf);
	return;
} // Turns remote DEBUGEVENT into one representing a Nanomite at a given address

void LogDebugEvent()
{
	Context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pInfo.hThread, &Context);
	ReadProcessMemory(pInfo.hProcess, (LPCVOID) (Context.Esp + 4), &pRemoteDBE, 4, NULL);
	ReadProcessMemory(pInfo.hProcess, pRemoteDBE, &RemoteDBE, (SIZE_T)sizeof(DEBUG_EVENT), NULL);
	if (RemoteDBE.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
	{
		if (RemoteDBE.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) 
		{
			if ((DWORD) RemoteDBE.u.Exception.ExceptionRecord.ExceptionAddress < 0x70000000) 
			{
				if (logfirsttime)
				{
					childhProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, RemoteDBE.dwProcessId);
				}
				LogAddress = RemoteDBE.u.Exception.ExceptionRecord.ExceptionAddress;
				ReadProcessMemory(childhProcess, LogAddress, &logbyte, sizeof(BYTE), NULL);
				if (logbyte = 0xCC)
				{
					if (LogAddress != SaveAddress)
					{
						bool ret = LNano.insert((DWORD)LogAddress).second;
						// If not a duplicate, insert it into our nanomite log array
						if (ret)
						{
							LVNano.Address = (DWORD)LogAddress;
							LSNano.push_back(LVNano);
							LogNanos++;
						}
						SaveAddress = LogAddress;
					}
				}
			}
		}
	}
	// Continue Execution (WaitForDebugEvent):
//	BYTE BPCC = 0xCC;
	BYTE BPCC = 0xED;
	WriteProcessMemory(pInfo.hProcess, AddWaitForDebugEvent, &BPBWFDE, 1, &sbuf);
	Context.EFlags |= TF_BIT;
//	Context.Eip--;
	SetThreadContext(pInfo.hThread, &Context);
	ContinueDebugEvent(DBE.dwProcessId, DBE.dwThreadId, DBG_CONTINUE);
	WaitForDebugEvent(&DBE, 1000);
	AddWaitForDebugEvent = AddWaitForDebugEventR;
	BPBWFDE = BPBWFDER;
	WriteProcessMemory(pInfo.hProcess, AddWaitForDebugEvent, &BPCC, 1, &sbuf);
	return;
} // Turns remote DEBUGEVENT into one representing a Nanomite at a given address

BOOL CompareJumpTable(INT Type, LONG Destination) 
{
	BOOL Goes = FALSE;
	BYTE fOF = 0;
	BYTE fSF = 0;
	BYTE fZF = 0;
	BYTE fPF = 0;
	BYTE fCF = 0;
	BYTE fCX = 0;
	
	for (INT i = 0; i < 64; i++) 
	{
		fCX = (i & 1);		//  CX (low order word)
		fPF = (i & 2) / 2;	//  PF (parity flag)
		fOF = (i & 4) / 4;	//  OF (overflow flag)
		fSF = (i & 8) / 8;	//  SF (sign flag)
		fZF = (i & 16) / 16;//  ZF (zero flag)
		fCF = (i & 32) / 32;//  CF (carry flag)
		switch (Type) 
		{
			case JA:
				Goes = (fCF == 0 && fZF == 0);
				break;
			case JB:
				Goes = (fCF == 1);
				break;
			case JBE:
				Goes = (fCF == 1 || fZF == 1);
				break;
			case JC:
				Goes = (fCF == 1);
				break;
			case JCXZ:
				Goes = (fCX == 0);
				break;
			case JNCXZ:
				Goes = (fCX != 0);
				break;
			case JG:
				Goes = (fZF == 0 && fSF == fOF);
				break;
			case JGE:
				Goes = (fSF == fOF);
				break;
			case JL:
				Goes = (fSF != fOF);
				break;
			case JLE:
				Goes = (fZF == 1 || fSF != fOF);
				break;
			case JNB:
				Goes = (fCF == 0);
				break;
			case JNC:
				Goes = (fCF == 0);
				break;
			case JNO:
				Goes = (fOF == 0);
				break;
			case JNP:
				Goes = (fPF == 0);
				break;
			case JNS:
				Goes = (fSF == 0);
				break;
			case JNZ:
				Goes = (fZF == 0);
				break;
			case JO:
				Goes = (fOF == 1);
				break;
			case JP:
				Goes = (fPF == 1);
				break;
			case JPE:
				Goes = (fPF == 1);
				break;
			case JPO:
				Goes = (fPF == 0);
				break;
			case JS:
				Goes = (fSF == 1);
				break;
			case JZ:
				Goes = (fZF == 1);
				break;
		}
		if (Goes != (ConditionTable[i] == Destination))
		{
			return FALSE;
		}
	}
	return TRUE;
} // Compares the derived 'jump table' to that of the suspected Jcc

void IdentifyNano()
{
	SIZE_T Offset = 0;
	INT i = 0;
	BOOL IsJMP = TRUE;
	std::string Result("");

	// Calculate jump size:
	Nano[CNano].Size = ConditionTable[0];
	for (i = 1; i < 64; i++)
	{
		Offset = ConditionTable[i];
		if (Offset > 0) 
		{
			if (Offset != Nano[CNano].Size) 
			{
				IsJMP = FALSE;
				if ((Offset < Nano[CNano].Size) || (Nano[CNano].Size < 0)) 
				{
					Nano[CNano].Size = Offset;
					break;
				}
			}
		}
	}
	// Calculate jump destination & consistency
	for (i = 0; i < 64; i++)
	{
		Offset = ConditionTable[i];
		if (Offset == Nano[CNano].Size) 
		{
			// No Jump
		}
		else 
		{
			if (Nano[CNano].Destination == 0) 
			{
				Nano[CNano].Destination = ((Nano[CNano].Address) + Offset);
			}
			else 
			{
				if (Nano[CNano].Destination != ((ConditionTable[i] + Nano[CNano].Address))) 
				{
					Inconsistent = TRUE;
					Report("Error: Inconsistent jump address.");
				}
			}
		}
	}

	if (IsJMP) 
	{
		if (Nano[CNano].Size < 0)
		{
			Nano[CNano].Size = -Nano[CNano].Size;
		}
		Nano[CNano].JumpType = JMP;
		Nano[CNano].Destination = ((Nano[CNano].Address) + ConditionTable[0]);
		memset(dbuf,0,(SIZE_T)sizeof(dbuf));
		Result = ultoa(CNano, dbuf, 10);
		Result.append (" - Nanomite at ");
		memset(dbuf,0,(SIZE_T)sizeof(dbuf));
		Result.append(ultoa(Nano[CNano].Address, dbuf, 16));
		Result.append(" is unconditional; length ");
		memset(dbuf,0,(SIZE_T)sizeof(dbuf));
		Result.append(ultoa(Nano[CNano].Size, dbuf, 16));
		Result.append("h and destination ");
		memset(dbuf,0,(SIZE_T)sizeof(dbuf));
		Result.append(ultoa(Nano[CNano].Destination, dbuf, 16));
		Result.append(".\n");
		//Report(Result.c_str());
		return;
	}
	/*
	// Fill Alt variables
	for (i = 0; i < 64; i++){
		if (i > 0){
			if (ConditionTable[i] == ConditionTable[i-1]) Alt1 = FALSE;
		}
		if (i > 1){
			if (ConditionTable[i] == ConditionTable[i-2]) Alt2 = FALSE;
		}
		if (i > 3){
			if (ConditionTable[i] == ConditionTable[i-4]) Alt4 = FALSE;
		}
		if (i > 7){
			if (ConditionTable[i] == ConditionTable[i-8]) Alt8 = FALSE;
		}
		if (i > 15){
			if (ConditionTable[i] == ConditionTable[i-16]) Alt16 = FALSE;
		}
		if (i > 31){
			if (ConditionTable[i] == ConditionTable[i-32]) Alt32 = FALSE;
		}
	} 
	*/
	Offset = (SIZE_T)(Nano[CNano].Destination - Nano[CNano].Address);
	for (INT CompType = JNZ; CompType <= JNO; CompType++) 
	{
		if (CompareJumpTable(CompType, Offset)) 
		{
			Nano[CNano].JumpType = CompType;
			memset(dbuf,0,(SIZE_T)sizeof(dbuf));
			Result = ultoa(CNano, dbuf, 10);
			Result.append (" - Nanomite at ");
			memset(dbuf,0,(SIZE_T)sizeof(dbuf));
			Result.append(ultoa(Nano[CNano].Address, dbuf, 16));
			Result.append(" has type ");
			memset(dbuf,0,(SIZE_T)sizeof(dbuf));
			Result.append(itoa(Nano[CNano].JumpType, dbuf, 10));
			Result.append(", length ");
			memset(dbuf,0,(SIZE_T)sizeof(dbuf));
			Result.append(ultoa(Nano[CNano].Size, dbuf, 16));
			Result.append("h and destination ");
			memset(dbuf,0,(SIZE_T)sizeof(dbuf));
			Result.append(ultoa(Nano[CNano].Destination, dbuf, 16));
			Result.append(".\n");
			//Report(Result.c_str());
			return;
		}
	}
	memset(dbuf,0,(SIZE_T)sizeof(dbuf));
	Result = ultoa(CNano, dbuf, 10);
	Result.append(" - Unable to identify jump type at ");
	memset(dbuf,0,(SIZE_T)sizeof(dbuf));
	Result.append(ultoa(Nano[CNano].Address, dbuf, 16));
	Result.append(".\n");
	//Report(Result.c_str());
	return;
} // Analyses the jump table to determine the Jcc type (calculates the instruction being emulated by Armadillo)

void CompareContexts()
{
	INT i = 0;
	ConditionTable[CTIndex] = (PostContext.Eip - PreContext.Eip + 1);
	CTIndex++;
	if (CTIndex >= 64) 
	{
		IdentifyNano();
		if (Nano[CNano].JumpType == JUnknown)
		{
			Nano[CNano].JumpType = NotNanomite;
		}
		CNano++;
		CTIndex = 0;
		if (CNano >= NumNanos) 
		{
			Report("Completed Nanomites\n");
			running = FALSE;
			return;
		}
	}
	return;
} // Compares the 'Pre' & 'Post' thread contexts to decide whether Armadillo believes there is a Nanomite at the address.
  // Fills out the entry in the Nano vector and increments CNano accordingly

void DoBreakpoints()
{
	PVOID ReturnAddress = 0;
	byte P = 0;

	if (GetTickCount() - LastUpdate > 100) 
	{
		LastUpdate = GetTickCount();
		if (RunLogNanos)
		{
			DoUpdateLog();
		}
		else
		{
			DoUpdate();
		}
	}

	Address = DBE.u.Exception.ExceptionRecord.ExceptionAddress;
	ContinueCode = DBG_CONTINUE;

	if (Address == AddDebugActiveProcess)
	{
//		P = 0xCC;
		P = 0xED;
		WriteProcessMemory(pInfo.hProcess, AddWaitForDebugEvent , &P, 1, NULL);
		WriteProcessMemory(pInfo.hProcess, DBE.u.Exception.ExceptionRecord.ExceptionAddress, &BPBDAP, 1, NULL);
//		DecrementEIP();
	}
	else if (Address == StartAddress)
	{
		// Reset EIP
		WriteProcessMemory(pInfo.hProcess, DBE.u.Exception.ExceptionRecord.ExceptionAddress, &StartByte, 1, NULL);
		GetAddresses();
		P = 0xED;
		WriteProcessMemory(pInfo.hProcess, (LPVOID) AddWaitForDebugEvent , &P, 1, NULL);
	}
	else if (Address == AddWaitForDebugEvent)
	{
		if (RunLogNanos)
		{
			LogDebugEvent();
		}
		else
		{
			SpoofDebugEvent();
		}
	}
	else if (Address == AddGetThreadContextR)
	{
		ConsecutiveGTCs++;
		if (ConsecutiveGTCs > 1) 
		{
			// Duff nanomite
			FalseCCs++;
			CNano++;
			CTIndex = 0;
			if (CNano >= NumNanos) 
			{
				Report("Completed Nanomites\n");
				running = FALSE;
				return;
			}
			Nano[CNano].JumpType = NotNanomite;
		}
		Context.ContextFlags = CONTEXT_FULL;
		GetThreadContext(pInfo.hThread, &Context);
		ReadProcessMemory(pInfo.hProcess, (LPCVOID)(Context.Esp + 8), &pRemoteContext, 4, NULL);
		ReadProcessMemory(pInfo.hProcess, pRemoteContext, &RemoteContext, (SIZE_T)sizeof(CONTEXT), NULL);

		RemoteContext.EFlags = 0;
		(CTIndex & CX) ? RemoteContext.Ecx = 1 : RemoteContext.Ecx = 0;
		RemoteContext.Ecx = 1 & (CTIndex & CX);								//  CX (low order word)
		RemoteContext.EFlags |= (0x00000800 & -(INT)((CTIndex & OF) != 0));	//  OF (overflow flag)
		RemoteContext.EFlags |= (0x00000080 & -(INT)((CTIndex & SF) != 0));	//  SF (sign flag)
		RemoteContext.EFlags |= (0x00000040 & -(INT)((CTIndex & ZF) != 0));	//  ZF (zero flag)
		RemoteContext.EFlags |= (0x00000004 & -(INT)((CTIndex & PF) != 0));	//  PF (parity flag)
		RemoteContext.EFlags |= (0x00000001 & -(INT)((CTIndex & CF) != 0));	//  CF (carry flag)

		RemoteContext.Eip = Nano[CNano].Address;
		RemoteContext.Eip++;
		memcpy(&PreContext, &RemoteContext, (SIZE_T)sizeof(CONTEXT));
		WriteProcessMemory(pInfo.hProcess, pRemoteContext, &RemoteContext, (SIZE_T)sizeof(CONTEXT), NULL);
		// Continue Execution:
		ReadProcessMemory(pInfo.hProcess, (LPCVOID) Context.Esp, &Context.Eip, 4, &sbuf);
		Context.Esp += 12;
		Context.Eax = 1;
		SetThreadContext(pInfo.hThread, &Context);
	}
	else if (Address == AddSetThreadContextR)
	{
		ConsecutiveGTCs = 0;
		Context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
		GetThreadContext(pInfo.hThread, &Context);
		ReadProcessMemory(pInfo.hProcess, (LPCVOID) (Context.Esp + 8), &pRemoteContext, 4, NULL);
		ReadProcessMemory(pInfo.hProcess, pRemoteContext, &PostContext, (SIZE_T)sizeof(CONTEXT), NULL);
		CompareContexts();
		// Continue Execution:
		ReadProcessMemory(pInfo.hProcess, (LPCVOID) Context.Esp, &Context.Eip, 4, &sbuf);
		Context.Esp += 12;
		Context.Eax = 1;
		SetThreadContext(pInfo.hThread, &Context);
	}
EndDoBreakpoints:
	return;
} // The heart of the debug loop. It finds out which breakpoint has triggered and calls the appropriate function to deal with it

void DebugLoop() 
{
	// Adjust debug privileges on startup
	if (!LoadSeDebugPrivilege())
	{
		Report("unable to activate the SeDebugPrivilege\0");
	}

	//GetStartupInfo(&sInfo);
	if (!CreateProcess((LPCSTR) FileName.c_str(), NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, (LPCSTR) DirName.c_str(), &sInfo, &pInfo)) 
	{
		Report("Failed to open process.\0");
		return;
	}
	while (running) 
	{
		if (WaitForDebugEvent(&DBE, 1000)) 
		{
			ContinueCode = DBG_EXCEPTION_NOT_HANDLED;
			switch (DBE.dwDebugEventCode) 
			{
				case CREATE_PROCESS_DEBUG_EVENT:
					ContinueCode = DBG_CONTINUE;
					StartAddress = DBE.u.CreateProcessInfo.lpStartAddress;
					// Set a SWBP on module's EP
					ReadProcessMemory(pInfo.hProcess, StartAddress, &StartByte,
						(SIZE_T)sizeof(BYTE), &dwRead);
					WriteProcessMemory (pInfo.hProcess, StartAddress, &STARTRBYTE,
						(SIZE_T)sizeof(BYTE), &dwWritten);
					CloseHandle(DBE.u.CreateProcessInfo.hFile);
					//if (Debug) Report ("Create Process\n");
					break;
				case EXIT_PROCESS_DEBUG_EVENT:
					//Report ("Exit Process\n");
					running = false;
					CloseHandle(pInfo.hProcess);
					pInfo.hProcess = 0;
					CloseHandle(pInfo.hThread);
					pInfo.hThread = 0;
					if (childhProcess)
					{
						CloseHandle(childhProcess);
						childhProcess = 0;
					}
					break;
				case CREATE_THREAD_DEBUG_EVENT:
					ContinueCode = DBG_CONTINUE;
					//Report ("Create Thread\n");
					break;
				case EXIT_THREAD_DEBUG_EVENT:
					ContinueCode = DBG_CONTINUE;
					//Report ("Exit Thread\n");
					break;
				case LOAD_DLL_DEBUG_EVENT:
					ContinueCode = DBG_CONTINUE;
					//Report ("Load DLL\n");
					CloseHandle(DBE.u.LoadDll.hFile);
					break;
				case UNLOAD_DLL_DEBUG_EVENT:
					ContinueCode = DBG_CONTINUE;
					//Report ("Unload DLL\n");
					break;
				case EXCEPTION_DEBUG_EVENT:
					//if (DBE.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {Report ("Access Violation\n")}
					//if (DBE.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) Report ("Illegal Instruction\n");
					//if (DBE.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) Report ("Breakpoint\n");
					if (FirstException) 
					{
						if (!HideDebugger(pInfo.hProcess, pInfo.hThread))
						{
							Report("HideDebugger ERROR!");
						}
						PatchDebugActiveProcess();
						ContinueCode = DBG_CONTINUE;
						FirstException = FALSE;
					}
					else if (DBE.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) 
					{
						DoBreakpoints();
					}
					else if (DBE.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_PRIV_INSTRUCTION)
					{
						DoBreakpoints();
					}
					break;
				case OUTPUT_DEBUG_STRING_EVENT:
					ContinueCode = DBG_CONTINUE;
					//Report ("Debug String\n");
					break;
				case RIP_EVENT:
					Report ("Rip\n");
					break;
			}
			NeedToContinue = (!ContinueDebugEvent(DBE.dwProcessId, DBE.dwThreadId, ContinueCode));
		}
	}
	//TerminateProcess(pInfo.hProcess, 0);
	//DebugActiveProcessStop(pInfo.dwProcessId);
	return;
} // Creates the target process (debugged) and deals with any DEBUGEVENTs that occur

void CleanUp()
{
	if (pInfo.hProcess)
	{
		TerminateProcess(pInfo.hProcess, 0);
		CloseHandle(pInfo.hProcess);
		pInfo.hProcess = 0;
		CloseHandle(pInfo.hThread);
		pInfo.hThread = 0;
	}
	hKernel32 = 0;
	return;
} // Closes handles and frees memory

void ResetVariables()
{
	FirstException = TRUE;
	FirstWFDE = TRUE;
	StartedNanomites = FALSE;
	RunLogNanos=FALSE;
	ThreadsPatched = FALSE;
	running = TRUE;
	NeedToContinue = FALSE;
	ContinueCode = DBG_EXCEPTION_NOT_HANDLED;
	pRemoteDBE = 0;
	pRemoteContext = 0;
	ReturnAddress = 0;
	CNano = 0;
	CTIndex = 0;
	ConsecutiveGTCs = 0;
	NumNanos = 0;
	LogNanos = 0;
	FalseCCs = 0;
	Inconsistent = FALSE;
	if (pFinalTable)
	{
		delete[]pFinalTable;
		pFinalTable=0;
	}
	if (Nano.size()>0)
		Nano.clear();
	if (LSNano.size()>0)
		LSNano.clear();
	if (LNano.size()>0)
		LNano.clear();
	FileName = "";
	DirName = "";
	sbuf=0;
	memset(&sInfo, 0, (SIZE_T)sizeof(STARTUPINFO));
	memset(&pInfo, 0, (SIZE_T)sizeof(PROCESS_INFORMATION));
	memset(&DBE, 0, (SIZE_T)sizeof(DEBUG_EVENT));
	memset(&Context, 0, (SIZE_T)sizeof(CONTEXT));
	memset(&RemoteDBE, 0, (SIZE_T)sizeof(DEBUG_EVENT));
	memset(&RemoteContext, 0, (SIZE_T)sizeof(CONTEXT));
	memset(&UR, 0, (SIZE_T)sizeof(UR));
	memset(&UL, 0, (SIZE_T)sizeof(UL));
	memset(&LVNano, 0, (SIZE_T)sizeof(LVNano));
	memset(dbuf, 0, (SIZE_T)sizeof(dbuf));
	hKernel32 = 0;
	AddIsDebuggerPresent = 0;
	AddDebugActiveProcess = 0;
	AddGetThreadContextR = 0;
	AddSetThreadContextR = 0;
	AddWaitForDebugEvent = 0;
	AddContinueDebugEvent = 0;
	return;
} // Cleans up all variables so that ArmInline can call DoNanomites more than once per instance

void GetNanosFromProcess(DWORD pNumNanos, Nanomite *pVBTable)
{
	Nanomite TNano;
	memset(&TNano,0,(SIZE_T)sizeof(TNano));
	for (DWORD i = 0; i < pNumNanos; i++) 
	{
		TNano.Address = pVBTable[i].Address;
		Nano.push_back(TNano);
	}
	std::string NanoCount("");
	NumNanos = (DWORD) Nano.size();
	memset(dbuf,0,(SIZE_T)sizeof(dbuf));
	NanoCount = ultoa(NumNanos, dbuf, 10);
	NanoCount.append(" Nanomites found.\n");
	Report(NanoCount.c_str());
	return;
} // Scans process memory for 0xCC and generates a table of the addresses of potential Nanomites

void __declspec(dllexport) __stdcall DoNanomites(DWORD UpdateCallback, UpdateReport *pReport, 
	LPCSTR FName, LPCSTR DName, DWORD pNumNanos, Nanomite *TNano)
{
	VBCallback = (FNPTR)(DWORD) UpdateCallback;
	ResetVariables();
	FileName = FName;
	DirName = DName;
	GetNanosFromProcess(pNumNanos,&TNano[0]);
	if (Nano.size() == 0) 
	{
		Report("No nanomites to process.");
	}
	else 
	{
		Nano.begin();
		DebugLoop();
		std::string Summary("");
		memset(dbuf,0,(SIZE_T)sizeof(dbuf));
		Summary = ultoa(NumNanos - FalseCCs, dbuf, 10);
		Summary += " successfully processed, ";
		memset(dbuf,0,(SIZE_T)sizeof(dbuf));
		Summary += ultoa(FalseCCs, dbuf, 10);
		Summary += " failed.\n";
		Report(Summary.c_str());
		Summary = "Took ";
		memset(dbuf,0,(SIZE_T)sizeof(dbuf));
		Summary += ultoa(GetTickCount() - lTimer, dbuf, 10);
		Summary += " milliseconds.";
		Report(Summary.c_str());
	}
	DoUpdate();
	CleanUp();
	return;
} // The main interface with Armageddon.exe

void __declspec(dllexport) __stdcall DoLogNanomites(DWORD UpdateCallback, UpdateLog *pLog, 
		LPCSTR FName, LPCSTR DName)
{
	VBCalllog = (LNPTR)(LONG) UpdateCallback;
	ResetVariables();
	RunLogNanos=TRUE;
	FileName = FName;
	DirName = DName;
	DebugLoop();
	DoUpdateLog();
	CleanUp();
	return;
} // logs (inserts) valid nanomites addresses into a sorted/unique array

void __declspec(dllexport) __stdcall Populate(Nanomite *pVBTable)
{
	for (int i = 0; i < CNano; i++) 
	{
		pVBTable[i].Address = Nano[i].Address;
		pVBTable[i].Destination = Nano[i].Destination;
		pVBTable[i].JumpType = Nano[i].JumpType;
		pVBTable[i].Size = Nano[i].Size;
	}
	Nano.clear();
	return;
} // Fills out the finalised table for Armageddon.exe. 
//This only gets called after DoNanomites has returned control to the exe

void __declspec(dllexport) __stdcall PopulateLog(LogNano *pLogTable)
{
	int i=0;
	for ( it = LNano.begin( ); it != LNano.end( ); it++ )
	{
		pLogTable[i].Address = *it;
		i++;
	}
	LSNano.clear();
	return;
} // Fills out the finalised table for Armageddon.exe. 
//This only gets called after DoLogNanomites has returned control to the exe