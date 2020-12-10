#pragma once
#ifndef WINVER			// Specifies that the minimum required platform is Windows XP.
#define WINVER 0x0501
#endif

#ifndef _WIN32_WINNT	// Specifies that the minimum required platform is Windows XP.
#define _WIN32_WINNT 0x0501
#endif
//#define _WIN32_WINNT 0x0601
#define PSAPI_VERSION 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <atlstr.h>
#include <tchar.h>
#include <psapi.h>
#include <process.h>
#include <string>
#include <vector>
#include <set>
#include <math.h>
#include <strsafe.h>
#include <exception>
#include <shellapi.h>
#include "ArmNF.h"
#include "Nanolib.h"
#include "disasm.h"
#include "resource.h"
#include "BeaEngine.h"
#include <GdiPlus.h>
#pragma comment(lib, "gdiplus.lib")
#pragma hdrstop
#define	_CRT_SECURE_NO_DEPRECATE
#define BEA_USE_STDCALL    /* specify the usage of a stdcall version of BeaEngine */
#define WM_COMPLETED	(WM_USER+1236)
#define DFONT_SIZE 9	//dialog font size
#define BUFSIZE 256
#define WM_PROGRESS		(WM_USER+1234)
// GDI+
Gdiplus::GdiplusStartupInput	m_gdiplusStartupInput;
ULONG_PTR	m_gdiplusToken = 0;
Gdiplus::Bitmap *newbmp = 0;
Gdiplus::Bitmap *oldbmp = 0;
Gdiplus::Graphics *gr = 0;
HBITMAP newgdibmp = 0;
HBITMAP newgrybmp = 0;
HBITMAP newaboutbmp = 0;
HBITMAP newrefreshbmp = 0;
HBITMAP newcreditbmp = 0;
HBITMAP newhelpbmp = 0;

class myexception : public std::exception
{
	virtual const char* what() const throw()
	{
		return "My exception happened";
	}
} myex;
/*	Dialog related */
WNDCLASS wc = { 0 };
INITCOMMONCONTROLSEX cc = { 0 };
HWND 		hwndMain = NULL;			// Main window handle
HWND		hwndDlgA = NULL;			// Dialog controls 
HWND		hwnd01 = NULL;
HWND		hwnd02 = NULL;
HWND		hwnd03 = NULL;
HWND		hwnd04 = NULL;
HWND		hwnd07 = NULL;
HWND		hwnd08 = NULL;
HWND		hwnd09 = NULL;
HWND		hwnd10 = NULL;
HWND		hwnd12 = NULL;
HWND		hwnd13 = NULL;
HWND		hwnd14 = NULL;
HWND		hwnd15 = NULL;
HWND		hwnd16 = NULL;
HWND		hwnd17 = NULL;
HWND		hwnd18 = NULL;
HWND		hwnd19 = NULL;
HWND		hwnd20 = NULL;
HWND		hwnd21 = NULL;
HWND		hwnd22 = NULL;
HWND		hwnd23 = NULL;
HWND		hwnd24 = NULL;
HWND		hwnd25 = NULL;
HWND		hwnd26 = NULL;
HWND		hwnd27 = NULL;
HWND		hwnd30 = NULL;
HWND		hwnd31 = NULL;
HWND		hwnd32 = NULL;
HWND		hwnd34 = NULL;
HWND		hwnd35 = NULL;
HWND		hwnd36 = NULL;
HWND		hwnd43 = NULL;
HWND		hwnd44 = NULL;
HWND		hwnd45 = NULL;
HWND		hwnd46 = NULL;
HWND		hwnd47 = NULL;
HWND		hwnd48 = NULL;
HWND		hwndA = NULL;
HWND		hwndB = NULL;
HWND		hwndList = NULL;
HWND		hwndCtrl = NULL;
HWND		hwndIDLISTVIEW = NULL;
HBITMAP		hBitmap01 = NULL;
HBITMAP		hBitmap02 = NULL;
HBITMAP		hBitmap03 = NULL;
HBITMAP		hBitmap04 = NULL;
HBITMAP		hBitmap05 = NULL;	// Dialog bitmaps
HDC  		hDC = NULL;
HDC  		hdcStatic = NULL;		// Device context
BITMAP 		info = { 0 };
HFONT 		OrigFont = NULL;
HFONT 		hFont = NULL;
UINT		uiID = 0;
UINT		tlen = 0;
UINT		clen = 0;
UINT		stdlen = 0;
UINT		enhlen = 0;
LPTSTR		szCmdline = 0;
LPTSTR		sznewCmdline = 0;
HINSTANCE 	hinst = 0;
unsigned	dwThreadid = 0;
unsigned	dwThreadid1 = 0;
DWORD		dwPid = 0;
DWORD		dwTid = 0;
DWORD		dwTlsIndex = 0;
HANDLE 		hFile = 0;
HANDLE		hFile1 = 0;
HANDLE		hThread = 0;
DWORD		LastUpdate = 0;
int			iStatus = 0;
int			numitems = 0;
int			compilertype = 0;
char		isep[80] = "==========================================";
char		ibuf[80] = { 0 };
char		lbuf[80] = { 0 };
char		*f = "Loading target:";
char		*g = "Processing target...";
char		*h = "Dumping target...";
double 		scaleX = 0;
double 		scaleY = 0;
#define 	SCALEX(argX) ((int) ((argX) * scaleX))
#define 	SCALEY(argY) ((int) ((argY) * scaleY))
char		szOS[BUFSIZE] = { 0 };
char		bszOS[BUFSIZE] = { 0 };
char		dszOS[BUFSIZE] = { 0 };
char		stdfpbuf[10] = { 0 };
char		enhfpbuf[10] = { 0 };
DWORD		dwstdfp = 0;
DWORD		dwenhfp = 0;
char 		buffer[MAX_PATH] = { 0 };
char		savebuffer[MAX_PATH] = { 0 };
char 		inibuffer[MAX_PATH] = { 0 };
char		inisavebuffer[MAX_PATH] = { 0 };
char		nanobuffer[MAX_PATH] = { 0 };
char		nanologbuffer[MAX_PATH] = { 0 };
char		filebuffer[MAX_PATH] = { 0 };
char		armbuffer[MAX_PATH] = { 0 };
char		copybuffer[MAX_PATH] = { 0 };
char		logbuffer[MAX_PATH] = { 0 };
char		cmdbuffer[MAX_PATH] = { 0 };
char		sztempbuffer[1024] = { 0 };
char		nbufrwb32[MAX_PATH] = { 0 };
char		dbuffer[MAX_PATH] = { 0 };
char		nbuf[MAX_PATH] = { 0 };
char		dbuf[MAX_PATH] = { 0 };
char		Filename[MAX_PATH] = { 0 };
char		szCmdbuffer[MAX_PATH] = { 0 };
PCSTR		pszPathName = 0;
PCSTR		pszBaseExt = 0;
PCSTR		pszBaseName = 0;
char		pszDllName[MAX_PATH] = { 0 };
char		ebuf[80] = { 0 };
char		bufbp[33] = { 0 };
char		*bp = 0;
BOOL		greenimage = FALSE;
BOOL		EPhandled = FALSE;
LPSTR		buf = 0;
#define		MAXPAT  256
// Global variables and structures
//  Hardware Fingerprint
BYTE		BEGFP = { 0x68 };
typedef struct t_hwfp {
	WORD	hwfp1;
	WORD	hwfp2;
} t_hwfp;
t_hwfp	hwfp;
typedef struct b_hwfp {
	BYTE	bhwfp1;
	BYTE	bhwfp2;
	BYTE	bhwfp3;
	BYTE	bhwfp4;
} b_hwfp;
b_hwfp	bhwfp;
typedef struct c_hwfp {
	BYTE	chwfp1;
	BYTE	chwfp2;
	BYTE	chwfp3;
	BYTE	chwfp4;
} c_hwfp;
c_hwfp	chwfp;
BOOL chwfpone = TRUE;
typedef struct typed
{
	WORD T1;
	WORD T2;
} typed;
// Condition check for serial hardware fingerprint version
BYTE	bhwfpversion = 0;	// 0 = v5.x; 1 = v6.x
// Serial Hardware fingerprint for Armadillo v5.x
BYTE	bhwfp5bytes[5] = { 0xB8, 0x00, 0x00, 0x00, 0x00 };
// Serial Hardware fingerprint for Armadillo v6.x
BYTE	bhwfp6bytes[12] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0x5E, 0x8B, 0xE5, 0x5D, 0xC2, 0x08, 0x00 };
// Used for fast search
typedef struct {
	int plen;
	unsigned char pp[MAXPAT + 1];
	unsigned char pw[1];
	int skip[MAXPAT + 1];
} FINDSTRUCT, FAR *LPFIND;
typedef HANDLE HFIND;
FINDSTRUCT		fs = { 0 };
unsigned char *ss = 0;
unsigned char *sf = 0;
HFIND 		hfind = 0;
LPFIND 		lpfind = 0;
// WinVersion types
typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);
typedef BOOL(WINAPI *PGPI)(DWORD, DWORD, DWORD, DWORD, PDWORD);
// Global variables
//	IAT elimination
PVOID		IATELIMREAD = 0;	//IAT ELIMINATION ADDRESS
PVOID		IATELIMSAVE = 0;	//IAT ELIMINATION ADDRESS SAVED FOR MESSAGES
DWORD_PTR	IATELIMDISP = 0;	//IAT ELIMINATION STACK DISPLACEMENT ADDRESS
DWORD_PTR	IATELIMDIFF = 0;	//SUBTRACT THIS FROM REGISTER EBP TO OBTAIN STACK POINTER ADDRESS
WORD		BEGSTRING = { 0x83BD };	//WRAP THE IATELIMREAD VALUE WITH THIS
BYTE		ENDSTRING = { 0x00 };	//AND THIS TO CREATE HEX SEARCH STRING
WORD        TWONOPS = { 0x9090 }; // IAT ELIMINATION ALTERNATE
//  Code Splicing related
PVOID		CSOAddress = 0;
PVOID		CSORVAddress = 0;
PVOID		CSAddress = 0;
SIZE_T		CSOSize = 0;
SIZE_T		CSSize = 0;
//  IAT REDIRECTION
BYTE		retnbyte = { 0xC3 };
PVOID		IATREDIVARREAD = 0;		//USED FOR VARIABLE DWORD
PVOID		IATREDIVARWRITE = 0;	//USED FOR VARIABLE DWORD
PVOID		IATREDIREAD = 0;
DWORD_PTR	IATREDIDISP = 0;
DWORD_PTR	IATREDIDIFF = 0;
//  COPYMEM-II Related infos
PVOID		CMeventaddress = { 0x00000000 };	// copymem-II event address
PVOID		CMaddress = { 0x00000000 };		// copymem-II base page guard exception address
PVOID		CBaddress = { 0x00000000 };		// copymem-II incremental page guard exception address
//  PE Related info
PVOID		PESectionAddress = { 0x00000000 };
SIZE_T		PESectionSize = { 0x00000000 };
DWORD 		PEGuardProtect = { PAGE_EXECUTE_READWRITE | PAGE_GUARD }; // copymem-II protect attributes
DWORD 		PERWProtect = { PAGE_EXECUTE_READWRITE };
DWORD 		PEOldProtect = { 0x00000000 };
DWORD  		PESecProtect = { 0x00000000 };
//  Exception Addresses for Hardware BP's
PVOID		HWBPExceptionAddress[4] = { 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
//  Note: index = 8 used as pseudo single step SWBP (Child process only!!)
unsigned int	thisSWBP = 0;
//  Exception Addresses Software BP's
PVOID		SWBPExceptionAddress[20] = { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
0x00000000, 0x00000000 };
//  Function Addresses for API's
PVOID		FunctionAddress[15] = { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
0x00000000, 0x00000000, 0x00000000 };
//  SWBP Patch byte info:
//  Search (read) byte
BYTE 		scanbyte[20] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
//  Replace (write) byte
BYTE        replbyte[20] = { 0xED, 0xED, 0xED, 0xED, 0xED, 0xED, 0xED, 0xED, 0xED, 0xED,
0xED, 0xED, 0xED, 0xED, 0xED, 0xED, 0xED, 0xED, 0xED, 0xED };
BYTE 		ByteRead = 0;
PVOID       PvoidRead = 0;
PVOID       PvoidNext = 0;
PVOID       PvoidAddr = 0;
PVOID       SavePvoidAddr = 0;
DWORD_PTR	DwordRead = 0;
DWORD_PTR	DwordNext = 0;
DWORD_PTR	DwordArma = 0x4e4f4e45;
DWORD_PTR	SaveDwordRead = 0;
SIZE_T		dwRead = 0;
SIZE_T		dwWritten = 0;
SIZE_T		dwAPISize = 500;
SIZE_T		dwFileSize = 0;
SIZE_T		dwSaveFileSize = 0;
SIZE_T		dwAnfFileSize = 0;
DWORD_PTR	dwOffset = 0;
DWORD_PTR	SavedwOffset = 0;
SIZE_T		dwVMSize = 4096;
LPVOID		dwVMAddress = 0;
LPVOID		dwDASMAddress = 0;
DWORD		dwDASMreturn = 0;
SIZE_T		dwlength = 0;
LPVOID		dwZMVMAddress = 0;
LPVOID		dwIVVMAddress = 0;
LPVOID		dwBMVMAddress = 0;
LPVOID		SavedwBMVMAddress = 0;
DWORD_PTR	dwCalcAddress = 0;
DWORD_PTR	dwDataAddress = 0;
DWORD_PTR	dwBMVMOffset = 0;
DWORD_PTR	dwDecryptoffset = 0;
PVOID		dwBMVMValue = 0;
SIZE_T		dwArmVMSize = 0;
SIZE_T		dwArmVMNSize = 0;
LPVOID		dwoepcall = 0;
LPVOID		dwArmVMAddress = 0;
LPVOID		dwArmVMNAddress = 0;
LPVOID 		dwAddress = 0;
LPVOID 		PEdwAddress = 0;
LPVOID 		PESecdwAddress = 0;
SIZE_T		SecdwSize = 0;
SIZE_T		PEdwSize = 4096;
HMODULE     hMods[8092];
unsigned 	int	modlist[4096];
char		szModName[MAX_PATH] = { 0 };
DWORD 		nMods = 0;
DWORD 		cbNeeded = 0;
SIZE_T		dwSize = 0;		//Base Module's size
LPVOID		dwBase = 0;		//Base Module's load address
DWORD_PTR	roffset = 0;
SIZE_T		rsize = 0;
DWORD_PTR	voffset = 0;
DWORD_PTR	vsize = 0;
char 		b[512] = { 0 };
char 		c[80] = { 0 };
char 		d[80] = { 0 };
char 		a[80] = { 0 };
char 		e[512] = { 0 };
HANDLE		childhThread = 0;
HANDLE		childhProcess = 0;
DWORD		childpid = 0;
DWORD		childtid = 0;
UINT		instrcount = 0;
UINT		chkanalyzenf = 0;
UINT		chkanalyzest = 0;
UINT		chkanalyzelog = 0;
UINT		chkopenmutex = 0;
UINT		chksecuritydump = 0;
UINT		chksecurityload = 0;
UINT		chkignore2ndtext = 0;
UINT		chkbypass2ndtext = 0;
UINT		chkminimizesize = 0;
UINT		chkcodesplice = 0;
UINT		chkdumppdata = 0;
UINT		chkdb = 0;
UINT		chkcm2 = 0;
BOOL		foundarma = FALSE;
BOOL		breaknow = FALSE;
BOOL		detachnow = FALSE;
BOOL		detached = FALSE;
BOOL		debugblocker = FALSE;
BOOL        apiswbpdetect = FALSE;
BOOL		firsttime = FALSE;
BOOL		secondtime = FALSE;
BOOL		cserror = FALSE;
BOOL		firstmutex = TRUE;
BOOL		secondmutex = FALSE;
BOOL		foundjmp = FALSE;
BOOL		onetime = FALSE;
BOOL		copymem2 = FALSE;
BOOL		traceon = TRUE;
BOOL		bexitprocess = FALSE;
BOOL		bcGuardPage = FALSE;
BOOL		bGuardPage = FALSE;
BOOL		vadone = FALSE;
BOOL        iatdone = FALSE;
BOOL        iatadone = FALSE;
BOOL        ir1done = FALSE;
BOOL        ir2done = FALSE;
BOOL		checkredirect = FALSE;
BOOL		checkdumppdata = FALSE;
BOOL		checkforerrors = FALSE;
BOOL		checkdb = FALSE;
BOOL		checkcm2 = FALSE;
BOOL		checkformutex = FALSE;
BOOL		checksecuritydump = FALSE;
BOOL		checksecurityload = FALSE;
BOOL		checkignore2ndtext = FALSE;
BOOL		checkbypass2ndtext = FALSE;
BOOL		checkminimizesize = FALSE;
BOOL		analyzenf = FALSE;
BOOL		analyzest = FALSE;
BOOL		analyzelog = FALSE;
BOOL		checkanalyzenf = FALSE;
BOOL		checkanalyzest = FALSE;
BOOL		checkanalyzelog = FALSE;
BOOL		redirectsplicing = FALSE;
BOOL		variableredirectfound = FALSE;
BOOL		bWildcard = FALSE;
BOOL		isdll = FALSE;
BOOL		text1found = FALSE;
BOOL		datafound = FALSE;
BOOL		usingstdfp = FALSE;
BOOL		usingenhfp = FALSE;
BOOL        secondva = FALSE;
DWORD		cy = 0;
// Search related variables
unsigned char *p = 0;
unsigned char *end = 0;
unsigned char *pamiec = 0;
int 		hexFind_size = 0;
int 		selected_begin = 0;
int 		selected_end = 0;
int 		hexFind_from = 0;
int			i, j, k, n = 0;
int			sstrlen = 0;
unsigned char	*ustring = 0;
unsigned char	intext[MAXPAT + 1] = { 0 };
unsigned char	outtext[MAXPAT + 1] = { 0 };
unsigned char	hextext[MAXPAT + 1] = { 0 };
char		wildchar[1] = { '?' };	// default wildcard char
unsigned char   *wstring = 0;
/* ARTEAM IAT rebuilder / PE module minimize size functions */
/* Nacho_dj's ARImpRec.dll incorporated into this program via ARImpRec.lib */
/* Nacho_dj's ARMinSiz.dll incorporated into this program via ARMinSiz.lib */
/* This way, we don't need to include dll's in the distribution */
char		IRwarn[80] = { 0 };
DWORD		IRiatrva = 0;
DWORD		IRiatsize = 0;
DWORD		IRretn = 0;
DWORD		IRINT = 0;
char		*MSwarn = 0;
DWORD		MSretn = 0;
DWORD		MSINT = 0;
char		gnfobuffer[MAX_PATH] = { 0 };
/* prototypes used in ARImpRec.dll / ARMinSiz.dll */
extern "C" {
	DWORD	__declspec(dllimport) __stdcall SearchAndRebuildImportsIATOptimized(DWORD IRProcessId, LPSTR IRNameOfDumped,
		DWORD IROEP, DWORD OEPYES, DWORD *IRIATRVA, DWORD *IRIATSize, char *IRWarning);
	DWORD	__declspec(dllimport) __stdcall SearchAndRebuildImportsNoNewSection(DWORD IRNProcessId,
		LPSTR IRNNameOfDumped, DWORD IRNOEP, DWORD OEPYES, DWORD *IRNIATRVA, DWORD *IRNIATSize, char *IRNWarning);
	DWORD	__declspec(dllimport) __stdcall RebuildSectionsFromArmadillo(LPSTR MSNameOfProtected,
		LPSTR MSNameOfDumped, char *MSWarning);
	DWORD	__declspec(dllimport) __stdcall GetNameFileOptimized(LPSTR MSFileNameOrig, LPSTR MSFileNameOptimized);
	DWORD	__declspec(dllimport) __stdcall UnpackPdataSection(LPSTR MSNameOfProtected, LPSTR MSNameOfDumped, char *MSWarning);
	/* prototypes used in disasm.dll */
	int		__declspec(dllimport) __stdcall Assemble(char *cmd, unsigned long ip, t_asmmodel *model,
		int attempt, int constsize, char *errtext);
	/* prototypes used in ArmNF.dll */
	void __declspec(dllimport) __stdcall Init(char *StringError, DWORD pASM, DWORD pDisASM);
	int __declspec(dllimport) __stdcall Analyze(LPCSTR ADump, LPCSTR AProtected, DWORD PID, int type);
	DWORD __declspec(dllimport) __stdcall MakeLog(struct Log *log);
	int __declspec(dllimport) __stdcall AdvancedPatch(LPCSTR FileAddress, DWORD dwProcID, int Option);
	DWORD __declspec(dllimport) __stdcall LoadTable(LPCSTR LoadAddress);
	int __declspec(dllimport) __stdcall WriteTableToFile(LPCSTR SaveAddress);
}
/* Variables used in ArmNF.dll */
HMODULE		hdisasmdll = 0;
FARPROC		AsmAddr = { 0 };
FARPROC		DsmAddr = { 0 };
DWORD		AssembleAddress = 0;
DWORD		DisasmAddress = 0;
DWORD		NFDretn = 0;
int			NFIretn = 0;
Log			NFlog = { 0 };		//ArmNF log table
RNANO		*RNano = 0;		//pointer ArmNF nano table
HANDLE		hAnalThread = 0;
BOOL		isrunning = FALSE;
BOOL	    analyzeprob = FALSE;
BOOL		totalanalyzed = TRUE;
/* Global Variables used in BeaEngine.dll */
// this will hold the handle to the disassemble dll 
HINSTANCE hinstLib = 0;
// Functions we are interested in
typedef int(__stdcall *MYPROC)(LPDISASM);
MYPROC		ProcAdd = 0;
DWORD		retnsize = 0;
DWORD		lofinst = 0;
char		getstring[64] = { 0 };
std::string mystring = "";
///// BeaEngine.dll
DISASM MyDisasm = { 0 };
int len = 0;
int Error = 0;
DWORD_PTR jmpconst = 0;
/////
/* Admirals's external nanolib dll incorporated into this program */
// Use dynamic arrays as size isn't known at runtime!!
Nanomite	*VNano = 0;		// pointer to analyzed nanomite table
Nanomite	*VClean = 0;		// pointer to cleaned nanomite table
LogNano		*LNano = 0;		// pointer to logged nanomite table
Nanomite	*TNano = 0;		// Nanomite 0xCC array
std::vector<Nanomite> Nano;			// Contains the data of all the potential Nanomites
typedef std::set <DWORD> SET_LNano;	// unique/sorted logged nanomites address table
SET_LNano::iterator it;
SET_LNano	SNano;
BOOL		ReportedTotal = FALSE;
SIZE_T		NumNanos = 0;
SIZE_T		pNumNanos = 0;
SIZE_T		LogNanos = 0;
SIZE_T		Tally = 0;
SIZE_T		NewCount = 0;
UpdateReport	RStruct = { 0 };		// Report Nanomites
UpdateLog		LStruct = { 0 };		// Log Nanomites
/* prototypes used in Nanolib.dll		*/
void __declspec(dllimport) __stdcall DoNanomites(DWORD UpdateCallback, UpdateReport *pRStruct, LPCSTR FName, LPCSTR DName,
	SIZE_T NumNanos, Nanomite *pTNano);
void __declspec(dllimport) __stdcall DoLogNanomites(DWORD UpdateCallback, UpdateLog *pLStruct,
	LPCSTR FName, LPCSTR DName);
void __declspec(dllimport) __stdcall Populate(Nanomite *pVBTable);
void __declspec(dllimport) __stdcall PopulateLog(LogNano *pLogTable);
// struct used for ArmaNF return code
typedef struct t_ArmNFretn {
	WORD	hiNF;
	WORD	loNF;
} t_ArmNFretn;
t_ArmNFretn	ArmNFretn;
/* end variables */
/* 80x86 32-bit Disassembler and Assembler */
#define MAXCMDSIZE     16              // Maximal length of 80x86 command
#define TEXTLEN        256             // Maximal length of text string
//Structures used:
char		*pasm = 0;				// Pointer to text command
t_asmmodel	am = { 0 };					// Structure for assemble function
t_disasm	da = { 0 };					// Structure for disasm function
t_disasm	pda = { 0 };				// Structure for previous disasm function
char		cjumptype[TEXTLEN] = { 0 };
char		cjumpdest[TEXTLEN] = { 0 };
char		ccmd[MAXCMDSIZE] = { 0 };
char		s[TEXTLEN], errtext[TEXTLEN] = { 0 };
//******* SEARCH STRING ARRAYS *********//
//SWBP'S ON API RETN INSTRUCTION
//Note: hex "3F" denotes wildcard string "?"
char	*hexapiretn[1] = { "C23F00" };
char	*hexapijmp[1] = { "FF25" };
//unsigned char *hexapiretn = (unsigned char *)hexapiretnx;
//Armadillo virtual memory code specific hex search strings & .text section
//Note: hex "3F" denotes wildcard string "?"
char	*hexarmcode[12] = { "3B3F3F3F3F3F0F8E", "833F3F3F3F3F00743F8B3F3F3F3F3F2B3F3F3F3F3FC13F02",
"6800010000", "E83F3F3F3F83C40C", "444154454C41535452554E", "46494E4745525052494E5400444154454C41535452554E",
"C7853F3F3F3F3F3F3F3FEB3F8B3F3F3F3F3F833F0C893F3F3F3F3F8B", "0FB63F3FF73F1B3F813F11111111333F3345EC",
"FF153F3F3F3F8B3F3F5E8BE55DC20800", "41666649443D3C3E", "84C0753F813F3F3F3F3F723F833D3F3F3F3F00743FE9",
"FF153F3F3F3F8B3F3F8B3F3F3F3F3F893F3F8B3F3FA13F3F3F3F833F3F3F753FE9"};
// INDEX [0] = COPYMEM2 HEX SEARCH STRING
// INDEX [1] = IAT ELIMINATION HEX SEARCH STRING
// INDEX [2] = IAT REDIRECTION HEX SEARCH STRING (PUSH 100)
// INDEX [3] = IAT REDIRECTION HEX SEARCH STRING (CALL ????????, ADD ESP,0C)
// INDEX [4] = DATELASTRUN HEX SEARCH STRING (Hardware fingerprint standard)
// INDEX [5] = FINGERPRINT HEX SEARCH STRING (Hardware fingerprint enhanced)
// INDEX [6] = IAT VARIABLE REDIRECTION HEX SEARCH STRING
// INDEX [7] = SERIAL FINGERPRINT OVERRIDE HEX SEARCH STRING V5.X
// INDEX [8] = SERIAL FINGERPRINT OVERRIDE HEX SEARCH STRING V6.X
// INDEX [9] = ARMADILLO VERSION HEX SEARCH STRING
// INDEX [10] = IAT REDIRECTION HEX SEARCH STRING (CMP DWORD PTR DS:[40680A0],0)
// INDEX [11] = IAT ELIMINATION HEX SEARCH STRING ALTERNATE
// Structures used in running the process
STARTUPINFO 				si = { 0 };
PROCESS_INFORMATION 		pi = { 0 };
CONTEXT						Context = { 0 };
LDT_ENTRY					sel = { 0 };
MEMORY_BASIC_INFORMATION	mbi = { 0 };
MODULEINFO					mi = { 0 };
SECURITY_ATTRIBUTES 		sa = { 0 };
DEBUG_EVENT					DebugEv = { 0 }; 		// debugging event information
DEBUG_EVENT					CebugEv = { 0 };  		// child debugging event information
DEBUG_EVENT					SebugEv = { 0 };  		// save child debugging event information
LV_ITEM						lvi = { 0 }, lvin = { 0 };
LV_COLUMN 					lvc = { 0 }, lvcn = { 0 };
RECT						Rect = { 0 };
SYSTEMTIME					st = { 0 };
#define DBG_COND_EXECUTE	0
#define DBG_COND_WRITE		1
#define DBG_COND_READWRITE  3
//  Dynamic Control over Debug-child Flag
//  Useful information if you need to use it
#define DEBUG_PROCESS_ONLY_THIS_PROCESS 0x00000000
#define DEBUG_ANY_PROCESS 0x00000001
typedef enum _PROCESSINFOCLASS {
	ProcessDebugFlags = 31	// From ntddk.h
} PROCESSINFOCLASS;
typedef DWORD(CALLBACK * NTQUERYINFORMATIONPROCESS)(
	IN HANDLE               ProcessHandle,
	IN PROCESSINFOCLASS  ProcessInformationClass,
	OUT PVOID                ProcessInformation,
	IN ULONG                ProcessInformationLength,
	OUT PULONG					OPTIONAL);
typedef DWORD(CALLBACK * NTSETINFORMATIONPROCESS)(
	IN HANDLE               ProcessHandle,
	IN PROCESSINFOCLASS  ProcessInformationClass,
	OUT PVOID                ProcessInformation,
	IN ULONG                ProcessInformationLength);
HMODULE 	hNTModule = 0;
DWORD		retdebugflags = 0;
DWORD		DebugFlags = 0;
//  Note: Portions of the header logic in this routine taken
//  from the Portable Excutable File Format Abstract by:
//  ** Credits ** Johannes Plachy
LPVOID	UPX0VMaddress = { 0x00000000 };
SIZE_T	UPX0VMsize = { 0x00000000 };
LPVOID	UPX1VMaddress = { 0x00000000 };
SIZE_T	UPX1VMsize = { 0x00000000 };
LPVOID	TextVMaddress = { 0x00000000 };
SIZE_T	TextVMsize = { 0x00000000 };
LPVOID	ItextVMaddress = { 0x00000000 };
SIZE_T	ItextVMsize = { 0x00000000 };
LPVOID	Text1VMaddress = { 0x00000000 };
SIZE_T	Text1VMsize = { 0x00000000 };
LPVOID	RdataRVaddress = { 0x00000000 };
LPVOID	RdataVMaddress = { 0x00000000 };
SIZE_T	RdataVMsize = { 0x00000000 };
LPVOID	RdataNVMaddress = { 0x00000000 };
SIZE_T	RdataNVMsize = { 0x00000000 };
DWORD	RdataVMCharacteristics = { 0x00000000 };
LPVOID	RelocVMaddress = { 0x00000000 };
SIZE_T	RelocVMsize = { 0x00000000 };
LPVOID	BssVMaddress = { 0x00000000 };
SIZE_T	BssVMsize = { 0x00000000 };
LPVOID	IdataVMaddress = { 0x00000000 };
SIZE_T	IdataVMsize = { 0x00000000 };
LPVOID	AdataVMaddress = { 0x00000000 };
SIZE_T	AdataVMsize = { 0x00000000 };
LPVOID	AdataNVMaddress = { 0x00000000 };
SIZE_T	AdataNVMsize = { 0x00000000 };
LPVOID	Data1VMaddress = { 0x00000000 };
SIZE_T	Data1VMsize = { 0x00000000 };
LPVOID	Data1NVMaddress = { 0x00000000 };
SIZE_T	Data1NVMsize = { 0x00000000 };
LPVOID	PdataVMaddress = { 0x00000000 };
SIZE_T	PdataVMsize = { 0x00000000 };
LPVOID	DataVMaddress = { 0x00000000 };
SIZE_T	DataVMsize = { 0x00000000 };
LPVOID	BaseOfImage = { 0x00000000 };			// Module base load address
LPVOID	StartAddress = { 0x00000000 };		// Module EP address
LPVOID	OEPRVAddress = { 0x00000000 };		// Module OEP address
LPVOID	OEPVAddress = { 0x00000000 };			// Module OEP virtual address
LPVOID	OEPDelphiRVAddress = { 0x00000000 };	// Module PE header 2nd .itext section OEP address
LPVOID	OEPDelphiVAddress = { 0x00000000 };	// Module PE header 2nd .itext section OEP address
PBYTE 	g_pMappedFileBase = 0;				// Pointer to Virtual Memory Address of Base Module
PIMAGE_DOS_HEADER 		dosHeader;
PIMAGE_FILE_HEADER 		pImgFileHdr;
PIMAGE_OPTIONAL_HEADER 	pImgOptHdr;
PIMAGE_SECTION_HEADER 	pImgSectHdr;
PIMAGE_SECTION_HEADER 	pImgLSectHdr;
#define IMAGE_SR_SIGNATURE                  0x5253  // SR
#define IMAGE_SR_NOSIGNATURE                0x0000
#define SIZE_OF_NT_SIGNATURE		sizeof(DWORD_PTR)
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
			 sizeof (IMAGE_FILE_HEADER)))
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
			 sizeof (IMAGE_FILE_HEADER)	     +	\
			 sizeof (IMAGE_OPTIONAL_HEADER)))
//  Detach related
BYTE		ebfebytes[4] = { 0xEB, 0xFE, 0x90, 0x90 };
DWORD		securityentry = 0;
HMODULE 	hModule = 0;
HMODULE 	hDllModule = 0;
FARPROC		ProcAddr0 = { 0 };
FARPROC		ProcAddr1 = { 0 };
FARPROC		ProcAddr2 = { 0 };
FARPROC		ProcAddr3 = { 0 };
FARPROC		ProcAddr4 = { 0 };
FARPROC		ProcAddr5 = { 0 };
FARPROC		ProcAddr6 = { 0 };
FARPROC		ProcAddr7 = { 0 };
FARPROC		ProcAddr8 = { 0 };
FARPROC		ProcAddr9 = { 0 };
FARPROC		ProcAddr10 = { 0 };
FARPROC		ProcAddr11 = { 0 };
FARPROC		ProcAddr12 = { 0 };
FARPROC		ProcAddr13 = { 0 };
FARPROC		ProcAddr14 = { 0 };
/* prototypes */
LRESULT CALLBACK DialogProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK AboutProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK NanoProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK CommandProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
/* BMSEARCH prototypes */
HFIND SetFindPattern(unsigned char *lpszPattern);
void FreeFindPattern(HFIND hfind);
unsigned char * Find(HFIND hfind);

/* Admiral's Strategic Code Splicing begin	*/
BOOL	FuckedUp = FALSE;
PVOID	SStart = 0;
PVOID	TStart = 0;
SIZE_T	SLength = 0;
SIZE_T	TLength = 0;

typedef struct
{
	char		Opcode[TEXTLEN];
	DWORD		Length;
	BYTE		Bytes[32];
	BOOL		Active;
} Instruction;

Instruction		*Instrs = 0;
DWORD	NumSegments = 0;
BYTE	Asm[TEXTLEN] = { 0 };
BYTE	*Spliced = 0;
BYTE	*Target = 0;

BOOL	logitemreplace = FALSE;

void LogItem(LPCSTR fmt, ...)
{
	static DWORD LastError;
	static BOOL itemreplaced;

	BOOL replace = FALSE;
	if (logitemreplace)
	{
		logitemreplace = FALSE;
		if (!itemreplaced)
		{
			itemreplaced = TRUE;
		}
		else
		{
			replace = TRUE;
		}
	}
	else if (itemreplaced)
	{
		itemreplaced = FALSE;
		replace = TRUE;
	}

	if (fmt == NULL)
	{
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, LastError, 0,
			b, sizeof(b), NULL);
	}
	else
	{
		LastError = GetLastError();
		va_list args;
		va_start(args, fmt);
		StringCbVPrintf(b, sizeof(b), fmt, args);
		va_end(args);
	}
	if (replace)
	{
		ListView_SetItemText(hwndIDLISTVIEW, lvi.iItem, 0, b);
	}
	else
	{
		lvi.pszText = b;
		lvi.iItem = numitems++;
		ListView_InsertItem(hwndIDLISTVIEW, &lvi);
		ListView_Scroll(hwndIDLISTVIEW, 0, (int)cy);
		ListView_EnsureVisible(hwndIDLISTVIEW, lvi.iItem, FALSE);
	}
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	char title[80];
	char compt[80];

	GetWindowText(hwnd, title, sizeof(title));
	strcpy(compt, title);
	strupr(compt);
	if (strstr(compt, "ARMA") ||
		strstr(compt, "@ARM@"))
	{
		LogItem("EnumWindows: %s", title);
		SetWindowText(hwnd, "");
	}
	return TRUE;
}

/* display application information messages */
void MessageBoxInformation(char *text)
{
	MessageBox(NULL, (LPCSTR)text, "ArmaGeddon", MB_OK + MB_SYSTEMMODAL + MB_ICONINFORMATION);
	return;
}

/* Clear log entries in listview control */
void ClearListview(int type)
{
	switch (type)
	{
	case 0:
		// Turn off messaging until done
		SendMessage(hwndIDLISTVIEW, WM_SETREDRAW, (WPARAM)FALSE, 0);
		ListView_DeleteAllItems(hwndIDLISTVIEW);
		// Turn messaging back on
		SendMessage(hwndIDLISTVIEW, WM_SETREDRAW, (WPARAM)TRUE, 0);
		numitems = 0;
		LastUpdate = 0;
		break;
	case 1:
		ListView_DeleteAllItems(hwndList);
		break;
	}
	return;
}

void SelectAllListview()
{
	int		i = 0;
	int		iStatus = 0;
	UINT 	uState = 0;

	// Get itemcount
	iStatus = ListView_GetItemCount(hwndIDLISTVIEW);
	if (iStatus == 0)
	{
		return;
	}

	// Turn off messaging until done
	SendMessage(hwndIDLISTVIEW, WM_SETREDRAW, FALSE, 0);
	for (i = 0; i < iStatus; i++)
	{
		uState = LVIS_SELECTED;
		ListView_SetItemState(hwndIDLISTVIEW, i, uState, LVIS_SELECTED);
	}
	SendMessage(hwndIDLISTVIEW, WM_SETREDRAW, TRUE, 0);
	return;
}

void CopyAllListview()
{
	int		i = 0;
	int		iStatus = 0;
	int		sStatus = 0;
	UINT 	uState = 0;

	// Get itemcount
	iStatus = ListView_GetItemCount(hwndIDLISTVIEW);
	if (iStatus == 0)
	{
		return;
	}
	sStatus = ListView_GetSelectedCount(hwndIDLISTVIEW);
	// No items selected
	if (sStatus == 0)
	{
		return;
	}
	// Turn off messaging until done
	SendMessage(hwndIDLISTVIEW, WM_SETREDRAW, FALSE, 0);
	CString buffer = "";
	CString source = "";
	// Get selected items
	if (OpenClipboard(hwndDlgA))
	{
		HGLOBAL clipbuffer;
		char localbuffer[256] = { 0 };
		char *gbuffer;
		EmptyClipboard(); // Empty whatever's already there

		for (i = 0; i < iStatus; i++)
		{
			uState = ListView_GetItemState(hwndIDLISTVIEW, i, LVIS_SELECTED);
			if (uState)           //  If this item is selected, get it's text
			{
				memset(localbuffer, 0, sizeof(localbuffer));
				ListView_GetItemText(hwndIDLISTVIEW, i, 0, localbuffer, sizeof(localbuffer));
				buffer.Format("%s", localbuffer);
				// Annoyance: there is a trailing tab in the buffer, get rid of it
				buffer.TrimRight();
				// If you only use \n, not all programs (notepad!!!) will recognize the newline
				buffer.Append("\r\n");
				source.Append(buffer);
				buffer.ReleaseBuffer(0);
			}
		}
		clipbuffer = GlobalAlloc(GMEM_DDESHARE, source.GetLength() + 1);
		gbuffer = (char*)GlobalLock(clipbuffer);
		strcpy(gbuffer, LPCSTR(source));
		GlobalUnlock(clipbuffer);
		SetClipboardData(CF_TEXT, clipbuffer);	// Send the data
		CloseClipboard();						// VERY IMPORTANT
	}
	SendMessage(hwndIDLISTVIEW, WM_SETREDRAW, TRUE, 0);
	return;
}

void FreeBeaEngine(void)
{
	if (hinstLib)
	{
		FreeLibrary(hinstLib);
		hinstLib = 0;
	}
}

// Load BeaEngine.dll dynamically for disassembling code
BOOL LoadBeaEngine(void)
{
	hinstLib = LoadLibraryA((LPCSTR)"BeaEngine.dll");
	// check to make sure LoadLibrary() didn't return NULL 
	if (hinstLib == NULL)
	{
		LogItem("LoadLibrary error: BeaEngine.dll");
		return FALSE;
	}
	ProcAdd = (MYPROC)GetProcAddress(hinstLib, (LPCSTR)"_Disasm@4");
	if (ProcAdd == NULL)
	{
		LogItem("GetProcAddress error: _Disasm@4");
		return FALSE;
	}
	return TRUE;
}

// Open Armadillo protected File dialog function
int GetSecurityDllFileName(LPCSTR armbuffer)
{
	OPENFILENAME ofn;

	memset(&ofn, 0, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hInstance = GetModuleHandle(NULL);
	ofn.hwndOwner = GetActiveWindow();
	ofn.lpstrFile = (LPSTR)armbuffer;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrTitle = "Open Armadillo security file";
	ofn.nFilterIndex = 1;
	ofn.lpstrDefExt = "dll";
	ofn.Flags = OFN_FORCESHOWHIDDEN | OFN_HIDEREADONLY;
	ofn.lpstrFilter = "dll files (*.dll)\0""*.dll\0\0";
	return GetOpenFileName(&ofn);
}

// Save Armadillo protected File dialog function
int PutSecurityDllFileName(LPCSTR armbuffer)
{
	OPENFILENAME ofn;

	memset(&ofn, 0, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hInstance = GetModuleHandle(NULL);
	ofn.hwndOwner = GetActiveWindow();
	ofn.lpstrFile = (LPSTR)armbuffer;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrTitle = "Save Armadillo security file";
	ofn.nFilterIndex = 1;
	ofn.lpstrDefExt = "dll";
	ofn.Flags = OFN_FORCESHOWHIDDEN | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;
	ofn.lpstrFilter = "dll files (*.dll)\0""*.dll\0\0";
	return GetSaveFileName(&ofn);
}

// Open Armadillo protected File dialog function
int GetFileName(LPCSTR buffer)
{
	OPENFILENAME ofn;

	memset(&ofn, 0, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hInstance = GetModuleHandle(NULL);
	ofn.hwndOwner = GetActiveWindow();
	ofn.lpstrFile = (LPSTR)buffer;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrTitle = "Open Armadillo protected file";
	ofn.nFilterIndex = 1;
	ofn.lpstrDefExt = "exe";
	ofn.Flags = OFN_FORCESHOWHIDDEN;
	ofn.lpstrFilter = "executable/dll files (*.exe; *.dll)\0""*.exe;*.dll\0\0";
	return GetOpenFileName(&ofn);
}

// Open Armadillo Options "*.ini" File dialog function
int GetIniFileName(LPCSTR inibuffer)
{
	OPENFILENAME ofn;

	memset(&ofn, 0, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hInstance = GetModuleHandle(NULL);
	ofn.hwndOwner = GetActiveWindow();
	ofn.lpstrFile = (LPSTR)inibuffer;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrTitle = "Open Armageddon options file";
	ofn.nFilterIndex = 1;
	ofn.lpstrDefExt = "ini";
	ofn.Flags = OFN_FORCESHOWHIDDEN | OFN_HIDEREADONLY;
	ofn.lpstrFilter = "option files (*.ini)\0""*.ini\0\0";
	return GetOpenFileName(&ofn);
}

// Open Saved dump File dialog function
int GetDumpName(LPCSTR filebuffer)
{
	OPENFILENAME ofn;

	memset(&ofn, 0, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hInstance = GetModuleHandle(NULL);
	ofn.hwndOwner = GetActiveWindow();
	ofn.lpstrFile = (LPSTR)filebuffer;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrTitle = "Open saved dump file";
	ofn.lpstrInitialDir = (LPCSTR)nbuf;
	ofn.nFilterIndex = 1;
	ofn.lpstrDefExt = "exe";
	ofn.Flags = OFN_FORCESHOWHIDDEN | OFN_HIDEREADONLY;
	ofn.lpstrFilter = "Executable Files (*.exe)\0""*.exe\0\0";
	return GetOpenFileName(&ofn);
}

// Save Dump File dialog function
int PutFileName(LPCSTR savebuffer)
{
	OPENFILENAME ofn;
	memset(&ofn, 0, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hInstance = GetModuleHandle(NULL);
	ofn.hwndOwner = GetActiveWindow();
	ofn.lpstrFile = (LPSTR)savebuffer;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrTitle = "Save dumped file";
	ofn.lpstrInitialDir = (LPCSTR)nbuf;
	ofn.nFilterIndex = 1;
	if (isdll)
	{
		ofn.lpstrDefExt = "dll";
		ofn.lpstrFilter = "dll files (*.dll)\0""*.dll\0\0";
	}
	else
	{
		ofn.lpstrDefExt = "exe";
		ofn.lpstrFilter = "executable files (*.exe)\0""*.exe\0\0";
	}
	ofn.Flags = OFN_FORCESHOWHIDDEN | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;
	return GetSaveFileName(&ofn);
}

// Save Options "*.ini" File dialog function
int PutIniFileName(LPCSTR inisavebuffer)
{
	OPENFILENAME ofn;
	memset(&ofn, 0, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hInstance = GetModuleHandle(NULL);
	ofn.hwndOwner = GetActiveWindow();
	ofn.lpstrFile = (LPSTR)inisavebuffer;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrTitle = "Save Armageddon options file";
	ofn.lpstrInitialDir = (LPCSTR)nbuf;
	ofn.nFilterIndex = 1;
	ofn.lpstrDefExt = "ini";
	ofn.lpstrFilter = "option files (*.ini)\0""*.ini\0\0";
	ofn.Flags = OFN_FORCESHOWHIDDEN | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;
	return GetSaveFileName(&ofn);
}

// Save Nanomite File dialog function
int PutNanoName(LPCSTR nanobuffer)
{
	OPENFILENAME ofn;

	memset(&ofn, 0, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hInstance = GetModuleHandle(NULL);
	ofn.hwndOwner = GetActiveWindow();
	ofn.lpstrFile = (LPSTR)nanobuffer;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrTitle = "Save Nanomite file";
	ofn.lpstrInitialDir = (LPCSTR)nbuf;
	ofn.nFilterIndex = 1;
	ofn.lpstrDefExt = "anf";
	ofn.lpstrFilter = "anf Files (*.anf)\0""*.anf\0\0";
	ofn.Flags = OFN_FORCESHOWHIDDEN | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;
	return GetSaveFileName(&ofn);
}

// Open Saved Nanomite Anf File dialog function
int GetNanoAnfName(LPCSTR nanobuffer)
{
	OPENFILENAME ofn;

	memset(&ofn, 0, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hInstance = GetModuleHandle(NULL);
	ofn.hwndOwner = GetActiveWindow();
	ofn.lpstrFile = (LPSTR)nanobuffer;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrTitle = "Open Nanomite anf file";
	ofn.lpstrInitialDir = (LPCSTR)nbuf;
	ofn.nFilterIndex = 1;
	ofn.lpstrDefExt = "anf";
	ofn.lpstrFilter = "log Files (*.anf)\0""*.anf\0\0";
	ofn.Flags = OFN_FORCESHOWHIDDEN | OFN_HIDEREADONLY;
	return GetOpenFileName(&ofn);
}

// Begin: Nanomite Fixer Section
// 	Initialize the nanomites fixer dll.reset all variable.call this function every time
//  you want to start new Analyze.
BOOL ArmNF_Init(void)
{
	// Get a handle to the dll's we want
	hdisasmdll = GetModuleHandle((LPCSTR)"disasm.dll");
	if (!hdisasmdll)
	{
		LogItem("Module: disasm.dll; Function: GetModuleHandle Failed");
		return FALSE;
	}
	// Find the proc address to the function we want
	AsmAddr = (FARPROC)GetProcAddress(hdisasmdll, (LPCSTR)"_Assemble@24");
	if (!AsmAddr)
	{
		LogItem("Function Assemble, GetProcAddress Failed");
		return FALSE;
	}
	AssembleAddress = (DWORD)AsmAddr;
	// Find the proc address to the function we want
	DsmAddr = (FARPROC)GetProcAddress(hdisasmdll, (LPCSTR)"_Disasm@20");
	if (!DsmAddr)
	{
		LogItem("Function Disasm, GetProcAddress Failed");
		return FALSE;
	}
	DisasmAddress = (DWORD)DsmAddr;
	char xbuf[80] = { 0 };
	Init(xbuf, AssembleAddress, DisasmAddress);
	if (strlen(xbuf) > 0)
		return FALSE;
	else
		return TRUE;
}

//Start The Main search for finding INT3. This function doesn't create any thread.
unsigned __stdcall ArmNF_Analyze(void *)
{
	DWORD thispid = 0;
	typed td = { 0 };
	int retncd = 0;
	// Resolve nanomites in saved dumped exe file
	if (GetDumpName((LPCSTR)filebuffer))
	{
		// continue
	}
	else
	{
		memset(filebuffer, 0, sizeof(MAX_PATH));
		goto ANALRETN;
	}
	LogItem("%s", isep);
	td.T2 = ThroughFile;
	td.T1 = UNKNOWN_COMPILR;
	int typei = 0;
	memcpy(&typei, &td, 4);
	retncd = Analyze(filebuffer, buffer, thispid, typei);
ANALRETN:
	isrunning = FALSE;
	return retncd;
}

// Save Arma nanofixer nanofile (*.anf) of this target process
int ArmNF_WriteTableToFile(void)
{
	// Do we have any nanomites in table to save?
	if (NFlog.TRN == 0)
	{
		LogItem("No Real nanomites found, action canceled");
		return 1;
	}
	// Create a nano file
	if (PutNanoName((LPCSTR)nanobuffer))
	{
		// continue
	}
	else
	{
		LogItem("Save nanomites table canceled");
		memset(nanobuffer, 0, sizeof(MAX_PATH));
		return 0;
	}
	LogItem("Saving Nanomites table...");
	int iArmNF = 0;
	iArmNF = WriteTableToFile(nanobuffer);
	if (iArmNF == 0)
	{
		LogItem("%ul nanomites saved...", NFlog.TRN);
		LogItem("Done.");
	}
	return iArmNF;
}

// Main Arma nanofixer routine calls all functions based on options selected
void ArmNF_DumpNanos(void)
{
	if (!ArmNF_Init())
	{
		return;
	}
	if (analyzenf)
	{
		// Initialize nanomite log structure
		NFDretn = 0;
		memset(&NFlog, 0, sizeof(Log));
		NFDretn = MakeLog(&NFlog);
		if (NFDretn != 0)
		{
			LogItem("Nanofixer Makelog function failed");
			return;
		}
		LogItem("------ NanoFixer Analyzing Nanomites ------");
		LogItem("Initializing...");
		// Create a new thread for this function
		hAnalThread = 0;
		isrunning = TRUE;
		totalanalyzed = TRUE;
		analyzeprob = FALSE;
		hAnalThread = (HANDLE)_beginthreadex(NULL, 0, &ArmNF_Analyze, NULL, 0, &dwThreadid);
		if (!hAnalThread)
		{
			isrunning = FALSE;
			LogItem("CreateThread failed for analyze nanomites");
			LogItem("please refresh and try again!");
			return;
		}
		while (isrunning)
		{
			Sleep(200);
			NFDretn = 0;
			memset(&NFlog, 0, sizeof(Log));
			NFDretn = MakeLog(&NFlog);
			if (NFDretn == 0)
			{
				logitemreplace = TRUE;
				if (totalanalyzed && NFlog.TotalCC > 0)
				{
					LogItem("%lu INT3 Found", NFlog.TotalCC);
					totalanalyzed = FALSE;
				}
				else
				{
					LogItem("%lu INT3 Analyzed, %lu False, %lu Real", NFlog.TACC, NFlog.TFCC, NFlog.TRN);
				}
			}
			else
			{
				isrunning = FALSE;
			}
		}
		if (hAnalThread)
		{
			CloseHandle(hAnalThread);
			hAnalThread = 0;
		}
		// if we are encountering any problems?
		if (analyzeprob)
		{
			LogItem("Less than 5%% and/or no activity for 30 seconds");
			LogItem("Check for multiple instances, anti virus running");
			LogItem("Analyze nanomites aborted, please try again later...");
			return;
		}
		if (NFIretn > 0)
		{
			// problem encountered analyzing nanomites!!
			switch (NFIretn)
			{
			case 1:
				sprintf(ibuf, "No Real nanomites found, Unknown Error");
				break;
			case 2:
				sprintf(ibuf, "No 0xCC Opcode Found, No INT3 Breakpoint Found");
				break;
			case 3:
				sprintf(ibuf, "Cannot open The File, File Header Is Corrupted");
				break;
			case 4:
				sprintf(ibuf, "Cannot Open Process");
				break;
			case 5:
				sprintf(ibuf, "VirtualAlloc Failed");
				break;
			case 6:
				sprintf(ibuf, "The Loaded .anf File Is Mismatched");
				break;
			case 7:
				sprintf(ibuf, "Return from Analyze() if there is no response");
				break;
			case 8:
				sprintf(ibuf, "Unsupported version of Nanomites");
				break;
			default:
				sprintf(ibuf, "Unknown error");
				break;
			}
			LogItem((LPSTR)ibuf);
			return;
		}
		else if (NFlog.TRN == 0)
		{
			// no nanomites found!!
			LogItem("No Nanomites found.");
			return;
		}
		else
		{
			// everything went OK!!
			LogItem("%lu INT3 Analyzed, %lu False, %lu Real", NFlog.TACC, NFlog.TFCC, NFlog.TRN);
			LogItem("Analyzing successfully completed");
			NFIretn = 0;
			NFIretn = ArmNF_WriteTableToFile();
			if (NFIretn != 0)
			{
				LogItem("Save nanomites table failed");
			}
		}
	}
	return;
}
// End: NF Function section

/* Process Nanomite analysis updates from Nanolib.dll back to this program */
void CALLBACK UpdateCB(UpdateReport *TStruct)
{
	if (!ReportedTotal)
	{
		ReportedTotal = TRUE;
		Tally = TStruct->NumNanos;
		LogItem("%lu potential INT3 found.", (DWORD)Tally);
		logitemreplace = TRUE;
		LogItem("0 INT3 processed...");
	}
	if (TStruct->CurrentNano > 0)
	{
		logitemreplace = TRUE;
		LogItem("%lu INT3 processed...", (DWORD)TStruct->CurrentNano);
	}
	memcpy(&RStruct, (const void *)TStruct, sizeof(RStruct));
	return;
}

/* Process Nanomite analysis updates from Nanolib.dll back to this program */
void CALLBACK UpdateCBlog(UpdateLog *SStruct)
{
	if (SStruct->LogNanos > 0)
	{
		logitemreplace = TRUE;
		LogItem("%lu INT3 logged...", (DWORD)SStruct->LogNanos);
	}
	memcpy(&LStruct, (const void *)SStruct, sizeof(LStruct));
	return;
}

// Save nanofile of target process
BOOL SaveNano(void)
{
	HANDLE	hFile3 = 0;

	// Create a nano file
	if (PutNanoName((LPCSTR)nanobuffer))
	{
		// continue
	}
	else
	{
		memset(nanobuffer, 0, sizeof(MAX_PATH));
		return FALSE;
	}
	// Find the last '\\' to obtain a pointer to just the base module name part
	pszPathName = strrchr((char *)nanobuffer, '\\');
	if (pszPathName)  // We found a path, so advance to the base module name
	{
		pszPathName++;
		strcpy(c, (const char *)pszPathName);
	}
	LogItem("Saving Nanomites table...");
	hFile3 = CreateFile((LPCSTR)nanobuffer,     // file to create
		GENERIC_WRITE,          // open for read/write
		FILE_SHARE_READ | FILE_SHARE_WRITE,       // share for read/write
		NULL,                  // default security
		OPEN_ALWAYS,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file
		NULL);                 // no attr. template
	if (hFile3 == INVALID_HANDLE_VALUE)
	{
		LogItem("CreateFile error %s %d", c, GetLastError());
		return FALSE;
	}
	WriteFile(hFile3, (LPCVOID)RNano, sizeof(RNANO)*NumNanos, &dwWritten, NULL);
	SetEndOfFile(hFile3);
	CloseHandle(hFile3);
	hFile3 = 0;
	LogItem("%lu nanomites saved...", (DWORD)NumNanos);
	LogItem("Done.");
	return TRUE;
}

/* Recreate Nanotable with valid nanomites, discard unused ones */
void PruneNanomites(void)
{
	DWORD	I = 0;
	NewCount = 0;
	try
	{
		VClean = new Nanomite[NumNanos + 1];
	}
	catch (std::exception& e)
	{
		LogItem("Unable to Prune nanomite table! exception %s", e.what());
		return;
	}
	for (I = 0; I < NumNanos; I++)
	{
		if (VNano[I].JumpType > 1)
		{
			VClean[NewCount] = VNano[I];
			NewCount++;
		}
	}
	try
	{
		if (VNano)
		{
			delete[] VNano;
			VNano = 0;
		}
		if (RNano)
		{
			delete[] RNano;
			RNano = 0;
			NumNanos = 0;
		}
		RNano = new RNANO[NewCount + 1];
	}
	catch (std::exception& e)
	{
		LogItem("Unable to Prune nanomite table! exception: %s", e.what());
		return;
	}
	for (I = 0; I < NewCount; I++)
	{
		RNano[I].Address = VClean[I].Address;
		RNano[I].Dest = VClean[I].Destination;
		RNano[I].JumpType = VClean[I].JumpType;
	}
	if (NumNanos != NewCount)
	{
		LogItem("%lu useless Nanomites discarded.", (DWORD)(NumNanos - NewCount));
		NumNanos = NewCount;
	}
	if (VClean)
	{
		delete[] VClean;
		VClean = 0;
	}
	return;
}

/* Begin locate / analysis of Nanomites reference Nanolib.dll for processing */
void LocateNanomites(void)
{
	if (!debugblocker)
	{
		LogItem("Option only valid with Debug-Blocker.");
		return;
	}

	LogItem("------ Analyze Nanomites ------");
	ReportedTotal = FALSE;
	LogItem("Initializing...");
	memset(&RStruct, 0, sizeof(RStruct));
	DoNanomites((SIZE_T)UpdateCB, &RStruct, (LPSTR)buffer, (LPSTR)nbuf, pNumNanos, &TNano[0]);
	if (TNano)
	{
		delete[] TNano;
		TNano = 0;
	}
	if (RStruct.CurrentNano == 0)
	{
		LogItem("No Nanomites found.");
	}
	if ((RStruct.CurrentNano - RStruct.NumDuf) > 0)
	{
		NumNanos = RStruct.CurrentNano;
		try
		{
			if (VNano)
			{
				delete[] VNano;
				VNano = 0;
			}
			VNano = new Nanomite[NumNanos];
		}
		catch (std::exception& e)
		{
			LogItem("Unable to Prune nanomite table! Standard exception: %s", e.what());
			return;
		}
		Populate(&VNano[0]);
		PruneNanomites();
		LogItem("%lu INT3 found, %lu successfully analyzed.", (DWORD)RStruct.CurrentNano, (DWORD)NumNanos);
		EnableWindow(hwnd07, TRUE);
		EnableWindow(hwnd15, TRUE);
		SaveNano();
	}
	else
	{
		LogItem("Process didn't attempt to repair Nanomites.");
	}
	return;
}

/* Begin log of Nanomites reference Nanolib.dll for processing */
BOOL LogNanomites(void)
{
	if (!debugblocker)
	{
		LogItem("Option only valid with Debug-Blocker.");
		return FALSE;
	}
	LogItem("------ Log Nanomites ------");
	ReportedTotal = FALSE;
	LogItem("Initializing...");
	memset(&LStruct, 0, sizeof(LStruct));
	DoLogNanomites((SIZE_T)UpdateCBlog, &LStruct, (LPSTR)buffer, (LPSTR)nbuf);
	if (LStruct.LogNanos == 0)
	{
		LogNanos = 0;
		LogItem("No Nanomites found.");
		return FALSE;
	}
	else
	{
		LogNanos = LStruct.LogNanos;
		LogItem("%lu INT3 logged.", (DWORD)LogNanos);
		try
		{
			if (LNano)
			{
				delete[] LNano;
				LNano = 0;
			}
			LNano = new LogNano[LogNanos + 1];
		}
		catch (std::exception& e)
		{
			LogItem("Unable to allocate nanomites table!");
			return FALSE;
		}
		PopulateLog(&LNano[0]);
		if (!SNano.empty())
			SNano.clear();
		for (j = 0; j < LogNanos; j++)
		{
			SNano.insert(LNano[j].Address);
		}
		try
		{
			if (TNano)
			{
				delete[] TNano;
				TNano = 0;
			}
			TNano = new Nanomite[SNano.size() + 1];
		}
		catch (std::exception& e)
		{
			LogItem("Unable to allocate nanomites table!");
			return FALSE;
		}
		pNumNanos = 0;
		for (it = SNano.begin(); it != SNano.end(); it++)
		{
			TNano[pNumNanos].Address = (DWORD)*it;
			TNano[pNumNanos].Destination = 0;
			TNano[pNumNanos].Size = 0;
			TNano[pNumNanos].JumpType = 0;
			pNumNanos++;
		}
		if (!SNano.empty())
			SNano.clear();
		EnableWindow(hwnd15, TRUE);
		EnableWindow(hwnd07, TRUE);
	}
	return TRUE;
}

// Convert 32 bit number (DWORD_PTR) from big endian to little endian format
DWORD_PTR ByteSwap2(DWORD_PTR nLongNumber)
{
	return (((nLongNumber & 0x000000FF) << 24) + ((nLongNumber & 0x0000FF00) << 8) +
		((nLongNumber & 0x00FF0000) >> 8) + ((nLongNumber & 0xFF000000) >> 24));
}

// Begin: Strategic Code Splicing Section
// This function is called when copymemII is used in a delphi program
BOOL CSVerify(HANDLE thisProcess)
{
	DWORD_PTR	TPtr = 0;
	DWORD	OldProtect = 0;
	DWORD	NewProtect = 0;
	CSOAddress = 0;
	CSOSize = 0;
	TStart = TextVMaddress;
	TLength = TextVMsize;
	FuckedUp = FALSE;
	NumSegments = 0;
	try
	{
		Target = new BYTE[TLength];
	}
	catch (std::exception& e)
	{
		LogItem("Unable to create target code memory.");
		LogItem("Standard exception: %s", e.what());
		return FALSE;
	}
	NewProtect = PAGE_EXECUTE_READWRITE;
	if (!VirtualProtectEx(thisProcess, (LPVOID)TStart, TLength, NewProtect, &OldProtect))
	{
		LogItem("VirtualProtectEx Error CSVerify address: %p", TStart);
		LogItem(NULL);
		goto FINVERIFY;
	}
	if (!ReadProcessMemory(thisProcess, (LPVOID)TStart, &Target[0], TLength, &dwRead))
	{
		LogItem("ReadProcessMemory Error CSVerify address: %p", TStart);
		LogItem(NULL);
		goto FINVERIFY;
	}
	if (!VirtualProtectEx(thisProcess, (LPVOID)TStart, TLength, OldProtect, &NewProtect))
	{
		LogItem("VirtualProtect error target code.");
		goto FINVERIFY;
	}
	while (TPtr < TLength)
	{
		if (Target[TPtr] == 0xE9)
		{ // JMP to splice
			// Reverse next 4 bytes
			memset(&MyDisasm, 0, sizeof(DISASM));
			len = 0;
			/* ============================= Init EIP */
			MyDisasm.EIP = (UIntPtr)&Target[TPtr];
			MyDisasm.VirtualAddr = (UInt64)TStart + TPtr;
			/* ============================= Loop for Disasm */
			len = (ProcAdd)(&MyDisasm);
			if (len != UNKNOWN_OPCODE)
			{
				if (MyDisasm.Instruction.AddrValue < (DWORD_PTR)TStart || MyDisasm.Instruction.AddrValue >(DWORD_PTR)BaseOfImage + dwSize)
				{
					BOOL firsttime = TRUE;
					dwCalcAddress = (DWORD_PTR)MyDisasm.Instruction.AddrValue;
					for (j = 0; j < 3; j++)
					{
						if (CSOSize >= 65536)
							break;
						dwRead = VirtualQueryEx(
							thisProcess,
							(LPCVOID)dwCalcAddress,
							&mbi,
							sizeof(mbi)
							);
						if (dwRead)
						{
							// For this protection, increment Armadillo VM size
							if (mbi.Protect == PAGE_EXECUTE_READ)
							{
								if (firsttime)
								{
									CSOAddress = mbi.AllocationBase;
									dwCalcAddress = (DWORD_PTR)mbi.AllocationBase;
									firsttime = FALSE;
								}
								dwCalcAddress += (DWORD_PTR)mbi.RegionSize;
								CSOSize += (SIZE_T)mbi.RegionSize;
								NumSegments++;
							}
							else
							{
								j = 10;
								break;
							}
						}
						else
						{
							j = 10;
							break;
						}
					}
					break;
				}
			}
		}
		TPtr++;
	}
FINVERIFY:
	if (Target)
	{
		delete[] Target;
		Target = 0;
	}
	if (NumSegments == 0)
	{
		LogItem("%s", isep);
		LogItem("No splices found.");
		return FALSE;
	}
	return TRUE;
}

// Begin: Strategic Code Splicing Section
BOOL CSAcquire(HANDLE thisProcess)
{
	DWORD	OldProtect = 0;
	DWORD	NewProtect = 0;
	SStart = CSOAddress;
	TStart = TextVMaddress;
	if (CSOSize >= 65536)
	{
		SLength = ((CSOSize + 20480) / 65536) * 65536;
	}
	else
	{
		SLength = CSOSize;
	}
	TLength = TextVMsize;
	try
	{
		Spliced = new BYTE[SLength];
	}
	catch (std::exception& e)
	{
		LogItem("Unable to create spliced code memory.");
		LogItem("Standard exception: %s", e.what());
		return FALSE;
	}
	try
	{
		Target = new BYTE[TLength];
	}
	catch (std::exception& e)
	{
		LogItem("Unable to create target code memory.");
		LogItem("Standard exception: %s", e.what());
		return FALSE;
	}
	if (!ReadProcessMemory(thisProcess, (LPCVOID)SStart, &Spliced[0], SLength, &dwRead))
	{
		LogItem("ReadProcessMemory Error CSAcquire address: %p", SStart);
		LogItem(NULL);
		return FALSE;
	}
	else
	{
		SLength = dwRead;
	}
	NewProtect = PAGE_EXECUTE_READWRITE;
	if (!VirtualProtectEx(thisProcess, (LPVOID)TStart, TLength, NewProtect, &OldProtect))
	{
		LogItem("VirtualProtectEx Error CSAcquire address: %p", TStart);
		LogItem(NULL);
		return FALSE;
	}
	if (!ReadProcessMemory(thisProcess, (LPVOID)TStart, &Target[0], TLength, &dwRead))
	{
		LogItem("ReadProcessMemory Error CSAcquire address: %p", TStart);
		LogItem(NULL);
		return FALSE;
	}
	if (!VirtualProtectEx(thisProcess, (LPVOID)TStart, TLength, OldProtect, &NewProtect))
	{
		LogItem("VirtualProtectEx Error CSAcquire address: %p", TStart);
		LogItem(NULL);
		return FALSE;
	}
	LogItem("Process memory buffered successfully.");
	return TRUE;
}

BOOL AreInverse(char *O1, char *O2)
{
	int		Comma = 0;
	char	*pComma = 0;
	char	R1[TEXTLEN] = { 0 };
	char	R2[TEXTLEN] = { 0 };
	char	R3[TEXTLEN] = { 0 };
	char	R4[TEXTLEN] = { 0 };

	if (strncmp((const char *)O1, "not", 3) == 0)
	{
		if (strcmp(O1, O2) == 0)
			return TRUE;
	}
	else if (strncmp((const char *)O1, "pushfd", 6) == 0)
	{
		if (strncmp((const char *)O2, "popfd", 5) == 0)
			return TRUE;
	}
	else if (strncmp((const char *)O1, "pushad", 6) == 0)
	{
		if (strncmp((const char *)O2, "popad", 5) == 0)
			return TRUE;
	}
	else if (strncmp((const char *)O1, "push", 4) == 0)
	{
		if (strncmp((const char *)O2, "pop", 3) == 0 &&
			strncmp((const char *)O1 + 5, (const char *)O2 + 4, strlen(O1) - 4) == 0)
			return TRUE;
	}
	else if (strncmp((const char *)O1, "xchg", 4) == 0)
	{
		if (strcmp(O1, O2) == 0)
			return TRUE;
		if (strncmp((const char *)O2, "xchg", 4) == 0)
		{
			pComma = strchr(O1, ',');
			Comma = (int)(pComma - O1);
			memset(R1, 0, sizeof(R1));
			memset(R2, 0, sizeof(R2));
			memset(R3, 0, sizeof(R3));
			memset(R4, 0, sizeof(R4));
			if (Comma > 5)
			{
				strncpy(R1, O1 + 5, (Comma - 5));
				strncpy(R2, O1 + Comma + 2, (Comma - 5));
				strncpy(R3, O2 + 5, (Comma - 5));
				strncpy(R4, O2 + Comma + 2, (Comma - 5));
				if (strncmp((const char *)R1, (const char *)R4, strlen(R1)) == 0 &&
					strncmp((const char *)R2, (const char *)R3, strlen(R2)) == 0)
					return TRUE;
			}
		}
	}
	else if (strncmp((const char *)O1, "bswap", 5) == 0)
	{
		if (strcmp(O1, O2) == 0)
			return TRUE;
	}
	return FALSE;
}

BOOL Dependent(char *Opcode, char *Register)
{
	char	*pdest = 0;
	char	CReg[TEXTLEN] = { 0 };
	memset(CReg, 0, sizeof(CReg));
	if (strlen(Register) == 3)
	{
		strncpy(CReg, Register + 1, 2);
		pdest = strstr(Opcode, CReg);
		if (pdest)
			return TRUE;
	}
	else if (strlen(Register) == 2)
	{
		strncpy(CReg, Register, 2);
		pdest = strstr(Opcode, CReg);
		if (pdest)
			return TRUE;
	}
	else
	{
		strncpy(CReg, Register, strlen(Register));
		pdest = strstr(Opcode, CReg);
		if (pdest)
			return TRUE;
	}
	return FALSE;
}

void DoRC1(Instruction *Ins, int StartI, int EndI)
{
	char	R1[TEXTLEN] = { 0 };
	char	R2[TEXTLEN] = { 0 };
	char	*pComma = 0;
	int		Comma = 0;
	int		StackCount = 0;
	int		I, J, K = 0;
	BOOL	Independent = FALSE;
	try
	{
		// Remove paired redundant "PUSH" / "POP" opposing commands recursively
		for (I = StartI; I <= EndI; I++)
		{
			if (Ins[I].Active)
			{
				// Must be PUSH / POP
				for (J = I + 1; J <= EndI; J++)
				{
					if (Ins[J].Active)
					{
						if (AreInverse(Ins[I].Opcode, Ins[J].Opcode))
						{
							Independent = TRUE;
							if (J > I + 1)
							{
								DoRC1(Ins, I + 1, J);
								if (strncmp((const char *)Ins[I].Opcode, "push", 4) == 0)
								{
									StackCount = 0;
									pComma = strchr(Ins[I].Opcode, ' ');
									Comma = (int)(pComma - Ins[I].Opcode);
									memset(R1, 0, sizeof(R1));
									memset(R2, 0, sizeof(R2));
									strncpy(R1, Ins[I].Opcode + Comma + 1, strlen(Ins[I].Opcode) - Comma);
									for (K = I + 1; K < J; K++)
									{
										if (Ins[K].Active)
										{
											if (strncmp((const char *)Ins[K].Opcode, "push", 4) == 0)
											{
												StackCount++;
											}
											else if (strncmp((const char *)Ins[K].Opcode, "pop", 3) == 0)
											{
												StackCount--;
											}
										}
										if (Ins[K].Active)
										{
											if (Dependent(Ins[K].Opcode, R1))
											{
												Independent = FALSE;
												break;
											}
										}
									} // K
									if (StackCount != 0)
										Independent = FALSE;
								}
							}
							if (Independent)
							{
								if (Ins[J].Active && Ins[I].Active)
								{
									Ins[I].Active = FALSE;
									Ins[J].Active = FALSE;
									break;
								}
							}
						}
					}
				} // J
			}
		} // I
	}
	catch (std::exception& e)
	{
		LogItem("Function: DoRC1");
		LogItem("Standard exception: %s", e.what());
		return;
	}
	return;
}

void DoRC(Instruction *Ins, int StartI, int EndI)
{
	char	R1[TEXTLEN] = { 0 };
	char	R2[TEXTLEN] = { 0 };
	char	*pComma = 0;
	int		Comma = 0;
	int		I, J, K = 0;

	try
	{
		// Remove all instructions within "PUSHAD" / "PUSHFD and "POPAD" / "POPFD"
		for (I = StartI; I <= EndI; I++)
		{
			if (strncmp((const char *)Ins[I].Opcode, "pushad", 6) == 0)
			{
				// Find last POP instruction
				for (J = EndI; J >= StartI; J--)
				{
					if (strncmp((const char *)Ins[J].Opcode, "popad", 5) == 0)
					{
						// Invalidate all instructions within
						for (K = I; K <= J; K++)
						{
							(Ins[K].Active) = FALSE;
						}
					}
				}
			}
			if (strncmp((const char *)Ins[I].Opcode, "pushfd", 6) == 0)
			{
				// Find last POP instruction
				for (J = EndI; J >= StartI; J--)
				{
					if (strncmp((const char *)Ins[J].Opcode, "popfd", 5) == 0)
					{
						// Invalidate all instructions within
						for (K = I; K <= J; K++)
						{
							(Ins[K].Active) = FALSE;
						}
					}
				}
			}
		}
	}
	catch (std::exception& e)
	{
		LogItem("Function: DoRC");
		LogItem("Standard exception: %s", e.what());
		return;
	}
	try
	{
		// Remove all redundant single commands
		for (I = EndI; I >= StartI; I--)
		{
			if (strncmp((const char *)Ins[I].Opcode, "j", 1) == 0)
			{
				Ins[I].Active = FALSE;
			}
			else if (strncmp((const char *)Ins[I].Opcode, "xchg", 4) == 0)
			{
				pComma = strchr(Ins[I].Opcode, ',');
				Comma = (int)(pComma - Ins[I].Opcode);
				memset(R1, 0, sizeof(R1));
				memset(R2, 0, sizeof(R2));
				strncpy(R1, Ins[I].Opcode + 5, (Comma - 5));
				strncpy(R2, Ins[I].Opcode + Comma + 2, (Comma - 5));
				if (strcmp(R1, R2) == 0)
				{
					Ins[I].Active = FALSE;
				}
			}
			else if (strncmp((const char *)Ins[I].Opcode, "mov", 3) == 0)
			{
				pComma = strchr(Ins[I].Opcode, ',');
				Comma = (int)(pComma - Ins[I].Opcode);
				memset(R1, 0, sizeof(R1));
				memset(R2, 0, sizeof(R2));
				strncpy(R1, Ins[I].Opcode + 4, (Comma - 4));
				strncpy(R2, Ins[I].Opcode + Comma + 2, (Comma - 4));
				if (strcmp(R1, R2) == 0)
				{
					Ins[I].Active = FALSE;
				}
			}
			else if (strncmp((const char *)Ins[I].Opcode, "nop", 3) == 0)
			{
				Ins[I].Active = FALSE;
			}
		} // I
	}
	catch (std::exception& e)
	{
		LogItem("Function: DoRC");
		LogItem("Standard exception: %s", e.what());
		return;
	}
	try
	{
		// Remove paired redundant consecutive commands recursively
		for (I = StartI; I <= EndI; I++)
		{
			if (Ins[I].Active)
			{
				// Must be NOT, XCHG, or BSWAP
				for (J = I + 1; J <= EndI; J++)
				{
					if (Ins[J].Active)
					{
						if (strncmp((const char *)Ins[I].Opcode, "not", 3) == 0 ||
							strncmp((const char *)Ins[I].Opcode, "bswap", 5) == 0)
						{
							if (AreInverse(Ins[I].Opcode, Ins[J].Opcode))
							{
								Ins[I].Active = FALSE;
								Ins[J].Active = FALSE;
								break;
							}
						}
						else if (strncmp((const char *)Ins[I].Opcode, "xchg", 4) == 0)
						{
							if (AreInverse(Ins[I].Opcode, Ins[J].Opcode))
							{
								Ins[I].Active = FALSE;
								Ins[J].Active = FALSE;
								break;
							}
							if (strncmp((const char *)Ins[J].Opcode, "xchg", 4) == 0)
							{
								pComma = strchr(Ins[I].Opcode, ',');
								Comma = (int)(pComma - Ins[I].Opcode);
								memset(R1, 0, sizeof(R1));
								memset(R2, 0, sizeof(R2));
								if (Comma > 5)
								{
									strncpy(R1, Ins[I].Opcode + 5, (Comma - 5));
									strncpy(R2, Ins[I].Opcode + Comma + 2, (Comma - 5));
									if (strlen(Ins[J].Opcode) > 9)
									{
										if (Dependent(Ins[J].Opcode, R1))
										{
											if (Dependent(Ins[J].Opcode, R2))
											{
												Ins[I].Active = FALSE;
												Ins[J].Active = FALSE;
												break;
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	catch (std::exception& e)
	{
		LogItem("Function: DoRC");
		LogItem("Standard exception: %s", e.what());
		return;
	}
	try
	{
		// Remove paired redundant inverse commands recursively
		for (I = StartI; I <= EndI; I++)
		{
			if (Ins[I].Active)
			{
				// Must be NOT, XCHG, or BSWAP
				for (J = EndI; J > I; J--)
				{
					if (Ins[J].Active)
					{
						if (strncmp((const char *)Ins[I].Opcode, "not", 3) == 0 ||
							strncmp((const char *)Ins[I].Opcode, "bswap", 5) == 0 ||
							strncmp((const char *)Ins[I].Opcode, "xchg", 4) == 0)
						{
							if (AreInverse(Ins[I].Opcode, Ins[J].Opcode))
							{
								Ins[I].Active = FALSE;
								Ins[J].Active = FALSE;
								break;
							}
						}
					}
				}
			}
		}
	}
	catch (std::exception& e)
	{
		LogItem("Function: DoRC");
		LogItem("Standard exception: %s", e.what());
		return;
	}
	try
	{
		// Remove paired redundant inverse dependent "XCHG" commands recursively
		for (I = StartI; I <= EndI; I++)
		{
			if (Ins[I].Active)
			{
				// Must be XCHG
				for (J = EndI; J > I; J--)
				{
					if (Ins[J].Active)
					{
						if (strncmp((const char *)Ins[I].Opcode, "xchg", 4) == 0)
						{
							if (strncmp((const char *)Ins[J].Opcode, "xchg", 4) == 0)
							{
								if (strlen(Ins[I].Opcode) == strlen(Ins[J].Opcode))
								{
									pComma = strchr(Ins[I].Opcode, ',');
									Comma = (int)(pComma - Ins[I].Opcode);
									memset(R1, 0, sizeof(R1));
									memset(R2, 0, sizeof(R2));
									strncpy(R1, Ins[I].Opcode + 5, (Comma - 5));
									strncpy(R2, Ins[I].Opcode + Comma + 2, (Comma - 5));
									if (Dependent(Ins[J].Opcode, R1))
									{
										Ins[I].Active = FALSE;
										Ins[J].Active = FALSE;
										break;
									}
									if (Dependent(Ins[J].Opcode, R2))
									{
										Ins[I].Active = FALSE;
										Ins[J].Active = FALSE;
										break;
									}
								}
							}
						}
					}
				}
			}
		}
	}
	catch (std::exception& e)
	{
		LogItem("Function: DoRC");
		LogItem("Standard exception: %s", e.what());
		return;
	}
	DoRC1(Ins, StartI, EndI);
	return;
}
// Address = Target's VA
// Redirect = JMP destination in-memory
void FixSplice(DWORD_PTR Address, DWORD_PTR Redirect)
{
	int		NumBytes = 0;
	int		NumInstr = 0;
	int		LenAsm = 0;
	INT_PTR	RPtr = 0;
	DWORD	OldProtect = 0;
	DWORD	NewProtect = 0;
	DWORD	RPMRet = 0;
	DWORD	RetVal = 0;
	int		RouteLength = 0;
	int		XPtr = 0;
	char	Opcodes[TEXTLEN] = { 0 };
	int		I = 0;
	int		J = 0;
	int		K = 0;
	BOOL	findroutelength = TRUE;
	BOOL	NonContig = FALSE;

	RPtr = Redirect - (DWORD_PTR)SStart;
	NumInstr = 0;
	memset(Opcodes, 0, sizeof(Opcodes));
	try
	{
		while (findroutelength)
		{
			if (Spliced[RPtr] == 0xE9)
			{
				// make sure next 4 bytes not 0's
				if (Spliced[RPtr + 1] == 0x00 && Spliced[RPtr + 2] == 0x00 &&
					Spliced[RPtr + 3] == 0x00 && Spliced[RPtr + 4] == 0x00)
				{
					goto NEXTINSTR;
				}
				else
				{
					findroutelength = FALSE;
					break;
				}
			}
			else if (Spliced[RPtr] == 0xC3)
			{
				findroutelength = FALSE;
				break;
			}
		NEXTINSTR:
			dwCalcAddress = Redirect + RPtr;
			dwDataAddress = (DWORD_PTR)&Spliced[RPtr];
			memset(&MyDisasm, 0, sizeof(DISASM));
			len = 0;
			/* ============================= Init EIP */
			MyDisasm.EIP = (UIntPtr)dwDataAddress;
			len = (ProcAdd)(&MyDisasm);
			if (len != UNKNOWN_OPCODE)
			{
				MyDisasm.EIP = MyDisasm.EIP + (UIntPtr)len;
				RPtr += len;
			}
			else
			{
				RPtr++;
			}
			if (RPtr > CSOSize)
			{
				// Generally can mean that the jump instruction from .text was not a TRUE
				// jump but an imbedded 0xE9 instruction
				NumSegments--;
				FuckedUp = TRUE;
				return;
			}
		}
	}
	catch (std::exception& e)
	{
		LogItem("Function: FixSplice");
		LogItem("Standard exception: %s", e.what());
		return;
	}
	RouteLength = RPtr - Redirect + (DWORD_PTR)SStart;
	Instrs = new Instruction[RouteLength + 1];
	RPtr = Redirect - (DWORD_PTR)SStart;
	try
	{
		while (!(RPtr >= Redirect + RouteLength - (DWORD_PTR)SStart))
		{
			dwCalcAddress = Redirect + RPtr;
			dwDataAddress = (DWORD_PTR)&Spliced[RPtr];
			memset(&MyDisasm, 0, sizeof(DISASM));
			len = 0;
			/* ============================= Init EIP */
			MyDisasm.EIP = (UIntPtr)dwDataAddress;
			len = (ProcAdd)(&MyDisasm);
			if (len != UNKNOWN_OPCODE)
			{
				MyDisasm.EIP = MyDisasm.EIP + (UIntPtr)len;
				lofinst = len;
			}
			else
			{
				lofinst = 1;
			}
			NumBytes = strlen((const char *)MyDisasm.CompleteInstr);
			memset(Opcodes, 0, sizeof(Opcodes));
			memset(&Instrs[NumInstr].Opcode, 0, sizeof(Instrs[NumInstr].Opcode));
			memset(&Instrs[NumInstr].Length, 0, sizeof(Instrs[NumInstr].Length));
			memset(&Instrs[NumInstr].Bytes, 0, sizeof(Instrs[NumInstr].Bytes));
			memset(&Instrs[NumInstr].Active, 0, sizeof(Instrs[NumInstr].Active));
			strncpy(Opcodes, (const char *)MyDisasm.CompleteInstr, NumBytes);
			strncpy(Instrs[NumInstr].Opcode, Opcodes, NumBytes);
			Instrs[NumInstr].Length = lofinst;
			for (I = 0; I < lofinst; I++)
			{
				Instrs[NumInstr].Bytes[I] = Spliced[RPtr + I];
			} // I

			RPtr += lofinst;
			NumInstr++;
			if (NumInstr > RouteLength)
			{
				Instrs = new Instruction[NumInstr + 10];
			}
		}
	}
	catch (std::exception& e)
	{
		LogItem("Function: FixSplice");
		LogItem("Standard exception: %s", e.what());
		return;
	}
	if (NumInstr > 0)
	{
		// continue
	}
	else
	{
		NumSegments--;
		FuckedUp = TRUE;
		return;
	}
	for (I = 0; I <= NumInstr; I++)
	{
		Instrs[I].Active = TRUE;
	} // I
	DoRC(Instrs, 0, NumInstr);
COMPILE:
	// Compile new code
	LenAsm = 0;
	memset(Asm, 0, sizeof(Asm));
	for (I = 0; I < NumInstr; I++)
	{
		if (Instrs[I].Active)
		{
			for (J = 0; J <= Instrs[I].Length; J++)
			{
				Asm[LenAsm + J] = Instrs[I].Bytes[J];
			} // J
			LenAsm += Instrs[I].Length;
		}
	} // I
	// double check length of instructions > 0 but < 5
	// if TRUE, fill remaining instruction bytes with NOP's
	if (LenAsm > 0)
	{
		// continue
	}
	else
	{
		NumSegments--;
		FuckedUp = TRUE;
		return;
	}
	if (LenAsm < 5)
	{
		for (I = LenAsm; I < 5; I++)
		{
			Asm[I] = (BYTE)0x90;
		}
		LenAsm = I;
		goto INSERT;
	}
	// Warning message issued for last instruction:
	I = NumInstr - 1;
	if ((strncmp((const char *)Instrs[I].Opcode, "mov edi,edi", 11) == 0 ||
		strncmp((const char *)Instrs[I].Opcode, "mov eax,eax", 11) == 0) &&
		!Instrs[I].Active)
	{
		LogItem("Potential residue after %08X [Accepted]", Address);
		LogItem("mov reg,reg (be prepared to fix manually.)");
		Instrs[I].Active = TRUE;
		goto COMPILE;
		//return;
	}
INSERT:
	// Insert into buffer
	for (I = 0; I < LenAsm; I++)
	{
		Target[Address + I - (DWORD_PTR)TStart] = Asm[I];
	} // I
	return;
}

void DoRemoveSplicing(HANDLE thisProcess)
{
	DWORD_PTR	TPtr = 0;
	DWORD	OldProtect = 0;
	DWORD	NewProtect = 0;
	int		I = 0;
	LogItem("%s", isep);
	LogItem("------- Code Splicing -------");

	if (!CSAcquire(thisProcess))
	{
		LogItem("Failed to fix code...");
		return;
	}
	LogItem("Fixing spliced segments...");

	FuckedUp = FALSE;
	TPtr = 0;
	NumSegments = 0;
	LastUpdate = GetTickCount();

	try
	{
		while (TPtr < TLength)
		{
			if (Target[TPtr] == 0xE9)
			{ // JMP to splice
				// Reverse next 4 bytes
				memset(&MyDisasm, 0, sizeof(DISASM));
				len = 0;
				/* ============================= Init EIP */
				MyDisasm.EIP = (UIntPtr)&Target[TPtr];
				MyDisasm.VirtualAddr = (UInt64)TStart + TPtr;
				/* ============================= Loop for Disasm */
				len = (ProcAdd)(&MyDisasm);
				if (len != UNKNOWN_OPCODE)
				{
					if (MyDisasm.Instruction.AddrValue >= (DWORD_PTR)SStart && MyDisasm.Instruction.AddrValue < (DWORD_PTR)SStart + SLength)
					{
						FixSplice((ULONG)MyDisasm.VirtualAddr, (ULONG)MyDisasm.Instruction.AddrValue);
						NumSegments++;

					}
				}
			}
			TPtr++;
			if (GetTickCount() - LastUpdate > 300)
			{
				LastUpdate = GetTickCount();
				logitemreplace = TRUE;
				LogItem("%lu splices repaired...", NumSegments);
			}
		}
	}
	catch (std::exception& e)
	{
		LogItem("Function: DoRemoveSplicing");
		LogItem("Standard exception: %s", e.what());
		return;
	}
	if (NumSegments == 0)
	{
		LogItem("No splices found.");
		return;
	}
	LogItem("%lu splices repaired...", NumSegments);
	LogItem("Splice repairing complete.");
	LogItem("Patching process...");

	NewProtect = PAGE_EXECUTE_READWRITE;
	if (!VirtualProtectEx(thisProcess, (LPVOID)TStart, TLength, NewProtect, &OldProtect))
	{
		LogItem("VirtualProtectEx Error DoRemoveSplicing address: %p", TStart);
		LogItem(NULL);
		return;
	}
	if (!WriteProcessMemory(thisProcess, (LPVOID)TStart, &Target[0], TLength, &dwWritten))
	{
		LogItem("WriteProcessMemory Error DoRemoveSplicing address: %p", TStart);
		LogItem(NULL);
		return;
	}
	if (!VirtualProtectEx(thisProcess, (LPVOID)TStart, TLength, OldProtect, &NewProtect))
	{
		LogItem("VirtualProtectEx Error DoRemoveSplicing address: %p", TStart);
		LogItem(NULL);
		return;
	}
FIXDONE:
	if (FuckedUp)
	{
		LogItem("Patch completed with some potential errors.");
		LogItem("Code section may be invalid.");
		LogItem("Try again or check option redirect");
		LogItem("code splices and try again.");
	}
	else
	{
		LogItem("Patch successful.");
	}
	if (Spliced)
	{
		delete[] Spliced;
		Spliced = 0;
	}
	if (Target)
	{
		delete[] Target;
		Target = 0;
	}
	return;
}
/* Admiral's Strategic Code Splicing end	*/

/*-----------------------------------------------------------------------------
func:   SetFindPattern
desc:   initialize the pattern to be matched and generate skip table
pass:   lpszPattern = pattern string
rtrn:   HFIND - the find handle for further text search
-----------------------------------------------------------------------------*/
HFIND SetFindPattern(unsigned char *lpszPattern)
{
	hfind = GlobalAlloc(GHND, sizeof(FINDSTRUCT));
	if (hfind != NULL)
	{
		if (!(lpfind = (LPFIND)GlobalLock(hfind)))
			return NULL;
	}
	memset(&fs, 0, sizeof(fs));
	lpfind->plen = sstrlen;

	if (lpfind->plen > MAXPAT)
		lpfind->plen = MAXPAT;

	ZeroMemory(&lpfind->pp, sizeof(lpfind->pp));
	ZeroMemory(&lpfind->skip, sizeof(lpfind->skip));

	memcpy(lpfind->pp, (unsigned char *)lpszPattern, lpfind->plen);
	// Wildcard related default "?" is used hex "3F"
	if ((unsigned char *)wstring)
	{
		memcpy(lpfind->pw, (unsigned char *)wstring, strlen((const char *)wstring));
	}
	else
	{
		lpfind->pw[0] = '0';
	}
	for (j = 0; j < 256; j++)
	{
		lpfind->skip[j] = lpfind->plen;
	}

	for (j = 0; j < lpfind->plen; j++)
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
void FreeFindPattern(HFIND hfind)
{
	GlobalFree(hfind);
	hfind = 0;
}

/*-----------------------------------------------------------------------------
func:   Find
desc:   match a pattern defined in SetFindPattern against search space
in forward manner
pass:   hfind = the find handle created by SetFindPattern
rtrn:   NULL = match fail
else = pointer in search space where match 1st byte pattern found
-----------------------------------------------------------------------------*/
unsigned char * Find(HFIND hfind)
{
	unsigned char *lpresult = 0;

	if (!(lpfind = (LPFIND)GlobalLock(hfind)))
		return (NULL);
	// pointer to memory space
	pamiec = (unsigned char *)dwAddress;
	// start of search space
	p = pamiec + hexFind_from + lpfind->plen - 1;
	end = (unsigned char *)((unsigned char *)dwAddress + dwFileSize);
	__try
	{
		for (j = lpfind->plen - 1; j >= 0; j--, p--)
			while (*p != lpfind->pp[j] && lpfind->pp[j] != lpfind->pw[0])
			{
			if (bWildcard)
			{
				n = 1;
			}
			else
			{
				n = lpfind->skip[*p];
			}
			if (lpfind->plen - j > n)
				p += lpfind->plen - j;
			else
				p += n;
			if (p >= end)
			{
				GlobalUnlock(hfind);
				return NULL;
			}
			j = lpfind->plen - 1;
			}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
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
	switch (znak)
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
	for (i = 0; i < size; i++)
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
	ZeroMemory(&intext, sizeof(intext));
	ZeroMemory(&outtext, sizeof(outtext));
	//***** SEARCH *****//
	// type: '0' = API hexapiretn RETN address hex strings
	// type: '1' = Armadillo code hexarmcode hex strings
	// type: '2' = Armadillo dynamic code hex string
	// type: '3' = API hexapijmp JMP address hex strings
	if (type == 0)
	{
		std::string strapi = (hexapiretn[which]);
		memcpy(outtext, (unsigned char *)hexapiretn[which], strapi.size());
		strapi.clear();
	}
	else if (type == 1)
	{
		std::string strarm = (hexarmcode[which]);
		memcpy(outtext, (unsigned char *)hexarmcode[which], strarm.size());
		strarm.clear();
	}
	else if (type == 2)
	{
		std::string strhex = ((char *)hextext);
		memcpy(outtext, (unsigned char *)hextext, strhex.size());
		strhex.clear();
	}
	else if (type == 3)
	{
		std::string strapi = (hexapijmp[which]);
		memcpy(outtext, (unsigned char *)hexapijmp[which], strapi.size());
		strapi.clear();
	}
	else
	{
		MessageBoxInformation("DoSearch function: Unknown type");
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

// returns aligned PE section VM/RAW value
DWORD PEAlign(DWORD dwTarNum, DWORD dwAlignTo)
{
	return(((dwTarNum + dwAlignTo - 1) / dwAlignTo)*dwAlignTo);
}

// Save logfile of target process
void SaveLogfile(void)
{
	HANDLE	hFile2 = 0;
	DWORD	fp = 0;
	int		iStatus = 0;
	memcpy(logbuffer, buffer, (size_t)MAX_PATH);
	// Find the last '\\' to obtain a pointer to just the base module name part
	pszPathName = strrchr((char *)logbuffer, '\\');
	if (pszPathName)  // We found a path, so advance to the base module name
	{
		pszPathName++;
		strncpy((char *)pszPathName, "Armageddon_log.txt\0", 19);
	}
	else
	{
		if (numitems > 0)
		{
			LogItem("Cannot save. No target file selected!");
		}
		return;
	}
	hFile2 = CreateFile((LPCSTR)logbuffer,     // file to create
		GENERIC_WRITE,          // open for read/write
		FILE_SHARE_READ | FILE_SHARE_WRITE,       // share for read/write
		NULL,                  // default security
		OPEN_ALWAYS,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file
		NULL);                 // no attr. template
	if (hFile2 == INVALID_HANDLE_VALUE)
	{
		LogItem("CreateFile error %s %d", logbuffer, GetLastError());
		return;
	}
	// Get itemcount
	iStatus = ListView_GetItemCount(hwndIDLISTVIEW);
	LogItem("Saving logfile...");
	if (iStatus > 0)
	{
		lvi.pszText = sztempbuffer;
		lvi.cchTextMax = sizeof(sztempbuffer) - 2;
		for (i = 0; i < iStatus; i++)
		{
			int len = SendMessage(hwndIDLISTVIEW, LVM_GETITEMTEXT, i, (LPARAM)&lvi);
			strcpy(sztempbuffer + len, "\r\n");
			WriteFile(hFile2, (LPCVOID)sztempbuffer, len + 2, &dwWritten, NULL);
		}
	}
	SetEndOfFile(hFile2);
	CloseHandle(hFile2);
	hFile2 = 0;
	LogItem("Done.");
	return;
}

// Load Arma nanofixer nanofile (*.anf) from a previous target process
// for processing within Armageddon
BOOL LoadNanoAnf(void)
{
	// load a nano *.anf file
	if (GetNanoAnfName((LPCSTR)nanobuffer))
	{
		// continue
	}
	else
	{
		memset(nanobuffer, 0, sizeof(MAX_PATH));
		return FALSE;
	}
	// Find the last '\\' to obtain a pointer to just the base module name part
	pszPathName = strrchr((char *)nanobuffer, '\\');
	if (pszPathName)  // We found a path, so advance to the base module name
	{
		pszPathName++;
		strcpy(c, (const char *)pszPathName);
	}
	LogItem("Loading Nanomites table...");

	HANDLE		hFile4 = 0;
	hFile4 = CreateFile((LPCSTR)nanobuffer,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,                  // default security
		OPEN_ALWAYS,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file
		NULL);                 // no attr. template
	if (hFile4 == INVALID_HANDLE_VALUE)
	{
		LogItem("CreateFile error %s %d", c, GetLastError());
		return FALSE;
	}
	// Initialize log arrays
	if (RNano)
	{
		delete[] RNano;
		RNano = 0;
		NumNanos = 0;
	}
	dwAnfFileSize = GetFileSize(
		hFile4,
		NULL);
	NumNanos = (dwAnfFileSize / sizeof(RNANO));
	RNano = new RNANO[NumNanos + 1];
	if (!ReadFile(hFile4, (LPVOID)RNano, sizeof(RNANO)*NumNanos, &dwRead, NULL))
	{
		LogItem("ReadFile Error LoadNanoAnf");
		LogItem(NULL);
	}
	CloseHandle(hFile4);
	hFile4 = 0;
	if (dwRead == 0)
	{
		LogItem("Possible invalid nanomite file %s", c);
		if (RNano)
		{
			delete[] RNano;
			RNano = 0;
			NumNanos = 0;
		}
		return FALSE;
	}
	LogItem("%lu nanomites anf loaded...", (DWORD)NumNanos);
	LogItem("Done.");
	return TRUE;
}

// Load saved armageddon options file
BOOL LoadIniFile(void)
{
	// open a saved options file
	if (GetIniFileName((LPCSTR)inibuffer))
	{
		// continue
	}
	else
	{
		memset(inibuffer, 0, sizeof(MAX_PATH));
		return FALSE;
	}
	LogItem("Loading Armageddon options file...");
	DWORD dwret = 0;
	memset(szCmdbuffer, 0, sizeof(szCmdbuffer));
	// Get the options section - commandline argument
	dwret = GetPrivateProfileString("APPNAME",
		"armageddon",
		"",
		szCmdbuffer,
		MAX_PATH,
		inibuffer);
	if (dwret == 0)
	{
		LogItem("This doesn't appear to be an Armageddon *.ini file!");
		return FALSE;
	}
	memset(szCmdbuffer, 0, sizeof(szCmdbuffer));
	// Get the options section - commandline argument
	dwret = GetPrivateProfileString("OPTIONS",
		"cmdline",
		"",
		szCmdbuffer,
		MAX_PATH,
		inibuffer);
	szCmdline = (LPTSTR)szCmdbuffer;
	char option[2] = { 0 };
	// Get the options section - option
	GetPrivateProfileString("OPTIONS",
		"redirectcs",
		"0",
		option,
		sizeof(option),
		inibuffer);
	// the following 2 options are mutually exclusive
	// set switch status
	if (strncmp(option, "1", 1) == 0)
	{
		redirectsplicing = TRUE;
		Button_SetCheck(hwnd18, BST_CHECKED);
		Button_SetCheck(hwnd14, BST_UNCHECKED);
		checkminimizesize = FALSE;
	}
	else
	{
		redirectsplicing = FALSE;
		Button_SetCheck(hwnd18, BST_UNCHECKED);
	}
	//=====================================================//
	memset(option, 0, sizeof(option));
	GetPrivateProfileString("OPTIONS",
		"minimizesize",
		"0",
		option,
		sizeof(option),
		inibuffer);
	// set switch status
	if (strncmp(option, "1", 1) == 0)
	{
		checkminimizesize = TRUE;
		Button_SetCheck(hwnd18, BST_UNCHECKED);
		Button_SetCheck(hwnd14, BST_CHECKED);
		redirectsplicing = FALSE;
	}
	else
	{
		checkminimizesize = FALSE;
		Button_SetCheck(hwnd14, BST_UNCHECKED);
	}
	//=====================================================//
	memset(option, 0, sizeof(option));
	GetPrivateProfileString("OPTIONS",
		"securitydlldump",
		"0",
		option,
		sizeof(option),
		inibuffer);
	// set switch status
	if (strncmp(option, "1", 1) == 0)
	{
		checksecuritydump = TRUE;
		Button_SetCheck(hwnd35, BST_CHECKED);
	}
	else
	{
		checksecuritydump = FALSE;
		Button_SetCheck(hwnd35, BST_UNCHECKED);
	}
	//=====================================================//
	memset(option, 0, sizeof(option));
	GetPrivateProfileString("OPTIONS",
		"securitydllload",
		"0",
		option,
		sizeof(option),
		inibuffer);
	// set switch status
	if (strncmp(option, "1", 1) == 0)
	{
		checksecurityload = TRUE;
		Button_SetCheck(hwnd34, BST_CHECKED);
	}
	else
	{
		checksecurityload = FALSE;
		Button_SetCheck(hwnd34, BST_UNCHECKED);
	}
	//=====================================================//
	memset(option, 0, sizeof(option));
	GetPrivateProfileString("OPTIONS",
		"openmutex",
		"0",
		option,
		sizeof(option),
		inibuffer);
	// set switch status
	if (strncmp(option, "1", 1) == 0)
	{
		checkformutex = TRUE;
		Button_SetCheck(hwnd13, BST_CHECKED);
	}
	else
	{
		checkformutex = FALSE;
		Button_SetCheck(hwnd13, BST_UNCHECKED);
	}
	//=====================================================//
	memset(option, 0, sizeof(option));
	GetPrivateProfileString("OPTIONS",
		"dumppdata",
		"0",
		option,
		sizeof(option),
		inibuffer);
	// set switch status
	if (strncmp(option, "1", 1) == 0)
	{
		checkdumppdata = TRUE;
		Button_SetCheck(hwnd19, BST_CHECKED);
	}
	else
	{
		checkdumppdata = FALSE;
		Button_SetCheck(hwnd19, BST_UNCHECKED);
	}
	//=====================================================//
	memset(option, 0, sizeof(option));
	GetPrivateProfileString("OPTIONS",
		"ignore2ndtext",
		"0",
		option,
		sizeof(option),
		inibuffer);
	// the following 2 options are mutually exclusive
	// set switch status
	if (strncmp(option, "1", 1) == 0)
	{
		checkignore2ndtext = TRUE;
		Button_SetCheck(hwnd36, BST_CHECKED);
		checkbypass2ndtext = FALSE;
		Button_SetCheck(hwnd44, BST_UNCHECKED);
	}
	else
	{
		checkignore2ndtext = FALSE;
		Button_SetCheck(hwnd36, BST_UNCHECKED);
	}
	//=====================================================//
	memset(option, 0, sizeof(option));
	GetPrivateProfileString("OPTIONS",
		"bypass2ndtext",
		"0",
		option,
		sizeof(option),
		inibuffer);
	// the following 2 options are mutually exclusive
	// set switch status
	if (strncmp(option, "1", 1) == 0)
	{
		checkbypass2ndtext = TRUE;
		Button_SetCheck(hwnd44, BST_CHECKED);
		checkignore2ndtext = FALSE;
		Button_SetCheck(hwnd36, BST_UNCHECKED);
	}
	else
	{
		checkbypass2ndtext = FALSE;
		Button_SetCheck(hwnd44, BST_UNCHECKED);
	}

	char nanonx[2] = { 0 };

	//=====================================================//
	GetPrivateProfileString("NANOMITES",
		"analyzenf",
		"0",
		nanonx,
		sizeof(nanonx),
		inibuffer);
	// set switch status
	if (strncmp(nanonx, "1", 1) == 0)
	{
		analyzenf = TRUE;
		Button_SetCheck(hwnd43, BST_CHECKED);
	}
	else
	{
		analyzenf = FALSE;
		Button_SetCheck(hwnd43, BST_UNCHECKED);
	}

	//=====================================================//
	memset(nanonx, 0, sizeof(nanonx));
	GetPrivateProfileString("NANOMITES",
		"analyzest",
		"0",
		nanonx,
		sizeof(nanonx),
		inibuffer);
	// set switch status
	if (strncmp(nanonx, "1", 1) == 0)
	{
		analyzest = TRUE;
		Button_SetCheck(hwnd03, BST_CHECKED);
	}
	else
	{
		analyzest = FALSE;
		Button_SetCheck(hwnd03, BST_UNCHECKED);
	}

	//=====================================================//
	memset(nanonx, 0, sizeof(nanonx));
	GetPrivateProfileString("NANOMITES",
		"analyzelog",
		"0",
		nanonx,
		sizeof(nanonx),
		inibuffer);
	// set switch status
	if (strncmp(nanonx, "1", 1) == 0)
	{
		analyzelog = TRUE;
		Button_SetCheck(hwnd04, BST_CHECKED);
	}
	else
	{
		analyzelog = FALSE;
		Button_SetCheck(hwnd04, BST_UNCHECKED);
	}

	char fingerprint[10] = { 0 };

	//=====================================================//
	GetPrivateProfileString("HARDWAREFINGERPRINT",
		"standard",
		"0000-0000",
		fingerprint,
		sizeof(fingerprint),
		inibuffer);
	// set switch status
	if (strncmp(fingerprint, "0000-0000", 9) != 0)
	{
		SetDlgItemText(hwndDlgA, IDC_STANDARD, fingerprint);
	}
	else
	{
		// Set defaults
		SetDlgItemText(hwndDlgA, IDC_STANDARD, "0000-0000");
	}
	//=====================================================//
	memset(fingerprint, 0, sizeof(fingerprint));
	GetPrivateProfileString("HARDWAREFINGERPRINT",
		"enhanced",
		"0000-0000",
		fingerprint,
		sizeof(fingerprint),
		inibuffer);
	// set switch status
	if (strncmp(fingerprint, "0000-0000", 9) != 0)
	{
		SetDlgItemText(hwndDlgA, IDC_ENHANCED, fingerprint);
	}
	else
	{
		// Set defaults
		SetDlgItemText(hwndDlgA, IDC_ENHANCED, "0000-0000");
	}
	LogItem("Done.");
	return TRUE;
}

// Save armageddon options "*.ini" file
BOOL SaveIniFile(void)
{
	if (PutIniFileName((LPCSTR)inisavebuffer))
	{
		// continue
	}
	else
	{
		memset(inisavebuffer, 0, sizeof(MAX_PATH));
		return FALSE;
	}
	LogItem("Saving Armageddon options file...");

	// Put the appname section - Armageddon argument
	WritePrivateProfileString("APPNAME",
		"armageddon",
		"ARMAGEDDON",
		inisavebuffer);
	// Put the options section - commandline argument
	WritePrivateProfileString("OPTIONS",
		"cmdline",
		szCmdbuffer,
		inisavebuffer);
	char option[2] = { 0 };
	char *opt = option;
	//=====================================================//
	if (redirectsplicing)
		opt = "1";
	else
		opt = "0";
	// Get the options section - option
	WritePrivateProfileString("OPTIONS",
		"redirectcs",
		opt,
		inisavebuffer);
	//=====================================================//
	if (checkminimizesize)
		opt = "1";
	else
		opt = "0";
	// Get the options section - option
	WritePrivateProfileString("OPTIONS",
		"minimizesize",
		opt,
		inisavebuffer);
	//=====================================================//
	if (checksecuritydump)
		opt = "1";
	else
		opt = "0";
	// Get the options section - option
	WritePrivateProfileString("OPTIONS",
		"securitydlldump",
		opt,
		inisavebuffer);
	//=====================================================//
	if (checksecurityload)
		opt = "1";
	else
		opt = "0";
	// Get the options section - option
	WritePrivateProfileString("OPTIONS",
		"securitydllload",
		opt,
		inisavebuffer);
	//=====================================================//
	if (checkformutex)
		opt = "1";
	else
		opt = "0";
	// Get the options section - option
	WritePrivateProfileString("OPTIONS",
		"openmutex",
		opt,
		inisavebuffer);
	//=====================================================//
	if (checkdumppdata)
		opt = "1";
	else
		opt = "0";
	// Get the options section - option
	WritePrivateProfileString("OPTIONS",
		"dumppdata",
		opt,
		inisavebuffer);
	//=====================================================//
	if (checkignore2ndtext)
		opt = "1";
	else
		opt = "0";
	// Get the options section - option
	WritePrivateProfileString("OPTIONS",
		"ignore2ndtext",
		opt,
		inisavebuffer);
	//=====================================================//
	if (checkbypass2ndtext)
		opt = "1";
	else
		opt = "0";
	// Get the options section - option
	WritePrivateProfileString("OPTIONS",
		"bypass2ndtext",
		opt,
		inisavebuffer);

	char nanonx[2] = { 0 };
	char *nan = nanonx;
	//=====================================================//
	if (analyzenf)
		nan = "1";
	else
		nan = "0";
	// Get the options section - option
	WritePrivateProfileString("NANOMITES",
		"analyzenf",
		nan,
		inisavebuffer);
	//=====================================================//
	if (analyzest)
		nan = "1";
	else
		nan = "0";
	// Get the options section - option
	WritePrivateProfileString("NANOMITES",
		"analyzest",
		nan,
		inisavebuffer);
	//=====================================================//
	if (analyzelog)
		nan = "1";
	else
		nan = "0";
	// Get the options section - option
	WritePrivateProfileString("NANOMITES",
		"analyzelog",
		nan,
		inisavebuffer);
	//=====================================================//

	char fingerprint[10] = { 0 };
	char *finger = fingerprint;

	//=====================================================//
	GetDlgItemText(hwndDlgA, IDC_STANDARD, fingerprint, sizeof(fingerprint));
	WritePrivateProfileString("HARDWAREFINGERPRINT",
		"standard",
		finger,
		inisavebuffer);
	//=====================================================//
	GetDlgItemText(hwndDlgA, IDC_ENHANCED, fingerprint, sizeof(fingerprint));
	WritePrivateProfileString("HARDWAREFINGERPRINT",
		"enhanced",
		finger,
		inisavebuffer);
	LogItem("Done.");
	return TRUE;
}

// Free Scratch VM memory
void FreeArmZMMemory(void)
{
	if (dwZMVMAddress)
	{
		VirtualFree(
			dwZMVMAddress,
			0,
			MEM_RELEASE
			);
		dwZMVMAddress = 0;
	}
	return;
}

// Free Armadillo search space VM memory
void FreeArmBMMemory(void)
{
	if (dwBMVMAddress)
	{
		VirtualFree(
			dwBMVMAddress,
			0,
			MEM_RELEASE
			);
		dwBMVMAddress = 0;
	}
	return;
}

// Free Armadillo search space VM memory
void FreeArmDASMMemory(void)
{
	if (dwDASMAddress)
	{
		VirtualFree(
			dwDASMAddress,
			0,
			MEM_RELEASE
			);
		dwDASMAddress = 0;
	}
	return;
}

// Free PE related memory
void FreePESecMemory(void)
{
	if (PESecdwAddress)
	{
		VirtualFree(
			PESecdwAddress,
			0,
			MEM_RELEASE
			);
		PESecdwAddress = 0;
	}
	return;
}

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
		PEdwAddress = 0;
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
		dwAddress = 0;
	}
	return;
}

// If "Close" is selected, terminate our thread and process
void Terminate_Process(void)
{
	if (childhProcess)
	{
		TerminateProcess(childhProcess, 0);
		CloseHandle(childhProcess);
		childhProcess = 0;
		if (childhThread)
		{
			CloseHandle(childhThread);
			childhThread = 0;
		}
	}
	if (pi.hProcess)
	{
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		pi.hProcess = 0;
		if (pi.hThread)
		{
			CloseHandle(pi.hThread);
			pi.hThread = 0;
		}
	}
	return;
}

/* Reserved for future use				*/
/* Hardware breakpoint debug registers	*/
void SETBITS(DWORD dw, int lowBit, int bits, int newValue)
{
	int mask = (1 << bits) - 1; // e.g. 1 becomes 0001, 2 becomes 0011, 3 becomes 0111

	dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
	return;
}

/* Reserved for future use				*/
/* Hardware breakpoint debug registers	*/
BOOL SetHardwareBP(HANDLE thisThread, DWORD_PTR *HWBPExceptionAddress, DWORD Length, int Condition)
{
	Context.ContextFlags = CONTEXT_FULL;
	// get contents of every debug register
	if (!GetThreadContext(thisThread, &Context))
	{
		LogItem("GetThreadContext error. SetHardwareBP Failed");
		return FALSE;
	}
	for (n = 0; n < 4; n++)
	{
		switch (n)
		{
		case 0: Context.Dr0 = (DWORD_PTR)HWBPExceptionAddress[n]; break;
		case 1: Context.Dr1 = (DWORD_PTR)HWBPExceptionAddress[n]; break;
		case 2: Context.Dr2 = (DWORD_PTR)HWBPExceptionAddress[n]; break;
		case 3: Context.Dr3 = (DWORD_PTR)HWBPExceptionAddress[n]; break;
		default: break;
		}

		SETBITS(Context.Dr7, 16 + (n * 4), 2, Condition);
		SETBITS(Context.Dr7, 18 + (n * 4), 2, Length);
		SETBITS(Context.Dr7, n * 2, 1, 1);
	}

	if (!SetThreadContext(thisThread, &Context))
	{
		LogItem("SetThreadContext error. SetHardwareBP Failed");
		return FALSE;
	}
	return TRUE;
}

/* Reserved for future use				*/
/* Hardware breakpoint debug registers	*/
BOOL ClearHardwareBP(HANDLE thisThread, int DbgRegister)
{
	Context.ContextFlags = CONTEXT_FULL;
	// get contents of every debug register
	if (!GetThreadContext(thisThread, &Context))
	{
		LogItem("GetThreadContext error. ClearHardwareBP Failed");
		return FALSE;
	}
	SETBITS(Context.Dr7, DbgRegister * 2, 1, 0);
	// Clear Dr6
	Context.Dr6 = 0x00000000;
	if (!SetThreadContext(thisThread, &Context))
	{
		LogItem("SetThreadContext error. ClearHardwareBP Failed");
		return FALSE;
	}
	return TRUE;
}
// Set a pseudo single step with code retn address
BOOL SetPseudoSingleStep(HANDLE thisprocess)
{
	// Reset this SWBP
	if (!ReadProcessMemory(thisprocess, (LPVOID)SWBPExceptionAddress[8], &scanbyte[8],
		sizeof(BYTE), &dwRead))
	{
		LogItem("ReadProcessMemory Error SingleStep address: %p", SWBPExceptionAddress[8]);
		LogItem(NULL);
		breaknow = TRUE;
		return FALSE;
	}
	if (!WriteProcessMemory(thisprocess, (LPVOID)SWBPExceptionAddress[8], &replbyte[8],
		sizeof(BYTE), &dwWritten))
	{
		LogItem("WriteProcessMemory Error SingleStep address: %p", SWBPExceptionAddress[8]);
		LogItem(NULL);
		breaknow = TRUE;
		return FALSE;
	}
	return TRUE;
}
BOOL SetSingleStep(HANDLE thisThread)
{
	Context.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(thisThread, &Context))
	{
		LogItem("GetThreadContext error. SetSingleStep Failed");
		return FALSE;
	}
	Context.EFlags |= 0x100;	// set the "trap" flag for single step
	if (!SetThreadContext(thisThread, &Context))
	{
		LogItem("SetThreadContext error. SetSingleStep Failed");
		return FALSE;
	}
	return TRUE;
}

BOOL ClearSingleStep(HANDLE thisThread)
{
	Context.ContextFlags = CONTEXT_CONTROL;
	if (!GetThreadContext(thisThread, &Context))
	{
		LogItem("GetThreadContext error. ClearSingleStep Failed");
		return FALSE;
	}
	Context.EFlags = 0x00000000;	// clear the "trap" flag for single step
	if (!SetThreadContext(thisThread, &Context))
	{
		LogItem("SetThreadContext error. ClearSingleStep Failed");
		return FALSE;
	}
	return TRUE;
}

/* Read PE header for Armadillo sections */
BOOL DetermineArmSections(HANDLE thisProcess)
{
	int nSections = 0;
	// Allocate some memory to dump the 1st 4096 bytes of disk PE header data
	PEdwAddress = VirtualAlloc(
		NULL,
		PEdwSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
		);
	if (PEdwAddress == NULL)
	{
		LogItem("VirtualAlloc Error DetermineArmSections");
		LogItem(NULL);
		return FALSE;
	}
	// Find the last '\\' to obtain a pointer to just the base module name part
	pszPathName = strrchr((char *)buffer, '\\');
	if (pszPathName)  // We found a path, so advance to the base module name
	{
		pszPathName++;
		strcpy(c, (const char *)pszPathName);
	}
	// Read the target executable file for the PE header data
	hFile1 = CreateFile((LPCSTR)buffer,     // file to create
		GENERIC_READ,          // open for reading
		FILE_SHARE_READ,       // share for reading
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file
		NULL);                 // no attr. template

	if (hFile1 == INVALID_HANDLE_VALUE)
	{
		LogItem("CreateFile error %s %d", c, GetLastError());
		return FALSE;
	}
	dwSaveFileSize = GetFileSize(
		hFile1,
		NULL);
	// Read the base module's process address space PE header section into our process memory
	if (!ReadFile(hFile1, PEdwAddress, PEdwSize, &dwRead, NULL))
	{
		LogItem("VirtualAlloc Error CreateDump");
		LogItem(NULL);
		return FALSE;
	}
	// Get a pointer to our process memory from above.
	// As if we used CreateFile / CreateFileMapping / MapViewOfFile on the base module's file
	// g_pMappedFileBase represents a pointer to the base of the memory-mapped
	// executable file, and therein lies the convenience of memory-mapped files. No
	// file I/O needs to be performed; simply dereference this pointer to access
	// information in the file.
	g_pMappedFileBase = (PBYTE)PEdwAddress;
	dosHeader = (PIMAGE_DOS_HEADER)g_pMappedFileBase;
	pImgFileHdr = (PIMAGE_FILE_HEADER)PEFHDROFFSET(g_pMappedFileBase);
	pImgOptHdr = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET(g_pMappedFileBase);
	// 1st Section Header
	pImgSectHdr = (PIMAGE_SECTION_HEADER)SECHDROFFSET(g_pMappedFileBase);
	// last Section Header
#define LSECHDROFFSET(a) ((LPVOID)((BYTE *)a		     +	\
	((PIMAGE_DOS_HEADER)a)->e_lfanew    +	\
	SIZE_OF_NT_SIGNATURE		     +	\
	sizeof (IMAGE_FILE_HEADER)	     +	\
	sizeof (IMAGE_OPTIONAL_HEADER)   +  \
	(sizeof (IMAGE_SECTION_HEADER) *(pImgFileHdr->NumberOfSections-1))));
	pImgLSectHdr = (PIMAGE_SECTION_HEADER)LSECHDROFFSET(g_pMappedFileBase);
	// Do we have a valid pointer
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		// We grabbed wrong memory
		LogItem("IMAGE_DOS_SIGNATURE not found");
		LogItem("%s", c);
		CloseHandle(hFile1);
		hFile1 = 0;
		return FALSE;
	}
	if (*(DWORD *)NTSIGNATURE(g_pMappedFileBase) != IMAGE_NT_SIGNATURE)
	{
		// Not a valid PE file
		LogItem("IMAGE_NT_SIGNATURE not found");
		LogItem("%s", c);
		CloseHandle(hFile1);
		hFile1 = 0;
		return FALSE;
	}
	if (*(WORD *)SRSIGNATURE(g_pMappedFileBase) != IMAGE_SR_SIGNATURE)	// 'SR'
	{
		LogItem("IMAGE_SR_SIGNATURE not found");
		LogItem("%s", c);
		LogItem("Not an armadillo protected file!");
		CloseHandle(hFile1);
		hFile1 = 0;
		return FALSE;
	}
	else
	{
		// Remove signature bytes and replace with '00'
		*(WORD *)SRSIGNATURE(g_pMappedFileBase) = IMAGE_SR_NOSIGNATURE;
	}
	// Cycle through each Section
	// Save the VM address + size
	nSections = pImgFileHdr->NumberOfSections;
	char *CompName = 0;
	// additional byte '\0' needed to avoid errors!!
	char SuprName[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
	if (pImgSectHdr)
	{
		/* Process each section */
		/* This first pass loops from the last PE section to the first for the .pdata section (only) */
		for (n = nSections; n > 0; n--)
		{
			memset(SuprName, 0, sizeof(SuprName));
			memcpy((void *)SuprName, (void *)pImgLSectHdr->Name, IMAGE_SIZEOF_SHORT_NAME);
			CompName = strupr((char *)SuprName);
			if ((strncmp((const char *)CompName, ".PDATA", 6) == 0 ||
				strncmp((const char *)CompName, "PDATA", 5) == 0 ||
				(pImgLSectHdr->Characteristics >= 0xC0000040 && pImgLSectHdr->Characteristics <= 0xC1000000
				&& pImgLSectHdr->SizeOfRawData > 0x00000000)))
			{
				if (PdataVMaddress == 0x00000000)
				{
					PdataVMaddress = (LPVOID)(pImgLSectHdr->VirtualAddress + (DWORD_PTR)BaseOfImage);
					PdataVMsize = pImgLSectHdr->Misc.VirtualSize;
					// Insure we are not referencing a .rsrc section
					// Read the 1st dword from this address space into our process memory
					PvoidRead = 0x00000000;
					if (!ReadProcessMemory(thisProcess, PdataVMaddress, &PvoidRead, sizeof(DWORD_PTR), &dwRead))
					{
						LogItem("ReadProcessMemory Error DetermineArmSections address: %p", PdataVMaddress);
						LogItem(NULL);
					}
					// should not be equal to zeroes
					else if (PvoidRead != 0)
					{
						char *pdata = ".pdata";
						//memcpy((void *)pImgLSectHdr->Name,pdata, IMAGE_SIZEOF_SHORT_NAME);
						n = 0;
						break;
					}
					else
					{
						// we need to continue
						PdataVMaddress = 0x00000000;
						PdataVMsize = 0x00000000;
					}
				}
			}
			pImgLSectHdr--;
		}

		/* Process each section */
		for (n = 0; n < nSections; n++)
		{
			memset(SuprName, 0, sizeof(SuprName));
			memcpy((void *)SuprName, (void *)pImgSectHdr->Name, IMAGE_SIZEOF_SHORT_NAME);
			CompName = strupr((char *)SuprName);

			// UPX specific
			if (strncmp((const char *)CompName, "UPX0", 4) == 0 &&
				n == 0)
			{
				if (UPX0VMaddress == 0x00000000)
				{
					// Note: This address s/b same as .text address
					dwCalcAddress = pImgSectHdr->VirtualAddress + (DWORD_PTR)BaseOfImage;
					UPX0VMaddress = (PVOID)dwCalcAddress;
					UPX0VMsize = pImgSectHdr->Misc.VirtualSize;
					// We will consider this same as 1st .text section in normal program
					goto DOTEXT;
				}
			}
			if (strncmp((const char *)CompName, "UPX1", 4) == 0 &&
				n == 1)
			{
				if (UPX1VMaddress == 0x00000000)
				{
					dwCalcAddress = pImgSectHdr->VirtualAddress + (DWORD_PTR)BaseOfImage;
					UPX1VMaddress = (PVOID)dwCalcAddress;
					UPX1VMsize = pImgSectHdr->Misc.VirtualSize;
				}
			}
			// Armadillo specific
			if (strncmp((const char *)CompName, ".TEXT", 5) == 0 ||
				strncmp((const char *)CompName, ".CODE", 5) == 0 ||
				strncmp((const char *)CompName, "TEXT", 4) == 0 ||
				strncmp((const char *)CompName, "CODE", 4) == 0 ||
				n == 0)
			{
				// Make sure the characteristics are correct
				if ((pImgSectHdr->Characteristics >= 0xE0000020 && pImgSectHdr->Characteristics <= 0xE1000000) ||
					(pImgSectHdr->Characteristics >= 0x60000020 && pImgSectHdr->Characteristics <= 0x61000000))
				{
				DOTEXT:
					if (TextVMaddress == 0x00000000)
					{
						TextVMaddress = (LPVOID)(pImgSectHdr->VirtualAddress + (DWORD_PTR)BaseOfImage);
						TextVMsize = pImgSectHdr->Misc.VirtualSize;
						char *pdata = ".text";
						//memcpy((void *)pImgSectHdr->Name,pdata, IMAGE_SIZEOF_SHORT_NAME);
						goto NEXTSECT;
					}
				}
			}
			// For randomized PE section names, this may have to be adjusted
			if (strncmp((const char *)CompName, ".ITEXT", 6) == 0 ||
				strncmp((const char *)CompName, "ITEXT", 5) == 0 ||
				n == 1)
			{
				// Make sure the characteristics are correct
				if ((pImgSectHdr->Characteristics >= 0xE0000020 && pImgSectHdr->Characteristics <= 0xE1000000) ||
					(pImgSectHdr->Characteristics >= 0x60000020 && pImgSectHdr->Characteristics <= 0x61000000))
				{
					// Make sure we had a valid 1st .text section
					if (TextVMaddress == 0x00000000)
					{
						goto DOTEXT;
					}
				DOITEXT:
					// if option bypass 2nd text is checked, or UPX has been detected, bypass this condition!!
					if (ItextVMaddress == 0x00000000 && !checkbypass2ndtext && UPX1VMaddress == 0)
					{
						ItextVMaddress = (LPVOID)(pImgSectHdr->VirtualAddress + (DWORD_PTR)BaseOfImage);
						ItextVMsize = pImgSectHdr->Misc.VirtualSize;
						char *pdata = ".itext";
						//memcpy((void *)pImgSectHdr->Name,pdata, IMAGE_SIZEOF_SHORT_NAME);
						goto NEXTSECT;
					}
				}
			}
			if ((strncmp((const char *)CompName, ".RDATA", 6) == 0 ||
				strncmp((const char *)CompName, "RDATA", 5) == 0 ||
				(pImgSectHdr->Characteristics >= 0x40000040 && pImgSectHdr->Characteristics <= 0x51000000)))
			{
				if (RdataVMaddress == 0x00000000)
				{
					RdataRVaddress = (LPVOID)pImgSectHdr->VirtualAddress;
					RdataVMaddress = (LPVOID)(pImgSectHdr->VirtualAddress + (DWORD_PTR)BaseOfImage);
					RdataVMsize = pImgSectHdr->Misc.VirtualSize;
					char *pdata = ".rdata";
					//memcpy((void *)pImgSectHdr->Name,pdata, IMAGE_SIZEOF_SHORT_NAME);
					// needed for BFG problem
					RdataVMCharacteristics = pImgSectHdr->Characteristics;
					goto NEXTSECT;
				}
			}
			// Mod to resolve problem with section names where .text1 is not found!!
			if ((strncmp((const char *)CompName, ".TEXT1", 6) == 0 ||
				strncmp((const char *)CompName, "TEXT1", 5) == 0 ||
				(pImgSectHdr->Characteristics >= 0xE0000020 && pImgSectHdr->Characteristics <= 0xE1000000) ||
				(pImgSectHdr->Characteristics >= 0x60000020 && pImgSectHdr->Characteristics <= 0x61000000)) &&
				n > 1 && pImgSectHdr->SizeOfRawData >= 0x00010000)
			{
			REDOTEXT1:
				if (Text1VMaddress == 0x00000000)
				{
					Text1VMaddress = (LPVOID)(pImgSectHdr->VirtualAddress + (DWORD_PTR)BaseOfImage);
					Text1VMsize = pImgSectHdr->Misc.VirtualSize;
					char *pdata = ".text1";
					//memcpy((void *)pImgSectHdr->Name,pdata, IMAGE_SIZEOF_SHORT_NAME);
					text1found = TRUE;
					goto NEXTSECT;
				}
				else
					// Uh oh, we may have multiple Arma section names in the PE header 
					// Display a messagebox to alert the user and ask for a response
					// Note: this may have to be adjusted in the future!
				{
					if (AdataVMaddress != 0x00000000 &&
						Data1VMaddress != 0x00000000 &&
						PdataVMaddress != 0x00000000)
					{
						sprintf(b, "PE section name: %s\n"
							"There appears to be multiple occurrences\n"
							"of Armadillo section names in this application!\n"
							"Check the PE file using LordPE or similar and\n"
							"look at the PE section names and/or characteristics.\n"
							"If you believe this message to be a FALSE alert,\n"
							"press the Cancel button to resume normal processing,\n"
							"otherwise, press the OK button and the appropriate action\n"
							"will be taken and processing will resume...\n\n"
							"Note: This message may also appear for PE section\n"
							"names that have been randomized!\n"
							"If you have any problems after pressing the Cancel button,\n"
							"Rerun and try pressing the OK button to continue!\n", CompName);
						if (MessageBox(NULL, (LPCSTR)b, "PE section names alert!",
							MB_OKCANCEL + MB_SYSTEMMODAL + MB_ICONEXCLAMATION) == IDCANCEL)
						{
							goto NEXTSECT;
						}
						// reinitialize arma section infos
						Text1VMaddress = 0x00000000;
						Text1VMsize = 0x00000000;
						text1found = FALSE;
						AdataVMaddress = 0x00000000;
						AdataVMsize = 0x00000000;
						Data1VMaddress = 0x00000000;
						Data1VMsize = 0x00000000;
						PdataVMaddress = 0x00000000;
						PdataVMsize = 0x00000000;
						goto REDOTEXT1;
					}
				}
			}
			if ((strncmp((const char *)CompName, ".ADATA", 6) == 0 ||
				strncmp((const char *)CompName, "ADATA", 5) == 0 ||
				(pImgSectHdr->Characteristics >= 0xE0000020 && pImgSectHdr->Characteristics <= 0xE1000000) ||
				(pImgSectHdr->Characteristics >= 0x60000020 && pImgSectHdr->Characteristics <= 0x61000000)) && (text1found))
			{
				if (AdataVMaddress == 0x00000000)
				{
					AdataVMaddress = (LPVOID)(pImgSectHdr->VirtualAddress + (DWORD_PTR)BaseOfImage);
					AdataVMsize = pImgSectHdr->Misc.VirtualSize;
					char *pdata = ".adata";
					//memcpy((void *)pImgSectHdr->Name,pdata, IMAGE_SIZEOF_SHORT_NAME);
					goto NEXTSECT;
				}
			}
			// Extraneous PE sections we don't need
			if (strncmp((const char *)CompName, ".RSRC", 5) == 0 ||
				strncmp((const char *)CompName, "RSRC", 4) == 0)
			{
				// skip it!
				goto NEXTSECT;
			}
			if (strncmp((const char *)CompName, ".RELOC", 6) == 0 ||
				strncmp((const char *)CompName, "RELOC", 5) == 0)
			{
				if (RelocVMaddress == 0x00000000)
				{
					RelocVMaddress = (LPVOID)(pImgSectHdr->VirtualAddress + (DWORD_PTR)BaseOfImage);
					RelocVMsize = pImgSectHdr->Misc.VirtualSize;
					goto NEXTSECT;
				}
			}
			if (strncmp((const char *)CompName, ".DEBUG", 6) == 0 ||
				strncmp((const char *)CompName, "DEBUG", 5) == 0)
			{
				// skip it!
				goto NEXTSECT;
			}
			if (strncmp((const char *)CompName, ".BSS", 4) == 0 ||
				strncmp((const char *)CompName, "BSS", 3) == 0)
			{
				if (BssVMaddress == 0x00000000)
				{
					BssVMaddress = (LPVOID)(pImgSectHdr->VirtualAddress + (DWORD_PTR)BaseOfImage);
					BssVMsize = pImgSectHdr->Misc.VirtualSize;
					goto NEXTSECT;
				}
			}
			if (strncmp((const char *)CompName, ".TLS", 4) == 0 ||
				strncmp((const char *)CompName, "TLS", 3) == 0)
			{
				// skip it!
				goto NEXTSECT;
			}
			if (strncmp((const char *)CompName, ".DATA", 5) == 0 ||
				strncmp((const char *)CompName, "DATA", 4) == 0 ||
				(pImgSectHdr->Characteristics >= 0xC0000040 && pImgSectHdr->Characteristics <= 0xC1000000
				&& pImgSectHdr->SizeOfRawData > 0x00000000))
			{
				if (DataVMaddress == 0x00000000)
				{
					DataVMaddress = (LPVOID)(pImgSectHdr->VirtualAddress + (DWORD_PTR)BaseOfImage);
					DataVMsize = pImgSectHdr->Misc.VirtualSize;
					char *pdata = ".data";
					//memcpy((void *)pImgSectHdr->Name,pdata, IMAGE_SIZEOF_SHORT_NAME);
					datafound = TRUE;
					goto NEXTSECT;
				}
			}
			if ((strncmp((const char *)CompName, ".IDATA", 6) == 0 ||
				strncmp((const char *)CompName, "IDATA", 5) == 0 ||
				(pImgSectHdr->Characteristics >= 0xC0000040 && pImgSectHdr->Characteristics <= 0xC1000000)) &&
				(pImgSectHdr->Misc.VirtualSize <= 0x00010000 && datafound))
			{
				if (IdataVMaddress == 0x00000000)
				{
					IdataVMaddress = (LPVOID)(pImgSectHdr->VirtualAddress + (DWORD_PTR)BaseOfImage);
					IdataVMsize = pImgSectHdr->Misc.VirtualSize;
					char *pdata = ".idata";
					//memcpy((void *)pImgSectHdr->Name,pdata, IMAGE_SIZEOF_SHORT_NAME);
					goto NEXTSECT;
				}
			}
			if ((strncmp((const char *)CompName, ".DATA1", 6) == 0 ||
				strncmp((const char *)CompName, "DATA1", 5) == 0 ||
				(pImgSectHdr->Characteristics >= 0xC0000040 && pImgSectHdr->Characteristics <= 0xC1000000)) &&
				(pImgSectHdr->Misc.VirtualSize >= 0x00010000 && text1found && datafound &&
				// it is not the last section
				n != nSections - 1))
			{
				if (Data1VMaddress == 0x00000000)
				{
					Data1VMaddress = (LPVOID)(pImgSectHdr->VirtualAddress + (DWORD_PTR)BaseOfImage);
					Data1VMsize = pImgSectHdr->Misc.VirtualSize;
					char *pdata = ".data1";
					//memcpy((void *)pImgSectHdr->Name,pdata, IMAGE_SIZEOF_SHORT_NAME);
					goto NEXTSECT;
				}
			}
			if ((strncmp((const char *)CompName, ".PDATA", 6) == 0 ||
				strncmp((const char *)CompName, "PDATA", 5) == 0 ||
				(pImgSectHdr->Characteristics >= 0xC0000040 && pImgSectHdr->Characteristics <= 0xC1000000)) && (pImgSectHdr->SizeOfRawData > 0x00000000 && text1found))
			{
				if (PdataVMaddress == 0x00000000)
				{
					PdataVMaddress = (LPVOID)(pImgSectHdr->VirtualAddress + (DWORD_PTR)BaseOfImage);
					PdataVMsize = pImgSectHdr->Misc.VirtualSize;
					char *pdata = ".pdata";
					//memcpy((void *)pImgSectHdr->Name,pdata, IMAGE_SIZEOF_SHORT_NAME);
					goto NEXTSECT;
				}
			}
		NEXTSECT:
			pImgSectHdr++;
		}
	}
DONE:
	if (pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress > 0x00000000)
	{
		pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = 0x00000000;
		pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = 0x00000000;
	}
	dwSize = pImgOptHdr->SizeOfImage;
	CloseHandle(hFile1);
	hFile1 = 0;
	return TRUE;
}

// Rebuild PE header / sections on dumped file by
// removing armadillo related sections
long DoRebuildSectionsFromArmadillo(void)
{
	MSINT = 0;
	MSINT = RebuildSectionsFromArmadillo(buffer, savebuffer, ibuf);
	LogItem(ibuf);
	return (MSINT);
}

// Rebuild imports on dumped file (no new IAT section added)
long DoSearchAndRebuildImportsNoNewSection(DWORD thispid)
{
	IRINT = 0;
	DWORD IROEP = 1;
	IRINT = SearchAndRebuildImportsNoNewSection(thispid, gnfobuffer, (DWORD)OEPVAddress,
		IROEP, &IRiatrva, &IRiatsize, IRwarn);
	return (IRINT);
}

// Rebuild imports on dumped file
long DoSearchAndRebuildImports(DWORD thispid)
{
	IRINT = 0;
	DWORD IROEP = 1;
	IRINT = SearchAndRebuildImportsIATOptimized(thispid, savebuffer, (DWORD)OEPVAddress, IROEP,
		&IRiatrva, &IRiatsize, IRwarn);
	return (IRINT);
}

// Adds new .nano section to PE header of repaired dump file
void AddNewSection(char* szName, DWORD dwSectsize)
{
	int			nSections = 0;
	nSections = pImgFileHdr->NumberOfSections;
	for (i = 0; i < nSections; i++)
	{
		if (i == nSections - 1)
		{
			pImgSectHdr->VirtualAddress =
				PEAlign(pImgSectHdr->VirtualAddress,
				pImgOptHdr->SectionAlignment);

			pImgSectHdr->Misc.VirtualSize =
				PEAlign(pImgSectHdr->Misc.VirtualSize,
				pImgOptHdr->SectionAlignment);
			// Update SizeOfImage & dwSize
			pImgOptHdr->SizeOfImage = pImgSectHdr->VirtualAddress + pImgSectHdr->Misc.VirtualSize;
			dwSize = pImgOptHdr->SizeOfImage;
		}
		roffset = pImgSectHdr->PointerToRawData + pImgSectHdr->SizeOfRawData;
		voffset = pImgSectHdr->VirtualAddress + pImgSectHdr->Misc.VirtualSize;
		pImgSectHdr++;
	}
	rsize = dwSectsize;	//PEAlign(dwSectsize,
	//pImgOptHdr->FileAlignment);
	vsize = PEAlign(dwSectsize,
		pImgOptHdr->SectionAlignment);

	memset(pImgSectHdr, 0, (size_t)sizeof(IMAGE_SECTION_HEADER));
	pImgSectHdr->PointerToRawData = roffset;
	pImgSectHdr->VirtualAddress = voffset;
	pImgSectHdr->SizeOfRawData = rsize;
	pImgSectHdr->Misc.VirtualSize = vsize;
	pImgSectHdr->Characteristics = 0xE00000E0;
	memcpy(pImgSectHdr->Name, szName, (size_t)strlen(szName));
	pImgFileHdr->NumberOfSections++;
	pImgOptHdr->SizeOfImage = pImgSectHdr->VirtualAddress + pImgSectHdr->Misc.VirtualSize;
	return;
}

// Create dumpfile of target process with fixed PE header section
void CreateDump(HANDLE thisProcess, int dumparmvm)
{
	DWORD_PTR	dwFileOffset = 0;
	int		nSections = 0;
	int		Comma = 0;
	char	*pComma = 0;

	// Create a dumped exe file
	if (PutFileName((LPCSTR)savebuffer))
	{
		// continue
	}
	else
	{
		memset(savebuffer, 0, sizeof(MAX_PATH));
		return;
	}
	// Find the last '\\' to obtain a pointer to just the base module name part
	pszPathName = strrchr((char *)savebuffer, '\\');
	if (pszPathName)  // We found a path, so advance to the base module name
	{
		pszPathName++;
		strcpy(c, (const char *)pszPathName);
	}
	LogItem("%s", isep);
	LogItem("%s", h);
	hFile = CreateFile((LPCSTR)savebuffer,     // file to create
		GENERIC_READ | GENERIC_WRITE,          // open for read/write
		FILE_SHARE_READ | FILE_SHARE_WRITE,        // share
		NULL,                   // default security
		CREATE_ALWAYS,          // overwrite existing
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template
	if (hFile == INVALID_HANDLE_VALUE)
	{
		LogItem("CreateFile error %s %d", c, GetLastError());
		goto FINISH;
	}
	SIZE_T vmSize = dwSize;
	// If dumping errors? Increase size by new section
	if (dumparmvm == 1)
	{
		vmSize += dwArmVMNSize;
	}
	// Allocate some memory to dump the base module process
	dwAddress = VirtualAlloc(
		NULL,
		vmSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
		);
	if (dwAddress == NULL)
	{
		LogItem("VirtualAlloc Error CreateDump");
		LogItem(NULL);
		goto FINISH;
	}
	// Insure read/write access on process VM for dump
	if (!VirtualProtectEx(thisProcess, dwBase, dwSize, PERWProtect, &PEOldProtect))
	{
		LogItem("VirtualProtectEx Error CreateDump address: %p", dwBase);
		LogItem(NULL);
		goto FINISH;
	}
	// Read the base module's process address space into our process memory
	if (!ReadProcessMemory(thisProcess, dwBase, dwAddress, dwSize, &dwRead))
	{
		LogItem("ReadProcessMemory Error CreateDump address: %p", dwBase);
		LogItem(NULL);
		goto FINISH;
	}
	// Copy saved PE header data from disk to dumped process memory 
	memcpy(dwAddress, PEdwAddress, PEdwSize);
	// Get a pointer to our process memory from above.
	// As if we used CreateFile / CreateFileMapping / MapViewOfFile on the base module's file
	// g_pMappedFileBase represents a pointer to the base of the memory-mapped
	// executable file, and therein lies the convenience of memory-mapped files. No
	// file I/O needs to be performed; simply dereference this pointer to access
	// information in the file.
	g_pMappedFileBase = (PBYTE)dwAddress;
	dosHeader = (PIMAGE_DOS_HEADER)g_pMappedFileBase;
	pImgFileHdr = (PIMAGE_FILE_HEADER)PEFHDROFFSET(g_pMappedFileBase);
	pImgOptHdr = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET(g_pMappedFileBase);
	pImgSectHdr = (PIMAGE_SECTION_HEADER)SECHDROFFSET(g_pMappedFileBase);

	// Do we have a valid pointer
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		// We grabbed wrong memory
		LogItem("IMAGE_DOS_SIGNATURE not found");
		LogItem("%s", c);
		goto FINISH;
	}
	if (*(DWORD *)NTSIGNATURE(g_pMappedFileBase) != IMAGE_NT_SIGNATURE)
	{
		// Not a valid PE file
		LogItem("IMAGE_NT_SIGNATURE not found");
		LogItem("%s", c);
		goto FINISH;
	}
	// FileAlignment s/b set to the value in SectionAlignment.
	// Section alignment can be no less than the page size (currently 4096 bytes on
	// the x86 platform)
	pImgOptHdr->FileAlignment = pImgOptHdr->SectionAlignment;

	// Fix Raw data in each Section
	nSections = pImgFileHdr->NumberOfSections;
	char *CompName = 0;
	BYTE SuprName[IMAGE_SIZEOF_SHORT_NAME];
	if (pImgSectHdr)
	{
		/* Process each section */
		for (i = 0; i < nSections; i++)
		{
			memcpy((void *)SuprName, (void *)pImgSectHdr->Name, IMAGE_SIZEOF_SHORT_NAME);
			CompName = strupr((char *)SuprName);
			// Note: the last section's entry is saved here
			// This is the pointer to the overlay data if needed
			dwFileOffset = pImgSectHdr->PointerToRawData +
				pImgSectHdr->SizeOfRawData;
			if (strncmp((const char *)CompName, ".RDATA", 6) == 0 ||
				strncmp((const char *)CompName, "RDATA", 5) == 0)
			{
				// needed for BFG problem
				pImgSectHdr->Characteristics = RdataVMCharacteristics;
			}

			pImgSectHdr->VirtualAddress =
				PEAlign(pImgSectHdr->VirtualAddress,
				pImgOptHdr->SectionAlignment);

			pImgSectHdr->Misc.VirtualSize =
				PEAlign(pImgSectHdr->Misc.VirtualSize,
				pImgOptHdr->SectionAlignment);

			pImgSectHdr->PointerToRawData =
				PEAlign(pImgSectHdr->VirtualAddress,
				pImgOptHdr->SectionAlignment);

			pImgSectHdr->SizeOfRawData =
				PEAlign(pImgSectHdr->Misc.VirtualSize,
				pImgOptHdr->SectionAlignment);

			// Update SizeOfImage & dwSize
			pImgOptHdr->SizeOfImage = pImgSectHdr->VirtualAddress + pImgSectHdr->Misc.VirtualSize;
			dwSize = pImgOptHdr->SizeOfImage;
			pImgSectHdr++;
		}
		// If dumparmvm = 0 (normal dump), dumparmvm = 1 (debug dump)
		// for debug dump, armadillo VM is copied to .pdata section for analysis
		if (dumparmvm == 1)
		{
			LogItem("Dump error option selected.");
			LogItem("Adding new .error section header...");
			pImgSectHdr = (PIMAGE_SECTION_HEADER)SECHDROFFSET(g_pMappedFileBase);
			AddNewSection(".error", dwArmVMNSize);
			LogItem("Appending new data...");
			PdataVMaddress = (LPVOID)(pImgSectHdr->VirtualAddress + (DWORD_PTR)dwAddress);
			DWORD_PTR vmAddress = (DWORD_PTR)dwAddress + dwSize;
			memcpy((LPVOID)vmAddress, dwBMVMAddress, vsize);
			dwSize += vsize;
		}
		// Set new BaseOfCode / SizeOfCode / BaseOfData / AddressOfEntryPoint (OEP) entries
		if (TextVMaddress != 0)
			pImgOptHdr->BaseOfCode = (DWORD_PTR)TextVMaddress - (DWORD_PTR)BaseOfImage;
		if (TextVMsize != 0)
			pImgOptHdr->SizeOfCode = PEAlign(TextVMsize,
			pImgOptHdr->SectionAlignment);
		if (DataVMaddress != 0)
			pImgOptHdr->BaseOfData = (DWORD_PTR)DataVMaddress - (DWORD_PTR)BaseOfImage;
		if (OEPRVAddress != 0)
			pImgOptHdr->AddressOfEntryPoint = (DWORD_PTR)OEPRVAddress;
		// Reset Directories Base Relocation Table -> to 1st .reloc section
		//if (RelocRVaddress != 0)
		//	pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = RelocRVaddress;
		// debug purposes only:
		//sprintf(b, "BaseOfCode: %08X\n"
		//	"SizeOfCode: %08X\n"
		//	"BaseOfData: %08X\n"
		//	"AddressOfEntryPoint: %08X",pImgOptHdr->BaseOfCode,pImgOptHdr->SizeOfCode,
		//	pImgOptHdr->BaseOfData,pImgOptHdr->AddressOfEntryPoint);
		//MessageBoxInformation(b);
	}
	// ----- WRITE FILE MEMORY TO DISK -----
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	WriteFile(hFile, dwAddress, dwSize, &dwWritten, NULL);
	// ------ FORCE CALCULATED FILE SIZE ------
	SetFilePointer(hFile, dwSize, NULL, FILE_BEGIN);
	SetEndOfFile(hFile);
	// print success
	LogItem("Dump done!");
	LogItem("Saved to: %s", c);
	if (dumparmvm == 1)
	{
		goto FINISH;
	}
	// Close the handle on dumped file for import rebuilding
	if (hFile)
	{
		CloseHandle(hFile);
		hFile = 0;
	}
	LogItem("%s", isep);
	LogItem("Rebuilding Imports...");
	if (debugblocker)
	{
		if (checkminimizesize)
		{
			LogItem("Rebuilding Sections...");
			MSretn = DoRebuildSectionsFromArmadillo();
			if (MSretn == 0)
			{
				// Get the optimized file name returned from above function
				MSretn = GetNameFileOptimized(savebuffer, gnfobuffer);
				if (MSretn > 0)
				{
					IRretn = DoSearchAndRebuildImportsNoNewSection(childpid);
				}
				else
				{
					LogItem("function: GetNameFileOptimized Error!");
				}
			}
		}
		else
		{
			IRretn = DoSearchAndRebuildImports(childpid);
		}
	}
	else
	{
		if (checkminimizesize)
		{
			LogItem("Rebuilding Sections...");
			MSretn = DoRebuildSectionsFromArmadillo();
			if (MSretn == 0)
			{
				// Get the optimized file name returned from above function
				MSretn = GetNameFileOptimized(savebuffer, gnfobuffer);
				if (MSretn > 0)
				{
					IRretn = DoSearchAndRebuildImportsNoNewSection(DebugEv.dwProcessId);
				}
				else
				{
					LogItem("function: GetNameFileOptimized Error!");
				}
			}
		}
		else
		{
			IRretn = DoSearchAndRebuildImports(DebugEv.dwProcessId);
		}
	}
	LogItem("Rebuilding Imports completed");
	LogItem("Return code: %X", IRretn);
	LogItem("%s", IRwarn);
	LogItem("%s", isep);
	LogItem("IAT RVA: %08X", IRiatrva);
	LogItem("IAT Size: %08X", IRiatsize);
	LogItem("OEP VA: %p", OEPVAddress);
	LogItem("OEP RVA: %p", OEPRVAddress);
	if (dwoepcall > 0)
	{
		LogItem("OEP call return VA: %p", dwoepcall);
		if (OEPDelphiRVAddress > 0 && OEPDelphiRVAddress != OEPRVAddress)
		{
			LogItem("2nd TEXT OEP VA: %p", OEPDelphiVAddress);
			LogItem("2nd TEXT OEP RVA: %p", OEPDelphiRVAddress);
		}
	}
	if (checkdumppdata)
	{
		LogItem("%s", isep);
		LogItem("Unpacking Pdata Section...");
		MSretn = UnpackPdataSection(buffer, savebuffer, ibuf);
		LogItem("Unpacking Pdata completed");
		LogItem("Return code: %X", MSretn);
		Comma = 35 + strcspn(ibuf + 35, " ");
		LogItem("%.*s", Comma, ibuf);
		if (MSretn == 0)
		{
			pComma = strrchr(ibuf, '\\');
			Comma = (int)(pComma - ibuf + 1);
		}
		LogItem("%s", ibuf + Comma);
	}
FINISH:
	if (hFile)
	{
		CloseHandle(hFile);
		hFile = 0;
	}
	return;
}

// Create dumpfile of target process security dll
void DumpSecurityDll(HANDLE thisProcess)
{
	dwArmVMAddress = 0;
	dwArmVMNSize = 0;
	LogItem("%s", isep);
	LogItem("Dumping security dll...");
	// Obtain security dll size 
	PvoidAddr = (PVOID)(DWORD_PTR)(Context.Esp + 8);
	if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &PvoidRead,
		sizeof(DWORD_PTR), &dwRead))
	{
		LogItem("ReadProcessMemory Error DetermineSecurityARMVM address: %p", PvoidAddr);
		LogItem(NULL);
		return;
	}
	if (PvoidRead != NULL)
	{
		dwArmVMNSize = (SIZE_T)PvoidRead;
	}
	else
	{
		return;
	}
	// Obtain security dll Address 
	PvoidAddr = (PVOID)(DWORD_PTR)(Context.Ebp - 48);
	if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &PvoidRead,
		sizeof(DWORD_PTR), &dwRead))
	{
		LogItem("ReadProcessMemory Error DetermineSecurityARMVM address: %p", PvoidAddr);
		LogItem(NULL);
		return;
	}
	if (PvoidRead != NULL)
	{
		dwArmVMAddress = PvoidRead;
	}
	else
	{
		return;
	}
	// Allocate some memory to dump the security.dll module process
	dwAddress = VirtualAlloc(
		NULL,
		dwArmVMNSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
		);
	if (dwAddress == NULL)
	{
		LogItem("VirtualAlloc Error dump security dll");
		LogItem(NULL);
		goto FINISH;
	}
	ZeroMemory(dwAddress, dwArmVMNSize);
	// Read the security.dll module's process address space into our process memory
	if (!ReadProcessMemory(thisProcess, dwArmVMAddress, dwAddress,
		dwArmVMNSize, &dwRead))
	{
		if (dwRead == NULL)
		{
			LogItem("ReadProcessMemory Error DumpSecurityDll address: %p", dwArmVMAddress);
			LogItem(NULL);
			goto FINISH;
		}
	}
	// Get a pointer to our process memory from above.
	// As if we used CreateFile / CreateFileMapping / MapViewOfFile on the base module's file
	// g_pMappedFileBase represents a pointer to the base of the memory-mapped
	// executable file, and therein lies the convenience of memory-mapped files. No
	// file I/O needs to be performed; simply dereference this pointer to access
	// information in the file.
	g_pMappedFileBase = (PBYTE)dwAddress;
	dosHeader = (PIMAGE_DOS_HEADER)g_pMappedFileBase;
	pImgFileHdr = (PIMAGE_FILE_HEADER)PEFHDROFFSET(g_pMappedFileBase);
	pImgOptHdr = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET(g_pMappedFileBase);
	pImgSectHdr = (PIMAGE_SECTION_HEADER)SECHDROFFSET(g_pMappedFileBase);

	// Do we have a valid pointer
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		// We grabbed wrong memory
		LogItem("IMAGE_DOS_SIGNATURE not found");
		goto FINISH;
	}
	if (*(DWORD *)NTSIGNATURE(g_pMappedFileBase) != IMAGE_NT_SIGNATURE)
	{
		// Not a valid PE file
		LogItem("IMAGE_NT_SIGNATURE not found");
		goto FINISH;
	}
	dwSize = pImgOptHdr->SizeOfImage;
	// Create a dumped dll file of security.dll (security.dll)
	if (PutSecurityDllFileName((LPCSTR)savebuffer))
	{
		// continue
	}
	else
	{
		memset(savebuffer, 0, sizeof(MAX_PATH));
		return;
	}
	// Find the last '\\' to obtain a pointer to just the base module name part
	pszPathName = strrchr((char *)savebuffer, '\\');
	if (pszPathName)  // We found a path, so advance to the base module name
	{
		pszPathName++;
	}
	hFile = CreateFile((LPCSTR)savebuffer,     // file to create
		GENERIC_READ | GENERIC_WRITE,          // open for read/write
		FILE_SHARE_READ | FILE_SHARE_WRITE,        // share
		NULL,                   // default security
		CREATE_ALWAYS,          // overwrite existing
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template
	if (hFile == INVALID_HANDLE_VALUE)
	{
		LogItem("CreateFile Error: %s", pszPathName);
		LogItem(NULL);
		goto FINISH;
	}
	// ----- WRITE FILE MEMORY TO DISK -----
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	if (!WriteFile(hFile, dwAddress, dwSize, &dwWritten, NULL))
	{
		LogItem("WriteFile Error: %s", pszPathName);
		LogItem(NULL);
		goto FINISH;
	}
	// ------ FORCE CALCULATED FILE SIZE ------
	SetFilePointer(hFile, dwSize, NULL, FILE_BEGIN);
	SetEndOfFile(hFile);
	// print success
	LogItem("Dump done!");
	LogItem("Saved to: %s", pszPathName);
FINISH:
	if (hFile)
	{
		CloseHandle(hFile);
		hFile = 0;
	}
	FreeVirtualMemory();
	return;
}

// Load security.dll file into process
void LoadSecurityDllFileName(HANDLE thisProcess)
{
	HANDLE	hFile5 = 0;
	dwArmVMAddress = 0;
	dwArmVMNSize = 0;
	if (GetSecurityDllFileName((LPCSTR)armbuffer))
	{
		// continue
	}
	else
	{
		memset(armbuffer, 0, sizeof(MAX_PATH));
		return;
	}
	// Find the last '\\' to obtain a pointer to just the base module name part
	pszPathName = strrchr((char *)armbuffer, '\\');
	if (pszPathName)  // We found a path, so advance to the base module name
	{
		pszPathName++;
	}
	if (LastUpdate > 0)
	{
		LastUpdate = 0;
	}
	LogItem("%s", isep);
	LogItem("Loading: %s", pszPathName);
	// Read the security dll file for the PE header data
	hFile5 = CreateFile((LPCSTR)armbuffer,     // file to create
		GENERIC_READ | GENERIC_WRITE,          // open for read/write
		FILE_SHARE_READ | FILE_SHARE_WRITE,       // share for read/write
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file
		NULL);                 // no attr. template
	if (hFile5 == INVALID_HANDLE_VALUE)
	{
		LogItem("CreateFile Error: %s", pszPathName);
		LogItem(NULL);
		return;
	}
	// Obtain ArmVM size 
	PvoidAddr = (PVOID)(DWORD_PTR)(Context.Esp + 8);
	if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &PvoidRead,
		sizeof(DWORD_PTR), &dwRead))
	{
		LogItem("ReadProcessMemory Error DetermineSecurityARMVM address: %p", PvoidAddr);
		LogItem(NULL);
		return;
	}
	if (PvoidRead != NULL)
	{
		dwArmVMNSize = (SIZE_T)PvoidRead;
	}
	else
	{
		return;
	}
	// Obtain ArmVM Address 
	PvoidAddr = (PVOID)(DWORD_PTR)(Context.Ebp - 48);
	if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &PvoidRead,
		sizeof(DWORD_PTR), &dwRead))
	{
		LogItem("ReadProcessMemory Error DetermineSecurityARMVM address: %p", PvoidAddr);
		LogItem(NULL);
		return;
	}
	if (PvoidRead != NULL)
	{
		dwArmVMAddress = PvoidRead;
	}
	else
	{
		return;
	}
	// Allocate some memory to dump the security.dll module process
	dwAddress = VirtualAlloc(
		NULL,
		dwArmVMNSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
		);
	if (dwAddress == NULL)
	{
		LogItem("VirtualAlloc Error load security dll");
		LogItem(NULL);
		goto ARMDONE;
	}
	ZeroMemory(dwAddress, dwArmVMNSize);
	dwSize = dwArmVMNSize;
	// Read the security dll file info into our process memory
	if (!ReadFile(hFile5, dwAddress, dwSize, &dwRead, NULL))
	{
		LogItem("ReadFile Error: %s", pszPathName);
		LogItem(NULL);
		goto ARMDONE;
	}
	g_pMappedFileBase = (PBYTE)dwAddress;
	dosHeader = (PIMAGE_DOS_HEADER)g_pMappedFileBase;
	pImgFileHdr = (PIMAGE_FILE_HEADER)PEFHDROFFSET(g_pMappedFileBase);
	pImgOptHdr = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET(g_pMappedFileBase);
	// 1st Section Header
	pImgSectHdr = (PIMAGE_SECTION_HEADER)SECHDROFFSET(g_pMappedFileBase);
	// Do we have a valid pointer
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		// We grabbed wrong memory
		LogItem("IMAGE_DOS_SIGNATURE not found");
		goto ARMDONE;
	}
	if (*(DWORD *)NTSIGNATURE(g_pMappedFileBase) != IMAGE_NT_SIGNATURE)
	{
		// Not a valid PE file
		LogItem("IMAGE_NT_SIGNATURE not found");
		goto ARMDONE;
	}
	PvoidAddr = dwArmVMAddress;
	dwSize = pImgOptHdr->SizeOfImage;
	// Write the security.dll module's process address space into our process memory
	if (!WriteProcessMemory(thisProcess, (LPVOID)PvoidAddr, dwAddress,
		dwSize, &dwWritten))
	{
		LogItem("WriteProcessMemory Error LoadSecurityDll address: %p", PvoidAddr);
		LogItem(NULL);
		goto ARMDONE;
	}
	LogItem("Load Done.");
ARMDONE:
	if (hFile5)
	{
		CloseHandle(hFile5);
		hFile5 = 0;
	}
	FreeVirtualMemory();
	return;
}

// Disassemble a dumped/fixed file
BOOL DisassembleDump(void)
{
	HANDLE	hFile5 = 0;
	char	hex[10] = "FFFFFFFF", *end;
	BOOL	prevint3 = FALSE;
	BOOL	prevretn = FALSE;
	BOOL	prevcall = FALSE;
	BOOL	addtotbl = FALSE;
	DWORD	thisaddress = 0;
	size_t		pszVAL = 0;
	size_t		pszINT3 = 0;
	size_t		pszRETN = 0;
	size_t		pszCALL = 0;
	size_t		pszINST = 0;
	pNumNanos = 0;

	// Resolve nanomites in saved dumped exe file
	if (GetDumpName((LPCSTR)filebuffer))
	{
		// continue
	}
	else
	{
		memset(filebuffer, 0, sizeof(MAX_PATH));
		return FALSE;
	}
	// Find the last '\\' to obtain a pointer to just the base module name part
	pszPathName = strrchr((char *)filebuffer, '\\');
	if (pszPathName)  // We found a path, so advance to the base module name
	{
		pszPathName++;
		strcpy(c, (const char *)pszPathName);
	}
	LogItem("------ Disassembling Dump ------");
	// Read the saved dump executable file for the PE header data
	hFile5 = CreateFile((LPCSTR)filebuffer,     // file to create
		GENERIC_READ | GENERIC_WRITE,          // open for read/write
		FILE_SHARE_READ | FILE_SHARE_WRITE,       // share for read/write
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file
		NULL);                 // no attr. template
	if (hFile5 == INVALID_HANDLE_VALUE)
	{
		LogItem("CreateFile error %s", c);
		LogItem(NULL);
		goto DISDONE;
	}
	// Allocate some memory to dump the 1st 4096 bytes of disk PE header data
	PEdwAddress = VirtualAlloc(
		NULL,
		PEdwSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
		);
	if (PEdwAddress == NULL)
	{
		LogItem("VirtualAlloc Error DisassembleDump");
		LogItem(NULL);
		goto DISDONE;
	}
	// Read the PE header file info into our process memory
	if (!ReadFile(hFile5, PEdwAddress, PEdwSize, &dwRead, NULL))
	{
		LogItem("ReadFile Error DisassembleDump");
		LogItem(NULL);
		goto DISDONE;
	}
	g_pMappedFileBase = (PBYTE)PEdwAddress;
	dosHeader = (PIMAGE_DOS_HEADER)g_pMappedFileBase;
	pImgFileHdr = (PIMAGE_FILE_HEADER)PEFHDROFFSET(g_pMappedFileBase);
	pImgOptHdr = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET(g_pMappedFileBase);
	// 1st Section Header
	pImgSectHdr = (PIMAGE_SECTION_HEADER)SECHDROFFSET(g_pMappedFileBase);
	// Do we have a valid pointer
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		// We grabbed wrong memory
		LogItem("IMAGE_DOS_SIGNATURE not found");
		LogItem("%s", c);
		goto DISDONE;
	}
	if (*(DWORD *)NTSIGNATURE(g_pMappedFileBase) != IMAGE_NT_SIGNATURE)
	{
		// Not a valid PE file
		LogItem("IMAGE_NT_SIGNATURE not found");
		LogItem("%s", c);
		goto DISDONE;
	}
	dwSize = pImgOptHdr->SizeOfImage;
	BaseOfImage = (LPVOID)pImgOptHdr->ImageBase;
	TextVMaddress = 0;
	TextVMsize = 0;
	// Get the 1st PE code section info
	int nSections = pImgFileHdr->NumberOfSections;
	if (pImgSectHdr)
	{
		/* Process each section */
		for (i = 0; i < 1; i++)
		{
			TextVMaddress = (LPVOID)((DWORD_PTR)pImgSectHdr->VirtualAddress + (DWORD_PTR)BaseOfImage);
			TextVMsize = pImgSectHdr->Misc.VirtualSize;
			pImgSectHdr++;
		}
	}
	// Free the PE header memory
	FreePEMemory();
	// Allocate some memory to dump the base module process
	dwAddress = VirtualAlloc(
		NULL,
		dwSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
		);
	if (dwAddress == NULL)
	{
		LogItem("VirtualAlloc Error DisassembleDump");
		LogItem(NULL);
		goto DISDONE;
	}
	// Reduce size for header just read
	dwSize -= 4096;
	// Read the rest of the file into our process memory
	if (!ReadFile(hFile5, dwAddress, dwSize, &dwRead, NULL))
	{
		LogItem("ReadFile Error DisassembleDump");
		LogItem(NULL);
		goto DISDONE;
	}
	// Process the dumped file
	// allocate a potential nanomite array
	try
	{
		TNano = new Nanomite[TextVMsize + 1];
	}
	catch (std::exception& e)
	{
		LogItem("Unable to allocate nanomites table!");
		goto DISDONE;
	}
	// Allocate some memory to store the string information for BeaEngine.dll
	retnsize = 0;
	lofinst = 0;
	memset(getstring, 0, sizeof(getstring));
	mystring = "";
	dwCalcAddress = (DWORD_PTR)TextVMaddress;
	dwDataAddress = (DWORD_PTR)dwAddress;

	LastUpdate = GetTickCount();
	LogItem("%s", isep);
	logitemreplace = TRUE;
	LogItem("%lu potential nanomites...", (DWORD)pNumNanos);

	memset(&MyDisasm, 0, sizeof(DISASM));
	len = 0;
	/* ============================= Init EIP */
	MyDisasm.EIP = (UIntPtr)dwDataAddress;
	/* ============================= Loop for Disasm */
	while (retnsize < TextVMsize)
	{
		MyDisasm.EIP += (UIntPtr)len;
		dwCalcAddress += len;
		dwDataAddress += len;
		retnsize += len;
		len = (ProcAdd)(&MyDisasm);
		if (len != UNKNOWN_OPCODE) 
		{
			memcpy(getstring, MyDisasm.CompleteInstr, sizeof(getstring));
			mystring.assign(getstring);
			if (GetTickCount() - LastUpdate > 200)
			{
				LastUpdate = GetTickCount();
				logitemreplace = TRUE;
				LogItem("%lu potential nanomites...", (DWORD)pNumNanos);
			}
			// Need to parse the data for INT3 instruction
			pszINT3 = mystring.find("int3");
			if (pszINT3 != std::string::npos)
			{
				// We have an INT3 instruction
				// If previous instruction was an INT3, bypass
				if (prevint3)
				{
					mystring.clear();
					memset(&getstring, 0, sizeof(getstring));
					// If we encounter an INT3 instruction that is followed
					// by another INT3 instr and we added the nanomite to the table
					// then decrement counter and remove item.
					if (addtotbl)
					{
						pNumNanos--;
						TNano[pNumNanos].Address = 0;
						addtotbl = FALSE;
					}
					continue;
				}
				else
				{
					prevint3 = TRUE;
				}
				// If previous instruction was a RETN, bypass
				if (prevretn)
				{
					prevint3 = FALSE;
					mystring.clear();
					memset(&getstring, 0, sizeof(getstring));
					continue;
				}
				// If previous instruction was a CALL, followed by the conditions below, bypass
				if (prevcall)
				{
					// Need to parse the data for PUSH -1 instruction
					pszINST = mystring.find("push FF");
					if (pszINST != std::string::npos)
					{
						prevint3 = FALSE;
						mystring.clear();
						memset(&getstring, 0, sizeof(getstring));
						continue;
					}
					// Need to parse the data for MOV EDI,EDI instruction
					pszINST = mystring.find("mov edi,edi");
					if (pszINST != std::string::npos)
					{
						prevint3 = FALSE;
						mystring.clear();
						memset(&getstring, 0, sizeof(getstring));
						continue;
					}
				}
				// this may be a potential nanomite. Strip out the address, add to table
				TNano[pNumNanos].Address = dwCalcAddress;
				TNano[pNumNanos].Destination = 0;
				TNano[pNumNanos].Size = 0;
				TNano[pNumNanos].JumpType = 0;
				addtotbl = TRUE;
				pNumNanos++;
			}
			else
			{
				prevint3 = FALSE;
			}
			// Need to parse the data for RETN instruction
			pszRETN = mystring.find("ret");
			if (pszRETN != std::string::npos)
			{
				// We have a RETN instruction
				prevretn = TRUE;
			}
			else
			{
				prevretn = FALSE;
			}
			// Need to parse the data for CALL instruction
			pszCALL = mystring.find("call");
			if (pszCALL != std::string::npos)
			{
				// We have a CALL instruction
				prevcall = TRUE;
			}
			else
			{
				prevcall = FALSE;
			}
			mystring.clear();
			memset(&getstring, 0, sizeof(getstring));
		}
		else 
		{
			len = 1;
		}
	}

DISDONE:
	logitemreplace = TRUE;
	LogItem("%s potential nanomites...", pNumNanos);
	if (hFile5)
	{
		CloseHandle(hFile5);
		hFile = 0;
	}
	FreePEMemory();
	FreeVirtualMemory();
	return TRUE;
}

// Patch saved dumpfile of target process using nanomite vector
// Resolves nanomites by replacing the original code with fixed code directly
BOOL ResolveDump(void)
{
	HANDLE	hFile5 = 0;
	DWORD_PTR	rawaddr = 0;
	char	rawbuffer[TEXTLEN] = { 0 };
	DWORD	resolvednanos = 0;
	BOOL    error = FALSE;
	BYTE    dumpbyte = 0;
	// Do we have any data to resolve?
	if (NumNanos == 0)
	{
		LogItem("Please Load a nanomites *anf file to continue!");
		EnableWindow(hwnd15, FALSE);
		EnableWindow(hwnd07, FALSE);
		return FALSE;
	}
	// Resolve nanomites in saved dumped exe file
	if (GetDumpName((LPCSTR)filebuffer))
	{
		// continue
	}
	else
	{
		memset(filebuffer, 0, sizeof(MAX_PATH));
		return FALSE;
	}
	// Find the last '\\' to obtain a pointer to just the base module name part
	pszPathName = strrchr((char *)filebuffer, '\\');
	if (pszPathName)  // We found a path, so advance to the base module name
	{
		pszPathName++;
		strcpy(c, (const char *)pszPathName);
	}
	LogItem("------ Resolving Nanomites ------");
	// Read the saved dump executable file for the PE header data
	hFile5 = CreateFile((LPCSTR)filebuffer,     // file to create
		GENERIC_READ | GENERIC_WRITE,          // open for read/write
		FILE_SHARE_READ | FILE_SHARE_WRITE,       // share for read/write
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file
		NULL);                 // no attr. template
	if (hFile5 == INVALID_HANDLE_VALUE)
	{
		LogItem("CreateFile error %s %d", c, GetLastError());
		return FALSE;
	}
	// Allocate some memory to dump the 1st 4096 bytes of disk PE header data
	PEdwAddress = VirtualAlloc(
		NULL,
		PEdwSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
		);
	if (PEdwAddress == NULL)
	{
		LogItem("VirtualAlloc Error ResolveDump");
		LogItem(NULL);
		error = TRUE;
		goto RESOLVEDONE;
		;
	}
	// Read the PE header file info into our process memory
	if (!ReadFile(hFile5, PEdwAddress, PEdwSize, &dwRead, NULL))
	{
		LogItem("ReadFile Error ResolveDump");
		LogItem(NULL);
		error = TRUE;
		goto RESOLVEDONE;
	}
	g_pMappedFileBase = (PBYTE)PEdwAddress;
	dosHeader = (PIMAGE_DOS_HEADER)g_pMappedFileBase;
	pImgFileHdr = (PIMAGE_FILE_HEADER)PEFHDROFFSET(g_pMappedFileBase);
	pImgOptHdr = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET(g_pMappedFileBase);
	// 1st Section Header
	pImgSectHdr = (PIMAGE_SECTION_HEADER)SECHDROFFSET(g_pMappedFileBase);
	// Do we have a valid pointer
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		// We grabbed wrong memory
		LogItem("IMAGE_DOS_SIGNATURE not found");
		LogItem("%s", c);
		error = TRUE;
		goto RESOLVEDONE;
	}
	if (*(DWORD *)NTSIGNATURE(g_pMappedFileBase) != IMAGE_NT_SIGNATURE)
	{
		// Not a valid PE file
		LogItem("IMAGE_NT_SIGNATURE not found");
		LogItem("%s", c);
		error = TRUE;
		goto RESOLVEDONE;
	}
	dwSize = pImgOptHdr->SizeOfImage;
	BaseOfImage = (LPVOID)pImgOptHdr->ImageBase;
	TextVMaddress = 0;
	TextVMsize = 0;
	// Get the 1st PE code section info
	int nSections = pImgFileHdr->NumberOfSections;
	if (pImgSectHdr)
	{
		/* Process each section */
		for (i = 0; i < 1; i++)
		{
			TextVMaddress = (LPVOID)((DWORD_PTR)pImgSectHdr->VirtualAddress + (DWORD_PTR)BaseOfImage);
			TextVMsize = pImgSectHdr->Misc.VirtualSize;
			pImgSectHdr++;
		}
	}
	// Reduce size for header just read
	dwSize -= 4096;
	// Allocate some memory to dump the base module process
	dwAddress = VirtualAlloc(
		NULL,
		dwSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
		);
	if (dwAddress == NULL)
	{
		LogItem("VirtualAlloc Error ResolveDump");
		LogItem(NULL);
		error = TRUE;
		goto RESOLVEDONE;
	}
	// Read the rest of the file into our process memory
	if (!ReadFile(hFile5, dwAddress, dwSize, &dwRead, NULL))
	{
		LogItem("ReadFile Error ResolveDump");
		LogItem(NULL);
		error = TRUE;
		goto RESOLVEDONE;
	}
	// Allocate some memory to store the string information for BeaEngine.dll
	retnsize = 0;
	lofinst = 0;
	memset(getstring, 0, sizeof(getstring));
	mystring = "";
	// Process the nanomite vector
	for (int i = 0; i < NumNanos; i++)
	{
		memset(cjumptype, 0, sizeof(cjumptype));
		memset(cjumpdest, 0, sizeof(cjumpdest));
		memset(ccmd, 0, sizeof(ccmd));
		memset(s, 0, sizeof(s));
		switch (RNano[i].JumpType)
		{
		case 0:
			sprintf(cjumptype, "%s", "JUnknown");
			break;
		case 1:
			sprintf(cjumptype, "%s", "NotNanomite");
			break;
		case 2:
		case 25:
			sprintf(cjumptype, "%s", "JMP");
			break;
		case 3:
			sprintf(cjumptype, "%s", "JNZ");
			break;
		case 4:
			sprintf(cjumptype, "%s", "JZ");
			break;
		case 5:
			sprintf(cjumptype, "%s", "JB");
			break;
		case 6:
			sprintf(cjumptype, "%s", "JBE");
			break;
		case 7:
			sprintf(cjumptype, "%s", "JA");
			break;
		case 8:
			sprintf(cjumptype, "%s", "JNB");
			break;
		case 9:
			sprintf(cjumptype, "%s", "JG");
			break;
		case 10:
			sprintf(cjumptype, "%s", "JGE");
			break;
		case 11:
			sprintf(cjumptype, "%s", "JL");
			break;
		case 12:
			sprintf(cjumptype, "%s", "JLE");
			break;
		case 13:
			sprintf(cjumptype, "%s", "JP");
			break;
		case 14:
			sprintf(cjumptype, "%s", "JPE");
			break;
		case 15:
			sprintf(cjumptype, "%s", "JNP");
			break;
		case 16:
			sprintf(cjumptype, "%s", "JPO");
			break;
		case 17:
			sprintf(cjumptype, "%s", "JS");
			break;
		case 18:
			sprintf(cjumptype, "%s", "JNS");
			break;
		case 19:
			sprintf(cjumptype, "%s", "JCXZ");
			break;
		case 20:
			sprintf(cjumptype, "%s", "JNCXZ");
			break;
		case 21:
			sprintf(cjumptype, "%s", "JC");
			break;
		case 22:
			sprintf(cjumptype, "%s", "JNC");
			break;
		case 23:
			sprintf(cjumptype, "%s", "JO");
			break;
		case 24:
			sprintf(cjumptype, "%s", "JNO");
			break;
		default:
			sprintf(cjumptype, "%s", "JUnknown");
			break;
		}
		sprintf(cjumpdest, "%08X", RNano[i].Dest);
		// Create our text command to convert
		sprintf(ccmd, "%s %s", cjumptype, cjumpdest);
		memset(&am, 0, sizeof(am));
		pasm = (char *)ccmd;
		// Assemble the command above. First try form with 32-bit immediate.
		// Ex: pasm="JZ 004040BF";
		j = 0;
		j = Assemble(pasm, RNano[i].Address, &am, 0, 0, (char *)errtext);
		if (j <= 0)
		{
			// We have an error! bypass this nanomite address
			LogItem("error= %s", errtext);
			LogItem("Address: %08X", RNano[i].Address);
			LogItem("Jumptype: %s", cjumptype);
			LogItem("Jumpdest: %08X", RNano[i].Dest);
		}
		else
		{
			// Determine raw dump address (offset)
			rawaddr = RNano[i].Address - (DWORD_PTR)BaseOfImage - ((DWORD_PTR)pImgSectHdr->VirtualAddress - (DWORD_PTR)pImgSectHdr->PointerToRawData);
			// Set file position accordingly
			SetFilePointer(hFile5, (DWORD_PTR)rawaddr, NULL, FILE_BEGIN);
			dumpbyte = 0;
			ReadFile(hFile5, (LPVOID)&dumpbyte, sizeof(BYTE), &dwRead, NULL);
			if (dumpbyte == 0xCC)
			{
				SetFilePointer(hFile5, (DWORD_PTR)rawaddr, NULL, FILE_BEGIN);
				WriteFile(hFile5, (LPCVOID)am.code, sizeof(BYTE)*j, &dwWritten, NULL);
				resolvednanos++;
			}
		}
		n = 0;
	}
	LogItem("%lu INT3 processed...", (DWORD)NumNanos);
	LogItem("%lu INT3 resolved...", resolvednanos);
	LogItem("Done.");
RESOLVEDONE:
	if (hFile5)
	{
		CloseHandle(hFile5);
		hFile5 = 0;
	}
	if (RNano)
	{
		delete[] RNano;
		RNano = 0;
		NumNanos = 0;
	}
	FreePEMemory();
	FreeVirtualMemory();
	if (error)
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

// Patch target process using nanomite vector
// Resolves nanomites by replacing the original code with fixed code directly
BOOL ResolveProcess(HANDLE thisProcess)
{
	DWORD	rawaddr = 0;
	char	rawbuffer[TEXTLEN] = { 0 };
	DWORD	resolvednanos = 0;
	DWORD	dwFileOffset = 0;
	BYTE    readbyte = 0;
	// load a previously saved nanomite *anf file
	if (LoadNanoAnf())
	{
		LogItem("------ Resolving Nanomites ------");
		// Process the nanomite vector
		for (int i = 0; i < NumNanos; i++)
		{
			memset(cjumptype, 0, sizeof(cjumptype));
			memset(cjumpdest, 0, sizeof(cjumpdest));
			memset(ccmd, 0, sizeof(ccmd));
			memset(s, 0, sizeof(s));
			switch (RNano[i].JumpType)
			{
			case 0:
				sprintf(cjumptype, "%s", "JUnknown");
				break;
			case 1:
				sprintf(cjumptype, "%s", "NotNanomite");
				break;
			case 2:
			case 25:
				sprintf(cjumptype, "%s", "JMP");
				break;
			case 3:
				sprintf(cjumptype, "%s", "JNZ");
				break;
			case 4:
				sprintf(cjumptype, "%s", "JZ");
				break;
			case 5:
				sprintf(cjumptype, "%s", "JB");
				break;
			case 6:
				sprintf(cjumptype, "%s", "JBE");
				break;
			case 7:
				sprintf(cjumptype, "%s", "JA");
				break;
			case 8:
				sprintf(cjumptype, "%s", "JNB");
				break;
			case 9:
				sprintf(cjumptype, "%s", "JG");
				break;
			case 10:
				sprintf(cjumptype, "%s", "JGE");
				break;
			case 11:
				sprintf(cjumptype, "%s", "JL");
				break;
			case 12:
				sprintf(cjumptype, "%s", "JLE");
				break;
			case 13:
				sprintf(cjumptype, "%s", "JP");
				break;
			case 14:
				sprintf(cjumptype, "%s", "JPE");
				break;
			case 15:
				sprintf(cjumptype, "%s", "JNP");
				break;
			case 16:
				sprintf(cjumptype, "%s", "JPO");
				break;
			case 17:
				sprintf(cjumptype, "%s", "JS");
				break;
			case 18:
				sprintf(cjumptype, "%s", "JNS");
				break;
			case 19:
				sprintf(cjumptype, "%s", "JCXZ");
				break;
			case 20:
				sprintf(cjumptype, "%s", "JNCXZ");
				break;
			case 21:
				sprintf(cjumptype, "%s", "JC");
				break;
			case 22:
				sprintf(cjumptype, "%s", "JNC");
				break;
			case 23:
				sprintf(cjumptype, "%s", "JO");
				break;
			case 24:
				sprintf(cjumptype, "%s", "JNO");
				break;
			default:
				sprintf(cjumptype, "%s", "JUnknown");
				break;
			}
			sprintf(cjumpdest, "%08X", RNano[i].Dest);
			// Create our text command to convert
			sprintf(ccmd, "%s %s", cjumptype, cjumpdest);
			memset(&am, 0, sizeof(am));
			pasm = (char *)ccmd;
			// Assemble the command above. First try form with 32-bit immediate.
			// Ex: pasm="JZ 004040BF";
			j = 0;
			j = Assemble(pasm, RNano[i].Address, &am, 0, 0, (char *)errtext);
			if (j <= 0)
			{
				// We have an error! bypass this nanomite address
				LogItem("error= %s", errtext);
				LogItem("Address: %08X", RNano[i].Address);
				LogItem("Jumptype: %s", cjumptype);
				LogItem("Jumpdest: %08X", RNano[i].Dest);
			}
			else
			{
				// Determine raw dump address (offset)
				rawaddr = RNano[i].Address;
				readbyte = 0;
				if (!ReadProcessMemory(thisProcess, (LPVOID)rawaddr, &readbyte,
					sizeof(BYTE), &dwRead))
				{
					LogItem("ReadProcessMemory Error ResolveProcess address: %08X", rawaddr);
					LogItem(NULL);
				}
				else
				{
					if (readbyte = 0xCC)
					{
						if (!WriteProcessMemory(thisProcess, (LPVOID)rawaddr, &am.code,
							sizeof(BYTE)*j, &dwWritten))
						{
							LogItem("WriteProcessMemory Error ResolveProcess address: %08X", rawaddr);
							LogItem(NULL);
						}
						else
						{
							resolvednanos++;
						}
					}
				}
			}
			n = 0;
		}
		LogItem("%lu INT3 processed...", (DWORD)NumNanos);
		LogItem("%lu INT3 resolved...", resolvednanos);
		LogItem("Done.");
		if (RNano)
		{
			delete[] RNano;
			RNano = 0;
			NumNanos = 0;
		}
	}
	return TRUE;
}

/* hide debugger */
BOOL HideDebugger(HANDLE thisProcess, HANDLE thisThread)
{
	SIZE_T		RVApeb = 0;
	DWORD		fsbase = 0;
	SIZE_T		numread = 0;
	WORD		beingDebugged = 0;

	// Get Thread context
	Context.ContextFlags = CONTEXT_SEGMENTS;
	GetThreadContext(thisThread, &Context);
	if (!GetThreadSelectorEntry(thisThread, Context.SegFs, &sel))
	{
		LogItem("Context error! GetThreadSelectorEntry Failed");
		return FALSE;
	}
	fsbase = (sel.HighWord.Bytes.BaseHi << 8 | sel.HighWord.Bytes.BaseMid) << 16 |
		sel.BaseLow;
	if (!ReadProcessMemory(thisProcess, (LPCVOID)(fsbase + 0x30), &RVApeb, 4, &numread) ||
		numread != 4)
	{
		LogItem("ReadProcessMemory Error HideDebugger address: %08X", (fsbase + 0x30));
		LogItem(NULL);
		return FALSE;
	}
	//PEB!IsDebugged
	//mov eax, fs:[30h] 
	//mov eax, byte [eax+2] 
	//test eax, eax 
	//jne @DebuggerDetected 
	if (!ReadProcessMemory(thisProcess, (LPCVOID)(RVApeb + 2), &beingDebugged, 2, &numread) ||
		numread != 2)
	{
		LogItem("ReadProcessMemory Error HideDebugger address: %08X", (RVApeb + 2));
		LogItem(NULL);
		return FALSE;
	}
	beingDebugged = 0;
	if (!WriteProcessMemory(thisProcess, (LPVOID)(RVApeb + 2), &beingDebugged, 2, &numread) ||
		numread != 2)
	{
		LogItem("WriteProcessMemory Error HideDebugger address: %08X", (RVApeb + 2));
		LogItem(NULL);
		return FALSE;
	}
	//PEB!NtGlobalFlags
	//mov eax, [eax+68h] 
	//and eax, 0x70 
	//test eax, eax 
	//jne @DebuggerDetected 
	if (!ReadProcessMemory(thisProcess, (LPCVOID)(RVApeb + 104), &beingDebugged, 2, &numread) ||
		numread != 2)
	{
		LogItem("ReadProcessMemory Error HideDebugger address: %08X", (RVApeb + 104));
		LogItem(NULL);
		return FALSE;
	}
	beingDebugged = 0;
	if (!WriteProcessMemory(thisProcess, (LPVOID)(RVApeb + 104), &beingDebugged, 2, &numread) ||
		numread != 2)
	{
		LogItem("WriteProcessMemory Error HideDebugger address: %08X", (RVApeb + 104));
		LogItem(NULL);
		return FALSE;
	}
	return TRUE;
}
/* Reserved for future use				*/
/* Informational way to obtain debug creation flag */
static DWORD DebugQueryProcessOptions(HANDLE hProcess)
{
	static NTQUERYINFORMATIONPROCESS g_NtQueryInformationProcess = 0;
	if (g_NtQueryInformationProcess == 0)
	{
		hNTModule = GetModuleHandle((LPCSTR)"ntdll.dll");
		if (!hNTModule)
		{
			LogItem("Module: ntdll.dll; Function: GetModuleHandle Failed");
			return GetLastError();
		}
		g_NtQueryInformationProcess =
			(NTQUERYINFORMATIONPROCESS)GetProcAddress(hNTModule, (LPCSTR)"NtQueryInformationProcess");
		if (!g_NtQueryInformationProcess)
		{
			LogItem("GetProcAddress Failed; NtQueryInformationProcess");
			return GetLastError();
		}
	}
	return g_NtQueryInformationProcess(hProcess, ProcessDebugFlags, &DebugFlags, sizeof(DebugFlags), NULL);
}
/* Reserved for future use				*/
/* Informational way to set debug creation flag */
static DWORD DebugSetProcessOptions(HANDLE hProcess)
{
	static NTSETINFORMATIONPROCESS g_NtSetInformationProcess = 0;
	if (g_NtSetInformationProcess == 0)
	{
		hNTModule = GetModuleHandle((LPCSTR)"ntdll.dll");
		if (!hNTModule)
		{
			LogItem("Module: ntdll.dll; Function: GetModuleHandle Failed");
			return GetLastError();
		}
		g_NtSetInformationProcess =
			(NTSETINFORMATIONPROCESS)GetProcAddress(hNTModule, (LPCSTR)"NtSetInformationProcess");
		if (!g_NtSetInformationProcess)
		{
			LogItem("GetProcAddress Failed; NtSetInformationProcess");
			return GetLastError();
		}
	}
	return g_NtSetInformationProcess(hProcess, ProcessDebugFlags, &DebugFlags, sizeof(DebugFlags));
}
/* Reset all Software Breakpoints (privilege instruction)*/
BOOL ClearSWBPS(HANDLE thisProcess)
{
	for (int i = 0; i < 20; i++)
	{
		// Turn off SWBP's except WaitForDebugEvent
		if (SWBPExceptionAddress[i] != 0x00000000 && scanbyte[i] != 0x00 && i != 5 && i != 7)
		{
			if (i == 3)
			{	// PUT BACK THE ORIGINAL BYTE for WriteProcessMemory
				if (!WriteProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[i], &scanbyte[i],
					sizeof(BYTE), &dwWritten))
				{
					LogItem("WriteProcessMemory Error ClearSWBPS address: %p", SWBPExceptionAddress[i]);
					LogItem(NULL);
					breaknow = TRUE;
					break;
				}
				// zero out VirtualAlloc SWBP
				SWBPExceptionAddress[i] = 0x00000000;
			}
			else // PUT BACK THE ORIGINAL BYTE for VirtualAlloc
			if (!WriteProcessMemory(thisProcess, (LPVOID)SWBPExceptionAddress[i], &scanbyte[i],
				sizeof(BYTE), &dwWritten))
			{
				LogItem("WriteProcessMemory Error ClearSWBPS address: %p", SWBPExceptionAddress[i]);
				LogItem(NULL);
				breaknow = TRUE;
				break;
			}
			// zero out VirtualAlloc SWBP
			SWBPExceptionAddress[i] = 0x00000000;
		}
	}
	if (breaknow)
		return FALSE;
	else
		return TRUE;
}

/* Reset context EIP on SWBP'S */
void Reset_EIP(HANDLE thisProcess, HANDLE thisThread, unsigned int indexSWBP)
{
	// Get Thread context
	Context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(thisThread, &Context);
	// PUT BACK THE ORIGINAL BYTE
	if (!WriteProcessMemory(thisProcess, (LPVOID)SWBPExceptionAddress[indexSWBP], &scanbyte[indexSWBP],
		sizeof(BYTE), &dwWritten))
	{
		LogItem("WriteProcessMemory Error Reset_EIP address: %p", SWBPExceptionAddress[indexSWBP]);
		LogItem(NULL);
		breaknow = TRUE;
		return;
	}
	return;
}

/* Determine how much of the actual Armadillo VM is being used for execution of code */
BOOL DetermineARMVM(HANDLE thisProcess, int mode)
{
	// bypass the PE header info
	dwCalcAddress = (DWORD_PTR)dwArmVMAddress + 4096;
	dwArmVMNAddress = (LPVOID)dwCalcAddress;
	dwArmVMNSize = 0;
	dwArmVMNSize += 4096;
	for (j = 0; j < 10; j++)
	{
		dwRead = VirtualQueryEx(
			thisProcess,
			dwArmVMNAddress,
			&mbi,
			sizeof(mbi)
			);
		if (dwRead)
		{
			// For this protection, increment Armadillo VM size
			if (mbi.Protect == PAGE_EXECUTE_READWRITE ||
				mbi.Protect == PAGE_EXECUTE_READ)
			{
				// Update the Actual armadillo VM info
				dwCalcAddress += (DWORD_PTR)mbi.RegionSize;
				dwArmVMNAddress = (LPVOID)dwCalcAddress;
				dwArmVMNSize += (SIZE_T)mbi.RegionSize;
			}
			else
			{
				// Include non executable data in calculation?
				if (mode == 1)
				{
					if (mbi.Protect == PAGE_READWRITE ||
						mbi.Protect == PAGE_READONLY)
					{
						// Update the Actual armadillo VM info
						dwCalcAddress += (DWORD_PTR)mbi.RegionSize;
						dwArmVMNAddress = (LPVOID)dwCalcAddress;
						dwArmVMNSize += (SIZE_T)mbi.RegionSize;
					}
				}
				else
				{
					j = 10;
					break;
				}
			}
		}
		else
		{
			j = 10;
			return FALSE;
		}
	}
	return TRUE;
}

/*
The following function activates the SeDebugPrivilege for the current process.
First, it accesses current process token by calling OpenProcessToken
with the appropriate rights. Then, it looks up the LUID value associated
with the SE_DEBUG_NAME string defined in winnt.h by calling LookupPrivilegeValue.
Finally it activates this privilege through a call to AdjustTokenPrivileges,
passing it a properly filled TOKEN_PRIVILEGES structure.
*/
int LoadSeDebugPrivilege(void)
{
	HANDLE hToken = 0;
	LUID Val;
	TOKEN_PRIVILEGES tp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES
		| TOKEN_QUERY, &hToken))
		return(GetLastError());

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Val))
		return(GetLastError());

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = Val;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp,
		sizeof(tp), NULL, NULL))
		return(GetLastError());

	CloseHandle(hToken);

	return 1;
}

/* Determine location and override instructions to modify */
/* Standard HW Fingerprint */
BOOL DetermineStdHardwareFingerprint(HANDLE thisProcess, int errmode)
{
	BOOL	find2ndcall = TRUE;
	// Allocate some memory for operation
	dwBMVMAddress = VirtualAlloc(NULL, dwArmVMNSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (dwBMVMAddress == NULL)
	{
		LogItem("VirtualAlloc Error DetermineStdHardwareFingerprint");
		LogItem(NULL);
		return FALSE;
	}
	// Read the Armadillo VM address space into our process memory
	if (!ReadProcessMemory(thisProcess, dwArmVMAddress, dwBMVMAddress,
		dwArmVMNSize, &dwRead))
	{
		LogItem("ReadProcessMemory Error DetermineStdHardwareFingerprint address: %p", dwArmVMAddress);
		LogItem(NULL);
		return FALSE;
	}
	dwFileSize = dwArmVMNSize;		//Size of search space
	dwAddress = dwBMVMAddress;		//Search begin address
	// not using wildcards
	bWildcard = FALSE;
	// Search for DATELASTRUN
	DoSearch(1, 4);
	// Search String not found! 
	if (!sf)
	{
		if (errmode == 0)
			return FALSE;
		LogItem("Armadillo DATELASTRUN search string not found!");
		if (checkforerrors)
		{
			CreateDump(thisProcess, 1);
			FreeVirtualMemory();
			FreePEMemory();
			breaknow = TRUE;
		}
		return FALSE;
	}
	else
	{
		dwOffset = ((DWORD_PTR)((HPSTR)sf - (HPSTR)ss));
	}
	// Set a pointer to our search offset armadillo VM code
	dwBMVMOffset = ((DWORD_PTR)dwArmVMAddress + dwOffset);
	// Now we need to find the PUSH dwBMVMOffset instruction
	// Convert dwBMVMOffset from big endian to little endian format
	dwBMVMOffset = ByteSwap2(dwBMVMOffset);
	// Copy dwBMVMOffset to hexpattern array with beg hex string
	sprintf(b, "%02X", BEGFP);
	sprintf(b + 2, "%08X", dwBMVMOffset);
	ZeroMemory(&hextext, sizeof(hextext));
	memcpy(hextext, (unsigned char *)b, 10);
	// Search for the 1st occurrence of PUSH dwBMVMOffset instruction
	// Turn off Wildcards
	bWildcard = FALSE;
	DoSearch(2, 0);
	// Search String not found! 
	if (!sf)
	{
		if (errmode == 0)
			return FALSE;
		LogItem("Armadillo DATELASTRUN search string not found!");
		if (checkforerrors)
		{
			CreateDump(thisProcess, 1);
			FreeVirtualMemory();
			FreePEMemory();
			breaknow = TRUE;
		}
		return FALSE;
	}
	else
	{
		dwOffset = ((DWORD_PTR)((HPSTR)sf - (HPSTR)ss));
	}
	// Find the 2nd CALL instruction
	instrcount = 0;
	dwCalcAddress = (DWORD_PTR)dwAddress;
	while (find2ndcall)
	{
		if (*(BYTE *)(dwCalcAddress + dwOffset) == 0xE8)
		{
			instrcount++;
			if (instrcount > 1)
			{
				find2ndcall = FALSE;
				break;
			}
		}
		if (dwOffset > dwFileSize)
		{
			LogItem("2nd CALL after DATELASTRUN not found!");
			if (checkforerrors)
			{
				CreateDump(thisProcess, 1);
				FreeVirtualMemory();
				FreePEMemory();
				breaknow = TRUE;
			}
			return FALSE;
		}
		memset(&MyDisasm, 0, sizeof(DISASM));
		len = 0;
		/* ============================= Init EIP */
		MyDisasm.EIP = (UIntPtr)dwCalcAddress + dwOffset;
		MyDisasm.VirtualAddr = (UInt64)dwArmVMAddress + dwOffset;
		/* ============================= Loop for Disasm */
		len = (ProcAdd)(&MyDisasm);
		if (len != UNKNOWN_OPCODE)
		{
			dwOffset += len;
		}
		else
		{
			dwOffset++;
		}
	}
	// disassembler call instruction for destination address
	// Assemble new instructions on this address
	memset(&MyDisasm, 0, sizeof(DISASM));
	len = 0;
	/* ============================= Init EIP */
	MyDisasm.EIP = (UIntPtr)dwCalcAddress + dwOffset;
	MyDisasm.VirtualAddr = (UInt64)dwArmVMAddress + dwOffset;
	/* ============================= Loop for Disasm */
	len = (ProcAdd)(&MyDisasm);
	if (len != UNKNOWN_OPCODE)
	{
		jmpconst = (DWORD_PTR)MyDisasm.Instruction.AddrValue;
		DwordRead = jmpconst;
	}
	for (instrcount = 0; instrcount < 2; instrcount++)
	{
		// Create instructions
		memset(cjumptype, 0, sizeof(cjumptype));
		memset(cjumpdest, 0, sizeof(cjumpdest));
		memset(ccmd, 0, sizeof(ccmd));
		switch (instrcount)
		{
		case 0:
			sprintf(ccmd, "%s %s", cjumptype, cjumpdest);
			pasm = (char *)ccmd;
			memset(&am, 0, sizeof(am));
			memcpy(&bhwfp, &dwstdfp, sizeof(DWORD_PTR));
			am.code[0] = 0xB8;
			am.code[1] = bhwfp.bhwfp1;
			am.code[2] = bhwfp.bhwfp2;
			am.code[3] = bhwfp.bhwfp3;
			am.code[4] = bhwfp.bhwfp4;
			j = 5;
			break;
		case 1:
			sprintf(ccmd, "%s", cjumptype);
			pasm = (char *)ccmd;
			memset(&am, 0, sizeof(am));
			am.code[0] = 0xC2;
			am.code[1] = 0x04;
			am.code[2] = 0x00;
			j = 3;
			break;
		}
		if (j <= 0)
		{
			// We have an error!
			LogItem("Standard Fingerprint enabled");
			LogItem("error= %s", errtext);
			LogItem("Address: %08X", DwordRead);
			LogItem("Binary Code: %s", am.code);
			return FALSE;
		}
		else
		{
			PvoidAddr = (PVOID)DwordRead;
			// Write the new instruction
			if (WriteProcessMemory(thisProcess, (LPVOID)PvoidAddr, &am.code,
				j, &dwWritten))
			{
				DwordRead += j;
			}
			else
			{
				LogItem("WriteProcessMemory Error DetermineStdHardwareFingerprint address: %p", PvoidAddr);
				LogItem(NULL);
				return FALSE;
			}
		}
	}
	memset(&hwfp, 0, sizeof(hwfp));
	memcpy(&hwfp, &dwstdfp, sizeof(DWORD_PTR));
	LogItem("Standard fingerprint enabled: %04X-%04X", hwfp.hwfp2, hwfp.hwfp1);
	return TRUE;
}

/* Determine location and override instructions to modify */
/* Enhanced HW Fingerprint */
BOOL DetermineEnhHardwareFingerprint(HANDLE thisProcess, int errmode)
{
	BOOL	find2ndcall = TRUE;
	// Allocate some memory for operation
	dwBMVMAddress = VirtualAlloc(NULL, dwArmVMNSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (dwBMVMAddress == NULL)
	{
		LogItem("VirtualAlloc Error DetermineEnhHardwareFingerprint");
		LogItem(NULL);
		return FALSE;
	}
	// Read the Armadillo VM address space into our process memory
	if (!ReadProcessMemory(thisProcess, dwArmVMAddress, dwBMVMAddress,
		dwArmVMNSize, &dwRead))
	{
		LogItem("ReadProcessMemory Error DetermineEnhHardwareFingerprint address: %p", dwArmVMAddress);
		LogItem(NULL);
		return FALSE;
	}
	dwFileSize = dwArmVMNSize;		//Size of search space
	dwAddress = dwBMVMAddress;		//Search begin address
	// not using wildcards
	bWildcard = FALSE;
	// Search for FINGERPRINT
	DoSearch(1, 5);
	// Search String not found! 
	if (!sf)
	{
		if (errmode == 0)
			return FALSE;
		LogItem("Armadillo FINGERPRINT search string not found!");
		if (checkforerrors)
		{
			CreateDump(thisProcess, 1);
			FreeVirtualMemory();
			FreePEMemory();
			breaknow = TRUE;
		}
		return FALSE;
	}
	else
	{
		dwOffset = ((DWORD_PTR)((HPSTR)sf - (HPSTR)ss));
	}
	// Set a pointer to our search offset armadillo VM code
	dwBMVMOffset = ((DWORD_PTR)dwArmVMAddress + dwOffset);
	// Now we need to find the PUSH dwBMVMOffset instruction
	// Convert dwBMVMOffset from big endian to little endian format
	dwBMVMOffset = ByteSwap2(dwBMVMOffset);
	// Copy dwBMVMOffset to hexpattern array with beg hex string
	sprintf(b, "%02X", BEGFP);
	sprintf(b + 2, "%08X", dwBMVMOffset);
	ZeroMemory(&hextext, sizeof(hextext));
	memcpy(hextext, (unsigned char *)b, 10);
	// Search for the 1st occurrence of PUSH dwBMVMOffset instruction
	// Turn off Wildcards
	bWildcard = FALSE;
	DoSearch(2, 0);
	// Search String not found! 
	if (!sf)
	{
		if (errmode == 0)
			return FALSE;
		LogItem("Armadillo FINGERPRINT search string not found!");
		if (checkforerrors)
		{
			CreateDump(thisProcess, 1);
			FreeVirtualMemory();
			FreePEMemory();
			breaknow = TRUE;
		}
		return FALSE;
	}
	else
	{
		dwOffset = ((DWORD_PTR)((HPSTR)sf - (HPSTR)ss));
	}
	// Find the 2nd CALL instruction
	instrcount = 0;
	dwCalcAddress = (DWORD_PTR)dwAddress;
	while (find2ndcall)
	{
		if (*(BYTE *)(dwCalcAddress + dwOffset) == 0xE8)
		{
			instrcount++;
			if (instrcount > 1)
			{
				find2ndcall = FALSE;
				break;
			}
		}
		if (dwOffset > dwFileSize)
		{
			LogItem("2nd CALL after FINGERPRINT not found!");
			if (checkforerrors)
			{
				CreateDump(thisProcess, 1);
				FreeVirtualMemory();
				FreePEMemory();
				breaknow = TRUE;
			}
			return FALSE;
		}
		memset(&MyDisasm, 0, sizeof(DISASM));
		len = 0;
		/* ============================= Init EIP */
		MyDisasm.EIP = (UIntPtr)dwCalcAddress + dwOffset;
		MyDisasm.VirtualAddr = (UInt64)dwArmVMAddress + dwOffset;
		/* ============================= Loop for Disasm */
		len = (ProcAdd)(&MyDisasm);
		if (len != UNKNOWN_OPCODE)
		{
			dwOffset += len;
		}
		else
		{
			dwOffset++;
		}
	}
	memset(&MyDisasm, 0, sizeof(DISASM));
	len = 0;
	/* ============================= Init EIP */
	MyDisasm.EIP = (UIntPtr)dwCalcAddress + dwOffset;
	MyDisasm.VirtualAddr = (UInt64)dwArmVMAddress + dwOffset;
	/* ============================= Loop for Disasm */
	len = (ProcAdd)(&MyDisasm);
	if (len != UNKNOWN_OPCODE)
	{
		jmpconst = (DWORD_PTR)MyDisasm.Instruction.AddrValue;
		DwordRead = jmpconst;
	}
	for (instrcount = 0; instrcount < 2; instrcount++)
	{
		// Create instructions
		memset(cjumptype, 0, sizeof(cjumptype));
		memset(cjumpdest, 0, sizeof(cjumpdest));
		memset(ccmd, 0, sizeof(ccmd));
		switch (instrcount)
		{
		case 0:
			sprintf(ccmd, "%s %s", cjumptype, cjumpdest);
			pasm = (char *)ccmd;
			memset(&am, 0, sizeof(am));
			memcpy(&bhwfp, &dwenhfp, sizeof(DWORD_PTR));
			am.code[0] = 0xB8;
			am.code[1] = bhwfp.bhwfp1;
			am.code[2] = bhwfp.bhwfp2;
			am.code[3] = bhwfp.bhwfp3;
			am.code[4] = bhwfp.bhwfp4;
			j = 5;
			break;
		case 1:
			sprintf(ccmd, "%s", cjumptype);
			pasm = (char *)ccmd;
			memset(&am, 0, sizeof(am));
			am.code[0] = 0xC2;
			am.code[1] = 0x04;
			am.code[2] = 0x00;
			j = 3;
			break;
		}
		if (j <= 0)
		{
			// We have an error!
			LogItem("Enhanced Fingerprint enabled");
			LogItem("error= %s", errtext);
			LogItem("Address: %08X", DwordRead);
			LogItem("Binary Code: %s", am.code);
			return FALSE;
		}
		else
		{
			// Write the new instruction
			PvoidAddr = (PVOID)DwordRead;
			if (WriteProcessMemory(thisProcess, (LPVOID)PvoidAddr, &am.code,
				j, &dwWritten))
			{
				DwordRead += j;
			}
			else
			{
				LogItem("WriteProcessMemory Error DetermineEnhHardwareFingerprint address: %p", PvoidAddr);
				LogItem(NULL);
				return FALSE;
			}
		}
	}
	memset(&hwfp, 0, sizeof(hwfp));
	memcpy(&hwfp, &dwenhfp, sizeof(DWORD_PTR));
	LogItem("Enhanced fingerprint enabled: %04X-%04X", hwfp.hwfp2, hwfp.hwfp1);
	return TRUE;
}

/* Determine location and override instructions to modify */
/* Serial HW Fingerprint */
BOOL DetermineSerialFingerprint(HANDLE thisProcess, int errmode)
{
	// No need to allocate memory as this should have
	// been done previously with standard / enhanced FP functions
	dwFileSize = dwArmVMNSize;		//Size of search space
	dwAddress = dwBMVMAddress;		//Search begin address
	// using wildcards
	bWildcard = TRUE;
	// Search for ARMADILLO V5.X FINGERPRINT
	DoSearch(1, 7);
	// Search String not found! 
	if (!sf)
	{
		// Search for ARMADILLO V6.X FINGERPRINT
		dwAddress = dwBMVMAddress;		//Search begin address
		DoSearch(1, 8);
		if (!sf)
		{
			if (errmode == 0)
				return FALSE;
			LogItem("Armadillo SERIAL FINGERPRINT search string not found");
			LogItem("Earlier releases i.e. v3.x,4.x can be safely ignored!");
			if (checkforerrors)
			{
				CreateDump(thisProcess, 1);
				FreeVirtualMemory();
				FreePEMemory();
				breaknow = TRUE;
			}
			return FALSE;
		}
		dwOffset = ((DWORD_PTR)((HPSTR)sf - (HPSTR)ss)) + 6;
		bhwfpversion = 1;
	}
	else
	{
		dwOffset = ((DWORD_PTR)((HPSTR)sf - (HPSTR)ss)) + 14;
		bhwfpversion = 0;
	}
	// Set a pointer to our search offset armadillo VM code
	DwordRead = ((DWORD_PTR)dwArmVMAddress + dwOffset);
	memset(&bhwfp, 0, sizeof(bhwfp));
	// Assemble new instructions on this address
	if (usingstdfp)
	{
		memcpy(&bhwfp, &dwstdfp, sizeof(DWORD_PTR));
	}
	else
	{
		memcpy(&bhwfp, &dwenhfp, sizeof(DWORD_PTR));
	}
	if (bhwfpversion == 0)
	{
		bhwfp5bytes[1] = bhwfp.bhwfp1;
		bhwfp5bytes[2] = bhwfp.bhwfp2;
		bhwfp5bytes[3] = bhwfp.bhwfp3;
		bhwfp5bytes[4] = bhwfp.bhwfp4;
		PvoidAddr = (PVOID)DwordRead;
		// Write the new instruction
		if (WriteProcessMemory(thisProcess, (LPVOID)PvoidAddr, &bhwfp5bytes,
			sizeof(bhwfp5bytes), &dwWritten))
		{
			goto CONTHWFP;
		}
		else
		{
			goto HWFPERROR;
		}
	}
	else if (bhwfpversion == 1)
	{
		bhwfp6bytes[1] = bhwfp.bhwfp1;
		bhwfp6bytes[2] = bhwfp.bhwfp2;
		bhwfp6bytes[3] = bhwfp.bhwfp3;
		bhwfp6bytes[4] = bhwfp.bhwfp4;
		PvoidAddr = (PVOID)DwordRead;
		// Write the new instruction
		if (WriteProcessMemory(thisProcess, (LPVOID)PvoidAddr, &bhwfp6bytes,
			sizeof(bhwfp6bytes), &dwWritten))
		{
			goto CONTHWFP;
		}
		else
		{
			goto HWFPERROR;
		}
	}
	else
	{
		goto CONTHWFP;
	}
HWFPERROR:
	LogItem("WriteProcessMemory Error DetermineSerialFingerprint address: %p", PvoidAddr);
	LogItem(NULL);
	return FALSE;
CONTHWFP:
	memset(&hwfp, 0, sizeof(hwfp));
	if (usingstdfp)
	{
		memcpy(&hwfp, &dwstdfp, sizeof(DWORD_PTR));
	}
	else
	{
		memcpy(&hwfp, &dwenhfp, sizeof(DWORD_PTR));
	}
	LogItem("Serial fingerprint enabled: %04X-%04X", hwfp.hwfp2, hwfp.hwfp1);
	return TRUE;
}

/* Determine if Strategic Code Splicing used by interrogating VirtualAlloc params */
/* 3RD CALL VIRTUALALLOC API SWBP */
BOOL DetermineStrategicCodeSplicing(HANDLE thisProcess, HANDLE thisThread)
{
	// Obtain return address pointer if necessary
	PvoidAddr = (PVOID)(DWORD_PTR)Context.Esp;
	if (!ReadProcessMemory(thisProcess, PvoidAddr, &PvoidRead,
		sizeof(DWORD_PTR), &dwRead))
	{
		LogItem("ReadProcessMemory Error DetermineStrategicCodeSplicing address: %p", PvoidAddr);
		LogItem(NULL);
		return FALSE;
	}
	// See if the Call was made from Arm VM
	// This value should fall within Armadillo VM
	if (DetermineARMVM(thisProcess, 1))
	{
		if (PvoidRead >= dwArmVMAddress &&
			PvoidRead <= (PVOID)((DWORD_PTR)dwArmVMAddress + dwArmVMNSize))
		{
			// continue
		}
		else
		{
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}
	// Read Esp + 4 to obtain VirtualAlloc address
	PvoidAddr = (LPVOID)((DWORD_PTR)Context.Esp + 4);
	if (!ReadProcessMemory(thisProcess, PvoidAddr, &PvoidRead,
		sizeof(DWORD_PTR), &dwRead))
	{
		LogItem("ReadProcessMemory Error DetermineStrategicCodeSplicing address: %p", PvoidAddr);
		LogItem(NULL);
		return FALSE;
	}
	// Note: The strategic code splicing address requested is not
	// always in hi-memory!!
	if (PvoidRead != 0)
	{
		// Save the Original VM address
		CSOAddress = PvoidRead;
		// Read Esp + 8 to obtain VirtualAlloc size pointer
		PvoidAddr = (LPVOID)((DWORD_PTR)Context.Esp + 8);
		if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &PvoidRead,
			sizeof(DWORD_PTR), &dwRead))
		{
			LogItem("ReadProcessMemory Error DetermineStrategicCodeSplicing address: %p", PvoidAddr);
			LogItem(NULL);
			return FALSE;
		}
		// Is the size >= 10000 hex
		if ((SIZE_T)PvoidRead >= 65536)
		{
			// Save the original size
			CSOSize = (SIZE_T)PvoidRead;
			// Read Esp + 12 to obtain VirtualAlloc allocation type
			PvoidAddr = (LPVOID)((DWORD_PTR)Context.Esp + 12);
			if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &PvoidRead,
				sizeof(DWORD_PTR), &dwRead))
			{
				LogItem("ReadProcessMemory Error DetermineStrategicCodeSplicing address: %p", PvoidAddr);
				LogItem(NULL);
				return FALSE;
			}
			if ((SIZE_T)PvoidRead == MEM_RESERVE)
			{
				// Read Esp + 16 to obtain VirtualAlloc allocation protect
				PvoidAddr = (LPVOID)((DWORD_PTR)Context.Esp + 16);
				if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &PvoidRead,
					sizeof(DWORD_PTR), &dwRead))
				{
					LogItem("ReadProcessMemory Error DetermineStrategicCodeSplicing address: %p", PvoidAddr);
					LogItem(NULL);
					return FALSE;
				}
				// We have code splicing. Is redirection option chosen?
				if ((SIZE_T)PvoidRead == PAGE_EXECUTE_READWRITE)
				{
					if (redirectsplicing)
					{
						// Return [Section] of our choice in Register EAX return value
						// 1st choice is .adata section
						// Insure we have read/write to the section
						if (!VirtualProtectEx(thisProcess, (LPVOID)AdataVMaddress,
							AdataVMsize, PERWProtect, &PEOldProtect))
						{
							LogItem("VirtualProtect error on .adata section");
							LogItem("Address: %p for strategic code splicing", AdataVMaddress);
							return FALSE;
						}
						// Allocate some zero memory for operation
						dwZMVMAddress = VirtualAlloc(NULL, AdataVMsize,
							MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
						if (dwZMVMAddress == NULL)
						{
							LogItem("VirtualAlloc Error DetermineStrategicCodeSplicing");
							LogItem(NULL);
						}
						else if (!WriteProcessMemory(thisProcess, AdataVMaddress, dwZMVMAddress,
							AdataVMsize, &dwWritten))
						{
							LogItem("WriteProcessMemory Error DetermineStrategicCodeSplicing address: %p", AdataVMaddress);
							LogItem(NULL);
							FreeArmZMMemory();
							return FALSE;
						}
						// Return [Section] of our choice in Register EAX return value
						// 1st choice is .adata section
						CSAddress = AdataVMaddress;
						CSSize = AdataVMsize;
						Context.Eax = (DWORD_PTR)CSAddress;
						SetThreadContext(thisThread, &Context);
						FreeArmZMMemory();
					}
					firsttime = FALSE;
					secondtime = TRUE;
					return TRUE;
				}
				else
				{
					CSOAddress = 0;
					CSOSize = 0;
				}
			}
			else
			{
				CSOAddress = 0;
				CSOSize = 0;
			}
		}
		else
		{
			CSOAddress = 0;
		}
	}
	return FALSE;
}
/* Verify that VirtualAlloc params agree with previous function */
/* 4TH CALL VIRTUALALLOC API SWBP */
BOOL VerifyStrategicCodeSplicing(HANDLE thisProcess, HANDLE thisThread)
{
	// Obtain return address pointer if necessary
	PvoidAddr = (PVOID)(DWORD_PTR)Context.Esp;
	if (!ReadProcessMemory(thisProcess, PvoidAddr, &PvoidRead,
		sizeof(DWORD_PTR), &dwRead))
	{
		LogItem("ReadProcessMemory Error VerifyStrategicCodeSplicing address: %p", PvoidAddr);
		LogItem(NULL);
		return FALSE;
	}
	// See if the Call was made from Arm VM
	// This value should fall within Armadillo VM
	if (DetermineARMVM(thisProcess, 1))
	{
		if (PvoidRead >= dwArmVMAddress &&
			PvoidRead <= (PVOID)((DWORD_PTR)dwArmVMAddress + dwArmVMNSize))
		{
			// continue
		}
		else
		{
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}
	// Read Esp + 8 to obtain VirtualAlloc size pointer
	PvoidAddr = (LPVOID)((DWORD_PTR)Context.Esp + 8);
	if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &PvoidRead,
		sizeof(DWORD_PTR), &dwRead))
	{
		LogItem("ReadProcessMemory Error VerifyStrategicCodeSplicing address: %p", PvoidAddr);
		LogItem(NULL);
		return FALSE;
	}
	if ((SIZE_T)PvoidRead == CSOSize)
	{
		// Read Esp + 4 to obtain VirtualAlloc address
		PvoidAddr = (LPVOID)((DWORD_PTR)Context.Esp + 4);
		if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &PvoidRead,
			sizeof(DWORD_PTR), &dwRead))
		{
			LogItem("ReadProcessMemory Error VerifyStrategicCodeSplicing address: %p", PvoidAddr);
			LogItem(NULL);
			return FALSE;
		}
		// If not, then previous allocated memory could be low-mem address
		// and this could be determination step
		if (PvoidRead == CSOAddress)
		{
			// Read Esp + 12 to obtain VirtualAlloc allocation type
			PvoidAddr = (LPVOID)((DWORD_PTR)Context.Esp + 12);
			if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &PvoidRead,
				sizeof(DWORD_PTR), &dwRead))
			{
				LogItem("ReadProcessMemory Error VerifyStrategicCodeSplicing address: %p", PvoidAddr);
				LogItem(NULL);
				return FALSE;
			}
			if ((SIZE_T)PvoidRead == MEM_COMMIT)
			{
				// Read Esp + 16 to obtain VirtualAlloc allocation protect
				PvoidAddr = (LPVOID)((DWORD_PTR)Context.Esp + 16);
				if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &PvoidRead,
					sizeof(DWORD_PTR), &dwRead))
				{
					LogItem("ReadProcessMemory Error VerifyStrategicCodeSplicing address: %p", PvoidAddr);
					LogItem(NULL);
					return FALSE;
				}
				// We have code splicing
				if ((SIZE_T)PvoidRead == PAGE_EXECUTE_READWRITE)
				{
					LogItem("%s", isep);
					if (redirectsplicing)
					{
						LogItem("Strategic Code Splicing Disabled!");
						LogItem("Code Splicing Section: .adata");
					}
					else
					{
						LogItem("Strategic Code Splicing Enabled!");
						LogItem("Code Splicing Section: .text");
					}
					LogItem("Old VMaddress: %p", CSOAddress);
					LogItem("Old VMsize: %08X", CSOSize);
					if (redirectsplicing)
					{
						LogItem("New VMaddress: %p", CSAddress);
						LogItem("New VMsize: %08X", CSSize);
						if (CSOSize > CSSize)
						{
							LogItem("Warning: Old VM size > New VM size");
						}
						// Return [Section] of our choice in Register EAX return value
						// 1st choice is .adata section
						Context.Eax = (DWORD_PTR)CSAddress;
						SetThreadContext(thisThread, &Context);
					}
					secondtime = FALSE;
					return TRUE;
				}
			}
		}
		else
		{
			cserror = TRUE;
			return FALSE;
		}
	}
	return FALSE;
}

/* Determine if we have a variable defined for IAT redirection */
BOOL DetermineIATVariableRedirection(HANDLE thisProcess, int errmode)
{
	//Use same search space as defined for iat elimination
	//Search for the IAT variable redirection
	dwFileSize = dwArmVMNSize;		//Size of search space
	dwAddress = dwBMVMAddress;		//Search begin address
	// Using wildcards
	bWildcard = TRUE;
	// Search for IAT elimination
	DoSearch(1, 6);
	// Search String not found! 
	if (!sf)
	{
		if (errmode == 0)
			return FALSE;
		LogItem("Armadillo variable redirection search string not found");
		if (checkforerrors)
		{
			CreateDump(thisProcess, 1);
			FreeVirtualMemory();
			FreePEMemory();
			breaknow = TRUE;
		}
		return FALSE;
	}
	else
	{
		dwOffset = ((DWORD_PTR)((HPSTR)sf - (HPSTR)ss));
	}
	// Set a pointer to our search offset armadillo VM code
	// Note: +6 is the displacement address that contains the variable value:
	dwBMVMOffset = ((DWORD_PTR)dwArmVMAddress + dwOffset) + 6;
	PvoidAddr = (PVOID)dwBMVMOffset;
	// Read the Armadillo VM address for the IAT elimination stack address
	if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &IATREDIVARREAD,
		sizeof(DWORD_PTR), &dwRead))
	{
		LogItem("ReadProcessMemory Error DetermineIATVariableRedirection address: %p", PvoidAddr);
		LogItem(NULL);
		return FALSE;
	}
	//Replace variable dword pointer with 0's
	if (IATREDIVARREAD != 0)
	{
		if (!ReadProcessMemory(thisProcess, (LPVOID)IATREDIVARREAD, &PvoidRead,
			sizeof(DWORD_PTR), &dwRead))
		{
			LogItem("ReadProcessMemory Error DetermineIATVariableRedirection address: %p", IATREDIVARREAD);
			LogItem(NULL);
			return FALSE;
		}
		if (!WriteProcessMemory(thisProcess, IATREDIVARREAD, &IATREDIVARWRITE,
			sizeof(DWORD_PTR), &dwWritten))
		{
			LogItem("WriteProcessMemory Error DetermineIATVariableRedirection address: %p", IATREDIVARREAD);
			LogItem(NULL);
			return FALSE;
		}
		variableredirectfound = TRUE;
		LogItem("%s", isep);
		LogItem("IAT Variable Redirection Disabled!");
		LogItem("VM address: %08X", dwBMVMOffset);
		LogItem("VM variable: %p", IATREDIVARREAD);
	}
	return TRUE;
}
/* Determine if we have IAT elimination */
BOOL DetermineIATElimination(HANDLE thisProcess, int errmode)
{
	FreeArmBMMemory();
	// Allocate some memory for operation
	dwBMVMAddress = VirtualAlloc(NULL, dwArmVMNSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (dwBMVMAddress == NULL)
	{
		LogItem("VirtualAlloc Error for IAT Elimination");
		LogItem(NULL);
		return FALSE;
	}
	// Read the Armadillo VM address space into our process memory
	if (!ReadProcessMemory(thisProcess, dwArmVMAddress, dwBMVMAddress,
		dwArmVMNSize, &dwRead))
	{
		LogItem("ReadProcessMemory Error DetermineIATElimination address: %p", dwArmVMAddress);
		LogItem(NULL);
		return FALSE;
	}
	//Search for the IAT elimination
	dwFileSize = dwArmVMNSize;		//Size of search space
	dwAddress = dwBMVMAddress;		//Search begin address
	// Using wildcards
	bWildcard = TRUE;
	// Search for IAT elimination
	DoSearch(1, 1);
	// Search String not found!
	if (!sf)
	{
		if (errmode == 0)
			return FALSE;
		LogItem("Armadillo IAT elimination search string not found!");
		if (checkforerrors)
		{
			CreateDump(thisProcess, 1);
			FreeVirtualMemory();
			FreePEMemory();
			breaknow = TRUE;
		}
		return FALSE;
	}
	else
	{
		dwOffset = ((DWORD_PTR)((HPSTR)sf - (HPSTR)ss));
	}
	// Save this offset, we'll use it later for iat redirection
	SavedwOffset = dwOffset;
	// Set a pointer to our search offset armadillo VM code
	// Note: +2 is the displacement address that contains the value:
	dwBMVMOffset = ((DWORD_PTR)dwArmVMAddress + dwOffset) + 2;
	PvoidAddr = (PVOID)dwBMVMOffset;
	// Read the Armadillo VM address for the IAT elimination stack address
	if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &IATELIMREAD,
		sizeof(DWORD_PTR), &dwRead))
	{
		LogItem("ReadProcessMemory Error DetermineIATElimination address: %p", PvoidAddr);
		LogItem(NULL);
		return FALSE;
	}
	if (IATELIMREAD != 0)
	{
		// Calculate address displacement
		IATELIMDISP = 0x00000000 - (DWORD_PTR)IATELIMREAD;
		// Convert IATELIMREAD from big endian to little endian format
		IATELIMREAD = (PVOID)ByteSwap2((DWORD_PTR)IATELIMREAD);
		// Copy IATELIMREAD to hexpattern array with beg / end hex strings
		sprintf(b, "%04X", BEGSTRING);
		sprintf(b + 4, "%p", IATELIMREAD);
		sprintf(b + 12, "%02X", ENDSTRING);
		ZeroMemory(&hextext, sizeof(hextext));
		memcpy(hextext, (unsigned char *)b, 14);
		// Search for the 1st occurrences of IATELIMREAD DWORD
		// This s/b the first CMP instruction
		// Turn off Wildcards
		bWildcard = FALSE;
		DoSearch(2, 0);
		// Search String not found! 
		if (!sf)
		{
			LogItem("Armadillo IAT elimination search string not found!");
			if (checkforerrors)
			{
				CreateDump(thisProcess, 1);
				FreeVirtualMemory();
				FreePEMemory();
				breaknow = TRUE;
			}
			return FALSE;
		}
		else
		{
			dwOffset = ((DWORD_PTR)((HPSTR)sf - (HPSTR)ss));
		}
		// Set a pointer to our search offset armadillo VM code
		dwBMVMOffset = (DWORD_PTR)dwArmVMAddress + dwOffset;
		// Set a SWBP on this address
		SWBPExceptionAddress[9] = (PVOID)dwBMVMOffset;
		if (!ReadProcessMemory(thisProcess, (LPVOID)SWBPExceptionAddress[9], &scanbyte[9],
			sizeof(BYTE), &dwRead))
		{
			LogItem("ReadProcessMemory Error DetermineIATElimination address: %p", SWBPExceptionAddress[9]);
			LogItem(NULL);
			return FALSE;
		}
		if (!WriteProcessMemory(thisProcess, (LPVOID)SWBPExceptionAddress[9], &replbyte[9],
			sizeof(BYTE), &dwWritten))
		{
			LogItem("WriteProcessMemory Error DetermineIATElimination address: %p", SWBPExceptionAddress[9]);
			LogItem(NULL);
			return FALSE;
		}
	}
	return TRUE;
}
/* Determine if we have IAT elimination */
BOOL DetermineIATEliminationAlternate(HANDLE thisProcess, int errmode)
{
	FreeArmBMMemory();
	// Allocate some memory for operation
	dwBMVMAddress = VirtualAlloc(NULL, dwArmVMNSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (dwBMVMAddress == NULL)
	{
		LogItem("VirtualAlloc Error for IAT Elimination");
		LogItem(NULL);
		return FALSE;
	}
	// Read the Armadillo VM address space into our process memory
	if (!ReadProcessMemory(thisProcess, dwArmVMAddress, dwBMVMAddress,
		dwArmVMNSize, &dwRead))
	{
		LogItem("ReadProcessMemory Error DetermineIATEliminationAlternate address: %p", dwArmVMAddress);
		LogItem(NULL);
		return FALSE;
	}
	//Search for the IAT elimination
	dwFileSize = dwArmVMNSize;		//Size of search space
	dwAddress = dwBMVMAddress;		//Search begin address
	// Using wildcards
	bWildcard = TRUE;
	// Search for IAT elimination alternate
	DoSearch(1, 11);
	// Search String not found!
	if (!sf)
	{
		if (errmode == 0)
			return FALSE;
		LogItem("Armadillo IAT elimination alternate search string not found!");
		if (checkforerrors)
		{
			CreateDump(thisProcess, 1);
			FreeVirtualMemory();
			FreePEMemory();
			breaknow = TRUE;
		}
		return FALSE;
	}
	else
	{
		dwOffset = ((DWORD_PTR)((HPSTR)sf - (HPSTR)ss));
	}
	// Set a pointer to our search offset armadillo VM code
	// Note: +30 is the displacement address that contains the value:
	dwBMVMOffset = ((DWORD_PTR)dwArmVMAddress + dwOffset) + 30;
	PvoidAddr = (PVOID)dwBMVMOffset;
	// Read the Armadillo VM address for the IAT elimination stack address
	if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &IATELIMREAD,
		sizeof(DWORD_PTR), &dwRead))
	{
		LogItem("ReadProcessMemory Error DetermineIATElimination address: %p", PvoidAddr);
		LogItem(NULL);
		return FALSE;
	}
	// Is it a JNE instruction?
	if ((DWORD_PTR)IATELIMREAD == 0xEFE90575)
	{
		// If yes, write 2 NOP's to this address to bypass
		if (!WriteProcessMemory(thisProcess, (LPVOID)PvoidAddr, &TWONOPS,
			sizeof(WORD), &dwWritten))
		{
			LogItem("WriteProcessMemory Error DetermineIATEliminationAlternate address: %p", PvoidAddr);
			LogItem(NULL);
			return FALSE;
		}
		LogItem("%s", isep);
		LogItem("IAT Elimination Alternate Disabled!");
		LogItem("VM address: %p", PvoidAddr);
	}
	return TRUE;
}
/* Set RETN for IAT redirection function in Arm VM code */
BOOL DetermineIATRedirection(HANDLE thisProcess, int errmode)
{
	//Search for the IAT redirection
	//Recalculate address & size based on previous iat elimination search
	//for the found search string offset
	dwFileSize -= SavedwOffset;		//Size of search space
	dwCalcAddress = (DWORD_PTR)dwBMVMAddress + SavedwOffset;
	SavedwBMVMAddress = (LPVOID)dwCalcAddress;
	dwAddress = SavedwBMVMAddress;		//Search begin address
	// Turn off wildcards
	bWildcard = FALSE;
	// Search for IAT redirection 1st string "PUSH 100"
	DoSearch(1, 2);
	// Search String not found! 
	if (!sf)
	{
		if (errmode == 0)
			return FALSE;
		LogItem("Armadillo fixed redirection search string not found!");
		if (checkforerrors)
		{
			CreateDump(thisProcess, 1);
			FreeVirtualMemory();
			FreePEMemory();
			breaknow = TRUE;
		}
		return FALSE;
	}
	else
	{
		dwOffset = ((DWORD_PTR)((HPSTR)sf - (HPSTR)ss));
	}
	SavedwOffset = dwOffset;
	//Recalculate address & size based on previous iat redirection search
	dwFileSize -= SavedwOffset;			//Size of search space
	dwCalcAddress += SavedwOffset;
	SavedwBMVMAddress = (LPVOID)dwCalcAddress;
	dwAddress = SavedwBMVMAddress;		//Search begin address
	dwBMVMOffset = (DWORD_PTR)dwArmVMAddress + ((DWORD_PTR)SavedwBMVMAddress - (DWORD_PTR)dwBMVMAddress);
	// Turn on Wildcards
	bWildcard = TRUE;
	DoSearch(1, 3);
	// Search String not found!
	if (!sf)
	{
		if (errmode == 0)
			return FALSE;
		LogItem("Armadillo fixed redirection search string not found!");
		if (checkforerrors)
		{
			CreateDump(thisProcess, 1);
			FreeVirtualMemory();
			FreePEMemory();
			breaknow = TRUE;
		}
		return FALSE;
	}
	else
	{
		dwOffset = ((DWORD_PTR)((HPSTR)sf - (HPSTR)ss));
	}
	SavedwOffset = dwOffset;
	dwCalcAddress += SavedwOffset;
	SavedwBMVMAddress = (LPVOID)dwCalcAddress;
	// The CALL address is +1 from our current offset pointer
	// Calculate new offset = Original Armadillo VM base address pointer + 
	// (saved BM address pointer - Original BM base address pointer) + new offset + 1
	dwBMVMOffset = (DWORD_PTR)dwArmVMAddress + ((DWORD_PTR)SavedwBMVMAddress - (DWORD_PTR)dwBMVMAddress) + 1;
	// Read the Armadillo VM memory to obtain address for the IAT redirection CALL address
	PvoidAddr = (PVOID)dwBMVMOffset;
	if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &IATREDIREAD,
		sizeof(DWORD_PTR), &dwRead))
	{
		LogItem("ReadProcessMemory Error DetermineIATRedirection address: %p", PvoidAddr);
		LogItem(NULL);
		return FALSE;
	}
	if (IATREDIREAD != 0)
	{
		// Calculate address displacement from current address
		IATREDIDISP = 0x00000000 - (DWORD_PTR)IATREDIREAD;
		// Calculate CALL address location
		IATREDIDIFF = (dwBMVMOffset + 4) - IATREDIDISP;
		// Function look like below for v5.x and >
		//55                   PUSH EBP			<< Write RETN instr 'C3' here
		//8BEC                 MOV EBP,ESP
		//83EC 2C              SUB ESP,2C
		//833D 00B60A01 00     CMP DWORD PTR DS:[10AB600],0	
		IATREDIREAD = 0;
		PvoidAddr = (PVOID)IATREDIDIFF;
		if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &IATREDIREAD,
			sizeof(DWORD_PTR), &dwRead))
		{
			LogItem("ReadProcessMemory Error DetermineIATRedirection address: %p", PvoidAddr);
			LogItem(NULL);
			return FALSE;
		}
		if (IATREDIREAD != 0)
		{
			//Write the RETN instruction at this armadillo VM offset address
			if (!WriteProcessMemory(thisProcess, (LPVOID)PvoidAddr, &retnbyte,
				sizeof(BYTE), &dwWritten))
			{
				LogItem("WriteProcessMemory Error DetermineIATRedirection address: %p", PvoidAddr);
				LogItem(NULL);
				return FALSE;
			}
			LogItem("%s", isep);
			LogItem("IAT Fixed Redirection Disabled!");
			LogItem("VM address: %08X", dwBMVMOffset);
		}
	}
	return TRUE;
}
/* Set variable for IAT redirection function in Arm VM code */
BOOL DetermineIATRedirectionAlternate(HANDLE thisProcess, int errmode)
{
	//Search for the IAT redirection alternate
	dwFileSize = dwArmVMNSize;		//Size of search space
	dwAddress = dwBMVMAddress;		//Search begin address
	// Using wildcards
	bWildcard = TRUE;
	// Search for IAT redirection alternate
	DoSearch(1, 10);
	// Search String not found!
	if (!sf)
	{
		if (errmode == 0)
		{
			checkredirect = TRUE;
			return FALSE;
		}
		LogItem("Armadillo IAT redirection search string not found!");
		if (checkforerrors)
		{
			CreateDump(thisProcess, 1);
			FreeVirtualMemory();
			FreePEMemory();
			breaknow = TRUE;
		}
		return FALSE;
	}
	else
	{
		dwOffset = ((DWORD_PTR)((HPSTR)sf - (HPSTR)ss));
	}
	// Set a pointer to our search offset armadillo VM code
	// Note: +14 is the displacement address that contains the DWORD PTR ADDRESS:
	dwBMVMOffset = ((DWORD_PTR)dwArmVMAddress + dwOffset) + 14;
	// Read the Armadillo VM memory to obtain address for the IAT redirection CMP address
	PvoidAddr = (PVOID)dwBMVMOffset;
	if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &IATREDIREAD,
		sizeof(DWORD_PTR), &dwRead))
	{
		LogItem("ReadProcessMemory Error DetermineIATRedirectionAlternate address: %p", PvoidAddr);
		LogItem(NULL);
		return FALSE;
	}
	if (IATREDIREAD != 0)
	{
		PVOID newvalue = 0x00000000;
		// Write our new value for this variable pointing to our target	
		if (!WriteProcessMemory(thisProcess, IATREDIREAD, &newvalue,
			sizeof(DWORD_PTR), &dwWritten))
		{
			LogItem("WriteProcessMemory Error DetermineIATRedirectionAlternate address: %p", IATREDIREAD);
			LogItem(NULL);
			return FALSE;
		}
		LogItem("%s", isep);
		LogItem("IAT Fixed Redirection Disabled!");
		LogItem("VM address: %08X", dwBMVMOffset);
		LogItem("VM variable: %p", IATREDIREAD);
	}
	return TRUE;
}
/* Perform redirection of IAT elimination VM code to program code */
BOOL DoIATElimination(HANDLE thisProcess)
{
	// Perform calculations to determine stack displacement
	// address pointer and value contained
	IATELIMDIFF = Context.Ebp - IATELIMDISP;
	// Read this Armadillo VM stack address pointer for IAT elimination address
	// Note: if this address ptr value = 0, then no elimination
	// else, we substitute a value [SECTION] address of our choosing
	IATELIMREAD = 0;
	PvoidAddr = (PVOID)(DWORD_PTR)IATELIMDIFF;
	if (!ReadProcessMemory(thisProcess, (LPVOID)PvoidAddr, &IATELIMREAD,
		sizeof(DWORD_PTR), &dwRead))
	{
		LogItem("ReadProcessMemory Error DoIATElimination address: %p", PvoidAddr);
		LogItem(NULL);
		return FALSE;
	}
	// IAT elimination
	if (IATELIMREAD != 0)
	{
		IATELIMSAVE = IATELIMREAD;
		if (Data1VMaddress != 0)
		{
			// Note: We'll only reference last 6000 hex bytes
			// Insure we have read/write to the .data1 section
			if (!VirtualProtectEx(thisProcess, Data1VMaddress,
				Data1VMsize, PERWProtect, &PEOldProtect))
			{
				LogItem("VirtualProtectEx Error DoIATElimination address: %p", Data1VMaddress);
				LogItem(NULL);
				return FALSE;
			}
			// Allocate some zero memory for operation (15% of actual size or 6000 bytes)
			float sizezm = .15 * (float)Data1VMsize;
			if (sizezm < 24576)
				sizezm = 24576;
			SIZE_T dwsizezm = (SIZE_T)sizezm;
			Data1NVMaddress = (LPVOID)(((DWORD_PTR)Data1VMaddress + Data1VMsize) - dwsizezm);
			Data1NVMsize = Data1VMsize - dwsizezm;
			dwZMVMAddress = VirtualAlloc(NULL, Data1NVMsize,
				MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (dwZMVMAddress == NULL)
			{
				LogItem("VirtualAlloc error .data1 section DoIATElimination");
				LogItem(NULL);
				return FALSE;
			}
			if (!WriteProcessMemory(thisProcess, Data1NVMaddress, dwZMVMAddress,
				Data1NVMsize, &dwWritten))
			{
				LogItem("WriteProcessMemory Error DoIATElimination address: %p", Data1NVMaddress);
				LogItem(NULL);
				FreeArmZMMemory();
				return FALSE;
			}
			IATELIMREAD = Data1NVMaddress;
			sprintf(c, ".data1");
			FreeArmZMMemory();
		}
		else if (IdataVMaddress != 0)
		{
			// Insure we have read/write to the .idata section
			if (!VirtualProtectEx(thisProcess, (LPVOID)IdataVMaddress,
				IdataVMsize, PERWProtect, &PEOldProtect))
			{
				LogItem("VirtualProtectEx Error DoIATElimination address: %p", IdataVMaddress);
				LogItem(NULL);
				return FALSE;
			}
			// Allocate some zero memory for operation
			dwZMVMAddress = VirtualAlloc(NULL, IdataVMsize,
				MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (dwZMVMAddress == NULL)
			{
				LogItem("VirtualAlloc error .idata section DoIATElimination");
				LogItem(NULL);
				return FALSE;
			}
			if (!WriteProcessMemory(thisProcess, IdataVMaddress, dwZMVMAddress,
				IdataVMsize, &dwWritten))
			{
				LogItem("WriteProcessMemory Error DoIATElimination address: %p", IdataVMaddress);
				LogItem(NULL);
				FreeArmZMMemory();
				return FALSE;
			}
			IATELIMREAD = IdataVMaddress;
			sprintf(c, ".idata");
			FreeArmZMMemory();
		}
		else if (BssVMaddress != 0)
		{
			// Insure we have read/write to the .bss section
			if (!VirtualProtectEx(thisProcess, BssVMaddress,
				BssVMsize, PERWProtect, &PEOldProtect))
			{
				LogItem("VirtualProtectEx Error DoIATElimination address: %p", BssVMaddress);
				LogItem(NULL);
				return FALSE;
			}
			// Allocate some zero memory for operation
			dwZMVMAddress = VirtualAlloc(NULL, BssVMsize,
				MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (dwZMVMAddress == NULL)
			{
				LogItem("VirtualAlloc error .bss section for IAT elimination");
				LogItem(NULL);
				return FALSE;
			}
			if (!WriteProcessMemory(thisProcess, BssVMaddress, dwZMVMAddress,
				BssVMsize, &dwWritten))
			{
				LogItem("WriteProcessMemory Error DoIATElimination address: %p", BssVMaddress);
				LogItem(NULL);
				FreeArmZMMemory();
				return FALSE;
			}
			IATELIMREAD = BssVMaddress;
			sprintf(c, ".bss");
			FreeArmZMMemory();
		}
		else if (RelocVMaddress != 0)
		{
			// Insure we have read/write to the .reloc section
			if (!VirtualProtectEx(thisProcess, RelocVMaddress,
				RelocVMsize, PERWProtect, &PEOldProtect))
			{
				LogItem("VirtualProtectEx Error DoIATElimination address: %p", RelocVMaddress);
				LogItem(NULL);
				return FALSE;
			}
			// Allocate some zero memory for operation
			dwZMVMAddress = VirtualAlloc(NULL, RelocVMsize,
				MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (dwZMVMAddress == NULL)
			{
				LogItem("VirtualAlloc error .reloc section for IAT elimination");
				LogItem(NULL);
				return FALSE;
			}
			if (!WriteProcessMemory(thisProcess, RelocVMaddress, dwZMVMAddress,
				RelocVMsize, &dwWritten))
			{
				LogItem("WriteProcessMemory Error DoIATElimination address: %p", RelocVMaddress);
				LogItem(NULL);
				FreeArmZMMemory();
				return FALSE;
			}
			IATELIMREAD = RelocVMaddress;
			sprintf(c, ".Reloc");
			FreeArmZMMemory();
		}
		else
			// we have a problem finding an area to allocate eliminated/redirected Imports
		{
			LogItem("No usable PE section available for IAT elimination");
			return FALSE;
		}
		// Write our desired new section address value
		PvoidAddr = (PVOID)IATELIMDIFF;
		if (!WriteProcessMemory(thisProcess, (LPVOID)PvoidAddr, &IATELIMREAD,
			sizeof(DWORD_PTR), &dwWritten))
		{
			LogItem("WriteProcessMemory Error DoIATElimination Address: %p", PvoidAddr);
			LogItem(NULL);
			return FALSE;
		}
	IATDONE:
		LogItem("%s", isep);
		LogItem("IAT Elimination Disabled!");
		LogItem("IAT elimination section: %s", c);
		LogItem("Old VMaddress: %p", IATELIMSAVE);
		LogItem("New VMaddress: %p", IATELIMREAD);
	}
	return TRUE;
}

BOOL GetOSDisplayString(LPSTR pszOS)
{
	OSVERSIONINFOEX osvi;
	SYSTEM_INFO si;
	PGNSI pGNSI;
	HKEY key;
	DWORD len;
	LONG res;

	ZeroMemory(&si, sizeof(SYSTEM_INFO));
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

	if (!GetVersionEx((OSVERSIONINFO *)&osvi))
		return 1;

	// Call GetNativeSystemInfo if supported or GetSystemInfo otherwise.

	pGNSI = (PGNSI)GetProcAddress(
		GetModuleHandleA((LPCSTR)"kernelbase.dll"),
		(LPCSTR)"GetNativeSystemInfo");
	if (NULL != pGNSI)
		pGNSI(&si);
	else GetSystemInfo(&si);

	if (VER_PLATFORM_WIN32_NT == osvi.dwPlatformId &&
		osvi.dwMajorVersion > 4)
	{
		res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion",
						   0, KEY_QUERY_VALUE, &key);
		if (res == ERROR_SUCCESS)
		{
			len = BUFSIZE;
			res = RegQueryValueEx(key, "ProductName", NULL, NULL, (LPBYTE)pszOS, &len);
			RegCloseKey(key);
		}
		if (res != ERROR_SUCCESS)
		{
			StringCchPrintf(pszOS, BUFSIZE, "Microsoft Windows %d.%d",
							osvi.dwMajorVersion, osvi.dwMinorVersion);
		}

		if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
			StringCchCat(pszOS, BUFSIZE, ", 64-bit");
		else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
			StringCchCat(pszOS, BUFSIZE, ", 32-bit");

		// Include service pack (if any) and build number.

		if (strlen(osvi.szCSDVersion) > 0)
		{
			StringCchCat(pszOS, BUFSIZE, ", ");
			StringCchCat(pszOS, BUFSIZE, osvi.szCSDVersion);
		}

		TCHAR buf[80];

		StringCchPrintf(buf, 80, ", build %d", osvi.dwBuildNumber);
		StringCchCat(pszOS, BUFSIZE, buf);

		return TRUE;
	}

	else
	{
		StringCchCopy(pszOS, BUFSIZE, "Unsupported");
		return FALSE;
	}
}

// Initialize screen options used in process
void InitializeOptions(void)
{
	chkopenmutex = 0;
	chksecuritydump = 0;
	chksecurityload = 0;
	chkminimizesize = 0;
	chkcodesplice = 0;
	chkdumppdata = 0;
	chkignore2ndtext = 0;
	chkbypass2ndtext = 0;
	chkdb = 0;
	chkcm2 = 0;
	checkdumppdata = FALSE;
	checkignore2ndtext = FALSE;
	checkbypass2ndtext = FALSE;
	checkforerrors = FALSE;
	checkdb = FALSE;
	checkcm2 = FALSE;
	checkformutex = FALSE;
	checksecuritydump = FALSE;
	checksecurityload = FALSE;
	checkminimizesize = FALSE;
	chkanalyzenf = 0;
	chkanalyzest = 0;
	chkanalyzelog = 0;
	analyzenf = FALSE;
	analyzest = FALSE;
	analyzelog = FALSE;
	checkanalyzenf = FALSE;
	checkanalyzest = FALSE;
	checkanalyzelog = FALSE;
	redirectsplicing = FALSE;
	usingstdfp = FALSE;
	usingenhfp = FALSE;
	stdlen = 0;
	enhlen = 0;
	uiID = 0;
}

// Initialize global variables used in process
void InitializeVariables(void)
{
	if (!bexitprocess)
	{
		Terminate_Process();
		bexitprocess = TRUE;
	}
	if (hThread)
	{
		CloseHandle(hThread);
		hThread = 0;
	}
	if (hFile)
	{
		CloseHandle(hFile);
		hFile = 0;
	}
	szCmdline = 0;
	sznewCmdline = 0;
	dwVMAddress = 0;
	SavedwBMVMAddress = 0;
	hFile = 0;
	hFile1 = 0;
	LastUpdate = 0;
	numitems = 0;
	compilertype = 0;
	memset(buffer, 0, sizeof(MAX_PATH));
	memset(savebuffer, 0, sizeof(MAX_PATH));
	memset(inibuffer, 0, sizeof(MAX_PATH));
	memset(inisavebuffer, 0, sizeof(MAX_PATH));
	memset(nanobuffer, 0, sizeof(MAX_PATH));
	memset(nanologbuffer, 0, sizeof(MAX_PATH));
	memset(filebuffer, 0, sizeof(MAX_PATH));
	memset(armbuffer, 0, sizeof(MAX_PATH));
	memset(copybuffer, 0, sizeof(MAX_PATH));
	memset(logbuffer, 0, sizeof(MAX_PATH));
	memset(cmdbuffer, 0, sizeof(MAX_PATH));
	memset(sztempbuffer, 0, sizeof(sztempbuffer));
	memset(nbufrwb32, 0, sizeof(MAX_PATH));
	memset(nbuf, 0, sizeof(MAX_PATH));
	memset(dbuf, 0, sizeof(MAX_PATH));
	memset(Filename, 0, sizeof(MAX_PATH));
	memset(pszDllName, 0, sizeof(MAX_PATH));
	memset(ibuf, 0, sizeof(ibuf));
	memset(bufbp, 0, sizeof(bufbp));
	memset(szCmdbuffer, 0, sizeof(MAX_PATH));
	pszPathName = 0;
	pszBaseExt = 0;
	pszBaseName = 0;
	bp = 0;
	sf = 0;
	ss = 0;
	hfind = 0;
	lpfind = 0;
	IATELIMREAD = 0;
	IATELIMSAVE = 0;
	IATELIMDISP = 0;
	IATELIMDIFF = 0;
	//  Code Splicing related
	CSOAddress = 0;
	CSORVAddress = 0;
	CSAddress = 0;
	CSOSize = 0;
	CSSize = 0;
	//  IAT REDIRECTION
	IATREDIVARREAD = 0;
	IATREDIVARWRITE = 0;
	IATREDIREAD = 0;
	IATREDIDISP = 0;
	IATREDIDIFF = 0;
	//  COPYMEM-II Related infos
	CMeventaddress = 0;
	CMaddress = 0;
	CBaddress = 0;
	//  PE Related info
	PESectionAddress = 0;
	PESectionSize = 0;
	PEOldProtect = 0;
	PESecProtect = 0;
	//  Exception Addresses for Hardware BP's
	for (i = 0; i < 4; i++)
	{
		HWBPExceptionAddress[i] = 0;
	}
	//  Note: index = 8 used as pseudo single step SWBP (Child process only!!)
	thisSWBP = 0;
	//  Exception Addresses Software BP's
	for (i = 0; i < 20; i++)
	{
		SWBPExceptionAddress[i] = 0;
	}
	//  Function Addresses for API's
	for (i = 0; i < 15; i++)
	{
		FunctionAddress[i] = 0;
	}
	//  Search (read) byte
	for (i = 0; i < 20; i++)
	{
		scanbyte[i] = 0;
	}
	ByteRead = 0;
	PvoidAddr = 0;
	SavePvoidAddr = 0;
	PvoidRead = 0;
	PvoidNext = 0;
	DwordRead = 0;
	SaveDwordRead = 0;
	dwRead = 0;
	dwWritten = 0;
	dwFileSize = 0;
	dwSaveFileSize = 0;
	dwAnfFileSize = 0;
	dwOffset = 0;
	SavedwOffset = 0;
	dwDASMreturn = 0;
	dwlength = 0;
	dwCalcAddress = 0;
	dwDataAddress = 0;
	dwBMVMOffset = 0;
	dwDecryptoffset = 0;
	dwBMVMValue = 0;
	dwArmVMSize = 0;
	dwArmVMNSize = 0;
	dwoepcall = 0;
	memset(hMods, 0, sizeof(hMods));
	memset(modlist, 0, sizeof(modlist));
	memset(szModName, 0, sizeof(MAX_PATH));
	nMods = 0;
	cbNeeded = 0;
	dwSize = 0;
	dwBase = 0;
	roffset = 0;
	rsize = 0;
	voffset = 0;
	vsize = 0;
	memset(b, 0, sizeof(b));
	memset(c, 0, sizeof(c));
	memset(d, 0, sizeof(d));
	memset(e, 0, sizeof(d));
	memset(szOS, 0, sizeof(BUFSIZE));
	memset(bszOS, 0, sizeof(BUFSIZE));
	memset(dszOS, 0, sizeof(BUFSIZE));
	childhThread = 0;
	childhProcess = 0;
	hThread = 0;
	childpid = 0;
	childtid = 0;
	dwThreadid = 0;
	dwThreadid1 = 0;
	instrcount = 0;
	breaknow = FALSE;
	detachnow = FALSE;
	detached = FALSE;
	debugblocker = FALSE;
	apiswbpdetect = FALSE;
	firsttime = FALSE;
	secondtime = FALSE;
	cserror = FALSE;
	firstmutex = TRUE;
	secondmutex = FALSE;
	foundjmp = FALSE;
	onetime = FALSE;
	copymem2 = FALSE;
	traceon = TRUE;
	bexitprocess = FALSE;
	bcGuardPage = FALSE;
	bGuardPage = FALSE;
	vadone = FALSE;
	iatdone = FALSE;
	iatadone = FALSE;
	ir1done = FALSE;
	ir2done = FALSE;
	checkredirect = FALSE;
	variableredirectfound = FALSE;
	bWildcard = FALSE;
	isdll = FALSE;
	text1found = FALSE;
	datafound = FALSE;
	secondva = FALSE;
	p = 0;
	end = 0;
	pamiec = 0;
	hexFind_size = 0;
	selected_begin = 0;
	selected_end = 0;
	hexFind_from = 0;
	i = j = k = n = 0;
	sstrlen = 0;
	ustring = 0;
	memset(intext, 0, sizeof(MAXPAT + 1));
	memset(outtext, 0, sizeof(MAXPAT + 1));
	memset(hextext, 0, sizeof(MAXPAT + 1));
	wstring = 0;
	memset(IRwarn, 0, sizeof(IRwarn));
	IRiatrva = 0;
	IRiatsize = 0;
	IRretn = 0;
	IRINT = 0;
	MSwarn = 0;
	MSretn = 0;
	MSINT = 0;
	memset(gnfobuffer, 0, sizeof(MAX_PATH));
	NumNanos = 0;
	memset(&NFlog, 0, sizeof(Log));
	pasm = 0;
	memset(&am, 0, sizeof(am));
	memset(&da, 0, sizeof(da));
	memset(cjumptype, 0, sizeof(TEXTLEN));
	memset(cjumpdest, 0, sizeof(TEXTLEN));
	memset(ccmd, 0, sizeof(MAXCMDSIZE));
	memset(s, 0, sizeof(TEXTLEN));
	memset(errtext, 0, sizeof(TEXTLEN));
	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	memset(&Context, 0, sizeof(Context));
	memset(&sel, 0, sizeof(sel));
	memset(&mbi, 0, sizeof(mbi));
	memset(&mi, 0, sizeof(mi));
	memset(&sa, 0, sizeof(sa));
	memset(&DebugEv, 0, sizeof(DebugEv));
	memset(&CebugEv, 0, sizeof(CebugEv));
	memset(&SebugEv, 0, sizeof(SebugEv));
	memset(&Rect, 0, sizeof(Rect));
	memset(&st, 0, sizeof(st));
	lvi.pszText = "";
	lvi.iItem = 0;
	hNTModule = 0;
	retdebugflags = 0;
	DebugFlags = 0;
	UPX0VMaddress = 0;
	UPX0VMsize = 0;
	UPX1VMaddress = 0;
	UPX1VMsize = 0;
	TextVMaddress = 0;
	TextVMsize = 0;
	ItextVMaddress = 0;
	ItextVMsize = 0;
	Text1VMaddress = 0;
	Text1VMsize = 0;
	RdataRVaddress = 0;
	RdataVMaddress = 0;
	RdataVMsize = 0;
	RdataNVMaddress = 0;
	RdataNVMsize = 0;
	RdataVMCharacteristics = 0;
	RelocVMaddress = 0;
	RelocVMsize = 0;
	BssVMaddress = 0;
	BssVMsize = 0;
	IdataVMaddress = 0;
	IdataVMsize = 0;
	AdataVMaddress = 0;
	AdataVMsize = 0;
	AdataNVMaddress = 0;
	AdataNVMsize = 0;
	Data1VMaddress = 0;
	Data1VMsize = 0;
	Data1NVMaddress = 0;
	Data1NVMsize = 0;
	PdataVMaddress = 0;
	PdataVMsize = 0;
	DataVMaddress = 0;
	DataVMsize = 0;
	BaseOfImage = 0;
	StartAddress = 0;
	OEPRVAddress = 0;
	OEPVAddress = 0;
	OEPDelphiVAddress = 0;
	OEPDelphiRVAddress = 0;
	g_pMappedFileBase = 0;
	FuckedUp = FALSE;
	SStart = 0;
	TStart = 0;
	SLength = 0;
	TLength = 0;
	Instrs = 0;
	NumSegments = 0;
	memset(Asm, 0, sizeof(TEXTLEN));
	Spliced = 0;
	Target = 0;
	securityentry = 0;
	hModule = 0;
	hDllModule = 0;
	ProcAddr0 = 0;
	ProcAddr1 = 0;
	ProcAddr2 = 0;
	ProcAddr3 = 0;
	ProcAddr4 = 0;
	ProcAddr5 = 0;
	ProcAddr6 = 0;
	ProcAddr7 = 0;
	ProcAddr8 = 0;
	ProcAddr9 = 0;
	ProcAddr10 = 0;
	ProcAddr11 = 0;
	ProcAddr12 = 0;
	ProcAddr13 = 0;
	ProcAddr14 = 0;
	// Arma nanofixer
	hdisasmdll = 0;
	AsmAddr = 0;
	DsmAddr = 0;
	AssembleAddress = 0;
	DisasmAddress = 0;
	NFDretn = 0;
	NFIretn = 0;
	hAnalThread = 0;
	isrunning = FALSE;
	analyzeprob = FALSE;
	totalanalyzed = TRUE;
	if (RNano)
	{
		delete[] RNano;
		RNano = 0;
		NumNanos = 0;
	}
	return;
}

BOOL GetNeededAPIs(HANDLE thisprocess)
{
	// Find additional API's to set SWBP addresses
	// Get a handle to the dll's we want
	hModule = GetModuleHandleA((LPCSTR)"kernel32.dll");
	if (!hModule)
	{
		LogItem("Module: kernel32.dll; Function: GetModuleHandle Failed");
		LogItem(NULL);
		return FALSE;
	}
	// Find the proc address to the function we want
	ProcAddr1 = (FARPROC)GetProcAddress(hModule, (LPCSTR)"VirtualAlloc");
	if (!ProcAddr1)
	{
		LogItem("Function: VirtualAlloc; kernel32.DLL: GetProcAddress Failed");
		LogItem(NULL);
		return FALSE;
	}
	else
	{
		// Store the function address
		FunctionAddress[1] = (PVOID)ProcAddr1;
		SWBPExceptionAddress[1] = FunctionAddress[1];
		// Store the SWBP
		if (!ReadProcessMemory(thisprocess, (LPVOID)SWBPExceptionAddress[1], &scanbyte[1],
			sizeof(BYTE), &dwRead))
		{
			LogItem("ReadProcessMemory Error VirtualAlloc address: %p", SWBPExceptionAddress[1]);
			LogItem(NULL);
			return FALSE;
		}
	}
	// Find the proc address to the function we want
	ProcAddr2 = (FARPROC)GetProcAddress(hModule, (LPCSTR)"CreateFileA");
	if (!ProcAddr2)
	{
		LogItem("Function: CreateFileA; kernel32.dll: GetProcAddress Failed");
		LogItem(NULL);
		return FALSE;
	}
	else
	{
		// Store the function address
		FunctionAddress[2] = (PVOID)ProcAddr2;
		SWBPExceptionAddress[2] = FunctionAddress[2];
		// Store the SWBP
		if (!ReadProcessMemory(thisprocess, (LPVOID)SWBPExceptionAddress[2], &scanbyte[2],
			sizeof(BYTE), &dwRead))
		{
			LogItem("ReadProcessMemory Error CreateFileA address: %p", SWBPExceptionAddress[2]);
			LogItem(NULL);
			return FALSE;
		}
	}
	// Find the proc address to the function we want
	ProcAddr3 = (FARPROC)GetProcAddress(hModule, (LPCSTR)"WriteProcessMemory");
	if (!ProcAddr3)
	{
		LogItem("Function: WriteProcessMemory; kernel32.dll: GetProcAddress Failed");
		LogItem(NULL);
		return FALSE;
	}
	else
	{
		// Store the function address
		FunctionAddress[3] = (PVOID)ProcAddr3;
		SWBPExceptionAddress[3] = FunctionAddress[3];
		// Store the SWBP
		if (!ReadProcessMemory(thisprocess, (LPVOID)SWBPExceptionAddress[3], &scanbyte[3],
			sizeof(BYTE), &dwRead))
		{
			LogItem("ReadProcessMemory Error WriteProcessMemory address: %p", SWBPExceptionAddress[3]);
			LogItem(NULL);
			return FALSE;
		}
	}
	// Find the proc address to the function we want
	ProcAddr4 = (FARPROC)GetProcAddress(hModule, (LPCSTR)"GetModuleHandleA");
	if (!ProcAddr4)
	{
		LogItem("Function: GetModuleHandleA; kernel32.dll: GetProcAddress Failed");
		LogItem(NULL);
		return FALSE;
	}
	else
	{
		// Store the function address
		FunctionAddress[4] = (PVOID)ProcAddr4;
		SWBPExceptionAddress[4] = FunctionAddress[4];
		// Store the SWBP
		if (!ReadProcessMemory(thisprocess, (LPVOID)SWBPExceptionAddress[4], &scanbyte[4],
			sizeof(BYTE), &dwRead))
		{
			LogItem("ReadProcessMemory Error GetModuleHandleA address: %p", SWBPExceptionAddress[4]);
			LogItem(NULL);
			return FALSE;
		}
	}
	// Find the proc address to the function we want
	ProcAddr5 = (FARPROC)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "WaitForDebugEvent");
	if (!ProcAddr5)
		ProcAddr5 = (FARPROC)GetProcAddress(hModule, (LPCSTR)"WaitForDebugEvent");
	if (!ProcAddr5)
	{
		LogItem("Function: WaitForDebugEvent; kernel32.dll: GetProcAddress Failed");
		LogItem(NULL);
		return FALSE;
	}
	else
	{
		// Store the function address
		FunctionAddress[5] = (PVOID)ProcAddr5;
		//Search for the RETN address in this API
		dwFileSize = dwAPISize;     //Size of search space
		dwAddress = (LPVOID)FunctionAddress[5]; //Search begin address
		// Using wildcards
		bWildcard = TRUE;
		DoSearch(0, 0);
		// Search String not found! 
		if (!sf)
		{
			LogItem("WaitForDebugEvent RETN search string not found!");
			return FALSE;
		}
		else
		{
			dwOffset = ((DWORD_PTR)((HPSTR)sf - (HPSTR)ss));
		}
		// Set a SWBP on GetThreadContext address (future use)
		dwCalcAddress = (DWORD_PTR)FunctionAddress[5] + dwOffset;
		SWBPExceptionAddress[5] = (PVOID)dwCalcAddress;
		// Apply the SWBP
		if (!ReadProcessMemory(thisprocess, (LPVOID)SWBPExceptionAddress[5], &scanbyte[5],
			sizeof(BYTE), &dwRead))
		{
			LogItem("ReadProcessMemory Error WaitForDebugEvent address: %p", SWBPExceptionAddress[5]);
			LogItem(NULL);
			return FALSE;
		}
		if (!WriteProcessMemory(thisprocess, (LPVOID)SWBPExceptionAddress[5], &replbyte[5],
			sizeof(BYTE), &dwWritten))
		{
			LogItem("WriteProcessMemory Error WaitForDebugEvent address: %p", SWBPExceptionAddress[5]);
			LogItem(NULL);
			return FALSE;
		}
	}
	// Find the proc address to the function we want
	ProcAddr6 = (FARPROC)GetProcAddress(hModule, (LPCSTR)"CreateThread");
	if (!ProcAddr6)
	{
		LogItem("Function: CreateThread; kernel32.dll: GetProcAddress Failed");
		LogItem(NULL);
		return FALSE;
	}
	else
	{
		// Store the function address
		FunctionAddress[6] = (PVOID)ProcAddr6;
		SWBPExceptionAddress[6] = FunctionAddress[6];
		// Store the SWBP
		if (!ReadProcessMemory(thisprocess, (LPVOID)SWBPExceptionAddress[6], &scanbyte[6],
			sizeof(BYTE), &dwRead))
		{
			LogItem("ReadProcessMemory Error CreateThread address: %p", SWBPExceptionAddress[6]);
			LogItem(NULL);
			return FALSE;
		}
	}
	// Find the proc address to the function we want
	ProcAddr7 = (FARPROC)GetProcAddress(hModule, (LPCSTR)"OutputDebugStringA");
	if (!ProcAddr7)
	{
		LogItem("Function: OutputDebugStringA; kernel32.dll: GetProcAddress Failed");
		LogItem(NULL);
		return FALSE;
	}
	else
	{
		// Store the function address
		FunctionAddress[7] = (PVOID)ProcAddr7;
		SWBPExceptionAddress[13] = FunctionAddress[7];
		// Store the SWBP
		if (!ReadProcessMemory(thisprocess, (LPVOID)SWBPExceptionAddress[13], &scanbyte[13],
			sizeof(BYTE), &dwRead))
		{
			LogItem("ReadProcessMemory Error OutputDebugStringA address: %p", SWBPExceptionAddress[13]);
			LogItem(NULL);
			return FALSE;
		}
		if (!WriteProcessMemory(thisprocess, (LPVOID)SWBPExceptionAddress[13], &replbyte[13],
			sizeof(BYTE), &dwWritten))
		{
			LogItem("WriteProcessMemory Error OutputDebugStringA address: %p", SWBPExceptionAddress[13]);
			LogItem(NULL);
			return FALSE;
		}
	}
	// Only if OpenMutextA trick selected
	if (checkformutex)
	{
		// Find the proc address to the function we want
		ProcAddr8 = (FARPROC)GetProcAddress(hModule, (LPCSTR)"OpenMutexA");
		if (!ProcAddr8)
		{
			LogItem("Function: OpenMutexA; kernel32.dll: GetProcAddress Failed");
			LogItem(NULL);
			return FALSE;
		}
		else
		{
			// Store the function address
			FunctionAddress[8] = (PVOID)ProcAddr8;
			SWBPExceptionAddress[10] = FunctionAddress[8];
			// Apply the SWBP
			if (!ReadProcessMemory(thisprocess, (LPVOID)SWBPExceptionAddress[10], &scanbyte[10],
				sizeof(BYTE), &dwRead))
			{
				LogItem("ReadProcessMemory Error OpenMutexA address: %p", SWBPExceptionAddress[10]);
				LogItem(NULL);
				return FALSE;
			}
			if (!WriteProcessMemory(thisprocess, (LPVOID)SWBPExceptionAddress[10], &replbyte[10],
				sizeof(BYTE), &dwWritten))
			{
				LogItem("WriteProcessMemory Error OpenMutexA address: %p", SWBPExceptionAddress[10]);
				LogItem(NULL);
				return FALSE;
			}
		}
	}
	// Find the proc address to the function we want
	ProcAddr12 = (FARPROC)GetProcAddress(hModule, (LPCSTR)"CreateFileMappingA");
	if (!ProcAddr12)
	{
		LogItem("Function: CreateFileMappingA; kernel32.dll: GetProcAddress Failed");
		LogItem(NULL);
		return FALSE;
	}
	else
	{
		// Store the function address
		FunctionAddress[12] = (PVOID)ProcAddr12;
		SWBPExceptionAddress[15] = FunctionAddress[12];
		// Store the SWBP
		if (!ReadProcessMemory(thisprocess, (LPVOID)SWBPExceptionAddress[15], &scanbyte[15],
			sizeof(BYTE), &dwRead))
		{
			LogItem("ReadProcessMemory Error CreateFileMappingA address: %p", SWBPExceptionAddress[15]);
			LogItem(NULL);
			return FALSE;
		}
	}
	// Find the proc address to the function we want
	ProcAddr13 = (FARPROC)GetProcAddress(hModule, (LPCSTR)"GetModuleFileNameA");
	if (!ProcAddr13)
	{
		LogItem("Function: GetModuleFileNameA; kernel32.dll: GetProcAddress Failed");
		LogItem(NULL);
		return FALSE;
	}
	else
	{
		// Store the function address
		FunctionAddress[13] = (PVOID)ProcAddr13;
		SWBPExceptionAddress[16] = FunctionAddress[13];
		// Store the SWBP
		if (!ReadProcessMemory(thisprocess, (LPVOID)SWBPExceptionAddress[16], &scanbyte[16],
			sizeof(BYTE), &dwRead))
		{
			LogItem("ReadProcessMemory Error GetModuleFileNameA address: %p", SWBPExceptionAddress[16]);
			LogItem(NULL);
			return FALSE;
		}
	}
	if (isdll)
	{
		// Find the proc address to the function we want
		hNTModule = GetModuleHandleA((LPCSTR)"ntdll.dll");
		if (!hNTModule)
		{
			LogItem("Module: ntdll.dll; Function: GetModuleHandle Failed");
			LogItem(NULL);
			return FALSE;
		}
		ProcAddr9 = (FARPROC)GetProcAddress(hNTModule, (LPCSTR)"LdrLoadDll");
		if (!ProcAddr9)
		{
			LogItem("Function: LdrLoadDll; NTDLL.DLL: GetProcAddress Failed");
			LogItem(NULL);
			return FALSE;
		}
		else
		{
			// Store the function address
			FunctionAddress[9] = (PVOID)ProcAddr9;
			SWBPExceptionAddress[11] = FunctionAddress[9];
			// Apply the SWBP
			if (!ReadProcessMemory(thisprocess, (LPVOID)SWBPExceptionAddress[11], &scanbyte[11],
				sizeof(BYTE), &dwRead))
			{
				LogItem("ReadProcessMemory Error LdrLoadDll address: %p", SWBPExceptionAddress[11]);
				LogItem(NULL);
				return FALSE;
			}
		}
		return TRUE;
	}
	// Determine all the armadillo PE header sections
	if (!DetermineArmSections(thisprocess))
	{
		FreePEMemory();
		return FALSE;
	}
	if (PdataVMaddress == 0x00000000)
	{
		// We have a problem
		LogItem("No .pdata section found in PE header!");
		LogItem("This doesn't appear to be an Armadillo protected program!");
		return FALSE;
	}
	if (TextVMaddress == 0x00000000)
	{
		// We have a problem
		LogItem("No .text section found in PE header!");
		return FALSE;
	}
	PESectionAddress = TextVMaddress;
	PESectionSize = TextVMsize;
	if (StartAddress >= Text1VMaddress &&
		StartAddress <= (LPVOID)((DWORD_PTR)PdataVMaddress + PdataVMsize))
	{
		//continue
	}
	else
	{
		// We have a problem
		LogItem("This doesn't appear to be an Armadillo protected program!");
		LogItem("The EP is not within the range of PE section .text1");
		return FALSE;
	}
	return TRUE;
}

// Create Thread/Process the Armadillo protected Process / Debug Process / Perform dump of process
//DWORD WINAPI RunExe(void)
unsigned __stdcall RunExe(void *)
{
	BOOL 		contproc = TRUE;
	BOOL		SSCVirtualAlloc = FALSE;
	BOOL		SSVirtualAlloc = FALSE;
	BOOL		SSGetModuleHandleA = FALSE;
	BOOL		SSGetModuleFileNameA = FALSE;
	BOOL		SSCreateFileA = FALSE;
	BOOL		SSDebugEvent = FALSE;
	BOOL        SSCreateThread = FALSE;
	BOOL		SSGuardPage = FALSE;
	BOOL		SSOpenMutexA = FALSE;
	LPVOID 		lpMsgBuf = 0;
	DWORD		dwContinueStatus = 0;
	DWORD		dwTime = 1000;	//1 second
	unsigned 	int i = 0;		//loop counter
	unsigned 	int j = 0;		//loop counter
	unsigned 	int k = 0;		//loop counter
	unsigned 	int l = 0;		//loop counter
	unsigned 	int m = 0;		//loop counter
	unsigned 	int n = 0;		//loop counter
	unsigned 	int xl = 0;		//loop counter
	unsigned 	int xm = 0;		//loop counter
	int			Comma = 0;
	char		*pComma = 0;
	char       *wpComma = 0;

	// Disable Load buttons
	EnableWindow(hwnd08, FALSE);

	// Adjust debug privileges on startup
	if (!LoadSeDebugPrivilege())
	{
		LogItem("LoadSeDebugPrivilege Failed for the current process!");
		LogItem(NULL);
	}
	// Create New Start in Folder for target executable based on buffer returned in Open dialog
	memcpy(nbuf, buffer, (size_t)MAX_PATH);
	// Find the last '\\' to obtain a pointer to just the base module name part
	pszPathName = strrchr((char *)nbuf, '\\');
	if (pszPathName)  // We found a path, so advance to the base module name
	{
		pszPathName++;
		strcpy(ibuf, (const char *)pszPathName);
		strcpy(pszDllName, (const char *)pszPathName);
		strncpy((char *)pszPathName, "\0", 1);
	}
	// Find .dll string in buffer
	memcpy(dbuf, buffer, (size_t)MAX_PATH);
	// find '.' to obtain a pointer to the extension
	pszBaseExt = strrchr((char *)dbuf, '.');
	if (pszBaseExt) 	// We found a '.'
	{
		pszBaseExt++;
	}
	else
	{
		LogItem("No valid *.exe / *.dll extension found in target file!");
		return 1;
	}
	if (strcmp(strupr((char *)pszBaseExt), "EXE") == 0)
	{
		// continue
	}
	else if (strcmp(strupr((char *)pszBaseExt), "DLL") == 0)
	{
		isdll = TRUE;
		// Get the current module name and path
		GetModuleFileName(
			NULL,
			Filename,
			MAX_PATH
			);
		// Copy pathname to our dll loader.exe buffer
		memcpy(cmdbuffer, Filename, (size_t)MAX_PATH);
		// Find the last '\\' to obtain a pointer to just the base module name part
		pszPathName = strrchr((char *)cmdbuffer, '\\');
		if (pszPathName)  // We found a path, so advance to the base module name
		{
			pszPathName++;
			// Append module name
			strncpy((char *)pszPathName, "dll loader.exe\0", 15);
		}
	}
	else
	{
		LogItem("No valid *.exe / *.dll extension found in target file!");
		return 1;
	}

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	// If so desired, set the bInheritHandle flag so pipe handles are inherited.
	ZeroMemory(&sa, sizeof(sa));
	//sa.nLength = sizeof(sa);
	//sa.bInheritHandle = TRUE;
	//sa.lpSecurityDescriptor = NULL;

	if (isdll)
	{
		strcat(cmdbuffer, " ");
		strcat(cmdbuffer, dbuf);
		// Start the child process.
		if (!CreateProcess(NULL, // If no module name (use command line).
			(LPSTR)cmdbuffer, 	// Command line.
			NULL,             	// Process handle not inheritable.
			NULL,             	// Thread handle not inheritable.
			FALSE,            	// Set handle inheritance to FALSE.
			DEBUG_PROCESS + DEBUG_ONLY_THIS_PROCESS,     	// Single Process Target.
			NULL,             	// Use parent's environment block.
			(LPCSTR)nbuf,       // Use Start in folder directory of target debugee process
			(LPSTARTUPINFO)&si, // Pointer to STARTUPINFO structure.
			&pi))             	// Pointer to PROCESS_INFORMATION structure.
		{
			LogItem("Create Process Failed! Missing or Invalid target dll");
			LogItem(NULL);
			return 1;
		}
	}
	else
	{
		// build commandline, if needed
		if (szCmdline != 0)
		{
			// add paren
			strcat(sztempbuffer, "\"");
			// add module
			strcat(sztempbuffer, buffer);
			// add paren
			strcat(sztempbuffer, "\"");
			// add white space
			strcat(sztempbuffer, " ");
			// add paren
			strcat(sztempbuffer, "\"");
			// add parameters
			strcat(sztempbuffer, szCmdline);
			// add paren
			strcat(sztempbuffer, "\"");
			// finish
			sznewCmdline = (LPTSTR)sztempbuffer;
		}
		// Start the child process.
		if (!CreateProcess(szCmdline != 0 ? NULL : (LPCSTR)buffer, // If no module name (use command line).
			sznewCmdline,		// Command line.
			NULL,             	// Process handle not inheritable.
			NULL,             	// Thread handle not inheritable.
			FALSE,            	// Set handle inheritance to FALSE.
			DEBUG_PROCESS + DEBUG_ONLY_THIS_PROCESS,     	// Single Process Target.
			NULL,             	// Use parent's environment block.
			(LPCSTR)nbuf,       // Use Start in folder directory of target debugee process
			(LPSTARTUPINFO)&si, // Pointer to STARTUPINFO structure.
			&pi))             	// Pointer to PROCESS_INFORMATION structure.
		{
			LogItem("Create Process Failed! Missing or Invalid target executable");
			LogItem(NULL);
			return 1;
		}
	}
	ClearListview(0);
	// Get listview height
	GetClientRect(hwndIDLISTVIEW, &Rect);
	cy = Rect.bottom - Rect.top;
	if (GetOSDisplayString(szOS))
	{
		LogItem("OS --> %s", szOS);
	}
	GetLocalTime(&st);
	LogItem("<------- %04u-%02u-%02u %02u:%02u:%02u ------->",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
	LogItem("%s", f);
	LogItem("%s", ibuf);

	while (TRUE)
	{
		if (detached)
		{
			detached = FALSE;
			// doesn't work well under win 7
			if (!SuspendThread(childhThread))
			{
				/*
				LogItem("Unable to SuspendThread: %p", childhThread);
				LogItem(NULL);
				*/
			}
			if (checkcm2)
			{
				if (MessageBox(NULL, (LPCSTR)"Resolve nanomites before continuing?", "ArmaGeddon",
					MB_OKCANCEL + MB_SYSTEMMODAL + MB_ICONINFORMATION) == IDCANCEL)
				{
					//continue
				}
				else
				{
					ResolveProcess(childhProcess);
				}
				if (!VirtualProtectEx(childhProcess, (LPVOID)PESectionAddress,
					PESectionSize, PEGuardProtect, &PEOldProtect))
				{
					LogItem("VirtualProtectEx Error RunExe address: %p", PESectionAddress);
					LogItem(NULL);
				}
				bcGuardPage = TRUE;
			}
		}
		if (breaknow)
		{
			breaknow = FALSE;
			detached = FALSE;
			if (!bexitprocess)
			{
				Terminate_Process();
				bexitprocess = TRUE;
			}
			FreeArmZMMemory();
			FreeArmBMMemory();
			FreeArmDASMMemory();
			FreePESecMemory();
			FreeVirtualMemory();
			FreePEMemory();
		}
	WAITFORDE:
		// Wait for a debugging event to occur. The second parameter indicates
		// that the function does not return until a debugging event occurs.
		if (WaitForDebugEvent(&DebugEv, dwTime)) // wait 1 second
		{
			switch (DebugEv.dwDebugEventCode)
			{

			case EXCEPTION_DEBUG_EVENT:

				switch (DebugEv.u.Exception.ExceptionRecord.ExceptionCode)
				{

				case EXCEPTION_ACCESS_VIOLATION:
					// First chance: Pass this on to the kernel.
					// Last chance: Display an appropriate error.

					if (DebugEv.u.Exception.dwFirstChance)
					{
						dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
					}
					else
					{
						breaknow = TRUE;
					}
					break;

				case EXCEPTION_PRIV_INSTRUCTION:
					if (DebugEv.u.Exception.dwFirstChance)
					{
						dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
						//Search SWBP Exception Address Array for our breakpoint
						for (l = 0; l < 20; l++)
						{
							if (DebugEv.u.Exception.ExceptionRecord.ExceptionAddress == SWBPExceptionAddress[l])
							{
								dwContinueStatus = DBG_CONTINUE;
								DebugEv.u.Exception.ExceptionRecord.ExceptionCode = EXCEPTION_BREAKPOINT;
								// Reset parent EIP
								Reset_EIP(pi.hProcess, pi.hThread, l);
								switch (l)
								{
									// Main Module's EP
								case 0:
									// Hide module from PEB linked list
									// HIDE DEBUGGER
									if (!HideDebugger(pi.hProcess, pi.hThread))
									{
										breaknow = TRUE;
										break;
									}
									// Hide Windows
									EnumWindows(EnumWindowsProc, NULL);
									// Get needed Api's
									if (!GetNeededAPIs(pi.hProcess))
									{
										breaknow = TRUE;
										break;
									}
									// Load Disassembler
									if (!LoadBeaEngine())
									{
										breaknow = TRUE;
										break;
									}
									// Set a SWBP on VirtualAlloc (PART I)
									if (checksecuritydump || checksecurityload)
									{
										if (!WriteProcessMemory(pi.hProcess, SWBPExceptionAddress[1], &replbyte[1],
											sizeof(BYTE), &dwWritten))
										{
											LogItem("WriteProcessMemory Error VirtualAlloc address: %p", SWBPExceptionAddress[1]);
											LogItem(NULL);
										}
									}
									LogItem("%s", g);
									l = 20;
									EPhandled = TRUE;
									break;
									// VirtualAlloc  (used for the Armadillo Virtual dll in VM)
								case 1:
									// If we have debugblocker in effect, disregard this SWBP
									if (debugblocker)
									{
										goto VAPDONE;
									}
									if (checksecuritydump)
									{
										DumpSecurityDll(pi.hProcess);
										checksecuritydump = FALSE;
										goto VAPDONE;
									}
									if (checksecurityload)
									{
										LoadSecurityDllFileName(pi.hProcess);
										checksecurityload = FALSE;
										goto VAPDONE;
									}
								FIRSTTRY:
									// Look for code splicing, check hi-address, vmsize and allocation type
									// to see if it qualifies for code-splicing
									if (firsttime)
									{
										DetermineStrategicCodeSplicing(pi.hProcess, pi.hThread);
										// Set this to maintain visibility of this SWBP
										SetSingleStep(pi.hThread);
										SSVirtualAlloc = TRUE;
										goto VAPDONE;
									}
									// Verify code splicing
									if (secondtime)
									{
										if (!VerifyStrategicCodeSplicing(pi.hProcess, pi.hThread))
										{
											if (cserror)
											{
												cserror = FALSE;
												firsttime = TRUE;
												secondtime = FALSE;
												CSOAddress = 0;
												CSOSize = 0;
												goto FIRSTTRY;
											}
											else
											{
												// Set this to maintain visibility of this SWBP
												SetSingleStep(pi.hThread);
												SSVirtualAlloc = TRUE;
											}
										}
									}
								VAPDONE:
									l = 20;
									break;
									// CreateFileA SWBP
								case 2:
									// If we have debugblocker in effect, disregard this SWBP
									if (debugblocker)
									{
										goto ENDCF;
									}
									// Obtain return address pointer if necessary
									PvoidAddr = (PVOID)(DWORD_PTR)Context.Esp;
									if (!ReadProcessMemory(pi.hProcess, (LPVOID)PvoidAddr, &DwordRead,
										sizeof(DWORD_PTR), &dwRead))
									{
										LogItem("ReadProcessMemory Error CreateFileA address: %p", PvoidAddr);
										LogItem(NULL);
										breaknow = TRUE;
										break;
									}
									// See if the Call was made from Arm VM
									// This value should fall within Armadillo VM
									if (DwordRead >= (DWORD_PTR)dwArmVMAddress &&
										DwordRead <= (DWORD_PTR)dwArmVMAddress + dwArmVMNSize)
									{
										// continue
									}
									else
									{
										// Set this to maintain visibility of this SWBP
										SetSingleStep(pi.hThread);
										SSCreateFileA = TRUE;
									}
								ENDCF:
									l = 20;
									break;
									// WriteProcessMemory  address
								case 3:
									if (copymem2)
									{
										//Read Esp+16 to obtain size
										PvoidAddr = (PVOID)((DWORD_PTR)Context.Esp + 16);
										if (!ReadProcessMemory(pi.hProcess, (LPVOID)PvoidAddr, &DwordRead,
											sizeof(DWORD_PTR), &dwRead))
										{
											LogItem("ReadProcessMemory Error CopyMemII address: %p", PvoidAddr);
											LogItem(NULL);
										}
										else if (DwordRead == 0x00001000)
										{
											// CopyMemII
											// Store the original OEP bytes and set a SWBP
											if (!ReadProcessMemory(childhProcess, SWBPExceptionAddress[7], &scanbyte[7],
												sizeof(BYTE), &dwWritten))
											{
												LogItem("ReadProcessMemory Error CopyMemII address: %p", SWBPExceptionAddress[7]);
												LogItem(NULL);
											}
											// Set a SWBP on the child's OEP
											else if (!WriteProcessMemory(childhProcess, SWBPExceptionAddress[7], &replbyte[7],
												sizeof(BYTE), &dwWritten))
											{
												LogItem("WriteProcessMemory Error CopyMemII address: %p", SWBPExceptionAddress[7]);
												LogItem(NULL);
											}
										}
									}
									l = 20;
									break;
									// GetModuleHandleA address
								case 4:
									// If we have debugblocker in effect, disregard this SWBP
									if (debugblocker)
									{
										goto ENDGETMOD1;
									}
									// Obtain return address pointer if necessary
									PvoidAddr = (PVOID)(DWORD_PTR)Context.Esp;
									if (!ReadProcessMemory(pi.hProcess, PvoidAddr, &PvoidRead,
										sizeof(DWORD_PTR), &dwRead))
									{
										LogItem("ReadProcessMemory Error GetModuleHandleA address: %p", PvoidAddr);
										LogItem(NULL);
										breaknow = TRUE;
										break;
									}
									// See if the Call was made from Arm VM
									// This value should fall within Armadillo VM
									else if (PvoidRead >= dwArmVMAddress &&
										PvoidRead <= (PVOID)((DWORD_PTR)dwArmVMAddress + dwArmVMNSize))
									{
										if (!DetermineARMVM(pi.hProcess, 0))
										{
											// We have a problem
											LogItem("Virtual Armadillo dll missing!");
											breaknow = TRUE;
											break;
										}
										if (!iatdone)
										{
											if (DetermineIATElimination(pi.hProcess, 0))
											{
												iatdone = TRUE;
											}
										}
										if (!iatadone)
										{
											if (DetermineIATEliminationAlternate(pi.hProcess, 0))
											{
												iatadone = TRUE;
											}
										}
										if (!ir1done)
										{
											if (DetermineIATRedirectionAlternate(pi.hProcess, 0))
											{
												ir1done = TRUE;
											}
										}
										if (!ir2done)
										{
											if (DetermineIATVariableRedirection(pi.hProcess, 0))
											{
												ir2done = TRUE;
											}
										}
										// Set a SWBP on CreateThread  address
										if (!WriteProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[6], &replbyte[6],
											sizeof(BYTE), &dwWritten))
										{
											LogItem("WriteProcessMemory Error CreateThread address: %p", SWBPExceptionAddress[6]);
											LogItem(NULL);
											breaknow = TRUE;
											break;
										}
										// For dll targets, CreateThread may not always be TRUE
										// So we set our memory breakpoint on access here!!
										if (isdll)
										{
											// Turn on Guard_Page attribute in .text section
											if (!VirtualProtectEx(pi.hProcess, (LPVOID)PESectionAddress,
												PESectionSize, PEGuardProtect, &PEOldProtect))
											{
												LogItem("VirtualProtectEx Error IAT Elimination address: %p", PESectionAddress);
												LogItem(NULL);
												breaknow = TRUE;
												break;
											}
											bGuardPage = TRUE;
										}
										// Set this to maintain visibility of this SWBP
										SetSingleStep(pi.hThread);
										SSGetModuleHandleA = TRUE;
									}
									else
									{
										// Set this to maintain visibility of this SWBP
										SetSingleStep(pi.hThread);
										SSGetModuleHandleA = TRUE;
									}
								ENDGETMOD1:
									l = 20;
									break;
									// WaitForDebugEvent RETN address (child debugging loop)
								case 5:
									if (detachnow)
									{
										//Read Esp to obtain return address
										PvoidAddr = (LPVOID)(DWORD_PTR)Context.Esp;
										if (!ReadProcessMemory(pi.hProcess, (LPVOID)PvoidAddr, &PvoidRead,
											sizeof(DWORD_PTR), &dwRead))
										{
											LogItem("ReadProcessMemory Error WaitForDebugEvent address: %p", PvoidAddr);
											LogItem(NULL);
										}
										else if (PvoidRead != 0)
										{
											if (PvoidRead >= Text1VMaddress &&
												PvoidRead <= (PVOID)((DWORD_PTR)Text1VMaddress + Text1VMsize))
											{
												// Find the proc address to the function we want
												ProcAddr10 = (FARPROC)GetProcAddress(hModule, (LPCSTR)"DebugActiveProcessStop");
												if (!ProcAddr10)
												{
													LogItem("Function: DebugActiveProcessStop");
													LogItem(NULL);
													LogItem("kernelbase.dll: GetProcAddress NULL");
													LogItem("Cannot detach from process!");
													LogItem("You must have WinXP or above!");
													breaknow = TRUE;
													break;
												}
												else
												{
													// Store the function address
													FunctionAddress[10] = (PVOID)ProcAddr10;
												}
												// Allocate some zero memory for operation
												dwZMVMAddress = VirtualAllocEx(pi.hProcess, NULL, 4096,
													MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
												if (dwZMVMAddress == NULL)
												{
													LogItem("VirtualAlloc Error DebugActiveProcessStop");
													LogItem(NULL);
													breaknow = TRUE;
													break;
												}
												DwordRead = (DWORD_PTR)dwZMVMAddress;
												for (instrcount = 0; instrcount < 6; instrcount++)
												{
													// Create instructions
													memset(cjumptype, 0, sizeof(cjumptype));
													memset(cjumpdest, 0, sizeof(cjumpdest));
													memset(ccmd, 0, sizeof(ccmd));
													switch (instrcount)
													{
													case 0:
														sprintf(cjumptype, "PUSH");
														sprintf(cjumpdest, "0%X", childpid);
														break;
													case 1:
														sprintf(cjumptype, "MOV");
														sprintf(cjumpdest, "EAX,%p", FunctionAddress[10]);
														break;
													case 2:
														sprintf(cjumptype, "CALL");
														sprintf(cjumpdest, "EAX");
														break;
													case 3:
														sprintf(cjumptype, "MOV");
														sprintf(cjumpdest, "EAX,1");
														break;
													case 4:
														sprintf(cjumptype, "PUSH");
														sprintf(cjumpdest, "%p", SWBPExceptionAddress[5]);
														break;
													case 5:
														sprintf(cjumptype, "RETN");
														break;
													}
													j = 0;
													// Create our text command to convert
													if (strlen(cjumpdest) > 0)
													{
														sprintf(ccmd, "%s %s", cjumptype, cjumpdest);
														pasm = (char *)ccmd;
														memset(&am, 0, sizeof(am));
														j = Assemble(pasm, DwordRead, &am, 0, 0, (char *)errtext);
													}
													else
													{
														sprintf(ccmd, "%s", cjumptype);
														pasm = (char *)ccmd;
														memset(&am, 0, sizeof(am));
														am.code[0] = 0xC3;
														j = 1;
													}
													if (j <= 0)
													{
														// We have an error!
														LogItem("error= %s", errtext);
														LogItem("Address: %08X", DwordRead);
														LogItem("Binary Code: %s", am.code);
														break;
													}
													else
													{
														// Write the new instruction
														if (!WriteProcessMemory(pi.hProcess, (LPVOID)DwordRead, &am.code,
															j, &dwWritten))
														{
															LogItem("WriteProcessMemory Error DebugActiveProcessStop address: %08X", DwordRead);
															LogItem(NULL);
															breaknow = TRUE;
															break;
														}
														else
														{
															DwordRead += j;
														}
													}
												}
												// Get Thread context
												Context.ContextFlags = CONTEXT_FULL;
												GetThreadContext(pi.hThread, &Context);
												Context.Eip = (DWORD_PTR)dwZMVMAddress;
												SetThreadContext(pi.hThread, &Context);
												memcpy(&CebugEv, &SebugEv, sizeof(CebugEv));
												if (!WriteProcessMemory(pi.hProcess, (LPVOID)SaveDwordRead, &CebugEv,
													sizeof(CebugEv), &dwWritten))
												{
													LogItem("WriteProcessMemory Error DebugActiveProcessStop address: %08X", SaveDwordRead);
													LogItem(NULL);
													breaknow = TRUE;
													break;
												}
												detachnow = FALSE;
												detached = TRUE;
												LogItem("Process %0X detached", childpid);
											}
										}
										l = 20;
										break;
									}
									//Read Esp+4 to obtain DebugEvent structure address pointer
									PvoidAddr = (PVOID)(DWORD_PTR)(Context.Esp + 4);
									DwordRead = 0;
									if (!ReadProcessMemory(pi.hProcess, (LPVOID)PvoidAddr, &DwordRead,
										sizeof(DWORD_PTR), &dwRead))
									{
										LogItem("ReadProcessMemory Error WaitForDebugEvent address: %p", PvoidAddr);
										LogItem(NULL);
										breaknow = TRUE;
										break;
									}
									if (DwordRead != 0)
									{
										// LOAD the debug event structure with the child exception
										// Convenient way to reference data elements
										PvoidAddr = (PVOID)DwordRead;
										if (!ReadProcessMemory(pi.hProcess, (LPVOID)PvoidAddr, &CebugEv,
											sizeof(CebugEv), &dwRead))
										{
											LogItem("ReadProcessMemory Error WaitForDebugEvent address: %p", PvoidAddr);
											LogItem(NULL);
											breaknow = TRUE;
											break;
										}
										SaveDwordRead = DwordRead;
										// interrogate child debug event codes
										switch (CebugEv.dwDebugEventCode)
										{
										case EXCEPTION_DEBUG_EVENT:
											switch (CebugEv.u.Exception.ExceptionRecord.ExceptionCode)
											{
												// Note: This is used for our child breakpoints
											case EXCEPTION_PRIV_INSTRUCTION:
												for (m = 0; m < 20; m++)
												{
													if (CebugEv.u.Exception.ExceptionRecord.ExceptionAddress == SWBPExceptionAddress[m])
													{
														// Reset child EIP
														Reset_EIP(childhProcess, childhThread, m);
														// Mod debug information exception code to a BreakPoint 0x80000003
														CebugEv.u.Exception.ExceptionRecord.ExceptionCode = EXCEPTION_BREAKPOINT;
														if (!WriteProcessMemory(pi.hProcess, (LPVOID)SaveDwordRead, &CebugEv,
															sizeof(CebugEv), &dwWritten))
														{
															LogItem("WriteProcessMemory Error PRIV_INSTRUCTION address: %08X", SaveDwordRead);
															LogItem(NULL);
															breaknow = TRUE;
															break;
														}
														switch (m)
														{
															// module entry
														case 0:
															m = 20;
															break;
															// VirtualAlloc  address
														case 1:
															if (checksecuritydump || checksecurityload)
															{
																if (secondva)
																{
																	if (checksecuritydump)
																	{
																		DumpSecurityDll(childhProcess);
																		checksecuritydump = FALSE;
																		goto VACDONE;
																	}
																	if (checksecurityload)
																	{
																		LoadSecurityDllFileName(childhProcess);
																		checksecurityload = FALSE;
																		goto VACDONE;
																	}
																}
																else
																{
																	secondva = TRUE;
																	// Obtain return address pointer if necessary
																	PvoidAddr = (PVOID)(DWORD_PTR)Context.Esp;
																	if (!ReadProcessMemory(childhProcess, (LPVOID)PvoidAddr, &DwordRead,
																		sizeof(DWORD_PTR), &dwRead))
																	{
																		LogItem("ReadProcessMemory Error VirtualAlloc address: %p", PvoidAddr);
																		LogItem(NULL);
																	}
																	thisSWBP = 1;
																	SWBPExceptionAddress[8] = (PVOID)DwordRead;
																	// Reset this SWBP
																	if (!SetPseudoSingleStep(childhProcess))
																		break;
																	goto VACDONE;
																}
															}
														FIRSTTRY1 :
															// Look for code splicing, check hi-address, vmsize and allocation type
															// to see if it qualifies for code-splicing
															if (firsttime)
															{
															// Obtain return address pointer if necessary
															PvoidAddr = (PVOID)(DWORD_PTR)Context.Esp;
															if (!ReadProcessMemory(childhProcess, (LPVOID)PvoidAddr, &DwordRead,
																sizeof(DWORD_PTR), &dwRead))
															{
																LogItem("ReadProcessMemory Error VirtualAlloc address: %p", PvoidAddr);
																LogItem(NULL);
																breaknow = TRUE;
																break;
															}
															thisSWBP = 1;
															SWBPExceptionAddress[8] = (PVOID)DwordRead;
															DetermineStrategicCodeSplicing(childhProcess, childhThread);
															// Reset this SWBP
															if (!SetPseudoSingleStep(childhProcess))
																break;
															goto VACDONE;
															}
																  // Verify code splicing
																  if (secondtime)
																  {
																	  // Obtain return address pointer if necessary
																	  PvoidAddr = (PVOID)(DWORD_PTR)Context.Esp;
																	  if (!ReadProcessMemory(childhProcess, (LPVOID)PvoidAddr, &DwordRead,
																		  sizeof(DWORD_PTR), &dwRead))
																	  {
																		  LogItem("ReadProcessMemory Error VirtualAlloc address: %p", PvoidAddr);
																		  LogItem(NULL);
																		  breaknow = TRUE;
																		  break;
																	  }
																	  // Set a pseudo single step with code retn address
																	  thisSWBP = 1;
																	  SWBPExceptionAddress[8] = (PVOID)DwordRead;
																	  if (!VerifyStrategicCodeSplicing(childhProcess, childhThread))
																	  {
																		  if (cserror)
																		  {
																			  cserror = FALSE;
																			  firsttime = TRUE;
																			  secondtime = FALSE;
																			  CSOAddress = 0;
																			  CSOSize = 0;
																			  goto FIRSTTRY1;
																		  }
																		  else
																		  {
																			  // Reset this SWBP
																			  if (!SetPseudoSingleStep(childhProcess))
																				  break;
																		  }
																	  }
																  }
															  VACDONE:
																  m = 20;
																  break;
																  // CreateFileA SWBP
														case 2:
															// Obtain return address pointer if necessary
															PvoidAddr = (PVOID)(DWORD_PTR)Context.Esp;
															if (!ReadProcessMemory(childhProcess, (LPVOID)PvoidAddr, &DwordRead,
																sizeof(DWORD_PTR), &dwRead))
															{
																LogItem("ReadProcessMemory Error CreateFileA address: %p", PvoidAddr);
																LogItem(NULL);
																breaknow = TRUE;
																break;
															}
															// See if the Call was made from Arm VM
															// This value should fall within Armadillo VM
															if (DwordRead >= (DWORD_PTR)dwArmVMAddress &&
																DwordRead <= (DWORD_PTR)dwArmVMAddress + dwArmVMNSize)
															{
																// breakout
															}
															else
															{
																thisSWBP = 2;
																SWBPExceptionAddress[8] = (PVOID)DwordRead;
																// reset this SWBP
																SetPseudoSingleStep(childhProcess);
															}
															m = 20;
															break;
															// GetModuleHandleA  address
														case 4:
															// Obtain return address pointer if necessary
															PvoidAddr = (PVOID)(DWORD_PTR)Context.Esp;
															if (!ReadProcessMemory(childhProcess, PvoidAddr, &PvoidRead,
																sizeof(DWORD_PTR), &dwRead))
															{
																LogItem("ReadProcessMemory Error GetModuleHandleA address: %p", PvoidAddr);
																LogItem(NULL);
																breaknow = TRUE;
																break;
															}
															// See if the Call was made from Arm VM
															// This value should fall within Armadillo VM
															else if (PvoidRead >= dwArmVMAddress &&
																PvoidRead <= (PVOID)((DWORD_PTR)dwArmVMAddress + dwArmVMNSize))
															{
																if (!DetermineARMVM(childhProcess, 0))
																{
																	// We have a problem
																	LogItem("Virtual Armadillo dll missing!");
																	breaknow = TRUE;
																	break;
																}
																if (!iatdone)
																{
																	if (DetermineIATElimination(childhProcess, 0))
																	{
																		iatdone = TRUE;
																	}
																}
																if (!iatadone)
																{
																	if (DetermineIATEliminationAlternate(childhProcess, 0))
																	{
																		iatadone = TRUE;
																	}
																}
																if (!ir1done)
																{
																	if (DetermineIATRedirectionAlternate(childhProcess, 0))
																	{
																		ir1done = TRUE;
																	}
																}
																if (!ir2done)
																{
																	if (DetermineIATVariableRedirection(childhProcess, 0))
																	{
																		ir2done = TRUE;
																	}
																}
																// Set a SWBP on CreateThread  address
																if (!WriteProcessMemory(childhProcess, (LPVOID)SWBPExceptionAddress[6], &replbyte[6],
																	sizeof(BYTE), &dwWritten))
																{
																	LogItem("WriteProcessMemory Error CreateThread address: %p", SWBPExceptionAddress[6]);
																	LogItem(NULL);
																	breaknow = TRUE;
																	break;
																}
																thisSWBP = 4;
																SWBPExceptionAddress[8] = PvoidRead;
																// reset this SWBP
																if (!SetPseudoSingleStep(childhProcess))
																	break;
															}
															else
															{
																thisSWBP = 4;
																SWBPExceptionAddress[8] = PvoidRead;
																// reset this SWBP
																if (!SetPseudoSingleStep(childhProcess))
																	break;
															}
															m = 20;
															break;
															// CreateThread address
														case 6:
															// Obtain return address pointer
															PvoidAddr = (PVOID)(DWORD_PTR)Context.Esp;
															if (!ReadProcessMemory(childhProcess, (LPVOID)PvoidAddr, &PvoidRead,
																sizeof(DWORD_PTR), &dwRead))
															{
																LogItem("ReadProcessMemory Error CreateThread address: %p", PvoidAddr);
																LogItem(NULL);
															}
															// See if the Call was made from Arm VM
															// This value should fall within Armadillo VM
															else if (PvoidRead >= dwArmVMAddress &&
																PvoidRead <= (PVOID)((DWORD_PTR)dwArmVMAddress + dwArmVMNSize))
															{
																// turn off any remaining code splicing determinations
																firsttime = FALSE;
																secondtime = FALSE;
																vadone = TRUE;
																// If this is a UPX compressed program use UPX1 section
																if (UPX1VMaddress != 0x00000000)
																{
																	LogItem("%s", isep);
																	LogItem("UPX compression detected, decompressing...");
																	Target = new BYTE[UPX1VMsize];
																	// Read the base module's process address space into our process memory
																	if (!ReadProcessMemory(childhProcess, (LPVOID)UPX1VMaddress, &Target[0],
																		UPX1VMsize, &dwRead))
																	{
																		LogItem("ReadProcessMemory Error CreateThread address: %p", UPX1VMaddress);
																		LogItem(NULL);
																		breaknow = TRUE;
																		break;
																	}
																	for (dwlength = UPX1VMsize; dwlength > 0; dwlength--)
																	{
																		if (Target[dwlength] == 0xE9)
																		{
																			dwCalcAddress = (DWORD_PTR)UPX1VMaddress + dwlength;
																			memset(&MyDisasm, 0, sizeof(DISASM));
																			len = 0;
																			/* ============================= Init EIP */
																			MyDisasm.EIP = (UIntPtr)&Target[dwlength];
																			MyDisasm.VirtualAddr = (UInt64)dwCalcAddress;
																			/* ============================= Loop for Disasm */
																			len = (ProcAdd)(&MyDisasm);
																			if (len != UNKNOWN_OPCODE)
																			{
																				jmpconst = (DWORD_PTR)MyDisasm.Instruction.AddrValue;
																				if (jmpconst >= (ulong)UPX0VMaddress &&
																					jmpconst <= (ulong)UPX0VMaddress + UPX0VMsize)
																				{
																					break;
																				}
																				else if (jmpconst >= (ulong)UPX1VMaddress &&
																					jmpconst <= (ulong)UPX1VMaddress + UPX1VMsize)
																				{
																					LogItem("Warning: JMP destination section UPX1, not OEP!");
																					break;
																				}
																				else
																				{
																					jmpconst = 0;
																				}
																			}
																		}
																	}
																	if (Target)
																	{
																		delete[] Target;
																		Target = 0;
																	}
																	if (jmpconst == 0)
																	{
																		LogItem("JMP UPX0 instruction not found in section UPX1");
																		LogItem("Unable to set breakpoint, using trace");
																		// Turn on Guard_Page attribute in UPX1 section
																		if (!VirtualProtectEx(childhProcess, (LPVOID)UPX1VMaddress,
																			UPX1VMsize, PEGuardProtect, &PEOldProtect))
																		{
																			LogItem("VirtualProtectEx Error CreateThread address: %p", UPX1VMaddress);
																			LogItem(NULL);
																			breaknow = TRUE;
																			break;
																		}
																		bcGuardPage = TRUE;
																	}
																	else
																	{
																		thisSWBP = 8;
																		// Save this JMP address to 1st .text section (UPX0)
																		dwCalcAddress = (DWORD_PTR)UPX1VMaddress + dwlength;
																		SWBPExceptionAddress[8] = (PVOID)dwCalcAddress;
																		if (!SetPseudoSingleStep(childhProcess))
																			break;
																	}
																}
																// If this is a Borland program, use .itext section
																else if (ItextVMaddress != 0x00000000)
																{
																	if (!VirtualProtectEx(childhProcess, (LPVOID)ItextVMaddress,
																		ItextVMsize, PEGuardProtect, &PEOldProtect))
																	{
																		LogItem("VirtualProtectEx Error CreateThread address: %p", ItextVMaddress);
																		LogItem(NULL);
																		breaknow = TRUE;
																		break;
																	}
																	bcGuardPage = TRUE;
																}
																else
																{
																SETGP1:
																	VirtualQueryEx(
																		childhProcess,
																		(LPVOID)PESectionAddress,
																		&mbi,
																		sizeof(mbi)
																		);
																	// If PAGE_GUARD protection is in effect then we
																	// have copymem2
																	// This value will be 100 + other protections
																	if (mbi.Protect > 0x00000100)
																	{
																		onetime = TRUE;
																		LogItem("%s", isep);
																		LogItem("CopyMem2 detected");
																		// Set a SWBP on WriteProcessMemory
																		if (!WriteProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[3], &replbyte[3],
																			sizeof(BYTE), &dwWritten))
																		{
																			LogItem("WriteProcessMemory Error WriteProcessMemory address: %p", SWBPExceptionAddress[3]);
																			LogItem(NULL);
																			breaknow = TRUE;
																			break;
																		}
																	}
																	// use the .text section
																	else if (!VirtualProtectEx(childhProcess, (LPVOID)PESectionAddress,
																		PESectionSize, PEGuardProtect, &PEOldProtect))
																	{
																		LogItem("VirtualProtectEx Error CreateThread address: %p", PESectionAddress);
																		LogItem(NULL);
																		breaknow = TRUE;
																		break;
																	}
																	bcGuardPage = TRUE;
																	// Set a SWBP on CreateFileA address
																	if (!WriteProcessMemory(childhProcess, (LPVOID)SWBPExceptionAddress[2], &replbyte[2],
																		sizeof(BYTE), &dwWritten))
																	{
																		LogItem("WriteProcessMemory Error CreateFileA address: %p", SWBPExceptionAddress[2]);
																		LogItem(NULL);
																		breaknow = TRUE;
																		break;
																	}
																}
															}
															else
															{
																thisSWBP = 6;
																SWBPExceptionAddress[8] = PvoidRead;
																// reset this SWBP
																if (!SetPseudoSingleStep(childhProcess))
																	break;
															}
															m = 20;
															break;
															// copymem2 OEP SWBP
														case 7:
														DOCOPYMEM2:
															// Increment .text section address by hex 1000 bytes
															dwCalcAddress = (DWORD_PTR)CBaddress;
																   dwCalcAddress += 4096;
																   CBaddress = (PVOID)dwCalcAddress;
																   if (CBaddress == CMaddress)
																   {
																	   dwCalcAddress += 4096;
																	   CBaddress = (PVOID)dwCalcAddress;
																   }
																   if (dwCalcAddress >= (DWORD_PTR)PESectionAddress + PESectionSize)
																   {
																	   copymem2 = FALSE;
																	   LogItem("CopyMem2 completed");
																	   // Original PAGE_GUARD exception
																	   // memory addresses for copymem-II
																	   memcpy(&CebugEv, &SebugEv, sizeof(CebugEv));
																	   PvoidAddr = (PVOID)SaveDwordRead;
																	   if (!WriteProcessMemory(pi.hProcess, (LPVOID)PvoidAddr, &CebugEv,
																		   sizeof(CebugEv), &dwRead))
																	   {
																		   LogItem("WriteProcessMemory Error CopyMemII address: %p", PvoidAddr);
																		   LogItem(NULL);
																	   }
																	   goto CHECKFOROEP;
																   }
																   else
																   {
																	   // Copy saved DEBUG_EVENT structure from
																	   // Original PAGE_GUARD exception and update
																	   // memory addresses for copymem-II
																	   memcpy(&CebugEv, &SebugEv, sizeof(CebugEv));
																	   CebugEv.u.Exception.ExceptionRecord.ExceptionAddress = CBaddress;
																	   CebugEv.u.Exception.ExceptionRecord.ExceptionInformation[1] = (ULONG_PTR)CBaddress;
																	   CebugEv.u.Exception.ExceptionRecord.ExceptionInformation[2] = (ULONG_PTR)CBaddress;
																	   PvoidAddr = (PVOID)SaveDwordRead;
																	   if (!WriteProcessMemory(pi.hProcess, (LPVOID)PvoidAddr, &CebugEv,
																		   sizeof(CebugEv), &dwWritten))
																	   {
																		   LogItem("WriteProcessMemory Error CopyMemII address: %p", PvoidAddr);
																		   LogItem(NULL);
																	   }
																	   // Get Child Thread context
																	   Context.ContextFlags = CONTEXT_FULL;
																	   GetThreadContext(childhThread, &Context);
																	   // CORRECT THE CHILD EIP ADDRESS FOR OUR SWBP ON OEP
																	   Context.Eip = (DWORD_PTR)SWBPExceptionAddress[7];
																	   SetThreadContext(childhThread, &Context);
																	   // Reset SWBP on the child's OEP
																	   if (!ReadProcessMemory(childhProcess, SWBPExceptionAddress[7], &scanbyte[7],
																		   sizeof(BYTE), &dwRead))
																	   {
																		   LogItem("ReadProcessMemory Error CopyMemII address: %p", SWBPExceptionAddress[7]);
																		   LogItem(NULL);
																	   }
																	   if (!WriteProcessMemory(childhProcess, SWBPExceptionAddress[7], &replbyte[7],
																		   sizeof(BYTE), &dwWritten))
																	   {
																		   LogItem("WriteProcessMemory Error CopyMemII address: %p", SWBPExceptionAddress[7]);
																		   LogItem(NULL);
																	   }
																   }
																   m = 20;
																   break;
																   // pseudo-single step SWBP
														case 8:
															Context.ContextFlags = CONTEXT_FULL;
															GetThreadContext(childhThread, &Context);
															if (Context.Eip >= (DWORD_PTR)PESectionAddress &&
																Context.Eip <= (DWORD_PTR)PESectionAddress + PESectionSize)
															{
																//goto NEXTGPC;
																if (!VirtualProtectEx(childhProcess, (LPVOID)PESectionAddress,
																	PESectionSize, PEGuardProtect, &PEOldProtect))
																{
																	LogItem("VirtualProtectEx Error CreateThread address: %p", PESectionAddress);
																	LogItem(NULL);
																	breaknow = TRUE;
																	break;
																}
																bcGuardPage = TRUE;
															}
															else
															{
																// Reset the SWBP
																if (!WriteProcessMemory(childhProcess, (LPVOID)SWBPExceptionAddress[thisSWBP], &replbyte[thisSWBP],
																	sizeof(BYTE), &dwWritten))
																{
																	LogItem("WriteProcessMemory Error Single Step address: %p", SWBPExceptionAddress[thisSWBP]);
																	LogItem(NULL);
																	breaknow = TRUE;
																}
															}
															m = 20;
															break;
															// IAT elimination SWBP
														case 9:
															if (!DoIATElimination(childhProcess))
															{
																FreeArmBMMemory();
																breaknow = TRUE;
																break;
															}
															if (checkredirect)
															{
																if (!DetermineIATRedirection(childhProcess,0))
																{
																	/*
																	FreeArmBMMemory();
																	breaknow = TRUE;
																	break;
																	*/
																}
															}
															FreeArmBMMemory();
															//Read stack for [EBP+4] to obtain return address to above function
															PvoidAddr = (PVOID)(DWORD_PTR)(Context.Ebp + 4);
															if (!ReadProcessMemory(childhProcess, (LPVOID)PvoidAddr, &PvoidRead,
																sizeof(DWORD_PTR), &dwRead))
															{
																LogItem("ReadProcessMemory Error IAT elimination address: %p", PvoidAddr);
																LogItem(NULL);
																breaknow = TRUE;
																break;
															}
															if (PvoidRead != 0)
															{
																// This value should fall within Armadillo VM
																if (PvoidRead >= dwArmVMAddress &&
																	PvoidRead <= (PVOID)((DWORD_PTR)dwArmVMAddress + dwArmVMNSize))
																{
																	// Apply the SWBP on this return address
																	SWBPExceptionAddress[12] = PvoidRead;
																	if (!ReadProcessMemory(childhProcess, (LPVOID)SWBPExceptionAddress[12], &scanbyte[12],
																		sizeof(BYTE), &dwRead))
																	{
																		LogItem("ReadProcessMemory Error IAT elimination address: %p", SWBPExceptionAddress[12]);
																		LogItem(NULL);
																		breaknow = TRUE;
																		break;
																	}
																	if (!WriteProcessMemory(childhProcess, (LPVOID)SWBPExceptionAddress[12], &replbyte[12],
																		sizeof(BYTE), &dwWritten))
																	{
																		LogItem("WriteProcessMemory Error IAT elimination address: %p", SWBPExceptionAddress[12]);
																		LogItem(NULL);
																		breaknow = TRUE;
																		break;
																	}
																}
																else
																{
																	LogItem("Warning: Cannot fix security.dll error");
																}
															}
															else
															{
																LogItem("Warning: Cannot fix security.dll error");
															}
															m = 20;
															break;
															// IAT ELIMINATION ADDRESS
														case 12:
															Context.ContextFlags = CONTEXT_FULL;
															GetThreadContext(childhThread, &Context);
															// Set register EAX to 1
															Context.Eax = 1;
															// Set Thread context
															SetThreadContext(childhThread, &Context);
															m = 20;
															break;
															// OutputDebugStringA ADDRESS
														case 13:
															// Obtain return address pointer
															PvoidAddr = (PVOID)(DWORD_PTR)(Context.Esp);
															if (!ReadProcessMemory(childhProcess, (LPVOID)PvoidAddr, &PvoidRead,
																sizeof(DWORD_PTR), &dwRead))
															{
																LogItem("ReadProcessMemory Error OutputDebugStringA address: %p", PvoidAddr);
																LogItem(NULL);
															}
															dwArmVMAddress = (PVOID)(DWORD_PTR)PvoidRead;
															dwRead = VirtualQueryEx(
																childhProcess,
																dwArmVMAddress,
																&mbi,
																sizeof(mbi)
																);
															if (dwRead)
															{
																if (mbi.AllocationBase != NULL)
																{
																	dwArmVMAddress = mbi.AllocationBase;
																}
																else
																{
																	thisSWBP = 13;
																	SWBPExceptionAddress[8] = PvoidRead;
																	// reset this SWBP
																	if (!SetPseudoSingleStep(childhProcess))
																		break;
																}
																if (!DetermineARMVM(childhProcess, 1))
																{
																	// We have a problem
																	LogItem("Virtual Armadillo dll missing!");
																	breaknow = TRUE;
																	break;
																}
																if (!vadone)
																{
																	firsttime = TRUE;
																	vadone = TRUE;
																	// Set a SWBP on VirtualAlloc address
																	if (!WriteProcessMemory(childhProcess, (LPVOID)SWBPExceptionAddress[1], &replbyte[1],
																		sizeof(BYTE), &dwWritten))
																	{
																		LogItem("WriteProcessMemory Error VirtualAlloc address: %p", SWBPExceptionAddress[1]);
																		LogItem(NULL);
																		breaknow = TRUE;
																		break;
																	}
																	// Set a SWBP on CreateFileMappingA address
																	if (!WriteProcessMemory(childhProcess, (LPVOID)SWBPExceptionAddress[15], &replbyte[15],
																		sizeof(BYTE), &dwWritten))
																	{
																		LogItem("WriteProcessMemory Error CreateFileMappingA address: %p", SWBPExceptionAddress[15]);
																		LogItem(NULL);
																		breaknow = TRUE;
																		break;
																	}
																	// Set a SWBP on GetModuleFileNameA address
																	if (!WriteProcessMemory(childhProcess, (LPVOID)SWBPExceptionAddress[16], &replbyte[16],
																		sizeof(BYTE), &dwWritten))
																	{
																		LogItem("WriteProcessMemory Error GetModuleFileNameA address: %p", SWBPExceptionAddress[16]);
																		LogItem(NULL);
																		breaknow = TRUE;
																		break;
																	}
																}
																if (usingstdfp)
																{
																	if (DetermineStdHardwareFingerprint(childhProcess, 0))
																	{
																		if (!usingenhfp)
																		{
																			DetermineSerialFingerprint(childhProcess, 0);
																		}
																		usingstdfp = FALSE;
																	}
																}
																if (usingenhfp)
																{
																	if (DetermineEnhHardwareFingerprint(childhProcess, 0))
																	{
																		DetermineSerialFingerprint(childhProcess, 0);
																		usingenhfp = FALSE;
																	}
																}
																FreeArmBMMemory();
															}
														OUTPUTDONE:
															m = 20;
															break;
															// CreateFileMappingA
														case 15:
															// Set a SWBP on GetModuleHandleA address
															if (!WriteProcessMemory(childhProcess, (LPVOID)SWBPExceptionAddress[4], &replbyte[4],
																sizeof(BYTE), &dwWritten))
															{
																LogItem("WriteProcessMemory Error GetModuleHandleA address: %p", SWBPExceptionAddress[4]);
																LogItem(NULL);
																breaknow = TRUE;
																break;
															}
															m = 20;
															break;
															// GetModuleFileNameA address
														case 16:
															// Obtain return address pointer if necessary
															PvoidAddr = (PVOID)(DWORD_PTR)Context.Esp;
															if (!ReadProcessMemory(childhProcess, PvoidAddr, &PvoidRead,
																sizeof(DWORD_PTR), &dwRead))
															{
																LogItem("ReadProcessMemory Error GetModuleHandleA address: %p", PvoidAddr);
																LogItem(NULL);
																breaknow = TRUE;
																break;
															}
															// See if the Call was made from Arm VM
															// This value should fall within Armadillo VM
															else if (PvoidRead >= dwArmVMAddress &&
																PvoidRead <= (PVOID)((DWORD_PTR)dwArmVMAddress + dwArmVMNSize))
															{
																if (!DetermineARMVM(childhProcess, 0))
																{
																	// We have a problem
																	LogItem("Virtual Armadillo dll missing!");
																	breaknow = TRUE;
																	break;
																}
																if (!iatdone)
																{
																	if (DetermineIATElimination(childhProcess, 0))
																	{
																		iatdone = TRUE;
																	}
																	else
																	{
																		thisSWBP = 16;
																		SWBPExceptionAddress[8] = PvoidRead;
																		// reset this SWBP
																		if (!SetPseudoSingleStep(childhProcess))
																			break;
																	}
																}
																if (!ir1done)
																{
																	if (DetermineIATRedirectionAlternate(childhProcess, 0))
																	{
																		ir1done = TRUE;
																	}
																}
																if (!ir2done)
																{
																	if (DetermineIATVariableRedirection(childhProcess, 0))
																	{
																		ir2done = TRUE;
																	}
																}
															}
															else
															{
																thisSWBP = 4;
																SWBPExceptionAddress[8] = PvoidRead;
																// reset this SWBP
																if (!SetPseudoSingleStep(childhProcess))
																	break;
															}
															m = 20;
															break;
														default:
															m = 20;
															break;
														} // end switch
													} // end if
												} // end for
												break;
											case EXCEPTION_GUARD_PAGE:
												// Save this address
												CMeventaddress = CebugEv.u.Exception.ExceptionRecord.ExceptionAddress;
												if (bcGuardPage)
												{
													bcGuardPage = FALSE;
												}
											CHECKFOROEP:
												// See if we are in the .text section
												// If not, reset this event
												// Get Thread context
												Context.ContextFlags = CONTEXT_FULL;
												GetThreadContext(childhThread, &Context);
												if (Context.Eip >= (DWORD_PTR)PESectionAddress &&
													Context.Eip <= (DWORD_PTR)PESectionAddress + PESectionSize)
												{
													if (dwoepcall == 0)
													{
														// Was the OEP called from Armadillo VM?
														// Obtain return address pointer
														PvoidAddr = (PVOID)(DWORD_PTR)Context.Esp;
														if (!ReadProcessMemory(childhProcess, (LPVOID)PvoidAddr, &PvoidRead,
															sizeof(DWORD_PTR), &dwRead))
														{
															LogItem("ReadProcessMemory Error GUARD_PAGE address: %p", PvoidAddr);
															LogItem(NULL);
															breaknow = TRUE;
															break;
														}
														dwoepcall = PvoidRead;
													}
												ONETIME:
													if (onetime)
													{
														// Initialize copymem2 processing
														onetime = FALSE;
														copymem2 = TRUE;
														// Save this DEBUG_EVENT structure
														memcpy(&SebugEv, &CebugEv, sizeof(CebugEv));
														// Compute the base exception address
														CMaddress = (PVOID)((DWORD_PTR)CMeventaddress / 4096 * 4096);
														// Compute the incremental page guard address
														CBaddress = BaseOfImage;
														SWBPExceptionAddress[7] = CMeventaddress;
														// Setup search for computed # .text memory pages (4096 blocks)
														// copymem-II for encryption / decryption
														FreeArmBMMemory();
														// Allocate some memory for operation
														dwBMVMAddress = VirtualAlloc(NULL, Text1VMsize,
															MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
														// Read the parent's .text1 section address space into our process memory
														if (!ReadProcessMemory(pi.hProcess, Text1VMaddress, dwBMVMAddress,
															Text1VMsize, &dwRead))
														{
															LogItem("ReadProcessMemory Error Text1VMaddress address: %p", Text1VMaddress);
															LogItem(NULL);
															breaknow = TRUE;
															break;
														}
														//Search for the hex string
														dwFileSize = Text1VMsize;		//Size of search space
														dwAddress = dwBMVMAddress;		//Search begin address
														// Using wildcards
														bWildcard = TRUE;
														DoSearch(1, 0);
														// Search String not found! 
														if (!sf)
														{
															LogItem("decrypted pages for copymem2 search string not found!");
															if (checkforerrors)
															{
																CreateDump(pi.hProcess, 1);
																FreeVirtualMemory();
																FreePEMemory();
															}
															breaknow = TRUE;
															break;
														}
														else
														{
															dwOffset = ((DWORD_PTR)((HPSTR)sf - (HPSTR)ss));
														}
														// Turn off Wildcards
														bWildcard = FALSE;
														// Set a pointer to our search offset .data # page sections variable
														dwBMVMOffset = (DWORD_PTR)Text1VMaddress + dwOffset + 2;
														PvoidAddr = (PVOID)dwBMVMOffset;
														// Read the dword pointer for data variable
														if (!ReadProcessMemory(pi.hProcess, (LPVOID)PvoidAddr, &PvoidRead,
															sizeof(DWORD_PTR), &dwRead))
														{
															LogItem("ReadProcessMemory Error Text1VMaddress address: %p", PvoidAddr);
															LogItem(NULL);
															breaknow = TRUE;
															break;
														}
														if (PvoidRead != 0)
														{
															// Obtain the value contained in this dword pointer
															if (!ReadProcessMemory(pi.hProcess, (LPVOID)PvoidRead, &dwBMVMValue,
																sizeof(DWORD_PTR), &dwRead))
															{
																LogItem("ReadProcessMemory Error Text1VMaddress address: %p", PvoidRead);
																LogItem(NULL);
																breaknow = TRUE;
																break;
															}
														}
														// Increase # decrypted pages max variable value
														dwBMVMValue = (PVOID)0xFFFF;
														if (!WriteProcessMemory(pi.hProcess, (LPVOID)PvoidRead, &dwBMVMValue,
															sizeof(DWORD_PTR), &dwWritten))
														{
															LogItem("WriteProcessMemory Error Text1VMaddress address: %p", PvoidRead);
															LogItem(NULL);
															breaknow = TRUE;
															break;
														}
														break;
													}
												NEXTGPC:
													if (copymem2)
													{
														goto DOCOPYMEM2;
													}
													PEOldProtect = PAGE_EXECUTE_READWRITE;
													if (UPX1VMaddress != 0)
													{
														// Turn off Guard_Page attribute in UPX1 section
														if (!VirtualProtectEx(childhProcess, (LPVOID)UPX1VMaddress,
															UPX1VMsize, PEOldProtect, &PESecProtect))
														{
															LogItem("VirtualProtectEx Error GUARD_PAGE address: %p", UPX1VMaddress);
															LogItem(NULL);
															breaknow = TRUE;
															break;
														}
													}
													if (ItextVMaddress != 0)
													{
														// turn off guard page on 2nd text section
														if (!VirtualProtectEx(childhProcess, (LPVOID)ItextVMaddress,
															ItextVMsize, PEOldProtect, &PESecProtect))
														{
															LogItem("VirtualProtectEx Error GUARD_PAGE address: %p", ItextVMaddress);
															LogItem(NULL);
															breaknow = TRUE;
															break;
														}
													}
													// turn off guard page in the code / text section
													if (!VirtualProtectEx(childhProcess, (LPVOID)PESectionAddress,
														PESectionSize, PEOldProtect, &PESecProtect))
													{
														LogItem("VirtualProtectEx Error GUARD_PAGE address: %p", PESectionAddress);
														LogItem(NULL);
														breaknow = TRUE;
														break;
													}
													// Restore original OEP byte for copymem2
													if (SWBPExceptionAddress[7] != 0 && scanbyte[7] != 0x00)
													{
														if (checkignore2ndtext)
														{
															if (OEPDelphiVAddress != 0x00)
															{
																SWBPExceptionAddress[7] = (PVOID)OEPDelphiVAddress;
															}
														}
														// CORRECT THE CHILD EIP ADDRESS FOR OUR SWBP ON OEP
														Context.Eip = (DWORD_PTR)SWBPExceptionAddress[7];
														SetThreadContext(childhThread, &Context);
													}
													if (dwoepcall >= dwArmVMAddress &&
														dwoepcall <= (LPVOID)((DWORD_PTR)dwArmVMAddress + dwArmVMNSize))
													{
														if (OEPDelphiVAddress != 0)
														{
															sprintf(d, "Warning OEP: %p\n"
																"is in 2nd text section!!\n", OEPDelphiVAddress);
														}
														else
														{
															// disregard
															sprintf(d, "No warnings issued");
														}
													}
													else
													{
														sprintf(d, "Warning: OEP call return VA: %p\n"
															"is not from Armadillo VM!!\n", dwoepcall);
														if (isdll)
														{
															if (OEPDelphiVAddress != 0)
															{
																OEPDelphiRVAddress = (LPVOID)((DWORD_PTR)OEPDelphiVAddress - (DWORD_PTR)BaseOfImage);
																sprintf(e, "This is acceptable for dll's, however\n"
																	"2nd text section found!!\n");
															}
															else
															{
																sprintf(e, "This is acceptable for dll's");
															}
														}
														else if (OEPDelphiVAddress != 0)
														{
															dwCalcAddress = (DWORD_PTR)OEPDelphiVAddress - (DWORD_PTR)BaseOfImage;
															OEPDelphiRVAddress = (LPVOID)dwCalcAddress;
															sprintf(e, "2nd text section found!!\n");
														}
													}
													ClearSWBPS(childhProcess);
													OEPRVAddress = (LPVOID)((DWORD_PTR)CebugEv.u.Exception.ExceptionRecord.ExceptionAddress - (DWORD_PTR)BaseOfImage);
													CSORVAddress = OEPRVAddress;
													OEPVAddress = CebugEv.u.Exception.ExceptionRecord.ExceptionAddress;
													SWBPExceptionAddress[7] = CebugEv.u.Exception.ExceptionRecord.ExceptionAddress;
													if (checkignore2ndtext && OEPDelphiRVAddress != 0x00000000 && OEPDelphiVAddress != 0x00000000)
													{
														OEPRVAddress = OEPDelphiRVAddress;
														OEPVAddress = OEPDelphiVAddress;
													}
													if (!redirectsplicing)
													{
														if (CSOSize >= 65536)
														{
															DoRemoveSplicing(childhProcess);
														}
														else
														{
															if (CSVerify(childhProcess))
															{
																DoRemoveSplicing(childhProcess);
															}
														}
													}
													// Detach at OEP for copymemII ??
													if (checkcm2)
													{
														// Obtain OEP dword original bytes
														if (!ReadProcessMemory(childhProcess, (LPVOID)CebugEv.u.Exception.ExceptionRecord.ExceptionAddress,
															&DwordRead, sizeof(DWORD_PTR), &dwRead))
														{
															LogItem("ReadProcessMemory Error GUARD_PAGE address: %p", CebugEv.u.Exception.ExceptionRecord.ExceptionAddress);
															LogItem(NULL);
															breaknow = TRUE;
															break;
														}
														DwordRead = ByteSwap2(DwordRead);
														LogItem("%s", isep);
														LogItem("Entry Point: %08X", (DWORD_PTR)CebugEv.u.Exception.ExceptionRecord.ExceptionAddress);
														LogItem("Original Bytes:");
														LogItem("%08X", DwordRead);
														// Write EBFE bytes to OEP
														if (!WriteProcessMemory(childhProcess, CebugEv.u.Exception.ExceptionRecord.ExceptionAddress,
															&ebfebytes, sizeof(ebfebytes), &dwWritten))
														{
															LogItem("WriteProcessMemory Error CopyMemII detach address: %p", CebugEv.u.Exception.ExceptionRecord.ExceptionAddress);
															LogItem(NULL);
															breaknow = TRUE;
															break;
														}
														// Mod debug information exception code to a BreakPoint 0x80000003
														CebugEv.u.Exception.ExceptionRecord.ExceptionCode = EXCEPTION_BREAKPOINT;
														if (!WriteProcessMemory(pi.hProcess, (LPVOID)SaveDwordRead, &CebugEv,
															sizeof(CebugEv), &dwWritten))
														{
															LogItem("WriteProcessMemory Error GUARD_PAGE address: %08X", SaveDwordRead);
															LogItem(NULL);
															breaknow = TRUE;
															break;
														}
														memcpy(&SebugEv, &CebugEv, sizeof(CebugEv));
														detachnow = TRUE;
														break;
													}
													sprintf(c, "Child PID: %X", childpid);
													sprintf(b, "%s\n\n"
														"OEP VA: %p\n"
														"OEP RVA: %p\n\n"
														"%s\n"
														"%s", c,
														OEPVAddress, OEPRVAddress, d, e);
													if (MessageBox(NULL, (LPCSTR)b, "Ready to dump!", MB_OKCANCEL + MB_SYSTEMMODAL + MB_ICONINFORMATION) == IDCANCEL)
													{
														goto CHECK;
													}
													CreateDump(childhProcess, 0);
													FreeVirtualMemory();
													FreePEMemory();
												CHECK:
													breaknow = TRUE;	// stop debugging process
													break;
												}
												else
												{
													// 2nd .text section OEP for Delphi progs
													if (Context.Eip >= (DWORD_PTR)ItextVMaddress &&
														Context.Eip <= (DWORD_PTR)ItextVMaddress + ItextVMsize)
													{
														PvoidAddr = (PVOID)(DWORD_PTR)Context.Eip;
														OEPDelphiVAddress = (LPVOID)PvoidAddr;
														if (checkignore2ndtext)
														{
															PEOldProtect = PAGE_EXECUTE_READWRITE;
															// turn off guard page on 2nd text section
															if (!VirtualProtectEx(childhProcess, (LPVOID)ItextVMaddress,
																ItextVMsize, PEOldProtect, &PESecProtect))
															{
																LogItem("VirtualProtectEx Error GUARD_PAGE address: %p", ItextVMaddress);
																LogItem(NULL);
																breaknow = TRUE;
																break;
															}
															ItextVMaddress = 0;
															// else use .text section
															if (!VirtualProtectEx(childhProcess, (LPVOID)PESectionAddress,
																PESectionSize, PEGuardProtect, &PEOldProtect))
															{
																LogItem("VirtualProtectEx Error GUARD_PAGE address: %p", PESectionAddress);
																LogItem(NULL);
																breaknow = TRUE;
																break;
															}
															bcGuardPage = TRUE;
														}
														else
														{
															goto NEXTGPC;
														}
													}
													else
													{
														// Check if we our in the CopyMemII loop
														if (SWBPExceptionAddress[7] != 0 && scanbyte[7] != 0x00)
														{
															// we are so handle accordingly.
															// copy back the saved debug event structure??
															if (CebugEv.u.Exception.ExceptionRecord.ExceptionAddress != SWBPExceptionAddress[7])
															{
																memcpy(&CebugEv, &SebugEv, sizeof(CebugEv));
															}
															goto DOCOPYMEM2;
														}
														if (traceon)
														{
															traceon = FALSE;
															LogItem("%s", isep);
															LogItem("Tracing to OEP...");
														}
														if (GetTickCount() - LastUpdate > 500)
														{
															LastUpdate = GetTickCount();
															logitemreplace = TRUE;
															LogItem("Context.Eip: %08X", Context.Eip);
														}
														FreeArmDASMMemory();
													}
												}
												EGPDONE:
													break;
											default:
												break;
											}	// end switch
											break;
										case EXIT_THREAD_DEBUG_EVENT:
											break;
										case CREATE_PROCESS_DEBUG_EVENT:
											debugblocker = TRUE;
											// Obtain handles to the child process and thread
											// We can use these to manipulate the child process
											childhProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, CebugEv.dwProcessId);
											childhThread = OpenThread(THREAD_ALL_ACCESS, FALSE, CebugEv.dwThreadId);
											childpid = CebugEv.dwProcessId;
											childtid = CebugEv.dwThreadId;
											// Save some addresses
											BaseOfImage = CebugEv.u.CreateProcessInfo.lpBaseOfImage;
											dwBase = BaseOfImage;
											LogItem("%s", isep);
											LogItem("Debug Blocker detected");
											LogItem("child Process ID: %X", childpid);
											LogItem("child Thread ID: %X", childtid);
										CHECKDB:
											if (checkdb)
											{
												// Obtain EP dword original bytes
												if (!ReadProcessMemory(childhProcess, StartAddress,
													&DwordRead, sizeof(DWORD_PTR), &dwRead))
												{
													LogItem("ReadProcessMemory Error CREATE_PROCESS_DEBUG_EVENT address: %p", StartAddress);
													LogItem(NULL);
													breaknow = TRUE;
													break;
												}
												DwordRead = ByteSwap2(DwordRead);
												LogItem("%s", isep);
												LogItem("Entry Point: %p", StartAddress);
												LogItem("Original Bytes:");
												LogItem("%08X", DwordRead);
												if (!WriteProcessMemory(childhProcess, (LPVOID)StartAddress,
													&ebfebytes, sizeof(ebfebytes), &dwWritten))
												{
													LogItem("WriteProcessMemory Error debug block OEP address: %p", StartAddress);
													LogItem(NULL);
													breaknow = TRUE;
												}
												// Mod debug information exception code to a BreakPoint 0x80000003
												CebugEv.u.Exception.ExceptionRecord.ExceptionCode = EXCEPTION_BREAKPOINT;
												CebugEv.u.Exception.ExceptionRecord.ExceptionAddress = StartAddress;
												if (!WriteProcessMemory(pi.hProcess, (LPVOID)SaveDwordRead, &CebugEv,
													sizeof(CebugEv), &dwWritten))
												{
													LogItem("WriteProcessMemory Error GUARD_PAGE address: %08X", SaveDwordRead);
													LogItem(NULL);
													breaknow = TRUE;
													break;
												}
												memcpy(&SebugEv, &CebugEv, sizeof(CebugEv));
												detachnow = TRUE;
												break;
											}
											if (!WriteProcessMemory(childhProcess, (LPVOID)SWBPExceptionAddress[13], &replbyte[13],
												sizeof(BYTE), &dwWritten))
											{
												LogItem("WriteProcessMemory Error OutputDebugStringA address: %p", SWBPExceptionAddress[13]);
												LogItem(NULL);
												breaknow = TRUE;
												break;
											}
											// Set a SWBP on VirtualAlloc (PART I)
											if (checksecuritydump || checksecurityload)
											{
												if (!WriteProcessMemory(childhProcess, SWBPExceptionAddress[1], &replbyte[1],
													sizeof(BYTE), &dwWritten))
												{
													LogItem("WriteProcessMemory Error VirtualAlloc address: %p", SWBPExceptionAddress[1]);
													LogItem(NULL);
												}
											}
											break;
										case LOAD_DLL_DEBUG_EVENT:
											break;
										case EXIT_PROCESS_DEBUG_EVENT:
											if (LastUpdate > 0)
											{
												LastUpdate = 0;
											}
											LogItem("child Exit Process ID: %X", childpid);
											breaknow = TRUE;
											CloseHandle(childhProcess);
											childhProcess = 0;
											CloseHandle(childhThread);
											childhThread = 0;
											goto WFDEDONE;
										default:
											break;
										} // end switch
										// Set Single Step for next SWBP
										SetSingleStep(pi.hThread);
										SSDebugEvent = TRUE;
									} // end switch
								WFDEDONE:
									l = 20;
									break;
									// CreateThread SWBP
								case 6:
									// If we have debugblocker in effect, disregard this SWBP
									if (debugblocker)
									{
										goto ENDCREATE1;
									}
									// Obtain return address pointer
									PvoidAddr = (PVOID)(DWORD_PTR)Context.Esp;
									if (!ReadProcessMemory(pi.hProcess, (LPVOID)PvoidAddr, &PvoidRead,
										sizeof(DWORD_PTR), &dwRead))
									{
										LogItem("ReadProcessMemory Error CreateThread address: %p", PvoidAddr);
										LogItem(NULL);
									}
									// See if the Call was made from Arm VM
									// This value should fall within Armadillo VM
									else if (PvoidRead >= dwArmVMAddress &&
										PvoidRead <= (PVOID)((DWORD_PTR)dwArmVMAddress + dwArmVMNSize))
									{
										// turn off any remaining code splicing determinations
										firsttime = FALSE;
										secondtime = FALSE;
										vadone = TRUE;
										// If this is a UPX compressed program use UPX1 section
										if (UPX1VMaddress != 0x00000000)
										{
											LogItem("%s", isep);
											LogItem("UPX compression detected, decompressing...");
											Target = new BYTE[UPX1VMsize];
											// Read the base module's process address space into our process memory
											if (!ReadProcessMemory(pi.hProcess, UPX1VMaddress, &Target[0],
												UPX1VMsize, &dwRead))
											{
												LogItem("ReadProcessMemory Error WaitForDebugEvent address: %p", UPX1VMaddress);
												LogItem(NULL);
												breaknow = TRUE;
												break;
											}
											for (dwlength = UPX1VMsize; dwlength > 0; dwlength--)
											{
												if (Target[dwlength] == 0xE9)
												{
													dwCalcAddress = (DWORD_PTR)UPX1VMaddress + dwlength;
													memset(&MyDisasm, 0, sizeof(DISASM));
													len = 0;
													/* ============================= Init EIP */
													MyDisasm.EIP = (UIntPtr)&Target[dwlength];
													MyDisasm.VirtualAddr = (UInt64)dwCalcAddress;
													/* ============================= Loop for Disasm */
													len = (ProcAdd)(&MyDisasm);
													if (len != UNKNOWN_OPCODE)
													{
														jmpconst = (DWORD_PTR)MyDisasm.Instruction.AddrValue;
														if (jmpconst >= (ulong)UPX0VMaddress &&
															jmpconst <= (ulong)UPX0VMaddress + UPX0VMsize)
														{
															break;
														}
														else if (jmpconst >= (ulong)UPX1VMaddress &&
															jmpconst <= (ulong)UPX1VMaddress + UPX1VMsize)
														{
															LogItem("Warning: JMP destination section UPX1, not OEP!");
															break;
														}
														else
														{
															jmpconst = 0;
															break;
														}
													}
												}
											}
											if (Target)
											{
												delete[] Target;
												Target = 0;
											}
											if (jmpconst == 0)
											{
												LogItem("JMP UPX0 instruction not found in section UPX1");
												LogItem("Unable to set breakpoint, using trace");
												// Turn on Guard_Page attribute in UPX1 section
												if (!VirtualProtectEx(pi.hProcess, (LPVOID)UPX1VMaddress,
													UPX1VMsize, PEGuardProtect, &PEOldProtect))
												{
													LogItem("VirtualProtectEx Error CreateThread address: %p", UPX1VMaddress);
													LogItem(NULL);
													breaknow = TRUE;
													break;
												}
												bGuardPage = TRUE;
											}
											else
											{
												thisSWBP = 8;
												// Save this JMP address to 1st .text section (UPX0)
												dwCalcAddress = (DWORD_PTR)UPX1VMaddress + dwlength;
												SWBPExceptionAddress[8] = (PVOID)dwCalcAddress;
												if (!SetPseudoSingleStep(pi.hProcess))
													break;
											}
										}
										// If this is a Borland program, use .itext section
										else if (ItextVMaddress != 0x00000000)
										{
											// Set the guard page flag on .itext section
											if (!VirtualProtectEx(pi.hProcess, (LPVOID)ItextVMaddress,
												ItextVMsize, PEGuardProtect, &PEOldProtect))
											{
												LogItem("VirtualProtectEx Error CreateThread address: %p", ItextVMaddress);
												LogItem(NULL);
												breaknow = TRUE;
												break;
											}
											bGuardPage = TRUE;
										}
										else
										{
										SETGP:
											// Turn on Guard_Page attribute in .text section
											if (!VirtualProtectEx(pi.hProcess, (LPVOID)PESectionAddress,
												PESectionSize, PEGuardProtect, &PEOldProtect))
											{
												LogItem("VirtualProtectEx Error CreateThread address: %p", PESectionAddress);
												LogItem(NULL);
												breaknow = TRUE;
												break;
											}
											// Set a SWBP on CreateFileA address
											if (!WriteProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[2], &replbyte[2],
												sizeof(BYTE), &dwWritten))
											{
												LogItem("WriteProcessMemory Error CreateFileA address: %p", SWBPExceptionAddress[2]);
												LogItem(NULL);
												breaknow = TRUE;
												break;
											}
											bGuardPage = TRUE;
										}
									}
									else
									{
										// Set Single Step for next SWBP
										SetSingleStep(pi.hThread);
										SSCreateThread = TRUE;
									}
								ENDCREATE1:
									l = 20;
									break;
									// UPX decompression
								case 8:
									// Turn on Guard_Page attribute in .text section
									if (!VirtualProtectEx(pi.hProcess, (LPVOID)PESectionAddress,
										PESectionSize, PEGuardProtect, &PEOldProtect))
									{
										LogItem("VirtualProtectEx Error UPX address: %p", PESectionAddress);
										LogItem(NULL);
										breaknow = TRUE;
										break;
									}
									bGuardPage = TRUE;
									l = 20;
									break;
									// IAT elimination SWBP
								case 9:
									if (!DoIATElimination(pi.hProcess))
									{
										FreeArmBMMemory();
										breaknow = TRUE;
										break;
									}
									if (checkredirect)
									{
										if (!DetermineIATRedirection(pi.hProcess,0))
										{
											/*
											FreeArmBMMemory();
											breaknow = TRUE;
											break;
											*/
										}
									}
									FreeArmBMMemory();
									//Read stack for [EBP+4] to obtain return address to above function
									PvoidAddr = (PVOID)(DWORD_PTR)(Context.Ebp + 4);
									if (!ReadProcessMemory(pi.hProcess, (LPVOID)PvoidAddr, &DwordRead,
										sizeof(DWORD_PTR), &dwRead))
									{
										LogItem("ReadProcessMemory Error IAT elimination address: %p", PvoidAddr);
										LogItem(NULL);
										breaknow = TRUE;
										break;
									}
									if (DwordRead != 0)
									{
										// This value should fall within Armadillo VM
										if (DwordRead >= (DWORD_PTR)dwArmVMAddress &&
											DwordRead <= (DWORD_PTR)dwArmVMAddress + dwArmVMNSize)
										{
											// Apply the SWBP on this return address
											SWBPExceptionAddress[12] = (PVOID)DwordRead;
											if (!ReadProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[12], &scanbyte[12],
												sizeof(BYTE), &dwRead))
											{
												LogItem("ReadProcessMemory Error IAT elimination address: %p", SWBPExceptionAddress[12]);
												LogItem(NULL);
												breaknow = TRUE;
												break;
											}
											if (!WriteProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[12], &replbyte[12],
												sizeof(BYTE), &dwWritten))
											{
												LogItem("WriteProcessMemory Error IAT elimination address: %p", SWBPExceptionAddress[12]);
												LogItem(NULL);
												breaknow = TRUE;
												break;
											}
										}
										else
										{
											LogItem("Warning: Cannot fix security.dll error");
										}
									}
									else
									{
										LogItem("Warning: Cannot fix security.dll error");
									}
									l = 20;
									break;
									// OpenMutexA SWBP Nanomites
								case 10:
									//Read Esp to obtain return address
									PvoidAddr = (PVOID)(DWORD_PTR)Context.Esp;
									if (!ReadProcessMemory(pi.hProcess, (LPVOID)PvoidAddr, &DwordRead,
										sizeof(DWORD_PTR), &dwRead))
									{
										LogItem("ReadProcessMemory Error OpenMutexA address: %p", PvoidAddr);
										LogItem(NULL);
										breaknow = TRUE;
										break;
									}
									if (DwordRead != 0)
									{
										if (firstmutex)
										{
											firstmutex = FALSE;
											secondmutex = TRUE;
											// Set this to maintain visibility of this SWBP
											SetSingleStep(pi.hThread);
											SSOpenMutexA = TRUE;
										}
										else if (secondmutex)
										{
											secondmutex = FALSE;
										}
										else
										{
											goto OMDONE;
										}
										Context.ContextFlags = CONTEXT_FULL;
										GetThreadContext(pi.hThread, &Context);
										// Fall thru and set register EAX to 1
										Context.Eax = 1;
										// Set Thread context
										SetThreadContext(pi.hThread, &Context);
									}
								OMDONE:
									l = 20;
									break;
									// ntdll.LdrLoadDll SWBP used for dll's
									// dll is loaded, but initialization hasn't occurred
									// Use this to obtain dll infos
									// Only fires if isdll=TRUE
								case 11:
									// Use psapi.lib to enumerate modules and find
									// our dll's load address and entry point
									if (!EnumProcessModules(pi.hProcess, hMods, sizeof(hMods), &cbNeeded))
									{
										LogItem("function: EnumProcessModules Error; module: psapi.dll");
										breaknow = TRUE;
										goto EMDONE;
									}
									// Calculate number of modules in the process
									nMods = cbNeeded / sizeof(HMODULE);
									for (i = 0; i < nMods; i++)
									{
										hDllModule = hMods[i];
										GetModuleFileNameEx(pi.hProcess, hDllModule, szModName, sizeof(szModName));
										if (0 == i)   // First module is the EXE. Add to list and skip it.
										{
											modlist[i] = i;
										}
										else  	// Not the first module. It's a DLL
										{
											// Determine if this is a DLL we've already seen
											if (i == modlist[i])
											{
												continue;
											}
											else
											{
												// We haven't see it, add it to the list
												modlist[i] = i;
												//Get the module information
												GetModuleInformation(
													pi.hProcess,
													hDllModule,
													&mi,
													cbNeeded
													);
												// include DLL entry, name and base image address, etc. info
												// Find the last '\\' to obtain a pointer to just the base module name part
												// (i.e. mydll.dll w/o the path)
												pszBaseName = strrchr(szModName, '\\');
												if (pszBaseName)  // We found a path, so advance to the base module name
												{
													pszBaseName++;
												}
												else
												{
													pszBaseName = szModName;  // No path.  Use the same name for both
												}
												//Is this module we are looking for
												if (strcmp((const char *)strupr((char *)pszBaseName), (const char*)strupr(pszDllName)) == 0)
												{
													// Save some addresses
													BaseOfImage = hDllModule;
													StartAddress = mi.EntryPoint;
													dwBase = BaseOfImage;
													// Determine all the armadillo PE header sections
													if (!DetermineArmSections(pi.hProcess))
													{
														FreePEMemory();
														breaknow = TRUE;
														break;
													}
													if (PdataVMaddress == 0x00000000)
													{
														// We have a problem
														LogItem("No .pdata section found in PE header!");
														LogItem("This doesn't appear to be an Armadillo protected program!");
														breaknow = TRUE;
														break;
													}
													if (TextVMaddress == 0x00000000)
													{
														// We have a problem
														LogItem("No .text section found in PE header!");
														breaknow = TRUE;
														break;
													}
													PESectionAddress = TextVMaddress;
													PESectionSize = TextVMsize;
													if (StartAddress >= Text1VMaddress &&
														StartAddress <= (LPVOID)((DWORD_PTR)PdataVMaddress + PdataVMsize))
													{
														// continue
													}
													else
													{
														// We have a problem
														LogItem("This doesn't appear to be an Armadillo protected program!");
														LogItem("The EP is not within the range of PE section .text1");
														break;
													}
													i = nMods;
												}
											} //endif
										} //endif
									} //endfor
								EMDONE:
									l = 20;
									break;
									// IAT ELIMINATION  ADDRESS
								case 12:
									Context.ContextFlags = CONTEXT_FULL;
									GetThreadContext(pi.hThread, &Context);
									// Set register EAX to 1
									Context.Eax = 1;
									// Set Thread context
									SetThreadContext(pi.hThread, &Context);
									l = 20;
									break;
									// OutputDebugStringA
								case 13:
									// If we have debugblocker in effect, disregard this SWBP
									if (debugblocker)
									{
										goto OUTPUTDONE1;
									}
									// Obtain return address pointer
									PvoidAddr = (PVOID)(DWORD_PTR)(Context.Esp);
									if (!ReadProcessMemory(pi.hProcess, (LPVOID)PvoidAddr, &PvoidRead,
										sizeof(DWORD_PTR), &dwRead))
									{
										LogItem("ReadProcessMemory Error OutputDebugStringA address: %p", PvoidAddr);
										LogItem(NULL);
										breaknow = TRUE;
										break;
									}
									dwArmVMAddress = PvoidRead;
									dwRead = VirtualQueryEx(
										pi.hProcess,
										dwArmVMAddress,
										&mbi,
										sizeof(mbi)
										);
									if (dwRead)
									{
										dwArmVMAddress = mbi.AllocationBase;
										if (!DetermineARMVM(pi.hProcess, 1))
										{
											// We have a problem
											LogItem("Virtual Armadillo dll missing!");
											breaknow = TRUE;
											break;
										}
										if (!vadone)
										{
											firsttime = TRUE;
											vadone = TRUE;
											// Set a SWBP on VirtualAlloc address
											if (!WriteProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[1], &replbyte[1],
												sizeof(BYTE), &dwWritten))
											{
												LogItem("WriteProcessMemory Error VirtualAlloc address: %p", SWBPExceptionAddress[1]);
												LogItem(NULL);
												breaknow = TRUE;
												break;
											}
											// Set a SWBP on CreateFileMappingA address
											if (!WriteProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[15], &replbyte[15],
												sizeof(BYTE), &dwWritten))
											{
												LogItem("WriteProcessMemory Error CreateFileMappingA address: %p", SWBPExceptionAddress[15]);
												LogItem(NULL);
												breaknow = TRUE;
												break;
											}
											// Set a SWBP on GetModuleFileNameA address
											if (!WriteProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[16], &replbyte[16],
												sizeof(BYTE), &dwWritten))
											{
												LogItem("WriteProcessMemory Error GetModuleFileNameA address: %p", SWBPExceptionAddress[16]);
												LogItem(NULL);
												breaknow = TRUE;
												break;
											}
											// Set a SWBP on LdrLoadDll  address
											if (isdll)
											{
												if (!WriteProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[11], &replbyte[11],
													sizeof(BYTE), &dwWritten))
												{
													LogItem("WriteProcessMemory Error isdll address: %p", SWBPExceptionAddress[11]);
													LogItem(NULL);
													breaknow = TRUE;
													break;
												}
											}
										}
										if (usingstdfp)
										{
											if (DetermineStdHardwareFingerprint(pi.hProcess, 0))
											{
												if (!usingenhfp)
												{
													DetermineSerialFingerprint(pi.hProcess, 0);
												}
												usingstdfp = FALSE;
											}
										}
										if (usingenhfp)
										{
											if (DetermineEnhHardwareFingerprint(pi.hProcess, 0))
											{
												DetermineSerialFingerprint(pi.hProcess, 0);
												usingenhfp = FALSE;
											}
										}
										FreeArmBMMemory();
									}
									OUTPUTDONE1:
									l = 20;
									break;
									// CreateFileMappingA
								case 15:
									// Set a SWBP on GetModuleHandleA address
									if (!WriteProcessMemory(pi.hProcess, SWBPExceptionAddress[4], &replbyte[4],
										sizeof(BYTE), &dwWritten))
									{
										LogItem("WriteProcessMemory Error GetModuleHandleA address: %p", SWBPExceptionAddress[4]);
										LogItem(NULL);
										breaknow = TRUE;
										break;
									}
									l = 20;
									break;
									// GetModuleFileNameA address
								case 16:
									// Obtain return address pointer if necessary
									PvoidAddr = (PVOID)(DWORD_PTR)Context.Esp;
									if (!ReadProcessMemory(pi.hProcess, PvoidAddr, &PvoidRead,
										sizeof(DWORD_PTR), &dwRead))
									{
										LogItem("ReadProcessMemory Error GetModuleHandleA address: %p", PvoidAddr);
										LogItem(NULL);
										breaknow = TRUE;
										break;
									}
									// See if the Call was made from Arm VM
									// This value should fall within Armadillo VM
									else if (PvoidRead >= dwArmVMAddress &&
										PvoidRead <= (PVOID)((DWORD_PTR)dwArmVMAddress + dwArmVMNSize))
									{
										if (!DetermineARMVM(pi.hProcess, 0))
										{
											// We have a problem
											LogItem("Virtual Armadillo dll missing!");
											breaknow = TRUE;
											break;
										}
										if (!iatdone)
										{
											if (DetermineIATElimination(pi.hProcess, 0))
											{
												iatdone = TRUE;
											}
											else
											{
												// Set Single Step for next SWBP
												SetSingleStep(pi.hThread);
												SSGetModuleFileNameA = TRUE;
											}
										}
										if (!ir1done)
										{
											if (DetermineIATRedirectionAlternate(pi.hProcess, 0))
											{
												ir1done = TRUE;
											}
										}
										if (!ir2done)
										{
											if (DetermineIATVariableRedirection(pi.hProcess, 0))
											{
												ir2done = TRUE;
											}
										}
									}
									else
									{
										// Set Single Step for next SWBP
										SetSingleStep(pi.hThread);
										SSGetModuleFileNameA = TRUE;
									}
									l = 20;
									break;
								default:
									l = 20;
									break;
								}// end switch
							}
							else
							{
								//sprintf(b,"UNDEFINED EXCEPTION_BREAKPOINT\n"
								//	"Exception address: %08X",
								//	(DWORD) CebugEv.u.Exception.ExceptionRecord.ExceptionAddress);
								//MessageBoxInformation(b);
							}	// endif
						} // end for
					}
					else
					{
						breaknow = TRUE;
					}
					break;

				case EXCEPTION_SINGLE_STEP:
					if (DebugEv.u.Exception.dwFirstChance)
					{
						dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
						//Is it our Single Step BP?
						//Yes, Reset our SWBP  address
						if (SSVirtualAlloc)
						{
							dwContinueStatus = DBG_CONTINUE;
							if (!WriteProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[1], &replbyte[1],
								sizeof(BYTE), &dwWritten))
							{
								LogItem("WriteProcessMemory Error VirtualAlloc address: %p", SWBPExceptionAddress[1]);
								LogItem(NULL);
								breaknow = TRUE;
								break;
							}
							SSVirtualAlloc = FALSE;
						}
						if (SSCreateThread)
						{
							dwContinueStatus = DBG_CONTINUE;
							if (!WriteProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[6], &replbyte[6],
								sizeof(BYTE), &dwWritten))
							{
								LogItem("WriteProcessMemory Error CreateThread address: %p", SWBPExceptionAddress[6]);
								LogItem(NULL);
								breaknow = TRUE;
								break;
							}
							SSCreateThread = FALSE;
						}
						if (SSGetModuleHandleA)
						{
							dwContinueStatus = DBG_CONTINUE;
							if (!WriteProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[4], &replbyte[4],
								sizeof(BYTE), &dwWritten))
							{
								LogItem("WriteProcessMemory Error GetModuleHandleA address: %p", SWBPExceptionAddress[4]);
								LogItem(NULL);
								breaknow = TRUE;
								break;
							}
							SSGetModuleHandleA = FALSE;
						}
						if (SSGetModuleFileNameA)
						{
							dwContinueStatus = DBG_CONTINUE;
							if (!WriteProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[16], &replbyte[16],
								sizeof(BYTE), &dwWritten))
							{
								LogItem("WriteProcessMemory Error GetModuleFileNameA address: %p", SWBPExceptionAddress[16]);
								LogItem(NULL);
								breaknow = TRUE;
								break;
							}
							SSGetModuleFileNameA = FALSE;
						}
						if (SSCreateFileA)
						{
							dwContinueStatus = DBG_CONTINUE;
							if (!WriteProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[2], &replbyte[2],
								sizeof(BYTE), &dwWritten))
							{
								LogItem("WriteProcessMemory Error CreateFileA address: %p", SWBPExceptionAddress[2]);
								LogItem(NULL);
								breaknow = TRUE;
								break;
							}
							SSCreateFileA = FALSE;
						}
						if (SSOpenMutexA)
						{
							dwContinueStatus = DBG_CONTINUE;
							if (!WriteProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[10], &replbyte[10],
								sizeof(BYTE), &dwWritten))
							{
								LogItem("WriteProcessMemory Error OpenMutexA address: %p", SWBPExceptionAddress[10]);
								LogItem(NULL);
								breaknow = TRUE;
								break;
							}
							SSOpenMutexA = FALSE;
						}
						if (SSDebugEvent)
						{
							dwContinueStatus = DBG_CONTINUE;
							if (pi.hProcess != NULL)
							{
								if (!WriteProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[5], &replbyte[5],
									sizeof(BYTE), &dwWritten))
								{
									LogItem("WriteProcessMemory Error WaitForDebugEvent address: %p", SWBPExceptionAddress[5]);
									LogItem(NULL);
									breaknow = TRUE;
									break;
								}
							}
							SSDebugEvent = FALSE;
						}
						if (SSGuardPage)
						{
							dwContinueStatus = DBG_CONTINUE;
							Context.ContextFlags = CONTEXT_FULL;
							GetThreadContext(pi.hThread, &Context);
							if (Context.Eip >= (DWORD_PTR)PESectionAddress &&
								Context.Eip <= (DWORD_PTR)PESectionAddress + PESectionSize)
							{
								goto NEXTGP;
							}
							else if (bGuardPage)
							{
								// 2nd .text section OEP for Delphi progs
								if (ItextVMaddress != 0x00000000)
								{
									VirtualQueryEx(
										pi.hProcess,
										(LPVOID)ItextVMaddress,
										&mbi,
										sizeof(mbi)
										);
									// If PAGE_GUARD protection is in effect then we have copymem2
									// This value will be 100 + other protections
									if (mbi.Protect > 0x00000100)
									{
										SSGuardPage = FALSE;
									}
									else
									{
										// Turn on Guard_Page attribute in itext section
										if (!VirtualProtectEx(pi.hProcess, (LPVOID)ItextVMaddress,
											ItextVMsize, PEGuardProtect, &PEOldProtect))
										{
											LogItem("VirtualProtectEx Error GUARD_PAGE address: %p", ItextVMaddress);
											LogItem(NULL);
											breaknow = TRUE;
											break;
										}
										bGuardPage = TRUE;
									}
								}
								// UPX 
								else if (UPX1VMaddress != 0)
								{
									VirtualQueryEx(
										pi.hProcess,
										(LPVOID)UPX1VMaddress,
										&mbi,
										sizeof(mbi)
										);
									// If PAGE_GUARD protection is in effect then we have copymem2
									// This value will be 100 + other protections
									if (mbi.Protect > 0x00000100)
									{
										SSGuardPage = FALSE;
									}
									else
									{
										// Turn on Guard_Page attribute in UPX1 section
										if (!VirtualProtectEx(pi.hProcess, (LPVOID)UPX1VMaddress,
											UPX1VMsize, PEGuardProtect, &PEOldProtect))
										{
											LogItem("VirtualProtectEx Error GUARD_PAGE address: %p", UPX1VMaddress);
											LogItem(NULL);
											breaknow = TRUE;
											break;
										}
										bGuardPage = TRUE;
									}
								}
								else
								{
									VirtualQueryEx(
										pi.hProcess,
										(LPVOID)PESectionAddress,
										&mbi,
										sizeof(mbi)
										);
									// If PAGE_GUARD protection is in effect then we have copymem2
									// This value will be 100 + other protections
									if (mbi.Protect > 0x00000100)
									{
										SSGuardPage = FALSE;
									}
									else
									{
										// Turn on Guard_Page attribute in .text section
										if (!VirtualProtectEx(pi.hProcess, (LPVOID)PESectionAddress,
											PESectionSize, PEGuardProtect, &PEOldProtect))
										{
											LogItem("VirtualProtectEx Error GUARD_PAGE address: %p", PESectionAddress);
											LogItem(NULL);
											breaknow = TRUE;
											break;
										}
										bGuardPage = TRUE;
									}
								}
							}
							else
							{
								// Set this again
								SetSingleStep(pi.hThread);
								if (traceon)
								{
									traceon = FALSE;
									LogItem("%s", isep);
									LogItem("Tracing to OEP...");
								}
								if (GetTickCount() - LastUpdate > 500)
								{
									LastUpdate = GetTickCount();
									logitemreplace = TRUE;
									LogItem("Context.Eip: %08X", Context.Eip);
								}
							}
						}
					}
					else
					{
						breaknow = TRUE;
					}
					break;

				case EXCEPTION_GUARD_PAGE:
					if (bGuardPage)
					{
						dwContinueStatus = DBG_CONTINUE;
						// See if we are in the .text section
						// If not, reset this event
						// Get Thread context
						Context.ContextFlags = CONTEXT_FULL;
						GetThreadContext(pi.hThread, &Context);
						if (Context.Eip >= (DWORD_PTR)PESectionAddress &&
							Context.Eip <= (DWORD_PTR)PESectionAddress + PESectionSize)
						{
						NEXTGP:
							bGuardPage = FALSE;
							PEOldProtect = PAGE_EXECUTE_READWRITE;
							if (UPX1VMaddress != 0)
							{
								// Turn off Guard_Page attribute in UPX1 section
								if (!VirtualProtectEx(pi.hProcess, (LPVOID)UPX1VMaddress,
									UPX1VMsize, PEOldProtect, &PESecProtect))
								{
									LogItem("VirtualProtectEx Error GUARD_PAGE address: %p", UPX1VMaddress);
									LogItem(NULL);
									breaknow = TRUE;
									break;
								}
							}
							if (ItextVMaddress != 0)
							{
								// 2nd .text section OEP for Delphi progs
								// Turn off Guard_Page attribute in itext section
								OEPDelphiVAddress = (LPVOID)(DWORD_PTR)Context.Eip;
								if (!VirtualProtectEx(pi.hProcess, (LPVOID)ItextVMaddress,
									ItextVMsize, PEOldProtect, &PESecProtect))
								{
									LogItem("VirtualProtectEx Error GUARD_PAGE address: %p", ItextVMaddress);
									LogItem(NULL);
									breaknow = TRUE;
									break;
								}
							}
							// Turn off Guard_Page attribute in code/text section
							if (!VirtualProtectEx(pi.hProcess, (LPVOID)PESectionAddress,
								PESectionSize, PEOldProtect, &PESecProtect))
							{
								LogItem("VirtualProtectEx Error GUARD_PAGE address: %p", PESectionAddress);
								LogItem(NULL);
								breaknow = TRUE;
								break;
							}
							// Obtain return address pointer
							PvoidAddr = (PVOID)(DWORD_PTR)Context.Esp;
							if (!ReadProcessMemory(pi.hProcess, (LPVOID)PvoidAddr, &PvoidRead,
								sizeof(DWORD_PTR), &dwRead))
							{
								LogItem("ReadProcessMemory Error WaitForDebugEvent address: %p", PvoidAddr);
								LogItem(NULL);
								breaknow = TRUE;
								break;
							}
							dwoepcall = PvoidRead;
							if (dwoepcall >= dwArmVMAddress &&
								dwoepcall <= (LPVOID)((DWORD_PTR)dwArmVMAddress + dwArmVMNSize))
							{
								if (OEPDelphiVAddress != 0)
								{
									sprintf(d, "Warning OEP: %p\n"
										"is in 2nd text section!!\n", OEPDelphiVAddress);
								}
								else
								{
									// disregard
									sprintf(d, "No warnings issued");
								}
							}
							else
							{
								sprintf(d, "Warning: OEP call return VA: %p\n"
									"is not from Armadillo VM!!\n", dwoepcall);
								if (isdll)
								{
									if (OEPDelphiVAddress != 0)
									{
										OEPDelphiRVAddress = (LPVOID)((DWORD_PTR)OEPDelphiVAddress - (DWORD_PTR)BaseOfImage);
										sprintf(e, "This is acceptable for dll's, however\n"
											"2nd text section found!!\n");
									}
									else
									{
										sprintf(e, "This is acceptable for dll's");
									}
								}
								else if (OEPDelphiVAddress != 0)
								{
									OEPDelphiRVAddress = (LPVOID)((DWORD_PTR)OEPDelphiVAddress - (DWORD_PTR)BaseOfImage);
									sprintf(e, "2nd text section found!!\n");
								}
							}
							// Turn off SWBP's
							ClearSWBPS(pi.hProcess);
							OEPRVAddress = (LPVOID)((DWORD_PTR)DebugEv.u.Exception.ExceptionRecord.ExceptionAddress - (DWORD_PTR)BaseOfImage);
							CSORVAddress = OEPRVAddress;
							OEPVAddress = DebugEv.u.Exception.ExceptionRecord.ExceptionAddress;
							SWBPExceptionAddress[7] = DebugEv.u.Exception.ExceptionRecord.ExceptionAddress;
							if (checkignore2ndtext && OEPDelphiRVAddress != 0x00000000 && OEPDelphiVAddress != 0x00000000)
							{
								OEPRVAddress = OEPDelphiRVAddress;
								OEPVAddress = OEPDelphiVAddress;
							}
							if (!redirectsplicing)
							{
								if (CSOSize >= 65536)
								{
									DoRemoveSplicing(pi.hProcess);
								}
								else
								{
									if (CSVerify(pi.hProcess))
									{
										DoRemoveSplicing(pi.hProcess);
									}
								}
							}
							sprintf(c, "Parent PID: %X", DebugEv.dwProcessId);
							sprintf(b, "%s\n\n"
								"OEP VA: %p\n"
								"OEP RVA: %p\n\n"
								"%s\n"
								"%s", c,
								OEPVAddress, OEPRVAddress, d, e);
							if (MessageBox(NULL, (LPCSTR)b, "Ready to dump!", MB_OKCANCEL + MB_SYSTEMMODAL + MB_ICONINFORMATION) == IDCANCEL)
							{
								goto CHECK1;
							}
							CreateDump(pi.hProcess, 0);
							FreeVirtualMemory();
							FreePEMemory();
						CHECK1:
							breaknow = TRUE;	// stop debugging
							break;
						}
						else
						{
							// 2nd .text section OEP for Delphi progs
							if (Context.Eip >= (DWORD_PTR)ItextVMaddress &&
								Context.Eip <= (DWORD_PTR)ItextVMaddress + ItextVMsize)
							{
								OEPDelphiVAddress = (LPVOID)(DWORD_PTR)Context.Eip;
								if (checkignore2ndtext)
								{
									PEOldProtect = PAGE_EXECUTE_READWRITE;
									// turn off guard page on 2nd text section
									if (!VirtualProtectEx(pi.hProcess, (LPVOID)ItextVMaddress,
										ItextVMsize, PEOldProtect, &PESecProtect))
									{
										LogItem("VirtualProtectEx Error GUARD_PAGE address: %p", ItextVMaddress);
										LogItem(NULL);
										breaknow = TRUE;
										break;
									}
									ItextVMaddress = 0;
									// Turn on Guard_Page attribute in .text section
									if (!VirtualProtectEx(pi.hProcess, (LPVOID)PESectionAddress,
										PESectionSize, PEGuardProtect, &PEOldProtect))
									{
										LogItem("VirtualProtectEx Error GUARD_PAGE address: %p", PESectionAddress);
										LogItem(NULL);
										breaknow = TRUE;
										break;
									}
									bGuardPage = TRUE;
								}
								else
									goto NEXTGP;
							}
						}
						// Set this again
						SetSingleStep(pi.hThread);
						SSGuardPage = TRUE;
					}
					else
					{
						dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
					}
					break;

				case EXCEPTION_BREAKPOINT:
					dwContinueStatus = DBG_CONTINUE;
					break;

				default:
					//sprintf( b,"Exception address:%08X\n"
					//"Exception Code:%08X",
					//DebugEv.u.Exception.ExceptionRecord.ExceptionAddress, DebugEv.u.Exception.ExceptionRecord.ExceptionCode);
					//MessageBoxInformation(b);
					dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
					break;
				} // end switch
				break;

			case EXIT_PROCESS_DEBUG_EVENT:
				contproc = FALSE;
				if (pi.hProcess)
				{
					CloseHandle(pi.hProcess);
					pi.hProcess = 0;
					CloseHandle(pi.hThread);
					pi.hThread = 0;
					bexitprocess = TRUE;
				}
				break;

			case EXIT_THREAD_DEBUG_EVENT:
				dwContinueStatus = DBG_CONTINUE;
				break;

			case CREATE_THREAD_DEBUG_EVENT:
				dwContinueStatus = DBG_CONTINUE;
				break;

			case CREATE_PROCESS_DEBUG_EVENT:
				dwContinueStatus = DBG_CONTINUE;
				// Save some addresses
				BaseOfImage = DebugEv.u.CreateProcessInfo.lpBaseOfImage;
				StartAddress = DebugEv.u.CreateProcessInfo.lpStartAddress;
				dwBase = BaseOfImage;
				// Set a SWBP on module's EP
				SWBPExceptionAddress[0] = StartAddress;
				// Apply the SWBP
				if (!ReadProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[0], &scanbyte[0],
					sizeof(BYTE), &dwRead))
				{
					LogItem("ReadProcessMemory Error Start address: %p", SWBPExceptionAddress[0]);
					LogItem(NULL);
					breaknow = TRUE;
					CloseHandle(DebugEv.u.CreateProcessInfo.hFile);
					break;
				}
				if (!WriteProcessMemory(pi.hProcess, (LPVOID)SWBPExceptionAddress[0], &replbyte[0],
					sizeof(BYTE), &dwWritten))
				{
					LogItem("WriteProcessMemory Error Start address: %p", SWBPExceptionAddress[0]);
					LogItem(NULL);
					breaknow = TRUE;
					CloseHandle(DebugEv.u.CreateProcessInfo.hFile);
					break;
				}
				dwPid = DebugEv.dwProcessId;
				dwTid = DebugEv.dwThreadId;
				LogItem("Process ID: %X", dwPid);
				sprintf(ebuf, "Exit Process ID: %X", dwPid);
				CloseHandle(DebugEv.u.CreateProcessInfo.hFile);
				break;

			case LOAD_DLL_DEBUG_EVENT:
				dwContinueStatus = DBG_CONTINUE;
				// close handle to load dll event
				CloseHandle(DebugEv.u.LoadDll.hFile);
				break;

			case UNLOAD_DLL_DEBUG_EVENT:
				dwContinueStatus = DBG_CONTINUE;
				break;

			case OUTPUT_DEBUG_STRING_EVENT:
				dwContinueStatus = DBG_CONTINUE;
				break;

			case RIP_EVENT:
				FormatMessage(
					FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
					NULL,
					GetLastError(),
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
					(LPTSTR)&lpMsgBuf,
					0,
					NULL
					);

				// Display the string.
				MessageBox(NULL, (LPCSTR)lpMsgBuf, "RIP_EVENT", MB_OK + MB_SYSTEMMODAL + MB_ICONERROR);
				// Free the buffer.
				LocalFree(lpMsgBuf);
				SetLastError(ERROR_SUCCESS);
				breaknow = TRUE;
				dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				break;

			default:
				dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				break;
			} // end switch

		CONTINUE:
			if (!contproc)
				break;
			ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, dwContinueStatus);
		}	//end if
	}	//end while
	// Close process and thread handles.
	PostMessage(hwndDlgA, WM_COMPLETED, 0, 0);
	if (childhProcess)
	{
		TerminateProcess(childhProcess, 0);
		CloseHandle(childhProcess);
		childhProcess = 0;
		if (childhThread)
		{
			CloseHandle(childhThread);
			childhThread = 0;
		}
	}
	if (pi.hProcess)
	{
		CloseHandle(pi.hProcess);
		pi.hProcess = 0;
		if (pi.hThread)
		{
			CloseHandle(pi.hThread);
			pi.hThread = 0;
		}
	}
	// start here
	if (analyzenf)
	{
		SaveLogfile();
		ClearListview(0);
		ArmNF_DumpNanos();
	}
	if (analyzest)
	{
		SaveLogfile();
		ClearListview(0);
		DisassembleDump();
		if (pNumNanos == 0)
		{
			LogItem("No nanomites to process.");
		}
		else
		{
			LocateNanomites();
		}
	}
	if (analyzelog)
	{
		SaveLogfile();
		ClearListview(0);
		if (LogNanomites())
		{
			LocateNanomites();
		}
	}
	// Enable Load buttons
	EnableWindow(hwnd08, TRUE);
	FreeBeaEngine();
	FreeArmZMMemory();
	FreeArmBMMemory();
	FreeArmDASMMemory();
	FreePESecMemory();
	FreeVirtualMemory();
	FreePEMemory();
	return 0;
}
// function to scale a design that assumes 96-DPI pixels
void InitScaling(void)
{
	hDC = GetDC(0);
	scaleX = GetDeviceCaps(hDC, LOGPIXELSX) / 96.0;
	scaleY = GetDeviceCaps(hDC, LOGPIXELSY) / 96.0;
	ReleaseDC(0, hDC);
	return;
}
// Create our main dialog box
int APIENTRY WinMain(HINSTANCE hinst, HINSTANCE hinstPrev, LPSTR lpCmdLine, int nCmdShow)
{
	memset(&wc, 0, sizeof(wc));
	wc.lpfnWndProc = DialogProc;
	wc.cbWndExtra = DLGWINDOWEXTRA;
	wc.hInstance = hinst;
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wc.lpszClassName = (LPCSTR)"ARMA_GEDDON";
	RegisterClass(&wc);
	memset(&cc, 0, sizeof(cc));
	cc.dwSize = sizeof(cc);
	cc.dwICC = 0xffffffff;
	InitCommonControlsEx(&cc);

	DialogBox(hinst, (LPCSTR)MAKEINTRESOURCE(IDD_MAINDIALOG), hwndMain, (DLGPROC)DialogProc);
	return 0;
}
/* CommandLine dialog function */
LRESULT CALLBACK CommandProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_INITDIALOG:
	{
		// Obtain handles for needed controls
		hwnd48 = GetDlgItem(hwndDlg, IDC_CMDARGUE);
		// cmdline present?
		if (szCmdline != 0)
		{
			SetWindowText(hwnd48, szCmdline);
		}
		// Limit text to MAX_PATH in size
		SendMessage(hwnd48, EM_SETLIMITTEXT, (WPARAM)MAX_PATH, 0);
		// Get the first child window. Use it.
		HWND hwnd = GetWindow(hwndDlg, GW_CHILD | GW_HWNDFIRST);
		while (hwnd)
		{
			// Get the next window. Use it.
			SendMessage(hwnd, WM_SETFONT, (WPARAM)hFont, 0);
			hwnd = GetWindow(hwnd, GW_HWNDNEXT);
		}
	}
		return TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDOK:
		{
			tlen = GetWindowTextLength(hwnd48);
			if (tlen > 0)
			{
				GetWindowText(hwnd48, szCmdbuffer, tlen + 1);
				szCmdline = (LPTSTR)szCmdbuffer;
			}
			else
			{
				szCmdline = 0;
			}
			EnableWindow(hwndDlgA, TRUE);
			EndDialog(hwndDlg, wParam);
		}
			return TRUE;
		}
		break;
	}
	return FALSE;
}
/* About dialog function */
LRESULT CALLBACK AboutProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	char aboutbuf[2048] = "ArmaGeddon V2.2 (final) - ARTeam\n"
		"Release - November 2014\n"
		"CondZero: Contributing editor\n"
		"SSlEvIN: GFX support\n"
		"Ghandi: Dll Loader.exe (dll support) +\n"
		"Invaluable support on technical issues\n"
		"Nacho_dj: ARTeam Import Reconstructor 1.8.0 Beta +\n"
		"Minimize PE size and overlay generation engine\n"
		"Admiral: Remove code Splicing engine\n"
		"Authors and Contributors: BeaEngine.dll\n"
		"(disassembler library x86-64 (IA32 and Intel64)\n" 
		"Oleh Yuschuk: 32-bit Disassembler and 32-bit single\n"
		"line Assembler engine based on stripped version of\n"
		"code used in OllyDbg v1.04\n"
		"NeVaDa: UnReal-RCE PersianCrackers v1.2 ArmNF.dll +\n"
		"Armadillo Nanomites Fixer v1.2 (public release)\n"
		"Special Friends: Custom Build UnpackMes + Testing\n"
		"Colors: http://ethanschoonover.com/solarized";
	switch (msg)
	{
	case WM_INITDIALOG:
	{
		// Obtain handles for needed controls
		hwndA = GetDlgItem(hwndDlg, IDG_CREDITS);
		hwndB = GetDlgItem(hwndDlg, IDC_ABOUTBMP);
		SetDlgItemText(hwndDlg, IDL_TEXTA, aboutbuf);
		// Get the first child window. Use it.
		HWND hwnd = GetWindow(hwndDlg, GW_CHILD | GW_HWNDFIRST);
		while (hwnd)
		{
			// Get the next window. Use it.
			SendMessage(hwnd, WM_SETFONT, (WPARAM)hFont, 0);
			hwnd = GetWindow(hwnd, GW_HWNDNEXT);
		}
		//  Get the About RECT size
		GetClientRect(hwndB, &Rect);
		newbmp = new Gdiplus::Bitmap(Rect.right, Rect.bottom, PixelFormat32bppPARGB);
		gr = new Gdiplus::Graphics(newbmp);
		oldbmp = (Gdiplus::Bitmap *)Gdiplus::Bitmap::FromHBITMAP(hBitmap02, NULL);
		gr->Graphics::DrawImage(oldbmp, 0, 0, Rect.right, Rect.bottom);
		// Creates a gdi bitmap from gdi+
		newbmp->Bitmap::GetHBITMAP(Gdiplus::Color(0, 0, 0, 0), &newcreditbmp);
		delete gr;
		delete newbmp;
		delete oldbmp;
		gr = 0;
		newbmp = 0;
		oldbmp = 0;
		SendMessage(hwndB, BM_SETIMAGE, (WPARAM)IMAGE_BITMAP, (LPARAM)newcreditbmp);
	}
		return TRUE;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDOK:
			EnableWindow(hwndDlgA, TRUE);
			EndDialog(hwndDlg, wParam);
			return TRUE;
		}
		break;
	case WM_CTLCOLORSTATIC:
		hwndCtrl = (HWND)lParam;	// handle of static control
		hdcStatic = (HDC)wParam;	// handle of display context
		// Set groupbox literals to color blue
		if (hwndCtrl == hwndA)
		{
			SetTextColor(hdcStatic, RGB(0, 0, 255));
			SetBkMode(hdcStatic, TRANSPARENT);
			return (LRESULT)(HBRUSH)CreateSolidBrush(GetSysColor(COLOR_BTNFACE));
		}
		break;
	}
	return FALSE;
}

/* About dialog function */
LRESULT CALLBACK NanoProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_INITDIALOG:
	{
		// Obtain handles for needed controls
		hwndList = GetDlgItem(hwndDlg, IDC_LISTNANO);
		// Get the first child window. Use it.
		HWND hwnd = GetWindow(hwndDlg, GW_CHILD | GW_HWNDFIRST);
		while (hwnd)
		{
			// Get the next window. Use it.
			SendMessage(hwnd, WM_SETFONT, (WPARAM)hFont, 0);
			hwnd = GetWindow(hwnd, GW_HWNDNEXT);
		}
		GetClientRect(hwndList, &Rect);		//  Get the listview RECT size
		// Initialize the LVCOLUMN structure.
		// The mask specifies that the format, width, text, and subitem members
		// of the structure are valid.
		lvcn.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvcn.fmt = LVCFMT_CENTER;
		lvcn.cx = Rect.right - Rect.left;	//  Make bar width of window
		int iColw = lvcn.cx / 3;
		lvcn.cx = iColw;						// Width of column in pixels.
		char	*coltest[3] = { "Address", "Destination", "JumpType" };
		// Add the columns.
		for (int i = 0; i < 3; i++)
		{
			lvcn.iSubItem = i;
			lvcn.pszText = (char *)coltest[i];
			iStatus = ListView_InsertColumn(hwndList, i, &lvcn);
		}
		// Update Listview for progress
		lvin.mask = LVIF_PARAM | LVIF_TEXT | LVIF_STATE;
		lvin.state = 0;
		lvin.stateMask = LVIS_FOCUSED;
		lvin.lParam = 1;
		lvin.iImage = 0;
		COLORREF cbbkcolor = RGB(42, 161, 152);
		COLORREF cbtextcolor = RGB(7, 54, 66);
		ListView_SetExtendedListViewStyle(hwndList, LVS_EX_GRIDLINES);
		ListView_SetTextBkColor(hwndList, cbbkcolor);
		ListView_SetTextColor(hwndList, cbtextcolor);
		// Add the items.
		for (int i = 0; i < NumNanos; i++)
		{
			lvin.iItem = i;
			for (int l = 0; l < 3; l++)
			{
				lvin.iSubItem = l;
				switch (l)
				{
				case 0:
					memset(c, 0, sizeof(c));
					sprintf(c, "%08X", RNano[i].Address);
					iStatus = ListView_InsertItem(hwndList, &lvin);
					break;
				case 1:
					memset(c, 0, sizeof(c));
					sprintf(c, "%08X", RNano[i].Dest);
					break;
				case 2:
					memset(c, 0, sizeof(c));
					switch (RNano[i].JumpType)
					{
					case 0:
						sprintf(c, "%s", "JUnknown");
						break;
					case 1:
						sprintf(c, "%s", "NotNanomite");
						break;
					case 2:
					case 25:
						sprintf(c, "%s", "JMP");
						break;
					case 3:
						sprintf(c, "%s", "JNZ");
						break;
					case 4:
						sprintf(c, "%s", "JZ");
						break;
					case 5:
						sprintf(c, "%s", "JB");
						break;
					case 6:
						sprintf(c, "%s", "JBE");
						break;
					case 7:
						sprintf(c, "%s", "JA");
						break;
					case 8:
						sprintf(c, "%s", "JNB");
						break;
					case 9:
						sprintf(c, "%s", "JG");
						break;
					case 10:
						sprintf(c, "%s", "JGE");
						break;
					case 11:
						sprintf(c, "%s", "J");
						break;
					case 12:
						sprintf(c, "%s", "JLE");
						break;
					case 13:
						sprintf(c, "%s", "JP");
						break;
					case 14:
						sprintf(c, "%s", "JPE");
						break;
					case 15:
						sprintf(c, "%s", "JNP");
						break;
					case 16:
						sprintf(c, "%s", "JPO");
						break;
					case 17:
						sprintf(c, "%s", "JS");
						break;
					case 18:
						sprintf(c, "%s", "JNS");
						break;
					case 19:
						sprintf(c, "%s", "JCXZ");
						break;
					case 20:
						sprintf(c, "%s", "JNCXZ");
						break;
					case 21:
						sprintf(c, "%s", "JC");
						break;
					case 22:
						sprintf(c, "%s", "JNC");
						break;
					case 23:
						sprintf(c, "%s", "JO");
						break;
					case 24:
						sprintf(c, "%s", "JNO");
						break;
					default:
						sprintf(c, "%s", "JUnknown");
						break;
					}
					break;
				default:
					break;
				}
				lvin.pszText = (LPSTR)c;
				ListView_SetItemText(hwndList, i, l, lvin.pszText);
			}
		}
	}
		return TRUE;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDOK:
			EnableWindow(hwndDlgA, TRUE);
			EndDialog(hwndDlg, wParam);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

/*
This is the main function for the dialog. It handles all messages. Do what your
application needs to do here.
*/
LRESULT CALLBACK DialogProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	PAINTSTRUCT ps;
	RECT rc;
	POINT pt;
	switch (msg)
	{
	case WM_INITDIALOG:
	{
		hinst = GetModuleHandle(NULL);
		// Drag and drop support
		DragAcceptFiles(hwndDlg, TRUE);
		InitScaling();
		// Get the owner window and dialog box rectangles. 
		if ((hwndMain = GetParent(hwndDlg)) == NULL)
		{
			hwndMain = GetDesktopWindow();
		}
		GetCurrentDirectory(MAX_PATH, dbuffer);
		// Global dialog handle
		hwndDlgA = hwndDlg;
		// Load our Icons for the main dialog box
		SendMessage(hwndDlg, WM_SETICON, ICON_SMALL, (LPARAM)LoadIcon(hinst, MAKEINTRESOURCE(IDI_SW)));
		SendMessage(hwndDlg, WM_SETICON, ICON_BIG, (LPARAM)LoadIcon(hinst, MAKEINTRESOURCE(IDI_SW)));
		// Obtain handles for needed controls
		hwnd01 = GetDlgItem(hwndDlg, IDC_OPEN);
		hwnd02 = GetDlgItem(hwndDlg, IDC_ABOUT);
		hwnd03 = GetDlgItem(hwndDlg, IDC_ANALYZEST);
		hwnd04 = GetDlgItem(hwndDlg, IDC_ANALYZELOG);
		hwnd07 = GetDlgItem(hwndDlg, IDC_NANOVIEW);
		hwnd08 = GetDlgItem(hwndDlg, IDC_LOADNANF);
		hwnd09 = GetDlgItem(hwndDlg, IDG_NANOMITES);
		hwnd10 = GetDlgItem(hwndDlg, IDG_LOG);
		hwnd12 = GetDlgItem(hwndDlg, IDC_SAVELOG);
		hwnd13 = GetDlgItem(hwndDlg, IDC_OPENMUTEX);
		hwnd14 = GetDlgItem(hwndDlg, IDC_MINIMIZE);
		hwnd15 = GetDlgItem(hwndDlg, IDC_RESOLVE);
		hwnd16 = GetDlgItem(hwndDlg, IDC_CLEARLOG);
		hwnd17 = GetDlgItem(hwndDlg, IDG_LOGFILE);
		hwnd18 = GetDlgItem(hwndDlg, IDC_CODESPLICE);
		hwnd19 = GetDlgItem(hwndDlg, IDC_DUMPPDATA);
		hwnd20 = GetDlgItem(hwndDlg, IDC_DB);
		hwnd21 = GetDlgItem(hwndDlg, IDC_CM2);
		hwnd22 = GetDlgItem(hwndDlg, IDG_DETACH);
		hwnd23 = GetDlgItem(hwndDlg, IDG_FINGERPRINT);
		hwnd24 = GetDlgItem(hwndDlg, IDL_STANDARD);
		hwnd25 = GetDlgItem(hwndDlg, IDL_ENHANCED);
		hwnd26 = GetDlgItem(hwndDlg, IDC_STANDARD);
		hwnd27 = GetDlgItem(hwndDlg, IDC_ENHANCED);
		hwnd31 = GetDlgItem(hwndDlg, IDC_HELP);
		hwnd32 = GetDlgItem(hwndDlg, IDC_REFRESH);
		hwnd34 = GetDlgItem(hwndDlg, IDC_SECURITYLOAD);
		hwnd35 = GetDlgItem(hwndDlg, IDC_SECURITYDUMP);
		hwnd36 = GetDlgItem(hwndDlg, IDC_IGNORE2NDTEXT);
		hwnd43 = GetDlgItem(hwndDlg, IDC_ANALYZENF);
		hwnd44 = GetDlgItem(hwndDlg, IDC_BYPASS2NDTEXT);
		hwnd45 = GetDlgItem(hwndDlg, IDG_INIFILE);
		hwnd46 = GetDlgItem(hwndDlg, IDC_LOADINI);
		hwnd47 = GetDlgItem(hwndDlg, IDC_SAVEINI);
		hwndIDLISTVIEW = GetDlgItem(hwndDlg, IDC_LIST1);
		GetClientRect(hwndIDLISTVIEW, &Rect);     //  Get the listview RECT size
		// Initialize the LVCOLUMN structure.
		// The mask specifies that the format, width, text, and subitem members
		// of the structure are valid.
		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvc.fmt = LVCFMT_LEFT;
		lvc.cx = Rect.right - Rect.left;	//  Make bar width of window
		lvc.pszText = (LPSTR)"";
		lvc.iSubItem = 0;                   //  Add display column (for Report View)
		ListView_InsertColumn(hwndIDLISTVIEW, 0, &lvc);
		// Update Listview for progress
		lvi.mask = LVIF_PARAM | LVIF_TEXT | LVIF_STATE;
		lvi.state = 0;
		lvi.stateMask = LVIS_FOCUSED;
		lvi.iSubItem = 0;
		lvi.lParam = 1;
		lvi.iImage = 0;
		// Load our bitmaps
		hBitmap01 = LoadBitmap(hinst, MAKEINTRESOURCE(IDB_OPEN));
		hBitmap02 = LoadBitmap(hinst, MAKEINTRESOURCE(IDB_CREDIT));
		hBitmap03 = LoadBitmap(hinst, MAKEINTRESOURCE(IDB_HELP));
		hBitmap04 = LoadBitmap(hinst, MAKEINTRESOURCE(IDB_REFRESH));
		hBitmap05 = LoadBitmap(hinst, MAKEINTRESOURCE(IDB_OPENGRAY));
		//Size bitmaps to window OPEN control
		//  Get the Open RECT size
		GetClientRect(hwnd01, &Rect);
		// START GDI+ SUB SYSTEM
		Gdiplus::GdiplusStartup(&m_gdiplusToken, &m_gdiplusStartupInput, NULL);
		newbmp = new Gdiplus::Bitmap(Rect.right, Rect.bottom, PixelFormat32bppPARGB);
		gr = new Gdiplus::Graphics(newbmp);
		oldbmp = (Gdiplus::Bitmap *)Gdiplus::Bitmap::FromHBITMAP(hBitmap01, NULL);
		Gdiplus::RectF destrec(0, 0, Rect.right, Rect.bottom);
		gr->Graphics::DrawImage(oldbmp, destrec, 0, 0, oldbmp->GetWidth(), oldbmp->GetHeight(), Gdiplus::UnitPixel);
		// Creates a gdi bitmap from gdi+
		newbmp->Bitmap::GetHBITMAP(Gdiplus::Color(0, 0, 0, 0), &newgdibmp);
		delete gr;
		delete oldbmp;
		//-------------------------------------------------//
		gr = new Gdiplus::Graphics(newbmp);
		oldbmp = (Gdiplus::Bitmap *)Gdiplus::Bitmap::FromHBITMAP(hBitmap05, NULL);
		gr->Graphics::DrawImage(oldbmp, destrec, 0, 0, oldbmp->GetWidth(), oldbmp->GetHeight(), Gdiplus::UnitPixel);
		newbmp->Bitmap::GetHBITMAP(Gdiplus::Color(0, 0, 0, 0), &newgrybmp);
		delete gr;
		delete newbmp;
		delete oldbmp;
		gr = 0;
		newbmp = 0;
		oldbmp = 0;
		//  Get the Refresh RECT size
		GetClientRect(hwnd32, &Rect);
		newbmp = new Gdiplus::Bitmap(Rect.right, Rect.bottom, PixelFormat32bppPARGB);
		gr = new Gdiplus::Graphics(newbmp);
		oldbmp = (Gdiplus::Bitmap *)Gdiplus::Bitmap::FromHBITMAP(hBitmap04, NULL);
		Gdiplus::RectF destrec2(0, 0, Rect.right, Rect.bottom);
		gr->Graphics::DrawImage(oldbmp, destrec2, 0, 0, oldbmp->GetWidth(), oldbmp->GetHeight(), Gdiplus::UnitPixel);
		// Creates a gdi bitmap from gdi+
		newbmp->Bitmap::GetHBITMAP(Gdiplus::Color(0, 0, 0, 0), &newrefreshbmp);
		delete gr;
		delete oldbmp;
		delete newbmp;
		gr = 0;
		oldbmp = 0;
		newbmp = 0;
		//  Get the Help RECT size
		GetClientRect(hwnd31, &Rect);
		newbmp = new Gdiplus::Bitmap(Rect.right, Rect.bottom, PixelFormat32bppPARGB);
		gr = new Gdiplus::Graphics(newbmp);
		oldbmp = (Gdiplus::Bitmap *)Gdiplus::Bitmap::FromHBITMAP(hBitmap03, NULL);
		Gdiplus::RectF destrec3(0, 0, Rect.right, Rect.bottom);
		gr->Graphics::DrawImage(oldbmp, destrec3, 0, 0, oldbmp->GetWidth(), oldbmp->GetHeight(), Gdiplus::UnitPixel);
		// Creates a gdi bitmap from gdi+
		newbmp->Bitmap::GetHBITMAP(Gdiplus::Color(0, 0, 0, 0), &newhelpbmp);
		delete gr;
		delete oldbmp;
		delete newbmp;
		gr = 0;
		oldbmp = 0;
		newbmp = 0;
		//  Get the About RECT size
		GetClientRect(hwnd02, &Rect);
		newbmp = new Gdiplus::Bitmap(Rect.right, Rect.bottom, PixelFormat32bppPARGB);
		gr = new Gdiplus::Graphics(newbmp);
		oldbmp = (Gdiplus::Bitmap *)Gdiplus::Bitmap::FromHBITMAP(hBitmap02, NULL);
		Gdiplus::RectF destrec1(0, 0, Rect.right, Rect.bottom);
		gr->Graphics::DrawImage(oldbmp, destrec1, 0, 0, oldbmp->GetWidth(), oldbmp->GetHeight(), Gdiplus::UnitPixel);
		// Creates a gdi bitmap from gdi+
		newbmp->Bitmap::GetHBITMAP(Gdiplus::Color(0, 0, 0, 0), &newaboutbmp);
		delete gr;
		delete oldbmp;
		delete newbmp;
		gr = 0;
		oldbmp = 0;
		newbmp = 0;
		SendMessage(hwnd01, BM_SETIMAGE, (WPARAM)IMAGE_BITMAP, (LPARAM)newgdibmp);
		SendMessage(hwnd02, BM_SETIMAGE, (WPARAM)IMAGE_BITMAP, (LPARAM)newaboutbmp);
		SendMessage(hwnd31, BM_SETIMAGE, (WPARAM)IMAGE_BITMAP, (LPARAM)newhelpbmp);
		SendMessage(hwnd32, BM_SETIMAGE, (WPARAM)IMAGE_BITMAP, (LPARAM)newrefreshbmp);
		greenimage = TRUE;
		// Limit text to format length "0000-0000"
		SendMessage(hwnd26, EM_SETLIMITTEXT, (WPARAM)9, 0);
		SendMessage(hwnd27, EM_SETLIMITTEXT, (WPARAM)9, 0);
		// When you create fonts in Windows, you use pixels to specify the font size, 
		// so you should adjust for DPI:
		hDC = GetDC(0);
		OrigFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
		LOGFONT lf;
		GetObject(OrigFont, sizeof(lf), &lf);
		lf.lfHeight = -MulDiv(DFONT_SIZE, GetDeviceCaps(hDC, LOGPIXELSY), 72);
		lf.lfWeight = FW_BOLD;
		hFont = CreateFontIndirect(&lf);
		ReleaseDC(0, hDC);
		// Get the first child window. Use it.
		HWND hwnd = GetWindow(hwndDlg, GW_CHILD | GW_HWNDFIRST);
		while (hwnd)
		{
			// Get the next window. Use it.
			if (hwnd != hwndIDLISTVIEW)
			{
				SendMessage(hwnd, WM_SETFONT, (WPARAM)hFont, 0);
			}
			hwnd = GetWindow(hwnd, GW_HWNDNEXT);
		}
		// Set defaults
		SetDlgItemText(hwndDlg, IDC_STANDARD, "0000-0000");
		SetDlgItemText(hwndDlg, IDC_ENHANCED, "0000-0000");
		EnableWindow(hwnd07, FALSE);
		EnableWindow(hwnd15, FALSE);
		EnableWindow(hwnd08, TRUE);
	}
		return TRUE;

	case WM_NOTIFY:
		switch (((LPNMHDR)lParam)->code)
		{
		case NM_RCLICK:
			// Right click context menu in ListView Control
			GetCursorPos(&pt);
			HMENU hmenuP = LoadMenu(hinst, MAKEINTRESOURCE(IDR_CONTEXT));
			HMENU hmenuS = GetSubMenu(hmenuP, 0);
			TrackPopupMenu(hmenuS, TPM_LEFTBUTTON | TPM_RIGHTBUTTON |
				TPM_LEFTALIGN, pt.x, pt.y, 0, hwndDlg, NULL);
			break;
		}
		return TRUE;

	case WM_RBUTTONDOWN:
		return TRUE;

	case WM_DROPFILES:
	{
		// Drag & Drop support (only process 1st returned file)
		HDROP hDrop = (HDROP)wParam;
		UINT nFiles = DragQueryFile(hDrop, (UINT)-1, NULL, 0);
		for (int i = 0; i < nFiles; i++)
		{
			memset(buffer, 0, sizeof(MAX_PATH));
			if (DragQueryFile(hDrop, i, (LPSTR)buffer, MAX_PATH))
			{
				// Send a Refresh button click message if user wants to reopen a target
				if (hThread)
				{
					if (MessageBox(NULL, (LPCSTR)"Start a new session?", "ArmaGeddon",
						MB_OKCANCEL + MB_SYSTEMMODAL + MB_ICONINFORMATION) == IDCANCEL)
					{
						return 0;
					}
					else
					{
						uiID = GetDlgCtrlID(hwnd32);
						SendMessage(hwndDlg, WM_COMMAND, MAKEWPARAM(uiID, BN_CLICKED), (LPARAM)hwnd32);
					}
				}
				stdlen = GetDlgItemText(hwndDlg, IDC_STANDARD, (LPSTR)stdfpbuf, sizeof(stdfpbuf));
				strupr(stdfpbuf);
				if (stdlen == 0)
				{
					SetDlgItemText(hwndDlg, IDC_STANDARD, "0000-0000");
				}
				else if (stdlen != 9)
				{
					sprintf(b, "Standard Fingerprint Format = XXXX-XXXX");
					MessageBoxInformation(b);
					break;
				}
				else
				{
					if (stdfpbuf[4] != '-')
					{
						sprintf(b, "Standard Fingerprint Format = XXXX-XXXX");
						MessageBoxInformation(b);
						break;
					}
					else
					{
						SetDlgItemText(hwndDlg, IDC_STANDARD, (LPSTR)stdfpbuf);
						if (stdfpbuf[0] != '0' || stdfpbuf[1] != '0' ||
							stdfpbuf[2] != '0' || stdfpbuf[3] != '0' ||
							stdfpbuf[5] != '0' || stdfpbuf[6] != '0' ||
							stdfpbuf[7] != '0' || stdfpbuf[8] != '0')
						{
							memcpy(c, stdfpbuf, sizeof(stdfpbuf));
							memset(stdfpbuf, 0, sizeof(stdfpbuf));
							j = 0;
							for (i = 0; i < 9; i++)
							{
								if (isxdigit(c[i]))
								{
									stdfpbuf[j] = c[i];
									j++;
								}
							}
							ustring = (unsigned char *)stdfpbuf;
							if (strlen((const char *)ustring) == 8)
							{
								dwstdfp = strtoul((const char *)ustring, (char **)NULL, 16);
								usingstdfp = TRUE;
							}
							else
							{
								sprintf(b, "Standard Fingerprint contains invalid characters\n"
									"Allowable hex chars: 0 - 9, A - F");
								MessageBoxInformation(b);
								break;
							}
						}
					}
				}
				enhlen = GetDlgItemText(hwndDlg, IDC_ENHANCED, (LPSTR)enhfpbuf, sizeof(enhfpbuf));
				strupr(enhfpbuf);
				if (enhlen == 0)
				{
					SetDlgItemText(hwndDlg, IDC_ENHANCED, "0000-0000");
				}
				else if (enhlen != 9)
				{
					sprintf(b, "Enhanced Fingerprint Format = XXXX-XXXX");
					MessageBoxInformation(b);
					break;
				}
				else
				{
					if (enhfpbuf[4] != '-')
					{
						sprintf(b, "Enhanced Fingerprint Format = XXXX-XXXX");
						MessageBoxInformation(b);
						break;
					}
					else
					{
						SetDlgItemText(hwndDlg, IDC_ENHANCED, (LPSTR)enhfpbuf);
						if (enhfpbuf[0] != '0' || enhfpbuf[1] != '0' ||
							enhfpbuf[2] != '0' || enhfpbuf[3] != '0' ||
							enhfpbuf[5] != '0' || enhfpbuf[6] != '0' ||
							enhfpbuf[7] != '0' || enhfpbuf[8] != '0')
						{
							memcpy(c, enhfpbuf, sizeof(enhfpbuf));
							memset(enhfpbuf, 0, sizeof(enhfpbuf));
							j = 0;
							for (i = 0; i < 9; i++)
							{
								if (isxdigit(c[i]))
								{
									enhfpbuf[j] = c[i];
									j++;
								}
							}
							ustring = (unsigned char *)enhfpbuf;
							if (strlen((const char *)ustring) == 8)
							{
								dwenhfp = strtoul((const char *)ustring, (char **)NULL, 16);
								usingenhfp = TRUE;
							}
							else
							{
								sprintf(b, "Enhanced Fingerprint contains invalid characters\n"
									"Allowable hex chars: 0 - 9, A - F");
								MessageBoxInformation(b);
								break;
							}
						}
					}
				}
				hThread = (HANDLE)_beginthreadex(NULL, 0, &RunExe, NULL, 0, &dwThreadid);
				if (!hThread)
				{
					LogItem("CreateThread failed...try again!");
					break;
				}
				// Displays grayed Armadillo image denoting running process
				SendMessage(hwnd01, BM_SETIMAGE, (WPARAM)IMAGE_BITMAP, (LPARAM)newgrybmp);
				greenimage = FALSE;
			}
		}
		DragFinish(hDrop);
	}
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_OPEN:
			// Send a Refresh button click message if user wants to reopen a target
			if (hThread)
			{
				if (MessageBox(NULL, (LPCSTR)"Start a new session?", "ArmaGeddon",
					MB_OKCANCEL + MB_SYSTEMMODAL + MB_ICONINFORMATION) == IDCANCEL)
				{
					return 0;
				}
				else
				{
					uiID = GetDlgCtrlID(hwnd32);
					SendMessage(hwndDlg, WM_COMMAND, MAKEWPARAM(uiID, BN_CLICKED), (LPARAM)hwnd32);
				}
			}
			stdlen = GetDlgItemTextA(hwndDlg, IDC_STANDARD, stdfpbuf, sizeof(stdfpbuf));
			strupr(stdfpbuf);
			if (stdlen == 0)
			{
				SetDlgItemTextA(hwndDlg, IDC_STANDARD, "0000-0000");
			}
			else if (stdlen != 9)
			{
				sprintf(b, "Standard Fingerprint Format = XXXX-XXXX");
				MessageBoxInformation(b);
				break;
			}
			else
			{
				if (stdfpbuf[4] != '-')
				{
					sprintf(b, "Standard Fingerprint Format = XXXX-XXXX");
					MessageBoxInformation(b);
					break;
				}
				else
				{
					SetDlgItemTextA(hwndDlg, IDC_STANDARD, stdfpbuf);
					if (stdfpbuf[0] != '0' || stdfpbuf[1] != '0' ||
						stdfpbuf[2] != '0' || stdfpbuf[3] != '0' ||
						stdfpbuf[5] != '0' || stdfpbuf[6] != '0' ||
						stdfpbuf[7] != '0' || stdfpbuf[8] != '0')
					{
						memcpy(c, stdfpbuf, sizeof(stdfpbuf));
						memset(stdfpbuf, 0, sizeof(stdfpbuf));
						j = 0;
						for (i = 0; i < 9; i++)
						{
							if (isxdigit(c[i]))
							{
								stdfpbuf[j] = c[i];
								j++;
							}
						}
						ustring = (unsigned char *)stdfpbuf;
						if (strlen((const char *)ustring) == 8)
						{
							dwstdfp = strtoul((const char *)ustring, (char **)NULL, 16);
							usingstdfp = TRUE;
						}
						else
						{
							sprintf(b, "Standard Fingerprint contains invalid characters\n"
								"Allowable hex chars: 0 - 9, A - F");
							MessageBoxInformation(b);
							break;
						}
					}
				}
			}
			enhlen = GetDlgItemTextA(hwndDlg, IDC_ENHANCED, enhfpbuf, sizeof(enhfpbuf));
			strupr(enhfpbuf);
			if (enhlen == 0)
			{
				SetDlgItemTextA(hwndDlg, IDC_ENHANCED, "0000-0000");
			}
			else if (enhlen != 9)
			{
				sprintf(b, "Enhanced Fingerprint Format = XXXX-XXXX");
				MessageBoxInformation(b);
				break;
			}
			else
			{
				if (enhfpbuf[4] != '-')
				{
					sprintf(b, "Enhanced Fingerprint Format = XXXX-XXXX");
					MessageBoxInformation(b);
					break;
				}
				else
				{
					SetDlgItemTextA(hwndDlg, IDC_ENHANCED, enhfpbuf);
					if (enhfpbuf[0] != '0' || enhfpbuf[1] != '0' ||
						enhfpbuf[2] != '0' || enhfpbuf[3] != '0' ||
						enhfpbuf[5] != '0' || enhfpbuf[6] != '0' ||
						enhfpbuf[7] != '0' || enhfpbuf[8] != '0')
					{
						memcpy(c, enhfpbuf, sizeof(enhfpbuf));
						memset(enhfpbuf, 0, sizeof(enhfpbuf));
						j = 0;
						for (i = 0; i < 9; i++)
						{
							if (isxdigit(c[i]))
							{
								enhfpbuf[j] = c[i];
								j++;
							}
						}
						ustring = (unsigned char *)enhfpbuf;
						if (strlen((const char *)ustring) == 8)
						{
							dwenhfp = strtoul((const char *)ustring, (char **)NULL, 16);
							usingenhfp = TRUE;
						}
						else
						{
							sprintf(b, "Enhanced Fingerprint contains invalid characters\n"
								"Allowable hex chars: 0 - 9, A - F");
							MessageBoxInformation(b);
							break;
						}
					}
				}
			}
			if (GetFileName((LPCSTR)buffer))
			{
				hThread = (HANDLE)_beginthreadex(NULL, 0, &RunExe, NULL, 0, &dwThreadid);
				if (!hThread)
				{
					LogItem("CreateThread failed...try again!");
					break;
				}
				// Displays grayed Armadillo image denoting running process
				SendMessage(hwnd01, BM_SETIMAGE, (WPARAM)IMAGE_BITMAP, (LPARAM)newgrybmp);
				greenimage = FALSE;
			}
			break;
		case IDD_SELECTALL:
			SelectAllListview();
			break;
		case IDD_COPY:
			CopyAllListview();
			break;
		case IDD_CLEARALL:
			ClearListview(0);
			break;
		case IDC_REFRESH:
			// Set defaults
			ClearListview(0);
			ClearListview(1);
			SetDlgItemText(hwndDlg, IDC_STANDARD, "0000-0000");
			SetDlgItemText(hwndDlg, IDC_ENHANCED, "0000-0000");
			Button_SetCheck(hwnd20, BST_UNCHECKED);
			Button_SetCheck(hwnd21, BST_UNCHECKED);
			Button_SetCheck(hwnd18, BST_UNCHECKED);
			Button_SetCheck(hwnd14, BST_UNCHECKED);
			Button_SetCheck(hwnd19, BST_UNCHECKED);
			Button_SetCheck(hwnd13, BST_UNCHECKED);
			Button_SetCheck(hwnd34, BST_UNCHECKED);
			Button_SetCheck(hwnd35, BST_UNCHECKED);
			Button_SetCheck(hwnd36, BST_UNCHECKED);
			Button_SetCheck(hwnd03, BST_UNCHECKED);
			Button_SetCheck(hwnd04, BST_UNCHECKED);
			Button_SetCheck(hwnd43, BST_UNCHECKED);
			Button_SetCheck(hwnd44, BST_UNCHECKED);
			EnableWindow(hwnd07, FALSE);
			EnableWindow(hwnd15, FALSE);
			EnableWindow(hwnd08, TRUE);
			// Displays original green Armadillo image
			if (!greenimage)
			{
				SendMessage(hwnd01, BM_SETIMAGE, (WPARAM)IMAGE_BITMAP, (LPARAM)newgdibmp);
				greenimage = TRUE;
			}
			if (hThread)
			{
				if (!bexitprocess)
				{
					Terminate_Process();
					bexitprocess = TRUE;
				}
				if (hThread)
				{
					CloseHandle(hThread);
					hThread = 0;
				}
				if (hAnalThread)
				{
					CloseHandle(hAnalThread);
					hAnalThread = 0;
				}
			}
			InitializeOptions();
			InitializeVariables();
			InvalidateRect(hwndDlg, NULL, FALSE);
			SetFocus(hwnd01);
			return TRUE;
		case IDC_COMMAND:
			EnableWindow(hwndDlg, FALSE);
			DialogBox(hinst, (LPCSTR)MAKEINTRESOURCE(IDD_CMDLINE), hwndMain, (DLGPROC)CommandProc);
			break;
		case IDC_ABOUT:
			EnableWindow(hwndDlg, FALSE);
			DialogBox(hinst, (LPCSTR)MAKEINTRESOURCE(IDD_ABOUT), hwndMain, (DLGPROC)AboutProc);
			break;
		case IDC_NANOVIEW:
			EnableWindow(hwndDlg, FALSE);
			DialogBox(hinst, (LPCSTR)MAKEINTRESOURCE(IDD_DIALOGLIST), hwndMain, (DLGPROC)NanoProc);
			break;
		case IDC_HELP:
		{
			TCHAR  buffer[BUFSIZE] = TEXT("");
			strcpy((char *)&buffer, (char *)&dbuffer);
			strcat((char *)&buffer, "\\ArmaGeddon.chm");
			HINSTANCE hinsts = ShellExecute(hwndDlg, "Open", buffer, NULL, NULL, SW_SHOWNORMAL);
			if ((int)hinsts == ERROR_FILE_NOT_FOUND)
			{
				sprintf(b, "Help file %s\n"
					"not found!", buffer);
				MessageBoxInformation(b);
			}
		}
			break;
		case IDC_RESOLVE:
			if (ResolveDump())
			{
				EnableWindow(hwnd15, FALSE);
				EnableWindow(hwnd07, FALSE);
			}
			FreeVirtualMemory();
			break;
		case IDC_LOADINI:
			if (LoadIniFile())
			{
			}
			break;
		case IDC_SAVEINI:
			if (SaveIniFile())
			{
			}
			break;
			// NanoFixer options
		case IDC_ANALYZENF:
			chkanalyzenf = IsDlgButtonChecked(hwndDlg, IDC_ANALYZENF);
			if (chkanalyzenf)
			{
				if (checkanalyzenf)
				{
					analyzenf = FALSE;
					Button_SetCheck(hwnd43, BST_UNCHECKED);
					checkanalyzenf = FALSE;
				}
				else
				{
					checkanalyzenf = TRUE;
					analyzenf = TRUE;
					analyzest = FALSE;
					Button_SetCheck(hwnd03, BST_UNCHECKED);
					checkanalyzest = FALSE;
					analyzelog = FALSE;
					Button_SetCheck(hwnd04, BST_UNCHECKED);
					checkanalyzelog = FALSE;
				}
			}
			else
			{
				checkanalyzenf = FALSE;
			}
			break;
			// End: NanoFixer options
		case IDC_ANALYZEST:
			chkanalyzest = IsDlgButtonChecked(hwndDlg, IDC_ANALYZEST);
			if (chkanalyzest)
			{
				if (checkanalyzest)
				{
					analyzest = FALSE;
					Button_SetCheck(hwnd03, BST_UNCHECKED);
					checkanalyzest = FALSE;
				}
				else
				{
					checkanalyzest = TRUE;
					analyzest = TRUE;
					analyzelog = FALSE;
					Button_SetCheck(hwnd04, BST_UNCHECKED);
					checkanalyzelog = FALSE;
					analyzenf = FALSE;
					Button_SetCheck(hwnd43, BST_UNCHECKED);
					checkanalyzenf = FALSE;
				}
			}
			else
			{
				checkanalyzest = FALSE;
			}
			break;
		case IDC_ANALYZELOG:
			chkanalyzelog = IsDlgButtonChecked(hwndDlg, IDC_ANALYZELOG);
			if (chkanalyzelog)
			{
				if (checkanalyzelog)
				{
					analyzelog = FALSE;
					Button_SetCheck(hwnd04, BST_UNCHECKED);
					checkanalyzelog = FALSE;
				}
				else
				{
					checkanalyzelog = TRUE;
					analyzelog = TRUE;
					analyzest = FALSE;
					Button_SetCheck(hwnd03, BST_UNCHECKED);
					checkanalyzest = FALSE;
					analyzenf = FALSE;
					Button_SetCheck(hwnd43, BST_UNCHECKED);
					checkanalyzenf = FALSE;
				}
			}
			else
			{
				checkanalyzelog = FALSE;
			}
			break;
		case IDC_LOADNANF:
			if (LoadNanoAnf())
			{
				EnableWindow(hwnd08, FALSE);
				EnableWindow(hwnd07, TRUE);
				EnableWindow(hwnd15, TRUE);
			}
			break;
		case IDC_DB:
			chkdb = IsDlgButtonChecked(hwndDlg, IDC_DB);
			if (chkdb)
			{
				if (checkdb)
				{
					Button_SetCheck(hwnd20, BST_UNCHECKED);
					checkdb = FALSE;
				}
				else
				{
					checkdb = TRUE;
					checkcm2 = FALSE;
				}
			}
			else
			{
				checkdb = FALSE;
			}
			break;
		case IDC_CM2:
			chkcm2 = IsDlgButtonChecked(hwndDlg, IDC_CM2);
			if (chkcm2)
			{
				if (checkcm2)
				{
					Button_SetCheck(hwnd21, BST_UNCHECKED);
					checkcm2 = FALSE;
				}
				else
				{
					checkcm2 = TRUE;
					checkdb = FALSE;
				}
			}
			else
			{
				checkcm2 = FALSE;
			}
			break;
		case IDC_DUMPPDATA:
			chkdumppdata = IsDlgButtonChecked(hwndDlg, IDC_DUMPPDATA);
			if (chkdumppdata)
			{
				checkdumppdata = TRUE;
			}
			else
			{
				checkdumppdata = FALSE;
			}
			break;
		case IDC_OPENMUTEX:
			chkopenmutex = IsDlgButtonChecked(hwndDlg, IDC_OPENMUTEX);
			if (chkopenmutex)
			{
				checkformutex = TRUE;
			}
			else
			{
				checkformutex = FALSE;
			}
			break;
		case IDC_SECURITYDUMP:
			chksecuritydump = IsDlgButtonChecked(hwndDlg, IDC_SECURITYDUMP);
			if (chksecuritydump)
			{
				checksecuritydump = TRUE;
			}
			else
			{
				checksecuritydump = FALSE;
			}
			break;
		case IDC_SECURITYLOAD:
			chksecurityload = IsDlgButtonChecked(hwndDlg, IDC_SECURITYLOAD);
			if (chksecurityload)
			{
				checksecurityload = TRUE;
			}
			else
			{
				checksecurityload = FALSE;
			}
			break;
			// the following 2 options are mutually exclusive
		case IDC_IGNORE2NDTEXT:
			chkignore2ndtext = IsDlgButtonChecked(hwndDlg, IDC_IGNORE2NDTEXT);
			if (chkignore2ndtext)
			{
				checkignore2ndtext = TRUE;
				checkbypass2ndtext = FALSE;
				Button_SetCheck(hwnd44, BST_UNCHECKED);
			}
			else
			{
				checkignore2ndtext = FALSE;
			}
			break;
		case IDC_BYPASS2NDTEXT:
			chkbypass2ndtext = IsDlgButtonChecked(hwndDlg, IDC_BYPASS2NDTEXT);
			if (chkbypass2ndtext)
			{
				checkbypass2ndtext = TRUE;
				checkignore2ndtext = FALSE;
				Button_SetCheck(hwnd36, BST_UNCHECKED);
			}
			else
			{
				checkbypass2ndtext = FALSE;
			}
			break;
		case IDC_CODESPLICE:
			chkcodesplice = IsDlgButtonChecked(hwndDlg, IDC_CODESPLICE);
			if (chkcodesplice)
			{
				redirectsplicing = TRUE;
				CheckDlgButton(hwndDlg, IDC_MINIMIZE, BST_UNCHECKED);
				checkminimizesize = FALSE;
			}
			else
			{
				redirectsplicing = FALSE;
			}
			break;
		case IDC_MINIMIZE:
			chkminimizesize = IsDlgButtonChecked(hwndDlg, IDC_MINIMIZE);
			if (chkminimizesize)
			{
				checkminimizesize = TRUE;
				CheckDlgButton(hwndDlg, IDC_CODESPLICE, BST_UNCHECKED);
				redirectsplicing = FALSE;
			}
			else
			{
				checkminimizesize = FALSE;
			}
			break;
		case IDC_SAVELOG:
			SaveLogfile();
			InvalidateRect(hwndDlg, NULL, FALSE);
			break;
		case IDC_CLEARLOG:
			ClearListview(0);
			break;
		}
		break;

	case WM_PROGRESS:
		return TRUE;

	case WM_CTLCOLORSTATIC:
		hwndCtrl = (HWND)lParam;	// handle of static control
		hdcStatic = (HDC)wParam;	// handle of display context
		// Set static literals to color blue, background grey shadow
		if (hwndCtrl == hwnd03 || hwndCtrl == hwnd04 || hwndCtrl == hwnd08 ||
			hwndCtrl == hwnd09 || hwndCtrl == hwnd10 || hwndCtrl == hwnd13 ||
			hwndCtrl == hwnd14 || hwndCtrl == hwnd17 || hwndCtrl == hwnd18 ||
			hwndCtrl == hwnd19 || hwndCtrl == hwnd20 || hwndCtrl == hwnd21 ||
			hwndCtrl == hwnd22 || hwndCtrl == hwnd23 || hwndCtrl == hwnd24 ||
			hwndCtrl == hwnd25 || hwndCtrl == hwnd30 || hwndCtrl == hwnd34 ||
			hwndCtrl == hwnd35 || hwndCtrl == hwnd36 || hwndCtrl == hwnd43 ||
			hwndCtrl == hwnd44 || hwndCtrl == hwnd45)
		{
			SetTextColor(hdcStatic, RGB(238, 232, 213));
			SetBkMode(hdcStatic, TRANSPARENT);
			return (LRESULT)(HBRUSH)CreateSolidBrush(RGB(7, 54, 66));
		}
		break;
	case WM_CTLCOLORDLG:
		hwndCtrl = (HWND)lParam;	// handle of static control
		hdcStatic = (HDC)wParam;	// handle of display context
		if (hwndCtrl == hwndDlg)
		{
			SetBkMode(hdcStatic, TRANSPARENT);
			return (LRESULT)(HBRUSH)CreateSolidBrush(RGB(7, 54, 66));
		}
		break;

	case WM_DESTROY:
		if (hBitmap01)
			DeleteObject(hBitmap01);
		if (hBitmap02)
			DeleteObject(hBitmap02);
		if (hBitmap03)
			DeleteObject(hBitmap03);
		if (hBitmap04)
			DeleteObject(hBitmap04);
		if (hBitmap05)
			DeleteObject(hBitmap05);
		if (newgdibmp)
			DeleteObject(newgdibmp);
		if (newgrybmp)
			DeleteObject(newgrybmp);
		if (newrefreshbmp)
			DeleteObject(newrefreshbmp);
		if (newaboutbmp)
			DeleteObject(newaboutbmp);
		if (newcreditbmp)
			DeleteObject(newcreditbmp);
		if (newhelpbmp)
			DeleteObject(newhelpbmp);
		if (hFont)
			DeleteObject(hFont);
		break;
	case WM_CLOSE:
		// Shutdown GDI+ subsystem
		Gdiplus::GdiplusShutdown(m_gdiplusToken);
		DestroyWindow(hwndDlg);
		if (!bexitprocess)
		{
			Terminate_Process();
			bexitprocess = TRUE;
		}
		if (hThread)
		{
			CloseHandle(hThread);
			hThread = 0;
		}
		if (hAnalThread)
		{
			CloseHandle(hAnalThread);
			hAnalThread = 0;
		}
		if (RNano)
		{
			delete[] RNano;
			RNano = 0;
			NumNanos = 0;
		}
		ExitProcess(0);
		EndDialog(hwndDlg, 0);
		return TRUE;
	case WM_COMPLETED:
		LogItem("%s", ebuf);
		return TRUE;
	}
	return FALSE;
}
