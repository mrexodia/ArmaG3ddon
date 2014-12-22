

#ifndef ARMNF_DLL_H_
#define ARMNF_DLL_H_

#define export __declspec(dllexport)

#ifdef __cplusplus
#define extc           extern "C"    // Assure that names are not mangled
#else
#define extc           extern
#endif

#define estd __stdcall

//Compiler Option
#define MSVC 0
#define Borland 1
#define UNKNOWN_COMPILR 2

//IO Option
#define ThroughFile 0
#define ThroughProc 1
#define ToFile 0
#define ToProc 1

//Errors Return value
//#define ERROR_SUCCESS 0		//No Error
#define UNKNOWN_ERROR   1		//Unknown Error
#define NoCC	        2		//No 0xCC Opcode Find,No INT3 Breakpoint Found
#define FILE_ACCESS_ERROR 3		//Cannot open The File,File Header Is Corrupted
#define PROCESS_ERROR   4		//Cannot Open Process
#define AllocationError 5		//VirtualAlloc Failed
#define MisMatchFile    6		//The Loaded .nan File Is Mismatched
#define NoResponse 7			//Return from Analyze() if there is no response
#define Unsupported 8           //Unsupported version of Nanomites

struct RNANO							// Real Nanomites Struct
{
	DWORD Address;						// Address of Nanomites
	DWORD Dest;							// Destination of jump
	int  JumpType;						// JumpType
};				

struct Log
{
	DWORD TACC;		//Total Analyzed 0xCC
	DWORD TFCC;		//Total False 0xCC
	DWORD TRN;		//Total Real Nanomites
	DWORD TotalCC;	//Total 0xcc  	
};

#ifdef __cplusplus
extern "C" {
#endif
	
/* prototypes used in the ArmNF.dll */

/*
	Initialize the dll.reset all variable.call this function every time
	you want to start new Analyze.
	Parameter:
	String:Pointer to a buffer for error message.
	in some case i have put a message in the buffer according to the 
	returned error.Pass this parameter to NULL if you dont need error message.
	pASM:Address of Assemble function from your Disasm.dll.
	I remove the OllyDisasm Project from dll to reduce the size of dll.
	pDisasm:Address of Disasm Function.
*/
	//void export estd Init(char *StringError,DWORD pASM,DWORD pDisASM);
/****************************************************************/
/*
	Start The Main search for finding INT3.This function dont create any thread.
	Parameter:
	ADump:Address of dump file.You have to pass address of dump file
	if you want to make search from dumped file.[recommended].
	In this case the file must have GENERIC_READ access.
	AProtected:Address of protected file.
	PID:Pid of the child process if you want to make search from process.
	Attention:with this option , your child process must stop at the OEP.
	type:Type of search:containt 2 Word:
	HIWORD:
	#define ThroughFile 0	Start search with dumped file
	#define ThroughProc 1	Start search with child process PID
	LOWORD:
	Compiler Option:
	this parameter indicate whats the compiler of this file / process.
	I dont make any function to detect the compiler.
	If you dont know the compiler pass UNKNOWN_COMPILR.
	This increase the time of searching.
	Return Value:Error Code
 */
//int export estd Analyze(LPCSTR ADump,LPCSTR AProtected,DWORD PID,int type);
/*************************************************************************/
/*
	Logs of current search progress.there is 2 search function.
	when the seacond search function starts , the TRN increased.
	Parameter:Pointer to log struct
	Return Value:
	Return the last error occurred in the program.

*/
//DWORD export estd MakeLog(struct Log *log);
/*
	Patch the fixed table to a new dump file or to the
	child memory that stops at THE OEP OF CHILD PROCESS.
	Parameter:
	FileAddress:Address of dumped file.
	dwProcID:PID of child process .Only if you want to patch the current nano table.
	to child process.
	Option:
	ToFile:			Patch nanos to a new dump file
	ToProc:			Patch nanos to child process stoped at OEP.
	Return Value:Error Code
*/
//int export estd AdvancedPatch(LPCSTR FileAddress,DWORD dwProcID,int Option);
/**************************************************************************/
/*
	Loads the saved nano table with *.nan extention and
	RNANO struct.
	Parameter:
	LoadAddress:Address of nano table to load.
	Return value:have 2 WORD:
	LOWORD:
	Error Code.
	If Error code == Error_SUCCESS:
	HIWORD:
	Number of loaded Nanomites.

*/
//DWORD export estd LoadTable(LPCSTR LoadAddress);
/**********************************************/
/*
	Write Nano table to a *.nan file with RNANO struct.
	Parameter:
	SaveAddress:Address of *.nan file to save last table.
	Return Value:Error Code

*/
//int export estd WriteTableToFile(LPCSTR SaveAddress);	
	/* end prototypes used */
#ifdef __cplusplus
}
#endif





#endif