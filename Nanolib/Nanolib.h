#pragma once

#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <vector>
#include <set>

const INT JUnknown = 0;
const INT NotNanomite = 1;
const INT JMP = 2;
const INT JNZ = 3;
const INT JZ = 4;
const INT JB = 5;
const INT JBE = 6;
const INT JA = 7;
const INT JNB = 8;
const INT JG = 9;
const INT JGE = 10;
const INT JL = 11;
const INT JLE = 12;
const INT JP = 13;
const INT JPE = 14;
const INT JNP = 15;
const INT JPO = 16;
const INT JS = 17;
const INT JNS = 18;
const INT JCXZ = 19;
const INT JNCXZ = 20;
const INT JC = 21;
const INT JNC = 22;
const INT JO = 23;
const INT JNO = 24;

enum JFlag {
	CX = 1,
	PF = 2,
	OF = 4,
	SF = 8,
	ZF = 16,
	CF = 32,
};

struct Nanomite {
	DWORD Address;
	DWORD Destination;
	SIZE_T Size;
	INT JumpType;
};

struct LogNano {		// Use for logging / resolving Nanomites
	DWORD Address;
};

struct UpdateLog {
	SIZE_T LogNanos;
};

struct UpdateReport {
	DWORD CurrentNano;
	SIZE_T NumDuf;
	SIZE_T NumNanos;
	bool Inconsistency;
};