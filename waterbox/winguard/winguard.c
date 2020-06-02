#include <windows.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_TRIPS 16

typedef struct {
	uintptr_t start;
	uintptr_t length;
	uint8_t tripped[0];
} tripwire_t;

static tripwire_t* Trips[MAX_TRIPS];
static int HandlerInstalled;

static LONG VectoredHandler(struct _EXCEPTION_POINTERS* p_info)
{
	EXCEPTION_RECORD* p_record = p_info->ExceptionRecord;

	// CONTEXT* p_context = p_info->ContextRecord;
	// DWORD64 flags = p_record->ExceptionInformation[0];

	if (p_record->ExceptionCode != STATUS_ACCESS_VIOLATION)
		return EXCEPTION_CONTINUE_SEARCH;
	
	uintptr_t faultAddress = (uintptr_t)p_record->ExceptionInformation[1];
	for (int i = 0; i < MAX_TRIPS; i++)
	{
		if (Trips[i] && faultAddress >= Trips[i]->start && faultAddress < Trips[i]->start + Trips[i]->length)
		{
			DWORD oldprot;
			if (!VirtualProtect((void*)faultAddress, 1, PAGE_READWRITE, &oldprot))
			{
				RaiseFailFastException(NULL, NULL, 0);
				while (1)
					;
			}
			uintptr_t page = (faultAddress - Trips[i]->start) >> 12;
			Trips[i]->tripped[page] = 1;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

__declspec(dllexport) int64_t AddTripGuard(uintptr_t start, uintptr_t length)
{
	if (!HandlerInstalled)
	{
		if (!AddVectoredExceptionHandler(1 /* CALL_FIRST */, VectoredHandler))
			return 0;
		HandlerInstalled = 1;
	}
	uintptr_t npage = length >> 12;
	for (int i = 0; i < MAX_TRIPS; i++)
	{
		if (!Trips[i])
		{
			Trips[i] = calloc(1, sizeof(*Trips[i]) + npage);
			if (!Trips[i])
				return 0;
			Trips[i]->start = start;
			Trips[i]->length = length;
			return 1;
		}
	}
	return 0;
}

__declspec(dllexport) int64_t RemoveTripGuard(uintptr_t start, uintptr_t length)
{
	for (int i = 0; i < MAX_TRIPS; i++)
	{
		if (Trips[i] && Trips[i]->start == start && Trips[i]->length == length)
		{
			free(Trips[i]);
			Trips[i] = NULL;
			return 1;
		}
	}
	return 0;
}

__declspec(dllexport) uint8_t* ExamineTripGuard(uintptr_t start, uintptr_t length)
{
	for (int i = 0; i < MAX_TRIPS; i++)
	{
		if (Trips[i] && Trips[i]->start == start && Trips[i]->length == length)
			return &Trips[i]->tripped[0];
	}
	return NULL;
}
