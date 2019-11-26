//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ThreadSyncTest.cpp : Defines the entry point for the console application.
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "stdafx.h"
 
#define SESSIONBLOCKEVENT 0
#define SERVICEBLOCKEVENT 1
#define CREATIONTHREAD	  2
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _tagDataRequest
{
	int _x;
	int _y;
} REQUEST;
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _tagDataResponse
{
	_tagDataResponse( REQUEST& r ) : _request( r ) { ; }
	REQUEST	_request;
	int		_x;
	int		_y;
} RESPONSE;
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
void __stdcall SessionSetupThreadProc( PVOID pTHREADDATA )
{
HRESULT		hrThrdExit		= E_FAIL;
HANDLE	*	hReleaseEvents = reinterpret_cast<HANDLE*>(pTHREADDATA);
DWORD		waitResult	   = NULL;

	OutputDebugString(L"SessionSetupThreadProc running and entering Wait ...\n");
	switch( ( waitResult = ::WaitForMultipleObjects(3, hReleaseEvents, FALSE, 60000 ) ) )
	{
		case SESSIONBLOCKEVENT:
			OutputDebugString(L"SessionSetupThreadProc: thread released .... creating Csf session\n");
			OutputDebugString(L"SessionSetupThreadProc: calling  CsfSessionAdminMgr.CreateSession()\n");
			OutputDebugString(L"SessionSetupThreadProc: received CsfSessionAdminMgr.CreateSessionResponse\n");
			OutputDebugString(L"SessionSetupThreadProc: received CsfSession.SessionStateNotification\n");
			OutputDebugString(L"SessionSetupThreadProc: Signalling to release ServiceLogic into this Session\n");
			SetEvent(hReleaseEvents[SERVICEBLOCKEVENT]);
			hrThrdExit = S_OK;
			break;
		case CREATIONTHREAD: 
			OutputDebugString(L"SessionSetupThreadProc: thread resumed .... creating session\n");
			break;
		case WAIT_TIMEOUT:
			OutputDebugString(L"SessionSetupThreadProc: timeout - exiting\n");
			break;
		case WAIT_FAILED:
			OutputDebugString(L"SessionSetupThreadProc: timeout - exiting\n");
			break;
		default:
			OutputDebugString(L"SessionSetupThreadProc: default - exiting\n");
			break;
	}
	OutputDebugString(L"SessionSetupThreadProc exiting \n");
	::ExitThread(hrThrdExit);
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
class Ex
{
public: 
	Ex ( PWCHAR lpText, DWORD errorCode ) : _errorCode( errorCode ), 
									 	 _perrorMsg( lpText )
	{ ; } 

	void ReportError( void )
	{
		WCHAR _errorMsgbuffer[200];
		ZeroMemory(_errorMsgbuffer, sizeof _errorMsgbuffer);
		//wsprintf(_errorMsgbuffer, _FormatString, _perrorMsg, _errorCode );
		//OutputDebugStringW(_errorMsgbuffer);
	}

private:
	PWCHAR						_perrorMsg;
	static const WCHAR * const	_FormatString;
	DWORD						_errorCode;

};
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
HANDLE CreateSecuredEventObject( const LPWSTR eventName )
{

	LONG	lRes			 = 0;
	HANDLE	hEvent			 = NULL;
	DWORD	dwRes			 = 0;
	DWORD	dwDisposition	 = 0;
	PSID	pEveryoneSID	 = NULL;
	PSID	pAdminSID		 = NULL;
	PACL	pACL			 = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;;
	SID_IDENTIFIER_AUTHORITY SIDAuthNT	  = SECURITY_NT_AUTHORITY;
	SECURITY_ATTRIBUTES		 sa;
	EXPLICIT_ACCESS			 ACE[2];

	try
	{
		////////////////////////////////////////////////////////////////////////////////////////
		// Create a well-known SID for the Everyone group.
		////////////////////////////////////////////////////////////////////////////////////////
		if(NULL != AllocateAndInitializeSid(&SIDAuthWorld, 
											1,
											SECURITY_WORLD_RID,
											0, 0, 0, 0, 0, 0, 0,
											&pEveryoneSID ) )
		{
			ZeroMemory(&ACE[0], 2 * sizeof EXPLICIT_ACCESS );
			ACE[0].grfAccessPermissions = READ_CONTROL | GENERIC_ALL;
			ACE[0].grfAccessMode		= SET_ACCESS;
			ACE[0].grfInheritance		= NO_INHERITANCE;
			ACE[0].Trustee.TrusteeForm	= TRUSTEE_IS_SID;
			ACE[0].Trustee.TrusteeType	= TRUSTEE_IS_WELL_KNOWN_GROUP;
			ACE[0].Trustee.ptstrName	= (LPTSTR) pEveryoneSID;

			////////////////////////////////////////////////////////////////////////////////////////
			// Create a new ACL that contains the new ACEs.
			////////////////////////////////////////////////////////////////////////////////////////
			if (ERROR_SUCCESS != SetEntriesInAcl(1, ACE, NULL, &pACL) ) 
				throw Ex (L"SetEntriesInAcl failed: ", GetLastError() ); 

			////////////////////////////////////////////////////////////////////////////////////////
			// Initialize a security descriptor. memory mustbe on PAGE boundary via LocalAlloc
			////////////////////////////////////////////////////////////////////////////////////////
			if (NULL  == (pSD = (PSECURITY_DESCRIPTOR) LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH) ) )
				throw Ex(L"LocalAlloc Error", GetLastError() );
 
			if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) 
				throw Ex (L"InitializeSecurityDescriptor Error", GetLastError() );
 
			////////////////////////////////////////////////////////////////////////////////////////
			// Add the ACL to the security descriptor. 
			////////////////////////////////////////////////////////////////////////////////////////
			if (!SetSecurityDescriptorDacl( pSD, 
											TRUE,     // bDaclPresent flag   
											pACL, 
											FALSE))   // not a default DACL 
				throw Ex (L"SetSecurityDescriptorDacl Error", GetLastError() );

			////////////////////////////////////////////////////////////////////////////////////////
			// Initialize a security attributes structure assigning the security descriptor and then
			// create the secured resource 9in this case the event that represents the I'm Alive
			// broadcast message.
			////////////////////////////////////////////////////////////////////////////////////////
			sa.nLength = sizeof (SECURITY_ATTRIBUTES);
			sa.lpSecurityDescriptor = pSD;
			sa.bInheritHandle = FALSE;

			hEvent = ::CreateEvent(&sa, TRUE, FALSE, eventName ) ;

			if (pEveryoneSID) 
				FreeSid(pEveryoneSID);
			if (pACL) 
				LocalFree(pACL);
			if (pSD) 
				LocalFree(pSD);
		}
		else
			throw Ex (L"AllocateAndInitializeSid Error", GetLastError() );
	}
	catch(Ex errorObject)
	{
		if (pEveryoneSID) 
			FreeSid(pEveryoneSID);
		if (pACL) 
			LocalFree(pACL);
		if (pSD) 
			LocalFree(pSD);
		errorObject.ReportError();
	}
	return hEvent;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//
// Class/Method:	CreateManagementThread
// Precondition:
// Postconsdition:
// Author:
// Synopsis
//
//////////////////////////////////////////////////////////////////////////////////////////////
DWORD LaunchCreateSessionWorker(HANDLE hEvents[])
{
	DWORD dwErrorCode = 0;
	DWORD ThreadId = 0;
	OutputDebugString(L"LaunchCreateSessionWorker - Entered\n");

	if(INVALID_HANDLE_VALUE == (hEvents[ CREATIONTHREAD ] = CreateThread(	NULL,
																			0,
																			(LPTHREAD_START_ROUTINE)SessionSetupThreadProc,
																			(PVOID)hEvents,
																			0,
																			&ThreadId) ) )
	{
		dwErrorCode = GetLastError();
		OutputDebugString(L"LaunchCreateSessionWorker - Errored ... \n");
	}
	else
	{
		::ResumeThread( hEvents[ CREATIONTHREAD ] );
		OutputDebugString(L"LaunchCreateSessionWorker - Returning\n");
	}
	return dwErrorCode;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
void CreateEventSet(HANDLE _hSyncEvents[])
{
	WCHAR	pszGUID[2][128];
	GUID	newGUID[2] = { GUID_NULL, GUID_NULL };
	HRESULT hr = E_FAIL;

	if( SUCCEEDED( hr = ::CoCreateGuid(&newGUID[0]) ) && SUCCEEDED( hr = ::CoCreateGuid(&newGUID[1]) ) )
	{
		wsprintf(pszGUID[0], _T("SESSIONBLOCKEVENT{%08lX-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}"),
		newGUID[0].Data1, 
		newGUID[0].Data2, 
		newGUID[0].Data3,
		newGUID[0].Data4[0], 
		newGUID[0].Data4[1], 
		newGUID[0].Data4[2], 
		newGUID[0].Data4[3],
		newGUID[0].Data4[4], 
		newGUID[0].Data4[5], 
		newGUID[0].Data4[6], 
		newGUID[0].Data4[7] ) ;

		wsprintf(pszGUID[1], _T("SERVICEBLOCKEVENT{%08lX-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}"),
		newGUID[1].Data1, 
		newGUID[1].Data2, 
		newGUID[1].Data3,
		newGUID[1].Data4[0], 
		newGUID[1].Data4[1], 
		newGUID[1].Data4[2], 
		newGUID[1].Data4[3],
		newGUID[1].Data4[4], 
		newGUID[1].Data4[5], 
		newGUID[1].Data4[6], 
		newGUID[1].Data4[7] ) ;

		_hSyncEvents[ SESSIONBLOCKEVENT ] = INVALID_HANDLE_VALUE;
		_hSyncEvents[ SERVICEBLOCKEVENT ] = INVALID_HANDLE_VALUE;
		
		OutputDebugString(L"Creating event object ... ");
		OutputDebugString(pszGUID[0]);
		OutputDebugString(L"\n");

		if(NULL != (_hSyncEvents[ SESSIONBLOCKEVENT ] = CreateSecuredEventObject( &pszGUID[0][0] ) ) ) //::CreateEvent(NULL, FALSE, FALSE, constBROADCASTEVENT ) ) )
		{

			OutputDebugString(L"Creating event object ... ");
			OutputDebugString(pszGUID[1]);
			OutputDebugString(L"\n");

			if(NULL == (_hSyncEvents[ SERVICEBLOCKEVENT ] = CreateSecuredEventObject( &pszGUID[1][0] ) ) ) //::CreateEvent(NULL, FALSE, FALSE, constABORTPROFEVENT ) ) )
			{
				DWORD e = GetLastError();
				OutputDebugString(L"CreateEventSet failed to create event SERVICEBLOCKEVENT ...\n");
				CloseHandle(_hSyncEvents[ SESSIONBLOCKEVENT ]);
			}
		}
		else
		{
			DWORD e = GetLastError();
			OutputDebugString(L"CreateEventSet failed to create event SESSIONBLOCKEVENT ...\n");
		}
	}
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
RESPONSE* ServiceLogic( REQUEST& request )
{
	RESPONSE * resp = new RESPONSE( request );
	OutputDebugString(L"ServiceLogic executing .... \n");
	OutputDebugString(L"ServiceLogic returning RESPONSE .... \n");
	return resp;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PVOID ServiceLogicCallShim(HANDLE hEvents[], REQUEST& request)
{
	DWORD waitReturn=0;
	OutputDebugString(L"ServiceLogicCallShim called, signalling SESSIONBLOCKEVENT to release SessionSetupThreadProc thread... \n");
	waitReturn=SignalObjectAndWait( hEvents[ SESSIONBLOCKEVENT ], hEvents[ SERVICEBLOCKEVENT ], 60000, FALSE );
	switch( waitReturn )
	{
		case WAIT_TIMEOUT:
			
			// if base.IsWasSessionCreated == true try and clear down Session and raise alert/warning about stale session.

			OutputDebugString(L"ServiceLogicCallShim: timeout - Assume Session Creation failed : exiting (ServiceLogic not called)\n");
			return NULL;
			break;
		case WAIT_FAILED:

			// if base.IsWasSessionCreated == true try and clear down Session and raise alert/warning about stale session.

			OutputDebugString(L"ServiceLogicCallShim: failed - Assume Session Creation failed : exiting (ServiceLogic not called)\n");
			return NULL;
			break;
		default:
			break;
	}
	OutputDebugString(L"ServiceLogicCallShim released, calling ServiceLogic... \n");
	return (PVOID)ServiceLogic(request);
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
void EmulateClientcall(int instanceID)
{
	REQUEST req;
	OutputDebugString(L"Clientcall entry... \n");
	HANDLE	hEvents[3];

	OutputDebugString(L"Clientcall creating events... \n");
	::CreateEventSet(&hEvents[0]);
	OutputDebugString(L"Clientcall dispatching session creator thread... \n");
	::LaunchCreateSessionWorker( hEvents );
	OutputDebugString(L"Clientcall entering ServiceLogicCallShim... \n");
	PVOID p = ::ServiceLogicCallShim( hEvents, req );
	if(NULL != p)
	{
		RESPONSE * r = reinterpret_cast<RESPONSE*>(p);
		delete r;
	}

	return;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

int _tmain(int argc, _TCHAR* argv[])
{
	while(true)
	{
		for(int j = 0 ; j < 10 ; j++)
			EmulateClientcall( j );

		if(getchar() == 'x')
			break;
	}
	return 0;
}


























