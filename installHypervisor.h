#pragma once

namespace Hypervisor {
	enum class WinArch
	{
		None = 0,
		Intel = 1 << 0,
		Amd = 1 << 1
	};

	enum class WinVer : DWORD
	{
		WinVerNotSupported = 0,
		WinVer22H2 = 19045,
		WinVer21H2 = 19044,
		WinVer21H1 = 19043,
		WinVer20H2 = 19042,
		WinVer2004 = 19041,
		WinVer1909 = 18363,
		WinVer1903 = 18362,
		WinVer1809 = 17763,
		WinVer1803 = 17134
	};
	typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

	extern 	bool Install();
}