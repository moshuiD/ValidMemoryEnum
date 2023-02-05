#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <thread>
#include <chrono>
#include <concurrent_unordered_map.h>


class ValidMemoryEnum
{
private:
#if defined(_USRDLL)
	ValidMemoryEnum();
#else
	ValidMemoryEnum(DWORD pid) :
		m_Pid(pid)
	{
		m_ProcHandle = OpenProcess(PROCESS_ALL_ACCESS, false, m_Pid);
#endif
		m_HeapScanThread = std::thread(&ValidMemoryEnum::HeapScan, this);
		m_HeapScanThread.detach();

		m_StackScanThread = std::thread(&ValidMemoryEnum::StackScan, this);
		m_StackScanThread.detach();
	};

	~ValidMemoryEnum();

	ValidMemoryEnum(const ValidMemoryEnum&) = delete;
	ValidMemoryEnum(ValidMemoryEnum&&) = delete;
	void operator=(const ValidMemoryEnum&) = delete;
	void operator=(ValidMemoryEnum&&) = delete;

public:
#if defined(_USRDLL)
	static ValidMemoryEnum& GetInstance();
#else
	static ValidMemoryEnum& GetInstance(DWORD pid);
#endif
private:
	typedef struct _THREAD_BASIC_INFORMATION {
		LONG ExitStatus;
		PVOID TebBaseAddress;
		CLIENT_ID ClientId;
		LONG AffinityMask;
		LONG Priority;
		LONG BasePriority;
	} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

	typedef enum _THREADINFOCLASS {
		ThreadBasicInformation,
		ThreadTimes,
		ThreadPriority,
		ThreadBasePriority,
		ThreadAffinityMask,
		ThreadImpersonationToken,
		ThreadDescriptorTableEntry,
		ThreadEnableAlignmentFaultFixup,
	}THREADINFOCLASS;

private:
	void HeapScan();
	std::thread m_HeapScanThread;
	void StackScan();
	std::thread m_StackScanThread;

	DWORD m_Pid;
	HANDLE m_ProcHandle;

	using NtQueryInformationThreadFunc = NTSTATUS(WINAPI*)(HANDLE, ValidMemoryEnum::THREADINFOCLASS, PVOID, ULONG, PULONG);
	NtQueryInformationThreadFunc NtQueryInformationThread = (NtQueryInformationThreadFunc)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");
public:
	Concurrency::concurrent_unordered_map<DWORD64, SIZE_T>m_InvalidStackTable;//addr,size
	Concurrency::concurrent_unordered_map<DWORD64, SIZE_T>m_InvalidHeapTable;//addr,size
};



inline ValidMemoryEnum::~ValidMemoryEnum()
{

}
#if defined(_USRDLL)
inline ValidMemoryEnum& ValidMemoryEnum::GetInstance()
{
	static ValidMemoryEnum m_This;
#else
inline ValidMemoryEnum& ValidMemoryEnum::GetInstance(DWORD pid)
{
#endif
	static ValidMemoryEnum m_This(pid);
	return m_This;
}

inline void ValidMemoryEnum::HeapScan()
{
	while (true)
	{
		HEAPLIST32 heapList = { sizeof(HEAPLIST32) };
		HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, m_Pid);
		m_InvalidHeapTable.clear();
		for (auto bOK = Heap32ListFirst(snapShot, &heapList); bOK; bOK = Heap32ListNext(snapShot, &heapList))
		{

			HEAPENTRY32 heapEntry = { sizeof(HEAPENTRY32) };
			for (auto heap = Heap32First(&heapEntry, heapList.th32ProcessID, heapList.th32HeapID); heap; heap = Heap32Next(&heapEntry))
			{
				m_InvalidHeapTable.insert(std::make_pair((DWORD64)heapEntry.dwAddress, heapEntry.dwBlockSize));
			}

		}
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
}

inline void ValidMemoryEnum::StackScan()
{
	while (true)
	{
		THREADENTRY32 threadEntry{ sizeof(THREADENTRY32) };
		HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, m_Pid);
		for (auto thread = Thread32First(snapShot, (LPTHREADENTRY32)&threadEntry); thread; thread = Thread32Next(snapShot, (LPTHREADENTRY32)&threadEntry))
		{
			if (threadEntry.th32OwnerProcessID == m_Pid) {

				NT_TIB64 tib{};
				HANDLE threadHandle = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadEntry.th32ThreadID);
				if (threadHandle != INVALID_HANDLE_VALUE) {
					THREAD_BASIC_INFORMATION tbi{};
					if (NT_SUCCESS(NtQueryInformationThread(threadHandle, ThreadBasicInformation, &tbi, sizeof(tbi), NULL))) {
						PVOID stackStart = (PVOID)((NT_TIB64*)tbi.TebBaseAddress)->StackBase;
						SIZE_T stackSize = (SIZE_T)stackStart - ((NT_TIB64*)tbi.TebBaseAddress)->StackLimit;
						m_InvalidStackTable.insert(std::make_pair((DWORD64)stackStart, stackSize));
					}

					CloseHandle(threadHandle);
				}

			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
}

