/*
 * DarkstarDriver.c
 *
 * Custom unsigned kernel driver for DARKSTAR application.
 * Provides kernel-mode access to modify thread and process priorities
 * for protected processes (PPL - Protected Process Light).
 *
 * IOCTLs:
 *   0x800 - Set thread priority (with optional permanent boost disable)
 *   0x801 - Set thread affinity mask
 *   0x802 - Set process priority class
 *   0x803 - Set process I/O priority
 *   0x804 - Set process page priority
 *   0x805 - Set thread ideal processor
 *   0x806 - Temporary thread priority boost (auto-restores)
 *
 * Build: See build.txt or use DarkstarDriver.vcxproj with WDK.
 */

#include <ntddk.h>
#include <ntstrsafe.h>

/* Forward declarations for undocumented functions */
NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(
    _In_ HANDLE ThreadId,
    _Out_ PETHREAD *Thread
);

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PEPROCESS *Process
);

NTKERNELAPI NTSTATUS ObOpenObjectByPointer(
    _In_ PVOID Object,
    _In_ ULONG HandleAttributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE Handle
);

NTKERNELAPI NTSTATUS ZwSetInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength
);

NTKERNELAPI BOOLEAN PsIsThreadTerminating(
    _In_ PETHREAD Thread
);

/* KeSetDisableBoostThread is undocumented and not in ntoskrnl.lib.
 * Resolve dynamically via MmGetSystemRoutineAddress at DriverEntry. */
typedef VOID (*PFN_KeSetDisableBoostThread)(
    _Inout_ PKTHREAD Thread,
    _In_ BOOLEAN Disable
);
static PFN_KeSetDisableBoostThread pfnKeSetDisableBoostThread = NULL;

NTKERNELAPI CCHAR KeSetIdealProcessorThread(
    _Inout_ PKTHREAD Thread,
    _In_ CCHAR Processor
);

/* External kernel types */
extern POBJECT_TYPE *PsThreadType;
extern POBJECT_TYPE *PsProcessType;

/* Missing constants */
#define PROCESS_SET_INFORMATION 0x0200
#define DRIVER_TAG 'rksD'

/* Device and symbolic link names */
#define DEVICE_NAME  L"\\Device\\DarkstarDriver"
#define SYMLINK_NAME L"\\??\\DarkstarDriver"

/* IOCTL code definitions (must match KernelDriverInterface.cs) */
#define DARKSTAR_DEVICE_TYPE 0x8000
#define DARKSTAR_CTL_CODE(function) \
    CTL_CODE(DARKSTAR_DEVICE_TYPE, function, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_DARKSTAR_SET_THREAD_PRIORITY       DARKSTAR_CTL_CODE(0x800)
#define IOCTL_DARKSTAR_SET_THREAD_AFFINITY       DARKSTAR_CTL_CODE(0x801)
#define IOCTL_DARKSTAR_SET_PROCESS_PRIORITY      DARKSTAR_CTL_CODE(0x802)
#define IOCTL_DARKSTAR_SET_PROCESS_IO_PRIORITY   DARKSTAR_CTL_CODE(0x803)
#define IOCTL_DARKSTAR_SET_PROCESS_PAGE_PRIORITY DARKSTAR_CTL_CODE(0x804)
#define IOCTL_DARKSTAR_SET_IDEAL_PROCESSOR       DARKSTAR_CTL_CODE(0x805)
#define IOCTL_DARKSTAR_BOOST_THREAD              DARKSTAR_CTL_CODE(0x806)
#define IOCTL_DARKSTAR_SET_DPC_CORE0_LOCK       DARKSTAR_CTL_CODE(0x807)

/* ----------------------------------------------------------------
 * Input structures (must match C# StructLayout Sequential)
 * ---------------------------------------------------------------- */

typedef struct _DARKSTAR_SET_THREAD_PRIORITY_INPUT {
    ULONG ThreadId;
    LONG  Priority;
    UCHAR Permanent;    /* 1 = disable dynamic boosting after set */
} DARKSTAR_SET_THREAD_PRIORITY_INPUT, *PDARKSTAR_SET_THREAD_PRIORITY_INPUT;

typedef struct _DARKSTAR_SET_THREAD_AFFINITY_INPUT {
    ULONG     ThreadId;
    ULONG_PTR AffinityMask;
} DARKSTAR_SET_THREAD_AFFINITY_INPUT, *PDARKSTAR_SET_THREAD_AFFINITY_INPUT;

typedef struct _DARKSTAR_SET_PROCESS_PRIORITY_INPUT {
    ULONG ProcessId;
    UCHAR PriorityClass;
} DARKSTAR_SET_PROCESS_PRIORITY_INPUT, *PDARKSTAR_SET_PROCESS_PRIORITY_INPUT;

typedef struct _DARKSTAR_SET_PROCESS_IO_PRIORITY_INPUT {
    ULONG ProcessId;
    LONG  IoPriority;   /* 0=VeryLow, 1=Low, 2=Normal, 3=High, 4=Critical */
} DARKSTAR_SET_PROCESS_IO_PRIORITY_INPUT, *PDARKSTAR_SET_PROCESS_IO_PRIORITY_INPUT;

typedef struct _DARKSTAR_SET_PROCESS_PAGE_PRIORITY_INPUT {
    ULONG ProcessId;
    LONG  PagePriority; /* 0=Lowest .. 5=Normal */
} DARKSTAR_SET_PROCESS_PAGE_PRIORITY_INPUT, *PDARKSTAR_SET_PROCESS_PAGE_PRIORITY_INPUT;

typedef struct _DARKSTAR_SET_IDEAL_PROCESSOR_INPUT {
    ULONG ThreadId;
    UCHAR IdealProcessor;
} DARKSTAR_SET_IDEAL_PROCESSOR_INPUT, *PDARKSTAR_SET_IDEAL_PROCESSOR_INPUT;

typedef struct _DARKSTAR_BOOST_THREAD_INPUT {
    ULONG ThreadId;
    UCHAR BoostAmount;   /* 0-15 */
    ULONG DurationMs;    /* max 5000 */
} DARKSTAR_BOOST_THREAD_INPUT, *PDARKSTAR_BOOST_THREAD_INPUT;

typedef struct _DARKSTAR_SET_DPC_CORE0_LOCK_INPUT {
    UCHAR Enabled;
    ULONG Reserved;
} DARKSTAR_SET_DPC_CORE0_LOCK_INPUT, *PDARKSTAR_SET_DPC_CORE0_LOCK_INPUT;

/* Internal structure for ZwSetInformationProcess(ProcessPriorityClass) */
typedef struct _PROCESS_PRIORITY_CLASS {
    BOOLEAN Foreground;
    UCHAR   PriorityClass;
} PROCESS_PRIORITY_CLASS, *PPROCESS_PRIORITY_CLASS;

/* ----------------------------------------------------------------
 * Active boost tracking (for IOCTL 0x806)
 * ---------------------------------------------------------------- */

typedef struct _DEVICE_EXTENSION {
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING SymbolicLink;
    KSPIN_LOCK     Lock;
    LIST_ENTRY     ActiveBoosts;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

typedef struct _ACTIVE_BOOST {
    LIST_ENTRY        ListEntry;
    ULONG             ThreadId;
    PETHREAD          Thread;
    KTIMER            Timer;
    KDPC              Dpc;
    KPRIORITY         OriginalPriority;
    PDEVICE_EXTENSION DeviceExtension;
} ACTIVE_BOOST, *PACTIVE_BOOST;

/* Function prototypes */
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DarkstarUnload;
__drv_dispatchType(IRP_MJ_CREATE) DRIVER_DISPATCH DarkstarCreate;
__drv_dispatchType(IRP_MJ_CLOSE) DRIVER_DISPATCH DarkstarClose;
__drv_dispatchType(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH DarkstarDeviceControl;
KDEFERRED_ROUTINE BoostTimerDpc;

/* Global device object */
PDEVICE_OBJECT g_DeviceObject = NULL;
static volatile LONG *g_KeQuantumEndTimerIncrement = NULL;
static LONG g_OriginalQuantumEndTimerIncrement = 0;
static BOOLEAN g_HasOriginalQuantumValue = FALSE;

/* ================================================================
 * Helper: Open a kernel handle to a thread (bypasses PPL)
 * ================================================================ */
static NTSTATUS OpenThreadKernelHandle(
    _In_  ULONG   ThreadId,
    _Out_ HANDLE  *ThreadHandle,
    _Out_ PETHREAD *ThreadObject
)
{
    NTSTATUS status;
    PETHREAD threadObj = NULL;
    HANDLE   hThread   = NULL;

    status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)ThreadId, &threadObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ObOpenObjectByPointer(
        threadObj,
        OBJ_KERNEL_HANDLE,
        NULL,
        THREAD_SET_INFORMATION,
        *PsThreadType,
        KernelMode,
        &hThread);

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(threadObj);
        return status;
    }

    *ThreadHandle = hThread;
    *ThreadObject = threadObj;
    return STATUS_SUCCESS;
}

/* ================================================================
 * Helper: Open a kernel handle to a process (bypasses PPL)
 * ================================================================ */
static NTSTATUS OpenProcessKernelHandle(
    _In_  ULONG    ProcessId,
    _Out_ HANDLE   *ProcessHandle,
    _Out_ PEPROCESS *ProcessObject
)
{
    NTSTATUS  status;
    PEPROCESS processObj = NULL;
    HANDLE    hProcess   = NULL;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &processObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ObOpenObjectByPointer(
        processObj,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_SET_INFORMATION,
        *PsProcessType,
        KernelMode,
        &hProcess);

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(processObj);
        return status;
    }

    *ProcessHandle = hProcess;
    *ProcessObject = processObj;
    return STATUS_SUCCESS;
}

/* ================================================================
 * IOCTL 0x800: Set Thread Priority
 * ================================================================ */
static NTSTATUS SetThreadPriorityKernel(
    _In_ PDARKSTAR_SET_THREAD_PRIORITY_INPUT Input
)
{
    NTSTATUS status;
    PETHREAD threadObj = NULL;
    HANDLE   hThread   = NULL;

    status = OpenThreadKernelHandle(Input->ThreadId, &hThread, &threadObj);
    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: OpenThreadKernelHandle failed for TID %u: 0x%08X\n", Input->ThreadId, status));
        return status;
    }

    /* Set thread priority via Zw (bypasses PPL) */
    LONG priority = Input->Priority;
    status = ZwSetInformationThread(
        hThread,
        ThreadPriority,
        &priority,
        sizeof(LONG));

    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: ZwSetInformationThread(Priority) failed: 0x%08X\n", status));
    }

    /* Optionally disable dynamic priority boosting */
    if (NT_SUCCESS(status) && Input->Permanent) {
        if (pfnKeSetDisableBoostThread) {
            pfnKeSetDisableBoostThread((PKTHREAD)threadObj, TRUE);
            KdPrint(("DarkstarDriver: Disabled priority boost for TID %u\n", Input->ThreadId));
        }
    }

    ZwClose(hThread);
    ObDereferenceObject(threadObj);
    return status;
}

/* ================================================================
 * IOCTL 0x801: Set Thread Affinity
 * ================================================================ */
static NTSTATUS SetThreadAffinityKernel(
    _In_ PDARKSTAR_SET_THREAD_AFFINITY_INPUT Input
)
{
    NTSTATUS status;
    PETHREAD threadObj = NULL;
    HANDLE   hThread   = NULL;

    status = OpenThreadKernelHandle(Input->ThreadId, &hThread, &threadObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ULONG_PTR affinityMask = Input->AffinityMask;
    status = ZwSetInformationThread(
        hThread,
        ThreadAffinityMask,
        &affinityMask,
        sizeof(ULONG_PTR));

    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: ZwSetInformationThread(Affinity) failed: 0x%08X\n", status));
    }

    ZwClose(hThread);
    ObDereferenceObject(threadObj);
    return status;
}

/* ================================================================
 * IOCTL 0x802: Set Process Priority Class
 * ================================================================ */
static NTSTATUS SetProcessPriorityKernel(
    _In_ PDARKSTAR_SET_PROCESS_PRIORITY_INPUT Input
)
{
    NTSTATUS  status;
    PEPROCESS processObj = NULL;
    HANDLE    hProcess   = NULL;

    status = OpenProcessKernelHandle(Input->ProcessId, &hProcess, &processObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PROCESS_PRIORITY_CLASS priorityClassInfo;
    priorityClassInfo.Foreground = FALSE;
    priorityClassInfo.PriorityClass = Input->PriorityClass;

    status = ZwSetInformationProcess(
        hProcess,
        ProcessPriorityClass,
        &priorityClassInfo,
        sizeof(PROCESS_PRIORITY_CLASS));

    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: ZwSetInformationProcess(PriorityClass) failed: 0x%08X\n", status));
    }

    ZwClose(hProcess);
    ObDereferenceObject(processObj);
    return status;
}

/* ================================================================
 * IOCTL 0x803: Set Process I/O Priority
 * ================================================================ */
static NTSTATUS SetProcessIoPriorityKernel(
    _In_ PDARKSTAR_SET_PROCESS_IO_PRIORITY_INPUT Input
)
{
    NTSTATUS  status;
    PEPROCESS processObj = NULL;
    HANDLE    hProcess   = NULL;

    /* Validate: 0=VeryLow, 1=Low, 2=Normal, 3=High, 4=Critical */
    if (Input->IoPriority < 0 || Input->IoPriority > 4) {
        return STATUS_INVALID_PARAMETER;
    }

    status = OpenProcessKernelHandle(Input->ProcessId, &hProcess, &processObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ULONG ioPriority = (ULONG)Input->IoPriority;
    status = ZwSetInformationProcess(
        hProcess,
        33,  /* ProcessIoPriority */
        &ioPriority,
        sizeof(ULONG));

    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: ZwSetInformationProcess(IoPriority) failed: 0x%08X\n", status));
    }

    ZwClose(hProcess);
    ObDereferenceObject(processObj);
    return status;
}

/* ================================================================
 * IOCTL 0x804: Set Process Page Priority
 * ================================================================ */
static NTSTATUS SetProcessPagePriorityKernel(
    _In_ PDARKSTAR_SET_PROCESS_PAGE_PRIORITY_INPUT Input
)
{
    NTSTATUS  status;
    PEPROCESS processObj = NULL;
    HANDLE    hProcess   = NULL;

    /* Validate: 0=Lowest .. 5=Normal */
    if (Input->PagePriority < 0 || Input->PagePriority > 5) {
        return STATUS_INVALID_PARAMETER;
    }

    status = OpenProcessKernelHandle(Input->ProcessId, &hProcess, &processObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ULONG pagePriority = (ULONG)Input->PagePriority;
    status = ZwSetInformationProcess(
        hProcess,
        39,  /* ProcessPagePriority */
        &pagePriority,
        sizeof(ULONG));

    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: ZwSetInformationProcess(PagePriority) failed: 0x%08X\n", status));
    }

    ZwClose(hProcess);
    ObDereferenceObject(processObj);
    return status;
}

/* ================================================================
 * IOCTL 0x805: Set Thread Ideal Processor
 * ================================================================ */
static NTSTATUS SetThreadIdealProcessorKernel(
    _In_ PDARKSTAR_SET_IDEAL_PROCESSOR_INPUT Input
)
{
    NTSTATUS status;
    PETHREAD threadObj = NULL;
    HANDLE   hThread   = NULL;

    /* Validate processor number */
    ULONG processorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (Input->IdealProcessor >= processorCount) {
        return STATUS_INVALID_PARAMETER;
    }

    status = OpenThreadKernelHandle(Input->ThreadId, &hThread, &threadObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Use KeSetIdealProcessorThread for scheduler hint */
    KeSetIdealProcessorThread((PKTHREAD)threadObj, (CCHAR)Input->IdealProcessor);

    KdPrint(("DarkstarDriver: Thread %u ideal processor -> %u\n",
        Input->ThreadId, Input->IdealProcessor));

    ZwClose(hThread);
    ObDereferenceObject(threadObj);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Boost timer DPC callback - restores original priority
 * ================================================================ */
VOID BoostTimerDpc(
    _In_     PKDPC Dpc,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID Arg1,
    _In_opt_ PVOID Arg2
)
{
    PACTIVE_BOOST boost;
    PDEVICE_EXTENSION extension;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    boost = (PACTIVE_BOOST)Context;
    if (boost == NULL) return;

    extension = boost->DeviceExtension;

    /* Restore original priority if thread is still alive */
    if (!PsIsThreadTerminating(boost->Thread)) {
        KeSetPriorityThread((PKTHREAD)boost->Thread, boost->OriginalPriority);
        if (pfnKeSetDisableBoostThread)
            pfnKeSetDisableBoostThread((PKTHREAD)boost->Thread, FALSE);
    }

    /* Remove from active list */
    KeAcquireSpinLock(&extension->Lock, &oldIrql);
    RemoveEntryList(&boost->ListEntry);
    KeReleaseSpinLock(&extension->Lock, oldIrql);

    /* Cleanup */
    ObDereferenceObject(boost->Thread);
    ExFreePoolWithTag(boost, DRIVER_TAG);
}

/* ================================================================
 * IOCTL 0x806: Temporary Thread Priority Boost
 * Boosts thread priority for DurationMs, then auto-restores.
 * ================================================================ */
static NTSTATUS BoostThreadKernel(
    _In_ PDARKSTAR_BOOST_THREAD_INPUT Input,
    _In_ PDEVICE_EXTENSION Extension
)
{
    NTSTATUS      status;
    PETHREAD      threadObj = NULL;
    PACTIVE_BOOST boost     = NULL;
    KIRQL         oldIrql;
    KPRIORITY     currentPriority;
    KPRIORITY     newPriority;
    LARGE_INTEGER dueTime;

    /* Validate */
    if (Input->BoostAmount > 15 || Input->DurationMs == 0 || Input->DurationMs > 5000) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupThreadByThreadId(
        (HANDLE)(ULONG_PTR)Input->ThreadId, &threadObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (PsIsThreadTerminating(threadObj)) {
        ObDereferenceObject(threadObj);
        return STATUS_THREAD_IS_TERMINATING;
    }

    /* Allocate boost tracker */
    boost = (PACTIVE_BOOST)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(ACTIVE_BOOST), DRIVER_TAG);
    if (!boost) {
        ObDereferenceObject(threadObj);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Compute boosted priority */
    currentPriority = KeQueryPriorityThread((PKTHREAD)threadObj);
    newPriority = currentPriority + Input->BoostAmount;

    /* Clamp: stay below realtime (16) unless already there */
    if (newPriority > 31) newPriority = 31;
    if (currentPriority < 16 && newPriority >= 16) newPriority = 15;

    /* Setup boost tracking */
    boost->ThreadId         = Input->ThreadId;
    boost->Thread           = threadObj;   /* Keep reference (released in DPC) */
    boost->OriginalPriority = currentPriority;
    boost->DeviceExtension  = Extension;

    KeInitializeTimer(&boost->Timer);
    KeInitializeDpc(&boost->Dpc, BoostTimerDpc, boost);

    /* Apply boost */
    KeSetPriorityThread((PKTHREAD)threadObj, newPriority);
    if (pfnKeSetDisableBoostThread)
        pfnKeSetDisableBoostThread((PKTHREAD)threadObj, TRUE);

    /* Add to tracking list */
    KeAcquireSpinLock(&Extension->Lock, &oldIrql);
    InsertTailList(&Extension->ActiveBoosts, &boost->ListEntry);
    KeReleaseSpinLock(&Extension->Lock, oldIrql);

    /* Set timer to restore priority (relative time in 100ns units) */
    dueTime.QuadPart = -((LONGLONG)Input->DurationMs * 10000);
    KeSetTimer(&boost->Timer, dueTime, &boost->Dpc);

    KdPrint(("DarkstarDriver: Thread %u boosted %d -> %d for %u ms\n",
        Input->ThreadId, currentPriority, newPriority, Input->DurationMs));

    return STATUS_SUCCESS;
}


/* ================================================================
 * IOCTL 0x807: Experimental DPC Core0 lock via KeQuantumEndTimerIncrement
 * NOTE: this symbol is not guaranteed to be exported on all Windows builds.
 * ================================================================ */
static NTSTATUS SetDpcCore0LockKernel(
    _In_ PDARKSTAR_SET_DPC_CORE0_LOCK_INPUT Input
)
{
    if (g_KeQuantumEndTimerIncrement == NULL) {
        KdPrint(("DarkstarDriver: KeQuantumEndTimerIncrement symbol unavailable on this OS build\n"));
        return STATUS_NOT_SUPPORTED;
    }

    if (Input->Enabled) {
        if (!g_HasOriginalQuantumValue) {
            g_OriginalQuantumEndTimerIncrement = *g_KeQuantumEndTimerIncrement;
            g_HasOriginalQuantumValue = TRUE;
        }

        InterlockedExchange(g_KeQuantumEndTimerIncrement, 0x7FFFFFFF);
        KdPrint(("DarkstarDriver: DPC Core0 lock enabled (KeQuantumEndTimerIncrement set)\n"));
    } else {
        if (g_HasOriginalQuantumValue) {
            InterlockedExchange(g_KeQuantumEndTimerIncrement, g_OriginalQuantumEndTimerIncrement);
            KdPrint(("DarkstarDriver: DPC Core0 lock disabled (original value restored)\n"));
        }
    }

    return STATUS_SUCCESS;
}

/* ================================================================
 * DriverEntry - Driver initialization
 * ================================================================ */
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;
    PDEVICE_EXTENSION extension;

    UNREFERENCED_PARAMETER(RegistryPath);

    KdPrint(("DarkstarDriver: DriverEntry called\n"));

    /* Dynamically resolve undocumented KeSetDisableBoostThread */
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"KeSetDisableBoostThread");
        pfnKeSetDisableBoostThread = (PFN_KeSetDisableBoostThread)
            MmGetSystemRoutineAddress(&routineName);
        if (pfnKeSetDisableBoostThread) {
            KdPrint(("DarkstarDriver: Resolved KeSetDisableBoostThread\n"));
        } else {
            KdPrint(("DarkstarDriver: KeSetDisableBoostThread not found - boost disable unavailable\n"));
        }
    }

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);

    /* Optional exported kernel symbol for experimental DPC lock control. */
    {
        UNICODE_STRING quantumSymbol;
        RtlInitUnicodeString(&quantumSymbol, L"KeQuantumEndTimerIncrement");
        g_KeQuantumEndTimerIncrement = (volatile LONG*)MmGetSystemRoutineAddress(&quantumSymbol);
        if (g_KeQuantumEndTimerIncrement != NULL) {
            g_OriginalQuantumEndTimerIncrement = *g_KeQuantumEndTimerIncrement;
            g_HasOriginalQuantumValue = TRUE;
            KdPrint(("DarkstarDriver: Resolved KeQuantumEndTimerIncrement\n"));
        } else {
            KdPrint(("DarkstarDriver: KeQuantumEndTimerIncrement not exported on this build\n"));
        }
    }

    /* Create device object with extension for boost tracking */
    status = IoCreateDevice(
        DriverObject,
        sizeof(DEVICE_EXTENSION),
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject);

    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: Failed to create device: 0x%08X\n", status));
        return status;
    }

    /* Initialize device extension */
    extension = (PDEVICE_EXTENSION)g_DeviceObject->DeviceExtension;
    extension->DeviceObject = g_DeviceObject;
    RtlInitUnicodeString(&extension->SymbolicLink, SYMLINK_NAME);
    KeInitializeSpinLock(&extension->Lock);
    InitializeListHead(&extension->ActiveBoosts);

    /* Create symbolic link */
    RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);

    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: Failed to create symbolic link: 0x%08X\n", status));
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    /* Set dispatch routines */
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DarkstarCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DarkstarClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DarkstarDeviceControl;
    DriverObject->DriverUnload = DarkstarUnload;

    KdPrint(("DarkstarDriver: Driver loaded successfully\n"));
    return STATUS_SUCCESS;
}

/* ================================================================
 * DarkstarUnload - Driver cleanup
 * ================================================================ */
VOID DarkstarUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING symlinkName;
    PDEVICE_EXTENSION extension;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(DriverObject);

    KdPrint(("DarkstarDriver: Unloading driver\n"));

    if (g_KeQuantumEndTimerIncrement != NULL && g_HasOriginalQuantumValue) {
        InterlockedExchange(g_KeQuantumEndTimerIncrement, g_OriginalQuantumEndTimerIncrement);
    }

    if (g_DeviceObject != NULL) {
        extension = (PDEVICE_EXTENSION)g_DeviceObject->DeviceExtension;

        /* Cancel all active boosts and restore original priorities */
        KeAcquireSpinLock(&extension->Lock, &oldIrql);
        while (!IsListEmpty(&extension->ActiveBoosts)) {
            PLIST_ENTRY entry = RemoveHeadList(&extension->ActiveBoosts);
            PACTIVE_BOOST boost = CONTAINING_RECORD(entry, ACTIVE_BOOST, ListEntry);

            KeCancelTimer(&boost->Timer);

            if (!PsIsThreadTerminating(boost->Thread)) {
                KeSetPriorityThread((PKTHREAD)boost->Thread, boost->OriginalPriority);
                if (pfnKeSetDisableBoostThread)
                    pfnKeSetDisableBoostThread((PKTHREAD)boost->Thread, FALSE);
            }

            ObDereferenceObject(boost->Thread);
            ExFreePoolWithTag(boost, DRIVER_TAG);
        }
        KeReleaseSpinLock(&extension->Lock, oldIrql);

        /* Delete symbolic link and device */
        RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
        IoDeleteSymbolicLink(&symlinkName);
        IoDeleteDevice(g_DeviceObject);
    }

    KdPrint(("DarkstarDriver: Driver unloaded\n"));
}

/* ================================================================
 * DarkstarCreate - Handle IRP_MJ_CREATE
 * ================================================================ */
NTSTATUS DarkstarCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ================================================================
 * DarkstarClose - Handle IRP_MJ_CLOSE
 * ================================================================ */
NTSTATUS DarkstarClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ================================================================
 * DarkstarDeviceControl - Handle IRP_MJ_DEVICE_CONTROL (IOCTLs)
 * ================================================================ */
NTSTATUS DarkstarDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION irpStack;
    PDEVICE_EXTENSION extension;
    ULONG ioControlCode;
    PVOID inputBuffer;
    ULONG inputBufferLength;

    irpStack = IoGetCurrentIrpStackLocation(Irp);
    extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
    ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
    inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;

    switch (ioControlCode) {

        case IOCTL_DARKSTAR_SET_THREAD_PRIORITY:
        {
            if (inputBufferLength >= sizeof(DARKSTAR_SET_THREAD_PRIORITY_INPUT)) {
                status = SetThreadPriorityKernel(
                    (PDARKSTAR_SET_THREAD_PRIORITY_INPUT)inputBuffer);
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }

        case IOCTL_DARKSTAR_SET_THREAD_AFFINITY:
        {
            if (inputBufferLength >= sizeof(DARKSTAR_SET_THREAD_AFFINITY_INPUT)) {
                status = SetThreadAffinityKernel(
                    (PDARKSTAR_SET_THREAD_AFFINITY_INPUT)inputBuffer);
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }

        case IOCTL_DARKSTAR_SET_PROCESS_PRIORITY:
        {
            if (inputBufferLength >= sizeof(DARKSTAR_SET_PROCESS_PRIORITY_INPUT)) {
                status = SetProcessPriorityKernel(
                    (PDARKSTAR_SET_PROCESS_PRIORITY_INPUT)inputBuffer);
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }

        case IOCTL_DARKSTAR_SET_PROCESS_IO_PRIORITY:
        {
            if (inputBufferLength >= sizeof(DARKSTAR_SET_PROCESS_IO_PRIORITY_INPUT)) {
                status = SetProcessIoPriorityKernel(
                    (PDARKSTAR_SET_PROCESS_IO_PRIORITY_INPUT)inputBuffer);
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }

        case IOCTL_DARKSTAR_SET_PROCESS_PAGE_PRIORITY:
        {
            if (inputBufferLength >= sizeof(DARKSTAR_SET_PROCESS_PAGE_PRIORITY_INPUT)) {
                status = SetProcessPagePriorityKernel(
                    (PDARKSTAR_SET_PROCESS_PAGE_PRIORITY_INPUT)inputBuffer);
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }

        case IOCTL_DARKSTAR_SET_IDEAL_PROCESSOR:
        {
            if (inputBufferLength >= sizeof(DARKSTAR_SET_IDEAL_PROCESSOR_INPUT)) {
                status = SetThreadIdealProcessorKernel(
                    (PDARKSTAR_SET_IDEAL_PROCESSOR_INPUT)inputBuffer);
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }

        case IOCTL_DARKSTAR_BOOST_THREAD:
        {
            if (inputBufferLength >= sizeof(DARKSTAR_BOOST_THREAD_INPUT)) {
                status = BoostThreadKernel(
                    (PDARKSTAR_BOOST_THREAD_INPUT)inputBuffer, extension);
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }

        case IOCTL_DARKSTAR_SET_DPC_CORE0_LOCK:
        {
            if (inputBufferLength >= sizeof(DARKSTAR_SET_DPC_CORE0_LOCK_INPUT)) {
                status = SetDpcCore0LockKernel(
                    (PDARKSTAR_SET_DPC_CORE0_LOCK_INPUT)inputBuffer);
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }

        default:
            KdPrint(("DarkstarDriver: Unknown IOCTL: 0x%08X\n", ioControlCode));
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}
