/*
 * DarkstarDriver.c
 * 
 * Custom unsigned kernel driver for DARKSTAR application
 * Provides kernel-mode access to modify thread and process priorities
 * for protected processes (PPL - Protected Process Light).
 */

#include <ntddk.h>
#include <ntstrsafe.h>

// Forward declarations for undocumented functions
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

// External kernel types
extern POBJECT_TYPE *PsThreadType;
extern POBJECT_TYPE *PsProcessType;

// Missing constants
#define PROCESS_SET_INFORMATION 0x0200

// Device and symbolic link names
#define DEVICE_NAME L"\\Device\\DarkstarDriver"
#define SYMLINK_NAME L"\\??\\DarkstarDriver"

// IOCTL code definitions
#define DARKSTAR_DEVICE_TYPE 0x8000
#define DARKSTAR_CTL_CODE(function) \
    CTL_CODE(DARKSTAR_DEVICE_TYPE, function, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_DARKSTAR_SET_THREAD_PRIORITY  DARKSTAR_CTL_CODE(0x800)
#define IOCTL_DARKSTAR_SET_THREAD_AFFINITY  DARKSTAR_CTL_CODE(0x801)
#define IOCTL_DARKSTAR_SET_PROCESS_PRIORITY DARKSTAR_CTL_CODE(0x802)

// Input structures for IOCTL operations
typedef struct _DARKSTAR_SET_THREAD_PRIORITY_INPUT {
    ULONG ThreadId;
    LONG Priority;
} DARKSTAR_SET_THREAD_PRIORITY_INPUT, *PDARKSTAR_SET_THREAD_PRIORITY_INPUT;

typedef struct _DARKSTAR_SET_THREAD_AFFINITY_INPUT {
    ULONG ThreadId;
    ULONG_PTR AffinityMask;
} DARKSTAR_SET_THREAD_AFFINITY_INPUT, *PDARKSTAR_SET_THREAD_AFFINITY_INPUT;

typedef struct _DARKSTAR_SET_PROCESS_PRIORITY_INPUT {
    ULONG ProcessId;
    UCHAR PriorityClass;
} DARKSTAR_SET_PROCESS_PRIORITY_INPUT, *PDARKSTAR_SET_PROCESS_PRIORITY_INPUT;

// Internal structure required by ZwSetInformationProcess(ProcessPriorityClass)
typedef struct _PROCESS_PRIORITY_CLASS {
    BOOLEAN Foreground;
    UCHAR PriorityClass;
} PROCESS_PRIORITY_CLASS, *PPROCESS_PRIORITY_CLASS;

// Function prototypes
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DarkstarUnload;
__drv_dispatchType(IRP_MJ_CREATE) DRIVER_DISPATCH DarkstarCreate;
__drv_dispatchType(IRP_MJ_CLOSE) DRIVER_DISPATCH DarkstarClose;
__drv_dispatchType(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH DarkstarDeviceControl;

// Global device object
PDEVICE_OBJECT g_DeviceObject = NULL;

/*
 * DriverEntry - Driver initialization routine
 */
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;

    UNREFERENCED_PARAMETER(RegistryPath);

    KdPrint(("DarkstarDriver: DriverEntry called\n"));

    // Initialize device name
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);

    // Create device object
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: Failed to create device: 0x%08X\n", status));
        return status;
    }

    // Create symbolic link
    RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);

    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: Failed to create symbolic link: 0x%08X\n", status));
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Set dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DarkstarCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DarkstarClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DarkstarDeviceControl;
    DriverObject->DriverUnload = DarkstarUnload;

    KdPrint(("DarkstarDriver: Driver loaded successfully\n"));
    return STATUS_SUCCESS;
}

/*
 * DarkstarUnload - Driver cleanup routine
 */
VOID DarkstarUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING symlinkName;

    UNREFERENCED_PARAMETER(DriverObject);

    KdPrint(("DarkstarDriver: Unloading driver\n"));

    // Delete symbolic link
    RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);

    // Delete device object
    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
    }

    KdPrint(("DarkstarDriver: Driver unloaded\n"));
}

/*
 * DarkstarCreate - Handle IRP_MJ_CREATE
 */
NTSTATUS DarkstarCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    KdPrint(("DarkstarDriver: Create request\n"));

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/*
 * DarkstarClose - Handle IRP_MJ_CLOSE
 */
NTSTATUS DarkstarClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    KdPrint(("DarkstarDriver: Close request\n"));

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/*
 * SetThreadPriorityKernel - Set thread priority using kernel-mode access
 */
NTSTATUS SetThreadPriorityKernel(
    _In_ ULONG ThreadId,
    _In_ LONG Priority
)
{
    NTSTATUS status;
    PETHREAD threadObject = NULL;
    HANDLE threadHandle = NULL;

    // Lookup thread object by ID
    status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)ThreadId, &threadObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: PsLookupThreadByThreadId failed: 0x%08X\n", status));
        return status;
    }

    // Open handle to thread with KernelMode access (bypasses PPL)
    status = ObOpenObjectByPointer(
        threadObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        THREAD_SET_INFORMATION,
        *PsThreadType,
        KernelMode,
        &threadHandle
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: ObOpenObjectByPointer failed: 0x%08X\n", status));
        ObDereferenceObject(threadObject);
        return status;
    }

    // Set thread priority
    status = ZwSetInformationThread(
        threadHandle,
        ThreadPriority,
        &Priority,
        sizeof(LONG)
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: ZwSetInformationThread failed: 0x%08X\n", status));
    }

    // Cleanup
    ZwClose(threadHandle);
    ObDereferenceObject(threadObject);

    return status;
}

/*
 * SetThreadAffinityKernel - Set thread affinity using kernel-mode access
 */
NTSTATUS SetThreadAffinityKernel(
    _In_ ULONG ThreadId,
    _In_ ULONG_PTR AffinityMask
)
{
    NTSTATUS status;
    PETHREAD threadObject = NULL;
    HANDLE threadHandle = NULL;

    // Lookup thread object by ID
    status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)ThreadId, &threadObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: PsLookupThreadByThreadId failed: 0x%08X\n", status));
        return status;
    }

    // Open handle to thread with KernelMode access
    status = ObOpenObjectByPointer(
        threadObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        THREAD_SET_INFORMATION,
        *PsThreadType,
        KernelMode,
        &threadHandle
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: ObOpenObjectByPointer failed: 0x%08X\n", status));
        ObDereferenceObject(threadObject);
        return status;
    }

    // Set thread affinity
    status = ZwSetInformationThread(
        threadHandle,
        ThreadAffinityMask,
        &AffinityMask,
        sizeof(ULONG_PTR)
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: ZwSetInformationThread (affinity) failed: 0x%08X\n", status));
    }

    // Cleanup
    ZwClose(threadHandle);
    ObDereferenceObject(threadObject);

    return status;
}

/*
 * SetProcessPriorityKernel - Set process priority class using kernel-mode access
 */
NTSTATUS SetProcessPriorityKernel(
    _In_ ULONG ProcessId,
    _In_ UCHAR PriorityClass
)
{
    NTSTATUS status;
    PEPROCESS processObject = NULL;
    HANDLE processHandle = NULL;

    // Lookup process object by ID
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &processObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: PsLookupProcessByProcessId failed: 0x%08X\n", status));
        return status;
    }

    // Open handle to process with KernelMode access
    status = ObOpenObjectByPointer(
        processObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_SET_INFORMATION,
        *PsProcessType,
        KernelMode,
        &processHandle
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: ObOpenObjectByPointer failed: 0x%08X\n", status));
        ObDereferenceObject(processObject);
        return status;
    }

    // Set process priority class using the required PROCESS_PRIORITY_CLASS structure
    PROCESS_PRIORITY_CLASS priorityClassInfo;
    priorityClassInfo.Foreground = FALSE;
    priorityClassInfo.PriorityClass = PriorityClass;
    
    status = ZwSetInformationProcess(
        processHandle,
        ProcessPriorityClass,
        &priorityClassInfo,
        sizeof(PROCESS_PRIORITY_CLASS)
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("DarkstarDriver: ZwSetInformationProcess failed: 0x%08X\n", status));
    }

    // Cleanup
    ZwClose(processHandle);
    ObDereferenceObject(processObject);

    return status;
}

/*
 * DarkstarDeviceControl - Handle IRP_MJ_DEVICE_CONTROL (IOCTLs)
 */
NTSTATUS DarkstarDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION irpStack;
    ULONG ioControlCode;
    PVOID inputBuffer;
    ULONG inputBufferLength;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpStack = IoGetCurrentIrpStackLocation(Irp);
    ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
    inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;

    KdPrint(("DarkstarDriver: DeviceIoControl - IOCTL: 0x%08X\n", ioControlCode));

    switch (ioControlCode) {
        case IOCTL_DARKSTAR_SET_THREAD_PRIORITY:
        {
            if (inputBufferLength == sizeof(DARKSTAR_SET_THREAD_PRIORITY_INPUT)) {
                PDARKSTAR_SET_THREAD_PRIORITY_INPUT input = 
                    (PDARKSTAR_SET_THREAD_PRIORITY_INPUT)inputBuffer;
                
                KdPrint(("DarkstarDriver: Setting thread %u priority to %d\n", 
                    input->ThreadId, input->Priority));
                
                status = SetThreadPriorityKernel(input->ThreadId, input->Priority);
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        }

        case IOCTL_DARKSTAR_SET_THREAD_AFFINITY:
        {
            if (inputBufferLength == sizeof(DARKSTAR_SET_THREAD_AFFINITY_INPUT)) {
                PDARKSTAR_SET_THREAD_AFFINITY_INPUT input = 
                    (PDARKSTAR_SET_THREAD_AFFINITY_INPUT)inputBuffer;
                
                KdPrint(("DarkstarDriver: Setting thread %u affinity to 0x%p\n", 
                    input->ThreadId, (PVOID)input->AffinityMask));
                
                status = SetThreadAffinityKernel(input->ThreadId, input->AffinityMask);
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        }

        case IOCTL_DARKSTAR_SET_PROCESS_PRIORITY:
        {
            if (inputBufferLength == sizeof(DARKSTAR_SET_PROCESS_PRIORITY_INPUT)) {
                PDARKSTAR_SET_PROCESS_PRIORITY_INPUT input = 
                    (PDARKSTAR_SET_PROCESS_PRIORITY_INPUT)inputBuffer;
                
                KdPrint(("DarkstarDriver: Setting process %u priority class to %u\n", 
                    input->ProcessId, input->PriorityClass));
                
                status = SetProcessPriorityKernel(input->ProcessId, input->PriorityClass);
            } else {
                status = STATUS_INVALID_PARAMETER;
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