// Warning: Auto-generated file. Your changes may be lost.

const int num_functions = 1603;
void* function_ptrs[num_functions];

const char* function_names[] = {
    "AcquireSRWLockExclusive",
    "AcquireSRWLockShared",
    "ActivateActCtx",
    "ActivateActCtxWorker",
    "AddAtomA",
    "AddAtomW",
    "AddConsoleAliasA",
    "AddConsoleAliasW",
    "AddDllDirectory",
    "AddIntegrityLabelToBoundaryDescriptor",
    "AddLocalAlternateComputerNameA",
    "AddLocalAlternateComputerNameW",
    "AddRefActCtx",
    "AddRefActCtxWorker",
    "AddResourceAttributeAce",
    "AddSIDToBoundaryDescriptor",
    "AddScopedPolicyIDAce",
    "AddSecureMemoryCacheCallback",
    "AddVectoredContinueHandler",
    "AddVectoredExceptionHandler",
    "AdjustCalendarDate",
    "AllocConsole",
    "AllocateUserPhysicalPages",
    "AllocateUserPhysicalPagesNuma",
    "AppPolicyGetClrCompat",
    "AppPolicyGetCreateFileAccess",
    "AppPolicyGetLifecycleManagement",
    "AppPolicyGetMediaFoundationCodecLoading",
    "AppPolicyGetProcessTerminationMethod",
    "AppPolicyGetShowDeveloperDiagnostic",
    "AppPolicyGetThreadInitializationType",
    "AppPolicyGetWindowingModel",
    "AppXGetOSMaxVersionTested",
    "ApplicationRecoveryFinished",
    "ApplicationRecoveryInProgress",
    "AreFileApisANSI",
    "AssignProcessToJobObject",
    "AttachConsole",
    "BackupRead",
    "BackupSeek",
    "BackupWrite",
    "BaseCheckAppcompatCache",
    "BaseCheckAppcompatCacheEx",
    "BaseCheckAppcompatCacheExWorker",
    "BaseCheckAppcompatCacheWorker",
    "BaseCheckElevation",
    "BaseCleanupAppcompatCacheSupport",
    "BaseCleanupAppcompatCacheSupportWorker",
    "BaseDestroyVDMEnvironment",
    "BaseDllReadWriteIniFile",
    "BaseDumpAppcompatCache",
    "BaseDumpAppcompatCacheWorker",
    "BaseElevationPostProcessing",
    "BaseFlushAppcompatCache",
    "BaseFlushAppcompatCacheWorker",
    "BaseFormatObjectAttributes",
    "BaseFormatTimeOut",
    "BaseFreeAppCompatDataForProcessWorker",
    "BaseGenerateAppCompatData",
    "BaseGetNamedObjectDirectory",
    "BaseInitAppcompatCacheSupport",
    "BaseInitAppcompatCacheSupportWorker",
    "BaseIsAppcompatInfrastructureDisabled",
    "BaseIsAppcompatInfrastructureDisabledWorker",
    "BaseIsDosApplication",
    "BaseQueryModuleData",
    "BaseReadAppCompatDataForProcessWorker",
    "BaseSetLastNTError",
    "BaseThreadInitThunk",
    "BaseUpdateAppcompatCache",
    "BaseUpdateAppcompatCacheWorker",
    "BaseUpdateVDMEntry",
    "BaseVerifyUnicodeString",
    "BaseWriteErrorElevationRequiredEvent",
    "Basep8BitStringToDynamicUnicodeString",
    "BasepAllocateActivationContextActivationBlock",
    "BasepAnsiStringToDynamicUnicodeString",
    "BasepAppContainerEnvironmentExtension",
    "BasepAppXExtension",
    "BasepCheckAppCompat",
    "BasepCheckWebBladeHashes",
    "BasepCheckWinSaferRestrictions",
    "BasepConstructSxsCreateProcessMessage",
    "BasepCopyEncryption",
    "BasepFreeActivationContextActivationBlock",
    "BasepFreeAppCompatData",
    "BasepGetAppCompatData",
    "BasepGetComputerNameFromNtPath",
    "BasepGetExeArchType",
    "BasepInitAppCompatData",
    "BasepIsProcessAllowed",
    "BasepMapModuleHandle",
    "BasepNotifyLoadStringResource",
    "BasepPostSuccessAppXExtension",
    "BasepProcessInvalidImage",
    "BasepQueryAppCompat",
    "BasepQueryModuleChpeSettings",
    "BasepReleaseAppXContext",
    "BasepReleaseSxsCreateProcessUtilityStruct",
    "BasepReportFault",
    "BasepSetFileEncryptionCompression",
    "Beep",
    "BeginUpdateResourceA",
    "BeginUpdateResourceW",
    "BindIoCompletionCallback",
    "BuildCommDCBA",
    "BuildCommDCBAndTimeoutsA",
    "BuildCommDCBAndTimeoutsW",
    "BuildCommDCBW",
    "CallNamedPipeA",
    "CallNamedPipeW",
    "CallbackMayRunLong",
    "CancelDeviceWakeupRequest",
    "CancelIo",
    "CancelIoEx",
    "CancelSynchronousIo",
    "CancelThreadpoolIo",
    "CancelTimerQueueTimer",
    "CancelWaitableTimer",
    "CeipIsOptedIn",
    "ChangeTimerQueueTimer",
    "CheckAllowDecryptedRemoteDestinationPolicy",
    "CheckElevation",
    "CheckElevationEnabled",
    "CheckForReadOnlyResource",
    "CheckForReadOnlyResourceFilter",
    "CheckNameLegalDOS8Dot3A",
    "CheckNameLegalDOS8Dot3W",
    "CheckRemoteDebuggerPresent",
    "CheckTokenCapability",
    "CheckTokenMembershipEx",
    "ClearCommBreak",
    "ClearCommError",
    "CloseConsoleHandle",
    "CloseHandle",
    "ClosePackageInfo",
    "ClosePrivateNamespace",
    "CloseProfileUserMapping",
    "ClosePseudoConsole",
    "CloseState",
    "CloseThreadpool",
    "CloseThreadpoolCleanupGroup",
    "CloseThreadpoolCleanupGroupMembers",
    "CloseThreadpoolIo",
    "CloseThreadpoolTimer",
    "CloseThreadpoolWait",
    "CloseThreadpoolWork",
    "CmdBatNotification",
    "CommConfigDialogA",
    "CommConfigDialogW",
    "CompareCalendarDates",
    "CompareFileTime",
    "CompareStringA",
    "CompareStringEx",
    "CompareStringOrdinal",
    "CompareStringW",
    "ConnectNamedPipe",
    "ConsoleMenuControl",
    "ContinueDebugEvent",
    "ConvertCalDateTimeToSystemTime",
    "ConvertDefaultLocale",
    "ConvertFiberToThread",
    "ConvertNLSDayOfWeekToWin32DayOfWeek",
    "ConvertSystemTimeToCalDateTime",
    "ConvertThreadToFiber",
    "ConvertThreadToFiberEx",
    "CopyContext",
    "CopyFile2",
    "CopyFileA",
    "CopyFileExA",
    "CopyFileExW",
    "CopyFileTransactedA",
    "CopyFileTransactedW",
    "CopyFileW",
    "CopyLZFile",
    "CreateActCtxA",
    "CreateActCtxW",
    "CreateActCtxWWorker",
    "CreateBoundaryDescriptorA",
    "CreateBoundaryDescriptorW",
    "CreateConsoleScreenBuffer",
    "CreateDirectoryA",
    "CreateDirectoryExA",
    "CreateDirectoryExW",
    "CreateDirectoryTransactedA",
    "CreateDirectoryTransactedW",
    "CreateDirectoryW",
    "CreateEnclave",
    "CreateEventA",
    "CreateEventExA",
    "CreateEventExW",
    "CreateEventW",
    "CreateFiber",
    "CreateFiberEx",
    "CreateFile2",
    "CreateFileA",
    "CreateFileMappingA",
    "CreateFileMappingFromApp",
    "CreateFileMappingNumaA",
    "CreateFileMappingNumaW",
    "CreateFileMappingW",
    "CreateFileTransactedA",
    "CreateFileTransactedW",
    "CreateFileW",
    "CreateHardLinkA",
    "CreateHardLinkTransactedA",
    "CreateHardLinkTransactedW",
    "CreateHardLinkW",
    "CreateIoCompletionPort",
    "CreateJobObjectA",
    "CreateJobObjectW",
    "CreateJobSet",
    "CreateMailslotA",
    "CreateMailslotW",
    "CreateMemoryResourceNotification",
    "CreateMutexA",
    "CreateMutexExA",
    "CreateMutexExW",
    "CreateMutexW",
    "CreateNamedPipeA",
    "CreateNamedPipeW",
    "CreatePipe",
    "CreatePrivateNamespaceA",
    "CreatePrivateNamespaceW",
    "CreateProcessA",
    "CreateProcessAsUserA",
    "CreateProcessAsUserW",
    "CreateProcessInternalA",
    "CreateProcessInternalW",
    "CreateProcessW",
    "CreatePseudoConsole",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "CreateSemaphoreA",
    "CreateSemaphoreExA",
    "CreateSemaphoreExW",
    "CreateSemaphoreW",
    "CreateSocketHandle",
    "CreateSymbolicLinkA",
    "CreateSymbolicLinkTransactedA",
    "CreateSymbolicLinkTransactedW",
    "CreateSymbolicLinkW",
    "CreateTapePartition",
    "CreateThread",
    "CreateThreadpool",
    "CreateThreadpoolCleanupGroup",
    "CreateThreadpoolIo",
    "CreateThreadpoolTimer",
    "CreateThreadpoolWait",
    "CreateThreadpoolWork",
    "CreateTimerQueue",
    "CreateTimerQueueTimer",
    "CreateToolhelp32Snapshot",
    "CreateWaitableTimerA",
    "CreateWaitableTimerExA",
    "CreateWaitableTimerExW",
    "CreateWaitableTimerW",
    "CtrlRoutine",
    "DeactivateActCtx",
    "DeactivateActCtxWorker",
    "DebugActiveProcess",
    "DebugActiveProcessStop",
    "DebugBreak",
    "DebugBreakProcess",
    "DebugSetProcessKillOnExit",
    "DecodePointer",
    "DecodeSystemPointer",
    "DefineDosDeviceA",
    "DefineDosDeviceW",
    "DelayLoadFailureHook",
    "DeleteAtom",
    "DeleteBoundaryDescriptor",
    "DeleteCriticalSection",
    "DeleteFiber",
    "DeleteFileA",
    "DeleteFileTransactedA",
    "DeleteFileTransactedW",
    "DeleteFileW",
    "DeleteProcThreadAttributeList",
    "DeleteSynchronizationBarrier",
    "DeleteTimerQueue",
    "DeleteTimerQueueEx",
    "DeleteTimerQueueTimer",
    "DeleteVolumeMountPointA",
    "DeleteVolumeMountPointW",
    "DeviceIoControl",
    "DisableThreadLibraryCalls",
    "DisableThreadProfiling",
    "DisassociateCurrentThreadFromCallback",
    "DiscardVirtualMemory",
    "DisconnectNamedPipe",
    "DnsHostnameToComputerNameA",
    "DnsHostnameToComputerNameExW",
    "DnsHostnameToComputerNameW",
    "DosDateTimeToFileTime",
    "DosPathToSessionPathA",
    "DosPathToSessionPathW",
    "DuplicateConsoleHandle",
    "DuplicateEncryptionInfoFileExt",
    "DuplicateHandle",
    "EnableThreadProfiling",
    "EncodePointer",
    "EncodeSystemPointer",
    "EndUpdateResourceA",
    "EndUpdateResourceW",
    "EnterCriticalSection",
    "EnterSynchronizationBarrier",
    "EnumCalendarInfoA",
    "EnumCalendarInfoExA",
    "EnumCalendarInfoExEx",
    "EnumCalendarInfoExW",
    "EnumCalendarInfoW",
    "EnumDateFormatsA",
    "EnumDateFormatsExA",
    "EnumDateFormatsExEx",
    "EnumDateFormatsExW",
    "EnumDateFormatsW",
    "EnumLanguageGroupLocalesA",
    "EnumLanguageGroupLocalesW",
    "EnumResourceLanguagesA",
    "EnumResourceLanguagesExA",
    "EnumResourceLanguagesExW",
    "EnumResourceLanguagesW",
    "EnumResourceNamesA",
    "EnumResourceNamesExA",
    "EnumResourceNamesExW",
    "EnumResourceNamesW",
    "EnumResourceTypesA",
    "EnumResourceTypesExA",
    "EnumResourceTypesExW",
    "EnumResourceTypesW",
    "EnumSystemCodePagesA",
    "EnumSystemCodePagesW",
    "EnumSystemFirmwareTables",
    "EnumSystemGeoID",
    "EnumSystemGeoNames",
    "EnumSystemLanguageGroupsA",
    "EnumSystemLanguageGroupsW",
    "EnumSystemLocalesA",
    "EnumSystemLocalesEx",
    "EnumSystemLocalesW",
    "EnumTimeFormatsA",
    "EnumTimeFormatsEx",
    "EnumTimeFormatsW",
    "EnumUILanguagesA",
    "EnumUILanguagesW",
    "EnumerateLocalComputerNamesA",
    "EnumerateLocalComputerNamesW",
    "EraseTape",
    "EscapeCommFunction",
    "ExitProcess",
    "ExitThread",
    "ExitVDM",
    "ExpandEnvironmentStringsA",
    "ExpandEnvironmentStringsW",
    "ExpungeConsoleCommandHistoryA",
    "ExpungeConsoleCommandHistoryW",
    "FatalAppExitA",
    "FatalAppExitW",
    "FatalExit",
    "FileTimeToDosDateTime",
    "FileTimeToLocalFileTime",
    "FileTimeToSystemTime",
    "FillConsoleOutputAttribute",
    "FillConsoleOutputCharacterA",
    "FillConsoleOutputCharacterW",
    "FindActCtxSectionGuid",
    "FindActCtxSectionGuidWorker",
    "FindActCtxSectionStringA",
    "FindActCtxSectionStringW",
    "FindActCtxSectionStringWWorker",
    "FindAtomA",
    "FindAtomW",
    "FindClose",
    "FindCloseChangeNotification",
    "FindFirstChangeNotificationA",
    "FindFirstChangeNotificationW",
    "FindFirstFileA",
    "FindFirstFileExA",
    "FindFirstFileExW",
    "FindFirstFileNameTransactedW",
    "FindFirstFileNameW",
    "FindFirstFileTransactedA",
    "FindFirstFileTransactedW",
    "FindFirstFileW",
    "FindFirstStreamTransactedW",
    "FindFirstStreamW",
    "FindFirstVolumeA",
    "FindFirstVolumeMountPointA",
    "FindFirstVolumeMountPointW",
    "FindFirstVolumeW",
    "FindNLSString",
    "FindNLSStringEx",
    "FindNextChangeNotification",
    "FindNextFileA",
    "FindNextFileNameW",
    "FindNextFileW",
    "FindNextStreamW",
    "FindNextVolumeA",
    "FindNextVolumeMountPointA",
    "FindNextVolumeMountPointW",
    "FindNextVolumeW",
    "FindPackagesByPackageFamily",
    "FindResourceA",
    "FindResourceExA",
    "FindResourceExW",
    "FindResourceW",
    "FindStringOrdinal",
    "FindVolumeClose",
    "FindVolumeMountPointClose",
    "FlsAlloc",
    "FlsFree",
    "FlsGetValue",
    "FlsSetValue",
    "FlushConsoleInputBuffer",
    "FlushFileBuffers",
    "FlushInstructionCache",
    "FlushProcessWriteBuffers",
    "FlushViewOfFile",
    "FoldStringA",
    "FoldStringW",
    "FormatApplicationUserModelId",
    "FormatMessageA",
    "FormatMessageW",
    "FreeConsole",
    "FreeEnvironmentStringsA",
    "FreeEnvironmentStringsW",
    "FreeLibrary",
    "FreeLibraryAndExitThread",
    "FreeLibraryWhenCallbackReturns",
    "FreeMemoryJobObject",
    "FreeResource",
    "FreeUserPhysicalPages",
    "GenerateConsoleCtrlEvent",
    "GetACP",
    "GetActiveProcessorCount",
    "GetActiveProcessorGroupCount",
    "GetAppContainerAce",
    "GetAppContainerNamedObjectPath",
    "GetApplicationRecoveryCallback",
    "GetApplicationRecoveryCallbackWorker",
    "GetApplicationRestartSettings",
    "GetApplicationRestartSettingsWorker",
    "GetApplicationUserModelId",
    "GetAtomNameA",
    "GetAtomNameW",
    "GetBinaryType",
    "GetBinaryTypeA",
    "GetBinaryTypeW",
    "GetCPInfo",
    "GetCPInfoExA",
    "GetCPInfoExW",
    "GetCachedSigningLevel",
    "GetCalendarDateFormat",
    "GetCalendarDateFormatEx",
    "GetCalendarDaysInMonth",
    "GetCalendarDifferenceInDays",
    "GetCalendarInfoA",
    "GetCalendarInfoEx",
    "GetCalendarInfoW",
    "GetCalendarMonthsInYear",
    "GetCalendarSupportedDateRange",
    "GetCalendarWeekNumber",
    "GetComPlusPackageInstallStatus",
    "GetCommConfig",
    "GetCommMask",
    "GetCommModemStatus",
    "GetCommProperties",
    "GetCommState",
    "GetCommTimeouts",
    "GetCommandLineA",
    "GetCommandLineW",
    "GetCompressedFileSizeA",
    "GetCompressedFileSizeTransactedA",
    "GetCompressedFileSizeTransactedW",
    "GetCompressedFileSizeW",
    "GetComputerNameA",
    "GetComputerNameExA",
    "GetComputerNameExW",
    "GetComputerNameW",
    "GetConsoleAliasA",
    "GetConsoleAliasExesA",
    "GetConsoleAliasExesLengthA",
    "GetConsoleAliasExesLengthW",
    "GetConsoleAliasExesW",
    "GetConsoleAliasW",
    "GetConsoleAliasesA",
    "GetConsoleAliasesLengthA",
    "GetConsoleAliasesLengthW",
    "GetConsoleAliasesW",
    "GetConsoleCP",
    "GetConsoleCharType",
    "GetConsoleCommandHistoryA",
    "GetConsoleCommandHistoryLengthA",
    "GetConsoleCommandHistoryLengthW",
    "GetConsoleCommandHistoryW",
    "GetConsoleCursorInfo",
    "GetConsoleCursorMode",
    "GetConsoleDisplayMode",
    "GetConsoleFontInfo",
    "GetConsoleFontSize",
    "GetConsoleHardwareState",
    "GetConsoleHistoryInfo",
    "GetConsoleInputExeNameA",
    "GetConsoleInputExeNameW",
    "GetConsoleInputWaitHandle",
    "GetConsoleKeyboardLayoutNameA",
    "GetConsoleKeyboardLayoutNameW",
    "GetConsoleMode",
    "GetConsoleNlsMode",
    "GetConsoleOriginalTitleA",
    "GetConsoleOriginalTitleW",
    "GetConsoleOutputCP",
    "GetConsoleProcessList",
    "GetConsoleScreenBufferInfo",
    "GetConsoleScreenBufferInfoEx",
    "GetConsoleSelectionInfo",
    "GetConsoleTitleA",
    "GetConsoleTitleW",
    "GetConsoleWindow",
    "GetCurrencyFormatA",
    "GetCurrencyFormatEx",
    "GetCurrencyFormatW",
    "GetCurrentActCtx",
    "GetCurrentActCtxWorker",
    "GetCurrentApplicationUserModelId",
    "GetCurrentConsoleFont",
    "GetCurrentConsoleFontEx",
    "GetCurrentDirectoryA",
    "GetCurrentDirectoryW",
    "GetCurrentPackageFamilyName",
    "GetCurrentPackageFullName",
    "GetCurrentPackageId",
    "GetCurrentPackageInfo",
    "GetCurrentPackagePath",
    "GetCurrentProcess",
    "GetCurrentProcessId",
    "GetCurrentProcessorNumber",
    "GetCurrentProcessorNumberEx",
    "GetCurrentThread",
    "GetCurrentThreadId",
    "GetCurrentThreadStackLimits",
    "GetDateFormatA",
    "GetDateFormatAWorker",
    "GetDateFormatEx",
    "GetDateFormatW",
    "GetDateFormatWWorker",
    "GetDefaultCommConfigA",
    "GetDefaultCommConfigW",
    "GetDevicePowerState",
    "GetDiskFreeSpaceA",
    "GetDiskFreeSpaceExA",
    "GetDiskFreeSpaceExW",
    "GetDiskFreeSpaceW",
    "GetDiskSpaceInformationA",
    "GetDiskSpaceInformationW",
    "GetDllDirectoryA",
    "GetDllDirectoryW",
    "GetDriveTypeA",
    "GetDriveTypeW",
    "GetDurationFormat",
    "GetDurationFormatEx",
    "GetDynamicTimeZoneInformation",
    "GetEnabledXStateFeatures",
    "GetEncryptedFileVersionExt",
    "GetEnvironmentStrings",
    "GetEnvironmentStringsA",
    "GetEnvironmentStringsW",
    "GetEnvironmentVariableA",
    "GetEnvironmentVariableW",
    "GetEraNameCountedString",
    "GetErrorMode",
    "GetExitCodeProcess",
    "GetExitCodeThread",
    "GetExpandedNameA",
    "GetExpandedNameW",
    "GetFileAttributesA",
    "GetFileAttributesExA",
    "GetFileAttributesExW",
    "GetFileAttributesTransactedA",
    "GetFileAttributesTransactedW",
    "GetFileAttributesW",
    "GetFileBandwidthReservation",
    "GetFileInformationByHandle",
    "GetFileInformationByHandleEx",
    "GetFileMUIInfo",
    "GetFileMUIPath",
    "GetFileSize",
    "GetFileSizeEx",
    "GetFileTime",
    "GetFileType",
    "GetFinalPathNameByHandleA",
    "GetFinalPathNameByHandleW",
    "GetFirmwareEnvironmentVariableA",
    "GetFirmwareEnvironmentVariableExA",
    "GetFirmwareEnvironmentVariableExW",
    "GetFirmwareEnvironmentVariableW",
    "GetFirmwareType",
    "GetFullPathNameA",
    "GetFullPathNameTransactedA",
    "GetFullPathNameTransactedW",
    "GetFullPathNameW",
    "GetGeoInfoA",
    "GetGeoInfoEx",
    "GetGeoInfoW",
    "GetHandleContext",
    "GetHandleInformation",
    "GetLargePageMinimum",
    "GetLargestConsoleWindowSize",
    "GetLastError",
    "GetLocalTime",
    "GetLocaleInfoA",
    "GetLocaleInfoEx",
    "GetLocaleInfoW",
    "GetLogicalDriveStringsA",
    "GetLogicalDriveStringsW",
    "GetLogicalDrives",
    "GetLogicalProcessorInformation",
    "GetLogicalProcessorInformationEx",
    "GetLongPathNameA",
    "GetLongPathNameTransactedA",
    "GetLongPathNameTransactedW",
    "GetLongPathNameW",
    "GetMailslotInfo",
    "GetMaximumProcessorCount",
    "GetMaximumProcessorGroupCount",
    "GetMemoryErrorHandlingCapabilities",
    "GetModuleFileNameA",
    "GetModuleFileNameW",
    "GetModuleHandleA",
    "GetModuleHandleExA",
    "GetModuleHandleExW",
    "GetModuleHandleW",
    "GetNLSVersion",
    "GetNLSVersionEx",
    "GetNamedPipeAttribute",
    "GetNamedPipeClientComputerNameA",
    "GetNamedPipeClientComputerNameW",
    "GetNamedPipeClientProcessId",
    "GetNamedPipeClientSessionId",
    "GetNamedPipeHandleStateA",
    "GetNamedPipeHandleStateW",
    "GetNamedPipeInfo",
    "GetNamedPipeServerProcessId",
    "GetNamedPipeServerSessionId",
    "GetNativeSystemInfo",
    "GetNextVDMCommand",
    "GetNumaAvailableMemoryNode",
    "GetNumaAvailableMemoryNodeEx",
    "GetNumaHighestNodeNumber",
    "GetNumaNodeNumberFromHandle",
    "GetNumaNodeProcessorMask",
    "GetNumaNodeProcessorMaskEx",
    "GetNumaProcessorNode",
    "GetNumaProcessorNodeEx",
    "GetNumaProximityNode",
    "GetNumaProximityNodeEx",
    "GetNumberFormatA",
    "GetNumberFormatEx",
    "GetNumberFormatW",
    "GetNumberOfConsoleFonts",
    "GetNumberOfConsoleInputEvents",
    "GetNumberOfConsoleMouseButtons",
    "GetOEMCP",
    "GetOverlappedResult",
    "GetOverlappedResultEx",
    "GetPackageApplicationIds",
    "GetPackageFamilyName",
    "GetPackageFullName",
    "GetPackageId",
    "GetPackageInfo",
    "GetPackagePath",
    "GetPackagePathByFullName",
    "GetPackagesByPackageFamily",
    "GetPhysicallyInstalledSystemMemory",
    "GetPriorityClass",
    "GetPrivateProfileIntA",
    "GetPrivateProfileIntW",
    "GetPrivateProfileSectionA",
    "GetPrivateProfileSectionNamesA",
    "GetPrivateProfileSectionNamesW",
    "GetPrivateProfileSectionW",
    "GetPrivateProfileStringA",
    "GetPrivateProfileStringW",
    "GetPrivateProfileStructA",
    "GetPrivateProfileStructW",
    "GetProcAddress",
    "GetProcessAffinityMask",
    "GetProcessDEPPolicy",
    "GetProcessDefaultCpuSets",
    "GetProcessGroupAffinity",
    "GetProcessHandleCount",
    "GetProcessHeap",
    "GetProcessHeaps",
    "GetProcessId",
    "GetProcessIdOfThread",
    "GetProcessInformation",
    "GetProcessIoCounters",
    "GetProcessMitigationPolicy",
    "GetProcessPreferredUILanguages",
    "GetProcessPriorityBoost",
    "GetProcessShutdownParameters",
    "GetProcessTimes",
    "GetProcessVersion",
    "GetProcessWorkingSetSize",
    "GetProcessWorkingSetSizeEx",
    "GetProcessorSystemCycleTime",
    "GetProductInfo",
    "GetProfileIntA",
    "GetProfileIntW",
    "GetProfileSectionA",
    "GetProfileSectionW",
    "GetProfileStringA",
    "GetProfileStringW",
    "GetQueuedCompletionStatus",
    "GetQueuedCompletionStatusEx",
    "GetShortPathNameA",
    "GetShortPathNameW",
    "GetStagedPackagePathByFullName",
    "GetStartupInfoA",
    "GetStartupInfoW",
    "GetStateFolder",
    "GetStdHandle",
    "GetStringScripts",
    "GetStringTypeA",
    "GetStringTypeExA",
    "GetStringTypeExW",
    "GetStringTypeW",
    "GetSystemAppDataKey",
    "GetSystemCpuSetInformation",
    "GetSystemDEPPolicy",
    "GetSystemDefaultLCID",
    "GetSystemDefaultLangID",
    "GetSystemDefaultLocaleName",
    "GetSystemDefaultUILanguage",
    "GetSystemDirectoryA",
    "GetSystemDirectoryW",
    "GetSystemFileCacheSize",
    "GetSystemFirmwareTable",
    "GetSystemInfo",
    "GetSystemPowerStatus",
    "GetSystemPreferredUILanguages",
    "GetSystemRegistryQuota",
    "GetSystemTime",
    "GetSystemTimeAdjustment",
    "GetSystemTimeAsFileTime",
    "GetSystemTimePreciseAsFileTime",
    "GetSystemTimes",
    "GetSystemWindowsDirectoryA",
    "GetSystemWindowsDirectoryW",
    "GetSystemWow64DirectoryA",
    "GetSystemWow64DirectoryW",
    "GetTapeParameters",
    "GetTapePosition",
    "GetTapeStatus",
    "GetTempFileNameA",
    "GetTempFileNameW",
    "GetTempPathA",
    "GetTempPathW",
    "GetThreadContext",
    "GetThreadDescription",
    "GetThreadErrorMode",
    "GetThreadGroupAffinity",
    "GetThreadIOPendingFlag",
    "GetThreadId",
    "GetThreadIdealProcessorEx",
    "GetThreadInformation",
    "GetThreadLocale",
    "GetThreadPreferredUILanguages",
    "GetThreadPriority",
    "GetThreadPriorityBoost",
    "GetThreadSelectedCpuSets",
    "GetThreadSelectorEntry",
    "GetThreadTimes",
    "GetThreadUILanguage",
    "GetTickCount",
    "GetTickCount64",
    "GetTimeFormatA",
    "GetTimeFormatAWorker",
    "GetTimeFormatEx",
    "GetTimeFormatW",
    "GetTimeFormatWWorker",
    "GetTimeZoneInformation",
    "GetTimeZoneInformationForYear",
    "GetUILanguageInfo",
    "GetUserDefaultGeoName",
    "GetUserDefaultLCID",
    "GetUserDefaultLangID",
    "GetUserDefaultLocaleName",
    "GetUserDefaultUILanguage",
    "GetUserGeoID",
    "GetUserPreferredUILanguages",
    "GetVDMCurrentDirectories",
    "GetVersion",
    "GetVersionExA",
    "GetVersionExW",
    "GetVolumeInformationA",
    "GetVolumeInformationByHandleW",
    "GetVolumeInformationW",
    "GetVolumeNameForVolumeMountPointA",
    "GetVolumeNameForVolumeMountPointW",
    "GetVolumePathNameA",
    "GetVolumePathNameW",
    "GetVolumePathNamesForVolumeNameA",
    "GetVolumePathNamesForVolumeNameW",
    "GetWindowsDirectoryA",
    "GetWindowsDirectoryW",
    "GetWriteWatch",
    "GetXStateFeaturesMask",
    "GlobalAddAtomA",
    "GlobalAddAtomExA",
    "GlobalAddAtomExW",
    "GlobalAddAtomW",
    "GlobalAlloc",
    "GlobalCompact",
    "GlobalDeleteAtom",
    "GlobalFindAtomA",
    "GlobalFindAtomW",
    "GlobalFix",
    "GlobalFlags",
    "GlobalFree",
    "GlobalGetAtomNameA",
    "GlobalGetAtomNameW",
    "GlobalHandle",
    "GlobalLock",
    "GlobalMemoryStatus",
    "GlobalMemoryStatusEx",
    "GlobalReAlloc",
    "GlobalSize",
    "GlobalUnWire",
    "GlobalUnfix",
    "GlobalUnlock",
    "GlobalWire",
    "Heap32First",
    "Heap32ListFirst",
    "Heap32ListNext",
    "Heap32Next",
    "HeapAlloc",
    "HeapCompact",
    "HeapCreate",
    "HeapDestroy",
    "HeapFree",
    "HeapLock",
    "HeapQueryInformation",
    "HeapReAlloc",
    "HeapSetInformation",
    "HeapSize",
    "HeapSummary",
    "HeapUnlock",
    "HeapValidate",
    "HeapWalk",
    "IdnToAscii",
    "IdnToNameprepUnicode",
    "IdnToUnicode",
    "InitAtomTable",
    "InitOnceBeginInitialize",
    "InitOnceComplete",
    "InitOnceExecuteOnce",
    "InitOnceInitialize",
    "InitializeConditionVariable",
    "InitializeContext",
    "InitializeContext2",
    "InitializeCriticalSection",
    "InitializeCriticalSectionAndSpinCount",
    "InitializeCriticalSectionEx",
    "InitializeEnclave",
    "InitializeProcThreadAttributeList",
    "InitializeSListHead",
    "InitializeSRWLock",
    "InitializeSynchronizationBarrier",
    "InstallELAMCertificateInfo",
    "InterlockedCompareExchange",
    "InterlockedCompareExchange64",
    "InterlockedDecrement",
    "InterlockedExchange",
    "InterlockedExchangeAdd",
    "InterlockedFlushSList",
    "InterlockedIncrement",
    "InterlockedPopEntrySList",
    "InterlockedPushEntrySList",
    "InterlockedPushListSList",
    "InterlockedPushListSListEx",
    "InvalidateConsoleDIBits",
    "IsBadCodePtr",
    "IsBadHugeReadPtr",
    "IsBadHugeWritePtr",
    "IsBadReadPtr",
    "IsBadStringPtrA",
    "IsBadStringPtrW",
    "IsBadWritePtr",
    "IsCalendarLeapDay",
    "IsCalendarLeapMonth",
    "IsCalendarLeapYear",
    "IsDBCSLeadByte",
    "IsDBCSLeadByteEx",
    "IsDebuggerPresent",
    "IsEnclaveTypeSupported",
    "IsNLSDefinedString",
    "IsNativeVhdBoot",
    "IsNormalizedString",
    "IsProcessCritical",
    "IsProcessInJob",
    "IsProcessorFeaturePresent",
    "IsSystemResumeAutomatic",
    "IsThreadAFiber",
    "IsThreadpoolTimerSet",
    "IsValidCalDateTime",
    "IsValidCodePage",
    "IsValidLanguageGroup",
    "IsValidLocale",
    "IsValidLocaleName",
    "IsValidNLSVersion",
    "IsWow64GuestMachineSupported",
    "IsWow64Process",
    "IsWow64Process2",
    "K32EmptyWorkingSet",
    "K32EnumDeviceDrivers",
    "K32EnumPageFilesA",
    "K32EnumPageFilesW",
    "K32EnumProcessModules",
    "K32EnumProcessModulesEx",
    "K32EnumProcesses",
    "K32GetDeviceDriverBaseNameA",
    "K32GetDeviceDriverBaseNameW",
    "K32GetDeviceDriverFileNameA",
    "K32GetDeviceDriverFileNameW",
    "K32GetMappedFileNameA",
    "K32GetMappedFileNameW",
    "K32GetModuleBaseNameA",
    "K32GetModuleBaseNameW",
    "K32GetModuleFileNameExA",
    "K32GetModuleFileNameExW",
    "K32GetModuleInformation",
    "K32GetPerformanceInfo",
    "K32GetProcessImageFileNameA",
    "K32GetProcessImageFileNameW",
    "K32GetProcessMemoryInfo",
    "K32GetWsChanges",
    "K32GetWsChangesEx",
    "K32InitializeProcessForWsWatch",
    "K32QueryWorkingSet",
    "K32QueryWorkingSetEx",
    "LCIDToLocaleName",
    "LCMapStringA",
    "LCMapStringEx",
    "LCMapStringW",
    "LZClose",
    "LZCloseFile",
    "LZCopy",
    "LZCreateFileW",
    "LZDone",
    "LZInit",
    "LZOpenFileA",
    "LZOpenFileW",
    "LZRead",
    "LZSeek",
    "LZStart",
    "LeaveCriticalSection",
    "LeaveCriticalSectionWhenCallbackReturns",
    "LoadAppInitDlls",
    "LoadEnclaveData",
    "LoadLibraryA",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "LoadLibraryW",
    "LoadModule",
    "LoadPackagedLibrary",
    "LoadResource",
    "LoadStringBaseExW",
    "LoadStringBaseW",
    "LocalAlloc",
    "LocalCompact",
    "LocalFileTimeToFileTime",
    "LocalFileTimeToLocalSystemTime",
    "LocalFlags",
    "LocalFree",
    "LocalHandle",
    "LocalLock",
    "LocalReAlloc",
    "LocalShrink",
    "LocalSize",
    "LocalSystemTimeToLocalFileTime",
    "LocalUnlock",
    "LocaleNameToLCID",
    "LocateXStateFeature",
    "LockFile",
    "LockFileEx",
    "LockResource",
    "MapUserPhysicalPages",
    "MapUserPhysicalPagesScatter",
    "MapViewOfFile",
    "MapViewOfFileEx",
    "MapViewOfFileExNuma",
    "MapViewOfFileFromApp",
    "Module32First",
    "Module32FirstW",
    "Module32Next",
    "Module32NextW",
    "MoveFileA",
    "MoveFileExA",
    "MoveFileExW",
    "MoveFileTransactedA",
    "MoveFileTransactedW",
    "MoveFileW",
    "MoveFileWithProgressA",
    "MoveFileWithProgressW",
    "MulDiv",
    "MultiByteToWideChar",
    "NeedCurrentDirectoryForExePathA",
    "NeedCurrentDirectoryForExePathW",
    "NlsCheckPolicy",
    "NlsEventDataDescCreate",
    "NlsGetCacheUpdateCount",
    "NlsUpdateLocale",
    "NlsUpdateSystemLocale",
    "NlsWriteEtwEvent",
    "NormalizeString",
    "NotifyMountMgr",
    "NotifyUILanguageChange",
    "NtVdm64CreateProcessInternalW",
    "OOBEComplete",
    "OfferVirtualMemory",
    "OpenConsoleW",
    "OpenConsoleWStub",
    "OpenEventA",
    "OpenEventW",
    "OpenFile",
    "OpenFileById",
    "OpenFileMappingA",
    "OpenFileMappingW",
    "OpenJobObjectA",
    "OpenJobObjectW",
    "OpenMutexA",
    "OpenMutexW",
    "OpenPackageInfoByFullName",
    "OpenPrivateNamespaceA",
    "OpenPrivateNamespaceW",
    "OpenProcess",
    "OpenProcessToken",
    "OpenProfileUserMapping",
    "OpenSemaphoreA",
    "OpenSemaphoreW",
    "OpenState",
    "OpenStateExplicit",
    "OpenThread",
    "OpenThreadToken",
    "OpenWaitableTimerA",
    "OpenWaitableTimerW",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "PackageFamilyNameFromFullName",
    "PackageFamilyNameFromId",
    "PackageFullNameFromId",
    "PackageIdFromFullName",
    "PackageNameAndPublisherIdFromFamilyName",
    "ParseApplicationUserModelId",
    "PeekConsoleInputA",
    "PeekConsoleInputW",
    "PeekNamedPipe",
    "PostQueuedCompletionStatus",
    "PowerClearRequest",
    "PowerCreateRequest",
    "PowerSetRequest",
    "PrefetchVirtualMemory",
    "PrepareTape",
    "PrivCopyFileExW",
    "PrivMoveFileIdentityW",
    "Process32First",
    "Process32FirstW",
    "Process32Next",
    "Process32NextW",
    "ProcessIdToSessionId",
    "PssCaptureSnapshot",
    "PssDuplicateSnapshot",
    "PssFreeSnapshot",
    "PssQuerySnapshot",
    "PssWalkMarkerCreate",
    "PssWalkMarkerFree",
    "PssWalkMarkerGetPosition",
    "PssWalkMarkerRewind",
    "PssWalkMarkerSeek",
    "PssWalkMarkerSeekToBeginning",
    "PssWalkMarkerSetPosition",
    "PssWalkMarkerTell",
    "PssWalkSnapshot",
    "PulseEvent",
    "PurgeComm",
    "QueryActCtxSettingsW",
    "QueryActCtxSettingsWWorker",
    "QueryActCtxW",
    "QueryActCtxWWorker",
    "QueryDepthSList",
    "QueryDosDeviceA",
    "QueryDosDeviceW",
    "QueryFullProcessImageNameA",
    "QueryFullProcessImageNameW",
    "QueryIdleProcessorCycleTime",
    "QueryIdleProcessorCycleTimeEx",
    "QueryInformationJobObject",
    "QueryIoRateControlInformationJobObject",
    "QueryMemoryResourceNotification",
    "QueryPerformanceCounter",
    "QueryPerformanceFrequency",
    "QueryProcessAffinityUpdateMode",
    "QueryProcessCycleTime",
    "QueryProtectedPolicy",
    "QueryThreadCycleTime",
    "QueryThreadProfiling",
    "QueryThreadpoolStackInformation",
    "QueryUnbiasedInterruptTime",
    "QueueUserAPC",
    "QueueUserWorkItem",
    "QuirkGetData2Worker",
    "QuirkGetDataWorker",
    "QuirkIsEnabled2Worker",
    "QuirkIsEnabled3Worker",
    "QuirkIsEnabledForPackage2Worker",
    "QuirkIsEnabledForPackage3Worker",
    "QuirkIsEnabledForPackage4Worker",
    "QuirkIsEnabledForPackageWorker",
    "QuirkIsEnabledForProcessWorker",
    "QuirkIsEnabledWorker",
    "RaiseException",
    "RaiseFailFastException",
    "RaiseInvalid16BitExeError",
    "ReOpenFile",
    "ReadConsoleA",
    "ReadConsoleInputA",
    "ReadConsoleInputExA",
    "ReadConsoleInputExW",
    "ReadConsoleInputW",
    "ReadConsoleOutputA",
    "ReadConsoleOutputAttribute",
    "ReadConsoleOutputCharacterA",
    "ReadConsoleOutputCharacterW",
    "ReadConsoleOutputW",
    "ReadConsoleW",
    "ReadDirectoryChangesExW",
    "ReadDirectoryChangesW",
    "ReadFile",
    "ReadFileEx",
    "ReadFileScatter",
    "ReadProcessMemory",
    "ReadThreadProfilingData",
    "ReclaimVirtualMemory",
    "RegCloseKey",
    "RegCopyTreeW",
    "RegCreateKeyExA",
    "RegCreateKeyExW",
    "RegDeleteKeyExA",
    "RegDeleteKeyExW",
    "RegDeleteTreeA",
    "RegDeleteTreeW",
    "RegDeleteValueA",
    "RegDeleteValueW",
    "RegDisablePredefinedCacheEx",
    "RegEnumKeyExA",
    "RegEnumKeyExW",
    "RegEnumValueA",
    "RegEnumValueW",
    "RegFlushKey",
    "RegGetKeySecurity",
    "RegGetValueA",
    "RegGetValueW",
    "RegLoadKeyA",
    "RegLoadKeyW",
    "RegLoadMUIStringA",
    "RegLoadMUIStringW",
    "RegNotifyChangeKeyValue",
    "RegOpenCurrentUser",
    "RegOpenKeyExA",
    "RegOpenKeyExW",
    "RegOpenUserClassesRoot",
    "RegQueryInfoKeyA",
    "RegQueryInfoKeyW",
    "RegQueryValueExA",
    "RegQueryValueExW",
    "RegRestoreKeyA",
    "RegRestoreKeyW",
    "RegSaveKeyExA",
    "RegSaveKeyExW",
    "RegSetKeySecurity",
    "RegSetValueExA",
    "RegSetValueExW",
    "RegUnLoadKeyA",
    "RegUnLoadKeyW",
    "RegisterApplicationRecoveryCallback",
    "RegisterApplicationRestart",
    "RegisterBadMemoryNotification",
    "RegisterConsoleIME",
    "RegisterConsoleOS2",
    "RegisterConsoleVDM",
    "RegisterWaitForInputIdle",
    "RegisterWaitForSingleObject",
    "RegisterWaitForSingleObjectEx",
    "RegisterWaitUntilOOBECompleted",
    "RegisterWowBaseHandlers",
    "RegisterWowExec",
    "ReleaseActCtx",
    "ReleaseActCtxWorker",
    "ReleaseMutex",
    "ReleaseMutexWhenCallbackReturns",
    "ReleaseSRWLockExclusive",
    "ReleaseSRWLockShared",
    "ReleaseSemaphore",
    "ReleaseSemaphoreWhenCallbackReturns",
    "RemoveDirectoryA",
    "RemoveDirectoryTransactedA",
    "RemoveDirectoryTransactedW",
    "RemoveDirectoryW",
    "RemoveDllDirectory",
    "RemoveLocalAlternateComputerNameA",
    "RemoveLocalAlternateComputerNameW",
    "RemoveSecureMemoryCacheCallback",
    "RemoveVectoredContinueHandler",
    "RemoveVectoredExceptionHandler",
    "ReplaceFile",
    "ReplaceFileA",
    "ReplaceFileW",
    "ReplacePartitionUnit",
    "RequestDeviceWakeup",
    "RequestWakeupLatency",
    "ResetEvent",
    "ResetWriteWatch",
    "ResizePseudoConsole",
    "ResolveDelayLoadedAPI",
    "ResolveDelayLoadsFromDll",
    "ResolveLocaleName",
    "RestoreLastError",
    "ResumeThread",
    "RtlCaptureContext",
    "RtlCaptureStackBackTrace",
    "RtlFillMemory",
    "RtlMoveMemory",
    "RtlPcToFileHeader",
    "RtlUnwind",
    "RtlZeroMemory",
    "ScrollConsoleScreenBufferA",
    "ScrollConsoleScreenBufferW",
    "SearchPathA",
    "SearchPathW",
    "SetCachedSigningLevel",
    "SetCalendarInfoA",
    "SetCalendarInfoW",
    "SetComPlusPackageInstallStatus",
    "SetCommBreak",
    "SetCommConfig",
    "SetCommMask",
    "SetCommState",
    "SetCommTimeouts",
    "SetComputerNameA",
    "SetComputerNameEx2W",
    "SetComputerNameExA",
    "SetComputerNameExW",
    "SetComputerNameW",
    "SetConsoleActiveScreenBuffer",
    "SetConsoleCP",
    "SetConsoleCtrlHandler",
    "SetConsoleCursor",
    "SetConsoleCursorInfo",
    "SetConsoleCursorMode",
    "SetConsoleCursorPosition",
    "SetConsoleDisplayMode",
    "SetConsoleFont",
    "SetConsoleHardwareState",
    "SetConsoleHistoryInfo",
    "SetConsoleIcon",
    "SetConsoleInputExeNameA",
    "SetConsoleInputExeNameW",
    "SetConsoleKeyShortcuts",
    "SetConsoleLocalEUDC",
    "SetConsoleMaximumWindowSize",
    "SetConsoleMenuClose",
    "SetConsoleMode",
    "SetConsoleNlsMode",
    "SetConsoleNumberOfCommandsA",
    "SetConsoleNumberOfCommandsW",
    "SetConsoleOS2OemFormat",
    "SetConsoleOutputCP",
    "SetConsolePalette",
    "SetConsoleScreenBufferInfoEx",
    "SetConsoleScreenBufferSize",
    "SetConsoleTextAttribute",
    "SetConsoleTitleA",
    "SetConsoleTitleW",
    "SetConsoleWindowInfo",
    "SetCriticalSectionSpinCount",
    "SetCurrentConsoleFontEx",
    "SetCurrentDirectoryA",
    "SetCurrentDirectoryW",
    "SetDefaultCommConfigA",
    "SetDefaultCommConfigW",
    "SetDefaultDllDirectories",
    "SetDllDirectoryA",
    "SetDllDirectoryW",
    "SetDynamicTimeZoneInformation",
    "SetEndOfFile",
    "SetEnvironmentStringsA",
    "SetEnvironmentStringsW",
    "SetEnvironmentVariableA",
    "SetEnvironmentVariableW",
    "SetErrorMode",
    "SetEvent",
    "SetEventWhenCallbackReturns",
    "SetFileApisToANSI",
    "SetFileApisToOEM",
    "SetFileAttributesA",
    "SetFileAttributesTransactedA",
    "SetFileAttributesTransactedW",
    "SetFileAttributesW",
    "SetFileBandwidthReservation",
    "SetFileCompletionNotificationModes",
    "SetFileInformationByHandle",
    "SetFileIoOverlappedRange",
    "SetFilePointer",
    "SetFilePointerEx",
    "SetFileShortNameA",
    "SetFileShortNameW",
    "SetFileTime",
    "SetFileValidData",
    "SetFirmwareEnvironmentVariableA",
    "SetFirmwareEnvironmentVariableExA",
    "SetFirmwareEnvironmentVariableExW",
    "SetFirmwareEnvironmentVariableW",
    "SetHandleContext",
    "SetHandleCount",
    "SetHandleInformation",
    "SetInformationJobObject",
    "SetIoRateControlInformationJobObject",
    "SetLastConsoleEventActive",
    "SetLastError",
    "SetLocalPrimaryComputerNameA",
    "SetLocalPrimaryComputerNameW",
    "SetLocalTime",
    "SetLocaleInfoA",
    "SetLocaleInfoW",
    "SetMailslotInfo",
    "SetMessageWaitingIndicator",
    "SetNamedPipeAttribute",
    "SetNamedPipeHandleState",
    "SetPriorityClass",
    "SetProcessAffinityMask",
    "SetProcessAffinityUpdateMode",
    "SetProcessDEPPolicy",
    "SetProcessDefaultCpuSets",
    "SetProcessInformation",
    "SetProcessMitigationPolicy",
    "SetProcessPreferredUILanguages",
    "SetProcessPriorityBoost",
    "SetProcessShutdownParameters",
    "SetProcessWorkingSetSize",
    "SetProcessWorkingSetSizeEx",
    "SetProtectedPolicy",
    "SetSearchPathMode",
    "SetStdHandle",
    "SetStdHandleEx",
    "SetSystemFileCacheSize",
    "SetSystemPowerState",
    "SetSystemTime",
    "SetSystemTimeAdjustment",
    "SetTapeParameters",
    "SetTapePosition",
    "SetTermsrvAppInstallMode",
    "SetThreadAffinityMask",
    "SetThreadContext",
    "SetThreadDescription",
    "SetThreadErrorMode",
    "SetThreadExecutionState",
    "SetThreadGroupAffinity",
    "SetThreadIdealProcessor",
    "SetThreadIdealProcessorEx",
    "SetThreadInformation",
    "SetThreadLocale",
    "SetThreadPreferredUILanguages",
    "SetThreadPriority",
    "SetThreadPriorityBoost",
    "SetThreadSelectedCpuSets",
    "SetThreadStackGuarantee",
    "SetThreadToken",
    "SetThreadUILanguage",
    "SetThreadpoolStackInformation",
    "SetThreadpoolThreadMaximum",
    "SetThreadpoolThreadMinimum",
    "SetThreadpoolTimer",
    "SetThreadpoolTimerEx",
    "SetThreadpoolWait",
    "SetThreadpoolWaitEx",
    "SetTimeZoneInformation",
    "SetTimerQueueTimer",
    "SetUnhandledExceptionFilter",
    "SetUserGeoID",
    "SetUserGeoName",
    "SetVDMCurrentDirectories",
    "SetVolumeLabelA",
    "SetVolumeLabelW",
    "SetVolumeMountPointA",
    "SetVolumeMountPointW",
    "SetVolumeMountPointWStub",
    "SetWaitableTimer",
    "SetWaitableTimerEx",
    "SetXStateFeaturesMask",
    "SetupComm",
    "ShowConsoleCursor",
    "SignalObjectAndWait",
    "SizeofResource",
    "Sleep",
    "SleepConditionVariableCS",
    "SleepConditionVariableSRW",
    "SleepEx",
    "SortCloseHandle",
    "SortGetHandle",
    "StartThreadpoolIo",
    "SubmitThreadpoolWork",
    "SuspendThread",
    "SwitchToFiber",
    "SwitchToThread",
    "SystemTimeToFileTime",
    "SystemTimeToTzSpecificLocalTime",
    "SystemTimeToTzSpecificLocalTimeEx",
    "TerminateJobObject",
    "TerminateProcess",
    "TerminateThread",
    "TermsrvAppInstallMode",
    "TermsrvConvertSysRootToUserDir",
    "TermsrvCreateRegEntry",
    "TermsrvDeleteKey",
    "TermsrvDeleteValue",
    "TermsrvGetPreSetValue",
    "TermsrvGetWindowsDirectoryA",
    "TermsrvGetWindowsDirectoryW",
    "TermsrvOpenRegEntry",
    "TermsrvOpenUserClasses",
    "TermsrvRestoreKey",
    "TermsrvSetKeySecurity",
    "TermsrvSetValueKey",
    "TermsrvSyncUserIniFileExt",
    "Thread32First",
    "Thread32Next",
    "TlsAlloc",
    "TlsFree",
    "TlsGetValue",
    "TlsSetValue",
    "Toolhelp32ReadProcessMemory",
    "TransactNamedPipe",
    "TransmitCommChar",
    "TryAcquireSRWLockExclusive",
    "TryAcquireSRWLockShared",
    "TryEnterCriticalSection",
    "TrySubmitThreadpoolCallback",
    "TzSpecificLocalTimeToSystemTime",
    "TzSpecificLocalTimeToSystemTimeEx",
    "UTRegister",
    "UTUnRegister",
    "UnhandledExceptionFilter",
    "UnlockFile",
    "UnlockFileEx",
    "UnmapViewOfFile",
    "UnmapViewOfFileEx",
    "UnregisterApplicationRecoveryCallback",
    "UnregisterApplicationRestart",
    "UnregisterBadMemoryNotification",
    "UnregisterConsoleIME",
    "UnregisterWait",
    "UnregisterWaitEx",
    "UnregisterWaitUntilOOBECompleted",
    "UpdateCalendarDayOfWeek",
    "UpdateProcThreadAttribute",
    "UpdateResourceA",
    "UpdateResourceW",
    "VDMConsoleOperation",
    "VDMOperationStarted",
    "VerLanguageNameA",
    "VerLanguageNameW",
    "VerSetConditionMask",
    "VerifyConsoleIoHandle",
    "VerifyScripts",
    "VerifyVersionInfoA",
    "VerifyVersionInfoW",
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualAllocExNuma",
    "VirtualFree",
    "VirtualFreeEx",
    "VirtualLock",
    "VirtualProtect",
    "VirtualProtectEx",
    "VirtualQuery",
    "VirtualQueryEx",
    "VirtualUnlock",
    "WTSGetActiveConsoleSessionId",
    "WaitCommEvent",
    "WaitForDebugEvent",
    "WaitForDebugEventEx",
    "WaitForMultipleObjects",
    "WaitForMultipleObjectsEx",
    "WaitForSingleObject",
    "WaitForSingleObjectEx",
    "WaitForThreadpoolIoCallbacks",
    "WaitForThreadpoolTimerCallbacks",
    "WaitForThreadpoolWaitCallbacks",
    "WaitForThreadpoolWorkCallbacks",
    "WaitNamedPipeA",
    "WaitNamedPipeW",
    "WakeAllConditionVariable",
    "WakeConditionVariable",
    "WerGetFlags",
    "WerGetFlagsWorker",
    "WerRegisterAdditionalProcess",
    "WerRegisterAppLocalDump",
    "WerRegisterCustomMetadata",
    "WerRegisterExcludedMemoryBlock",
    "WerRegisterFile",
    "WerRegisterFileWorker",
    "WerRegisterMemoryBlock",
    "WerRegisterMemoryBlockWorker",
    "WerRegisterRuntimeExceptionModule",
    "WerRegisterRuntimeExceptionModuleWorker",
    "WerSetFlags",
    "WerSetFlagsWorker",
    "WerUnregisterAdditionalProcess",
    "WerUnregisterAppLocalDump",
    "WerUnregisterCustomMetadata",
    "WerUnregisterExcludedMemoryBlock",
    "WerUnregisterFile",
    "WerUnregisterFileWorker",
    "WerUnregisterMemoryBlock",
    "WerUnregisterMemoryBlockWorker",
    "WerUnregisterRuntimeExceptionModule",
    "WerUnregisterRuntimeExceptionModuleWorker",
    "WerpGetDebugger",
    "WerpInitiateRemoteRecovery",
    "WerpLaunchAeDebug",
    "WerpNotifyLoadStringResourceWorker",
    "WerpNotifyUseStringResourceWorker",
    "WideCharToMultiByte",
    "WinExec",
    "Wow64DisableWow64FsRedirection",
    "Wow64EnableWow64FsRedirection",
    "Wow64GetThreadContext",
    "Wow64GetThreadSelectorEntry",
    "Wow64RevertWow64FsRedirection",
    "Wow64SetThreadContext",
    "Wow64SuspendThread",
    "Wow64Transition",
    "WriteConsoleA",
    "WriteConsoleInputA",
    "WriteConsoleInputVDMA",
    "WriteConsoleInputVDMW",
    "WriteConsoleInputW",
    "WriteConsoleOutputA",
    "WriteConsoleOutputAttribute",
    "WriteConsoleOutputCharacterA",
    "WriteConsoleOutputCharacterW",
    "WriteConsoleOutputW",
    "WriteConsoleW",
    "WriteFile",
    "WriteFileEx",
    "WriteFileGather",
    "WritePrivateProfileSectionA",
    "WritePrivateProfileSectionW",
    "WritePrivateProfileStringA",
    "WritePrivateProfileStringW",
    "WritePrivateProfileStructA",
    "WritePrivateProfileStructW",
    "WriteProcessMemory",
    "WriteProfileSectionA",
    "WriteProfileSectionW",
    "WriteProfileStringA",
    "WriteProfileStringW",
    "WriteTapemark",
    "ZombifyActCtx",
    "ZombifyActCtxWorker",
    "_hread",
    "_hwrite",
    "_lclose",
    "_lcreat",
    "_llseek",
    "_lopen",
    "_lread",
    "_lwrite",
    "lstrcat",
    "lstrcatA",
    "lstrcatW",
    "lstrcmp",
    "lstrcmpA",
    "lstrcmpW",
    "lstrcmpi",
    "lstrcmpiA",
    "lstrcmpiW",
    "lstrcpy",
    "lstrcpyA",
    "lstrcpyW",
    "lstrcpyn",
    "lstrcpynA",
    "lstrcpynW",
    "lstrlen",
    "lstrlenA",
    "lstrlenW",
    "timeBeginPeriod",
    "timeEndPeriod",
    "timeGetDevCaps",
    "timeGetSystemTime",
    "timeGetTime",
};

#ifndef FIX_AcquireSRWLockExclusive
    __declspec(naked) void __stdcall fixAcquireSRWLockExclusive(void) { __asm jmp dword ptr function_ptrs[0 * 4] }
#endif
#ifndef FIX_AcquireSRWLockShared
    __declspec(naked) void __stdcall fixAcquireSRWLockShared(void) { __asm jmp dword ptr function_ptrs[1 * 4] }
#endif
#ifndef FIX_ActivateActCtx
    __declspec(naked) void __stdcall fixActivateActCtx(void) { __asm jmp dword ptr function_ptrs[2 * 4] }
#endif
#ifndef FIX_ActivateActCtxWorker
    __declspec(naked) void __stdcall fixActivateActCtxWorker(void) { __asm jmp dword ptr function_ptrs[3 * 4] }
#endif
#ifndef FIX_AddAtomA
    __declspec(naked) void __stdcall fixAddAtomA(void) { __asm jmp dword ptr function_ptrs[4 * 4] }
#endif
#ifndef FIX_AddAtomW
    __declspec(naked) void __stdcall fixAddAtomW(void) { __asm jmp dword ptr function_ptrs[5 * 4] }
#endif
#ifndef FIX_AddConsoleAliasA
    __declspec(naked) void __stdcall fixAddConsoleAliasA(void) { __asm jmp dword ptr function_ptrs[6 * 4] }
#endif
#ifndef FIX_AddConsoleAliasW
    __declspec(naked) void __stdcall fixAddConsoleAliasW(void) { __asm jmp dword ptr function_ptrs[7 * 4] }
#endif
#ifndef FIX_AddDllDirectory
    __declspec(naked) void __stdcall fixAddDllDirectory(void) { __asm jmp dword ptr function_ptrs[8 * 4] }
#endif
#ifndef FIX_AddIntegrityLabelToBoundaryDescriptor
    __declspec(naked) void __stdcall fixAddIntegrityLabelToBoundaryDescriptor(void) { __asm jmp dword ptr function_ptrs[9 * 4] }
#endif
#ifndef FIX_AddLocalAlternateComputerNameA
    __declspec(naked) void __stdcall fixAddLocalAlternateComputerNameA(void) { __asm jmp dword ptr function_ptrs[10 * 4] }
#endif
#ifndef FIX_AddLocalAlternateComputerNameW
    __declspec(naked) void __stdcall fixAddLocalAlternateComputerNameW(void) { __asm jmp dword ptr function_ptrs[11 * 4] }
#endif
#ifndef FIX_AddRefActCtx
    __declspec(naked) void __stdcall fixAddRefActCtx(void) { __asm jmp dword ptr function_ptrs[12 * 4] }
#endif
#ifndef FIX_AddRefActCtxWorker
    __declspec(naked) void __stdcall fixAddRefActCtxWorker(void) { __asm jmp dword ptr function_ptrs[13 * 4] }
#endif
#ifndef FIX_AddResourceAttributeAce
    __declspec(naked) void __stdcall fixAddResourceAttributeAce(void) { __asm jmp dword ptr function_ptrs[14 * 4] }
#endif
#ifndef FIX_AddSIDToBoundaryDescriptor
    __declspec(naked) void __stdcall fixAddSIDToBoundaryDescriptor(void) { __asm jmp dword ptr function_ptrs[15 * 4] }
#endif
#ifndef FIX_AddScopedPolicyIDAce
    __declspec(naked) void __stdcall fixAddScopedPolicyIDAce(void) { __asm jmp dword ptr function_ptrs[16 * 4] }
#endif
#ifndef FIX_AddSecureMemoryCacheCallback
    __declspec(naked) void __stdcall fixAddSecureMemoryCacheCallback(void) { __asm jmp dword ptr function_ptrs[17 * 4] }
#endif
#ifndef FIX_AddVectoredContinueHandler
    __declspec(naked) void __stdcall fixAddVectoredContinueHandler(void) { __asm jmp dword ptr function_ptrs[18 * 4] }
#endif
#ifndef FIX_AddVectoredExceptionHandler
    __declspec(naked) void __stdcall fixAddVectoredExceptionHandler(void) { __asm jmp dword ptr function_ptrs[19 * 4] }
#endif
#ifndef FIX_AdjustCalendarDate
    __declspec(naked) void __stdcall fixAdjustCalendarDate(void) { __asm jmp dword ptr function_ptrs[20 * 4] }
#endif
#ifndef FIX_AllocConsole
    __declspec(naked) void __stdcall fixAllocConsole(void) { __asm jmp dword ptr function_ptrs[21 * 4] }
#endif
#ifndef FIX_AllocateUserPhysicalPages
    __declspec(naked) void __stdcall fixAllocateUserPhysicalPages(void) { __asm jmp dword ptr function_ptrs[22 * 4] }
#endif
#ifndef FIX_AllocateUserPhysicalPagesNuma
    __declspec(naked) void __stdcall fixAllocateUserPhysicalPagesNuma(void) { __asm jmp dword ptr function_ptrs[23 * 4] }
#endif
#ifndef FIX_AppPolicyGetClrCompat
    __declspec(naked) void __stdcall fixAppPolicyGetClrCompat(void) { __asm jmp dword ptr function_ptrs[24 * 4] }
#endif
#ifndef FIX_AppPolicyGetCreateFileAccess
    __declspec(naked) void __stdcall fixAppPolicyGetCreateFileAccess(void) { __asm jmp dword ptr function_ptrs[25 * 4] }
#endif
#ifndef FIX_AppPolicyGetLifecycleManagement
    __declspec(naked) void __stdcall fixAppPolicyGetLifecycleManagement(void) { __asm jmp dword ptr function_ptrs[26 * 4] }
#endif
#ifndef FIX_AppPolicyGetMediaFoundationCodecLoading
    __declspec(naked) void __stdcall fixAppPolicyGetMediaFoundationCodecLoading(void) { __asm jmp dword ptr function_ptrs[27 * 4] }
#endif
#ifndef FIX_AppPolicyGetProcessTerminationMethod
    __declspec(naked) void __stdcall fixAppPolicyGetProcessTerminationMethod(void) { __asm jmp dword ptr function_ptrs[28 * 4] }
#endif
#ifndef FIX_AppPolicyGetShowDeveloperDiagnostic
    __declspec(naked) void __stdcall fixAppPolicyGetShowDeveloperDiagnostic(void) { __asm jmp dword ptr function_ptrs[29 * 4] }
#endif
#ifndef FIX_AppPolicyGetThreadInitializationType
    __declspec(naked) void __stdcall fixAppPolicyGetThreadInitializationType(void) { __asm jmp dword ptr function_ptrs[30 * 4] }
#endif
#ifndef FIX_AppPolicyGetWindowingModel
    __declspec(naked) void __stdcall fixAppPolicyGetWindowingModel(void) { __asm jmp dword ptr function_ptrs[31 * 4] }
#endif
#ifndef FIX_AppXGetOSMaxVersionTested
    __declspec(naked) void __stdcall fixAppXGetOSMaxVersionTested(void) { __asm jmp dword ptr function_ptrs[32 * 4] }
#endif
#ifndef FIX_ApplicationRecoveryFinished
    __declspec(naked) void __stdcall fixApplicationRecoveryFinished(void) { __asm jmp dword ptr function_ptrs[33 * 4] }
#endif
#ifndef FIX_ApplicationRecoveryInProgress
    __declspec(naked) void __stdcall fixApplicationRecoveryInProgress(void) { __asm jmp dword ptr function_ptrs[34 * 4] }
#endif
#ifndef FIX_AreFileApisANSI
    __declspec(naked) void __stdcall fixAreFileApisANSI(void) { __asm jmp dword ptr function_ptrs[35 * 4] }
#endif
#ifndef FIX_AssignProcessToJobObject
    __declspec(naked) void __stdcall fixAssignProcessToJobObject(void) { __asm jmp dword ptr function_ptrs[36 * 4] }
#endif
#ifndef FIX_AttachConsole
    __declspec(naked) void __stdcall fixAttachConsole(void) { __asm jmp dword ptr function_ptrs[37 * 4] }
#endif
#ifndef FIX_BackupRead
    __declspec(naked) void __stdcall fixBackupRead(void) { __asm jmp dword ptr function_ptrs[38 * 4] }
#endif
#ifndef FIX_BackupSeek
    __declspec(naked) void __stdcall fixBackupSeek(void) { __asm jmp dword ptr function_ptrs[39 * 4] }
#endif
#ifndef FIX_BackupWrite
    __declspec(naked) void __stdcall fixBackupWrite(void) { __asm jmp dword ptr function_ptrs[40 * 4] }
#endif
#ifndef FIX_BaseCheckAppcompatCache
    __declspec(naked) void __stdcall fixBaseCheckAppcompatCache(void) { __asm jmp dword ptr function_ptrs[41 * 4] }
#endif
#ifndef FIX_BaseCheckAppcompatCacheEx
    __declspec(naked) void __stdcall fixBaseCheckAppcompatCacheEx(void) { __asm jmp dword ptr function_ptrs[42 * 4] }
#endif
#ifndef FIX_BaseCheckAppcompatCacheExWorker
    __declspec(naked) void __stdcall fixBaseCheckAppcompatCacheExWorker(void) { __asm jmp dword ptr function_ptrs[43 * 4] }
#endif
#ifndef FIX_BaseCheckAppcompatCacheWorker
    __declspec(naked) void __stdcall fixBaseCheckAppcompatCacheWorker(void) { __asm jmp dword ptr function_ptrs[44 * 4] }
#endif
#ifndef FIX_BaseCheckElevation
    __declspec(naked) void __stdcall fixBaseCheckElevation(void) { __asm jmp dword ptr function_ptrs[45 * 4] }
#endif
#ifndef FIX_BaseCleanupAppcompatCacheSupport
    __declspec(naked) void __stdcall fixBaseCleanupAppcompatCacheSupport(void) { __asm jmp dword ptr function_ptrs[46 * 4] }
#endif
#ifndef FIX_BaseCleanupAppcompatCacheSupportWorker
    __declspec(naked) void __stdcall fixBaseCleanupAppcompatCacheSupportWorker(void) { __asm jmp dword ptr function_ptrs[47 * 4] }
#endif
#ifndef FIX_BaseDestroyVDMEnvironment
    __declspec(naked) void __stdcall fixBaseDestroyVDMEnvironment(void) { __asm jmp dword ptr function_ptrs[48 * 4] }
#endif
#ifndef FIX_BaseDllReadWriteIniFile
    __declspec(naked) void __stdcall fixBaseDllReadWriteIniFile(void) { __asm jmp dword ptr function_ptrs[49 * 4] }
#endif
#ifndef FIX_BaseDumpAppcompatCache
    __declspec(naked) void __stdcall fixBaseDumpAppcompatCache(void) { __asm jmp dword ptr function_ptrs[50 * 4] }
#endif
#ifndef FIX_BaseDumpAppcompatCacheWorker
    __declspec(naked) void __stdcall fixBaseDumpAppcompatCacheWorker(void) { __asm jmp dword ptr function_ptrs[51 * 4] }
#endif
#ifndef FIX_BaseElevationPostProcessing
    __declspec(naked) void __stdcall fixBaseElevationPostProcessing(void) { __asm jmp dword ptr function_ptrs[52 * 4] }
#endif
#ifndef FIX_BaseFlushAppcompatCache
    __declspec(naked) void __stdcall fixBaseFlushAppcompatCache(void) { __asm jmp dword ptr function_ptrs[53 * 4] }
#endif
#ifndef FIX_BaseFlushAppcompatCacheWorker
    __declspec(naked) void __stdcall fixBaseFlushAppcompatCacheWorker(void) { __asm jmp dword ptr function_ptrs[54 * 4] }
#endif
#ifndef FIX_BaseFormatObjectAttributes
    __declspec(naked) void __stdcall fixBaseFormatObjectAttributes(void) { __asm jmp dword ptr function_ptrs[55 * 4] }
#endif
#ifndef FIX_BaseFormatTimeOut
    __declspec(naked) void __stdcall fixBaseFormatTimeOut(void) { __asm jmp dword ptr function_ptrs[56 * 4] }
#endif
#ifndef FIX_BaseFreeAppCompatDataForProcessWorker
    __declspec(naked) void __stdcall fixBaseFreeAppCompatDataForProcessWorker(void) { __asm jmp dword ptr function_ptrs[57 * 4] }
#endif
#ifndef FIX_BaseGenerateAppCompatData
    __declspec(naked) void __stdcall fixBaseGenerateAppCompatData(void) { __asm jmp dword ptr function_ptrs[58 * 4] }
#endif
#ifndef FIX_BaseGetNamedObjectDirectory
    __declspec(naked) void __stdcall fixBaseGetNamedObjectDirectory(void) { __asm jmp dword ptr function_ptrs[59 * 4] }
#endif
#ifndef FIX_BaseInitAppcompatCacheSupport
    __declspec(naked) void __stdcall fixBaseInitAppcompatCacheSupport(void) { __asm jmp dword ptr function_ptrs[60 * 4] }
#endif
#ifndef FIX_BaseInitAppcompatCacheSupportWorker
    __declspec(naked) void __stdcall fixBaseInitAppcompatCacheSupportWorker(void) { __asm jmp dword ptr function_ptrs[61 * 4] }
#endif
#ifndef FIX_BaseIsAppcompatInfrastructureDisabled
    __declspec(naked) void __stdcall fixBaseIsAppcompatInfrastructureDisabled(void) { __asm jmp dword ptr function_ptrs[62 * 4] }
#endif
#ifndef FIX_BaseIsAppcompatInfrastructureDisabledWorker
    __declspec(naked) void __stdcall fixBaseIsAppcompatInfrastructureDisabledWorker(void) { __asm jmp dword ptr function_ptrs[63 * 4] }
#endif
#ifndef FIX_BaseIsDosApplication
    __declspec(naked) void __stdcall fixBaseIsDosApplication(void) { __asm jmp dword ptr function_ptrs[64 * 4] }
#endif
#ifndef FIX_BaseQueryModuleData
    __declspec(naked) void __stdcall fixBaseQueryModuleData(void) { __asm jmp dword ptr function_ptrs[65 * 4] }
#endif
#ifndef FIX_BaseReadAppCompatDataForProcessWorker
    __declspec(naked) void __stdcall fixBaseReadAppCompatDataForProcessWorker(void) { __asm jmp dword ptr function_ptrs[66 * 4] }
#endif
#ifndef FIX_BaseSetLastNTError
    __declspec(naked) void __stdcall fixBaseSetLastNTError(void) { __asm jmp dword ptr function_ptrs[67 * 4] }
#endif
#ifndef FIX_BaseThreadInitThunk
    __declspec(naked) void __stdcall fixBaseThreadInitThunk(void) { __asm jmp dword ptr function_ptrs[68 * 4] }
#endif
#ifndef FIX_BaseUpdateAppcompatCache
    __declspec(naked) void __stdcall fixBaseUpdateAppcompatCache(void) { __asm jmp dword ptr function_ptrs[69 * 4] }
#endif
#ifndef FIX_BaseUpdateAppcompatCacheWorker
    __declspec(naked) void __stdcall fixBaseUpdateAppcompatCacheWorker(void) { __asm jmp dword ptr function_ptrs[70 * 4] }
#endif
#ifndef FIX_BaseUpdateVDMEntry
    __declspec(naked) void __stdcall fixBaseUpdateVDMEntry(void) { __asm jmp dword ptr function_ptrs[71 * 4] }
#endif
#ifndef FIX_BaseVerifyUnicodeString
    __declspec(naked) void __stdcall fixBaseVerifyUnicodeString(void) { __asm jmp dword ptr function_ptrs[72 * 4] }
#endif
#ifndef FIX_BaseWriteErrorElevationRequiredEvent
    __declspec(naked) void __stdcall fixBaseWriteErrorElevationRequiredEvent(void) { __asm jmp dword ptr function_ptrs[73 * 4] }
#endif
#ifndef FIX_Basep8BitStringToDynamicUnicodeString
    __declspec(naked) void __stdcall fixBasep8BitStringToDynamicUnicodeString(void) { __asm jmp dword ptr function_ptrs[74 * 4] }
#endif
#ifndef FIX_BasepAllocateActivationContextActivationBlock
    __declspec(naked) void __stdcall fixBasepAllocateActivationContextActivationBlock(void) { __asm jmp dword ptr function_ptrs[75 * 4] }
#endif
#ifndef FIX_BasepAnsiStringToDynamicUnicodeString
    __declspec(naked) void __stdcall fixBasepAnsiStringToDynamicUnicodeString(void) { __asm jmp dword ptr function_ptrs[76 * 4] }
#endif
#ifndef FIX_BasepAppContainerEnvironmentExtension
    __declspec(naked) void __stdcall fixBasepAppContainerEnvironmentExtension(void) { __asm jmp dword ptr function_ptrs[77 * 4] }
#endif
#ifndef FIX_BasepAppXExtension
    __declspec(naked) void __stdcall fixBasepAppXExtension(void) { __asm jmp dword ptr function_ptrs[78 * 4] }
#endif
#ifndef FIX_BasepCheckAppCompat
    __declspec(naked) void __stdcall fixBasepCheckAppCompat(void) { __asm jmp dword ptr function_ptrs[79 * 4] }
#endif
#ifndef FIX_BasepCheckWebBladeHashes
    __declspec(naked) void __stdcall fixBasepCheckWebBladeHashes(void) { __asm jmp dword ptr function_ptrs[80 * 4] }
#endif
#ifndef FIX_BasepCheckWinSaferRestrictions
    __declspec(naked) void __stdcall fixBasepCheckWinSaferRestrictions(void) { __asm jmp dword ptr function_ptrs[81 * 4] }
#endif
#ifndef FIX_BasepConstructSxsCreateProcessMessage
    __declspec(naked) void __stdcall fixBasepConstructSxsCreateProcessMessage(void) { __asm jmp dword ptr function_ptrs[82 * 4] }
#endif
#ifndef FIX_BasepCopyEncryption
    __declspec(naked) void __stdcall fixBasepCopyEncryption(void) { __asm jmp dword ptr function_ptrs[83 * 4] }
#endif
#ifndef FIX_BasepFreeActivationContextActivationBlock
    __declspec(naked) void __stdcall fixBasepFreeActivationContextActivationBlock(void) { __asm jmp dword ptr function_ptrs[84 * 4] }
#endif
#ifndef FIX_BasepFreeAppCompatData
    __declspec(naked) void __stdcall fixBasepFreeAppCompatData(void) { __asm jmp dword ptr function_ptrs[85 * 4] }
#endif
#ifndef FIX_BasepGetAppCompatData
    __declspec(naked) void __stdcall fixBasepGetAppCompatData(void) { __asm jmp dword ptr function_ptrs[86 * 4] }
#endif
#ifndef FIX_BasepGetComputerNameFromNtPath
    __declspec(naked) void __stdcall fixBasepGetComputerNameFromNtPath(void) { __asm jmp dword ptr function_ptrs[87 * 4] }
#endif
#ifndef FIX_BasepGetExeArchType
    __declspec(naked) void __stdcall fixBasepGetExeArchType(void) { __asm jmp dword ptr function_ptrs[88 * 4] }
#endif
#ifndef FIX_BasepInitAppCompatData
    __declspec(naked) void __stdcall fixBasepInitAppCompatData(void) { __asm jmp dword ptr function_ptrs[89 * 4] }
#endif
#ifndef FIX_BasepIsProcessAllowed
    __declspec(naked) void __stdcall fixBasepIsProcessAllowed(void) { __asm jmp dword ptr function_ptrs[90 * 4] }
#endif
#ifndef FIX_BasepMapModuleHandle
    __declspec(naked) void __stdcall fixBasepMapModuleHandle(void) { __asm jmp dword ptr function_ptrs[91 * 4] }
#endif
#ifndef FIX_BasepNotifyLoadStringResource
    __declspec(naked) void __stdcall fixBasepNotifyLoadStringResource(void) { __asm jmp dword ptr function_ptrs[92 * 4] }
#endif
#ifndef FIX_BasepPostSuccessAppXExtension
    __declspec(naked) void __stdcall fixBasepPostSuccessAppXExtension(void) { __asm jmp dword ptr function_ptrs[93 * 4] }
#endif
#ifndef FIX_BasepProcessInvalidImage
    __declspec(naked) void __stdcall fixBasepProcessInvalidImage(void) { __asm jmp dword ptr function_ptrs[94 * 4] }
#endif
#ifndef FIX_BasepQueryAppCompat
    __declspec(naked) void __stdcall fixBasepQueryAppCompat(void) { __asm jmp dword ptr function_ptrs[95 * 4] }
#endif
#ifndef FIX_BasepQueryModuleChpeSettings
    __declspec(naked) void __stdcall fixBasepQueryModuleChpeSettings(void) { __asm jmp dword ptr function_ptrs[96 * 4] }
#endif
#ifndef FIX_BasepReleaseAppXContext
    __declspec(naked) void __stdcall fixBasepReleaseAppXContext(void) { __asm jmp dword ptr function_ptrs[97 * 4] }
#endif
#ifndef FIX_BasepReleaseSxsCreateProcessUtilityStruct
    __declspec(naked) void __stdcall fixBasepReleaseSxsCreateProcessUtilityStruct(void) { __asm jmp dword ptr function_ptrs[98 * 4] }
#endif
#ifndef FIX_BasepReportFault
    __declspec(naked) void __stdcall fixBasepReportFault(void) { __asm jmp dword ptr function_ptrs[99 * 4] }
#endif
#ifndef FIX_BasepSetFileEncryptionCompression
    __declspec(naked) void __stdcall fixBasepSetFileEncryptionCompression(void) { __asm jmp dword ptr function_ptrs[100 * 4] }
#endif
#ifndef FIX_Beep
    __declspec(naked) void __stdcall fixBeep(void) { __asm jmp dword ptr function_ptrs[101 * 4] }
#endif
#ifndef FIX_BeginUpdateResourceA
    __declspec(naked) void __stdcall fixBeginUpdateResourceA(void) { __asm jmp dword ptr function_ptrs[102 * 4] }
#endif
#ifndef FIX_BeginUpdateResourceW
    __declspec(naked) void __stdcall fixBeginUpdateResourceW(void) { __asm jmp dword ptr function_ptrs[103 * 4] }
#endif
#ifndef FIX_BindIoCompletionCallback
    __declspec(naked) void __stdcall fixBindIoCompletionCallback(void) { __asm jmp dword ptr function_ptrs[104 * 4] }
#endif
#ifndef FIX_BuildCommDCBA
    __declspec(naked) void __stdcall fixBuildCommDCBA(void) { __asm jmp dword ptr function_ptrs[105 * 4] }
#endif
#ifndef FIX_BuildCommDCBAndTimeoutsA
    __declspec(naked) void __stdcall fixBuildCommDCBAndTimeoutsA(void) { __asm jmp dword ptr function_ptrs[106 * 4] }
#endif
#ifndef FIX_BuildCommDCBAndTimeoutsW
    __declspec(naked) void __stdcall fixBuildCommDCBAndTimeoutsW(void) { __asm jmp dword ptr function_ptrs[107 * 4] }
#endif
#ifndef FIX_BuildCommDCBW
    __declspec(naked) void __stdcall fixBuildCommDCBW(void) { __asm jmp dword ptr function_ptrs[108 * 4] }
#endif
#ifndef FIX_CallNamedPipeA
    __declspec(naked) void __stdcall fixCallNamedPipeA(void) { __asm jmp dword ptr function_ptrs[109 * 4] }
#endif
#ifndef FIX_CallNamedPipeW
    __declspec(naked) void __stdcall fixCallNamedPipeW(void) { __asm jmp dword ptr function_ptrs[110 * 4] }
#endif
#ifndef FIX_CallbackMayRunLong
    __declspec(naked) void __stdcall fixCallbackMayRunLong(void) { __asm jmp dword ptr function_ptrs[111 * 4] }
#endif
#ifndef FIX_CancelDeviceWakeupRequest
    __declspec(naked) void __stdcall fixCancelDeviceWakeupRequest(void) { __asm jmp dword ptr function_ptrs[112 * 4] }
#endif
#ifndef FIX_CancelIo
    __declspec(naked) void __stdcall fixCancelIo(void) { __asm jmp dword ptr function_ptrs[113 * 4] }
#endif
#ifndef FIX_CancelIoEx
    __declspec(naked) void __stdcall fixCancelIoEx(void) { __asm jmp dword ptr function_ptrs[114 * 4] }
#endif
#ifndef FIX_CancelSynchronousIo
    __declspec(naked) void __stdcall fixCancelSynchronousIo(void) { __asm jmp dword ptr function_ptrs[115 * 4] }
#endif
#ifndef FIX_CancelThreadpoolIo
    __declspec(naked) void __stdcall fixCancelThreadpoolIo(void) { __asm jmp dword ptr function_ptrs[116 * 4] }
#endif
#ifndef FIX_CancelTimerQueueTimer
    __declspec(naked) void __stdcall fixCancelTimerQueueTimer(void) { __asm jmp dword ptr function_ptrs[117 * 4] }
#endif
#ifndef FIX_CancelWaitableTimer
    __declspec(naked) void __stdcall fixCancelWaitableTimer(void) { __asm jmp dword ptr function_ptrs[118 * 4] }
#endif
#ifndef FIX_CeipIsOptedIn
    __declspec(naked) void __stdcall fixCeipIsOptedIn(void) { __asm jmp dword ptr function_ptrs[119 * 4] }
#endif
#ifndef FIX_ChangeTimerQueueTimer
    __declspec(naked) void __stdcall fixChangeTimerQueueTimer(void) { __asm jmp dword ptr function_ptrs[120 * 4] }
#endif
#ifndef FIX_CheckAllowDecryptedRemoteDestinationPolicy
    __declspec(naked) void __stdcall fixCheckAllowDecryptedRemoteDestinationPolicy(void) { __asm jmp dword ptr function_ptrs[121 * 4] }
#endif
#ifndef FIX_CheckElevation
    __declspec(naked) void __stdcall fixCheckElevation(void) { __asm jmp dword ptr function_ptrs[122 * 4] }
#endif
#ifndef FIX_CheckElevationEnabled
    __declspec(naked) void __stdcall fixCheckElevationEnabled(void) { __asm jmp dword ptr function_ptrs[123 * 4] }
#endif
#ifndef FIX_CheckForReadOnlyResource
    __declspec(naked) void __stdcall fixCheckForReadOnlyResource(void) { __asm jmp dword ptr function_ptrs[124 * 4] }
#endif
#ifndef FIX_CheckForReadOnlyResourceFilter
    __declspec(naked) void __stdcall fixCheckForReadOnlyResourceFilter(void) { __asm jmp dword ptr function_ptrs[125 * 4] }
#endif
#ifndef FIX_CheckNameLegalDOS8Dot3A
    __declspec(naked) void __stdcall fixCheckNameLegalDOS8Dot3A(void) { __asm jmp dword ptr function_ptrs[126 * 4] }
#endif
#ifndef FIX_CheckNameLegalDOS8Dot3W
    __declspec(naked) void __stdcall fixCheckNameLegalDOS8Dot3W(void) { __asm jmp dword ptr function_ptrs[127 * 4] }
#endif
#ifndef FIX_CheckRemoteDebuggerPresent
    __declspec(naked) void __stdcall fixCheckRemoteDebuggerPresent(void) { __asm jmp dword ptr function_ptrs[128 * 4] }
#endif
#ifndef FIX_CheckTokenCapability
    __declspec(naked) void __stdcall fixCheckTokenCapability(void) { __asm jmp dword ptr function_ptrs[129 * 4] }
#endif
#ifndef FIX_CheckTokenMembershipEx
    __declspec(naked) void __stdcall fixCheckTokenMembershipEx(void) { __asm jmp dword ptr function_ptrs[130 * 4] }
#endif
#ifndef FIX_ClearCommBreak
    __declspec(naked) void __stdcall fixClearCommBreak(void) { __asm jmp dword ptr function_ptrs[131 * 4] }
#endif
#ifndef FIX_ClearCommError
    __declspec(naked) void __stdcall fixClearCommError(void) { __asm jmp dword ptr function_ptrs[132 * 4] }
#endif
#ifndef FIX_CloseConsoleHandle
    __declspec(naked) void __stdcall fixCloseConsoleHandle(void) { __asm jmp dword ptr function_ptrs[133 * 4] }
#endif
#ifndef FIX_CloseHandle
    __declspec(naked) void __stdcall fixCloseHandle(void) { __asm jmp dword ptr function_ptrs[134 * 4] }
#endif
#ifndef FIX_ClosePackageInfo
    __declspec(naked) void __stdcall fixClosePackageInfo(void) { __asm jmp dword ptr function_ptrs[135 * 4] }
#endif
#ifndef FIX_ClosePrivateNamespace
    __declspec(naked) void __stdcall fixClosePrivateNamespace(void) { __asm jmp dword ptr function_ptrs[136 * 4] }
#endif
#ifndef FIX_CloseProfileUserMapping
    __declspec(naked) void __stdcall fixCloseProfileUserMapping(void) { __asm jmp dword ptr function_ptrs[137 * 4] }
#endif
#ifndef FIX_ClosePseudoConsole
    __declspec(naked) void __stdcall fixClosePseudoConsole(void) { __asm jmp dword ptr function_ptrs[138 * 4] }
#endif
#ifndef FIX_CloseState
    __declspec(naked) void __stdcall fixCloseState(void) { __asm jmp dword ptr function_ptrs[139 * 4] }
#endif
#ifndef FIX_CloseThreadpool
    __declspec(naked) void __stdcall fixCloseThreadpool(void) { __asm jmp dword ptr function_ptrs[140 * 4] }
#endif
#ifndef FIX_CloseThreadpoolCleanupGroup
    __declspec(naked) void __stdcall fixCloseThreadpoolCleanupGroup(void) { __asm jmp dword ptr function_ptrs[141 * 4] }
#endif
#ifndef FIX_CloseThreadpoolCleanupGroupMembers
    __declspec(naked) void __stdcall fixCloseThreadpoolCleanupGroupMembers(void) { __asm jmp dword ptr function_ptrs[142 * 4] }
#endif
#ifndef FIX_CloseThreadpoolIo
    __declspec(naked) void __stdcall fixCloseThreadpoolIo(void) { __asm jmp dword ptr function_ptrs[143 * 4] }
#endif
#ifndef FIX_CloseThreadpoolTimer
    __declspec(naked) void __stdcall fixCloseThreadpoolTimer(void) { __asm jmp dword ptr function_ptrs[144 * 4] }
#endif
#ifndef FIX_CloseThreadpoolWait
    __declspec(naked) void __stdcall fixCloseThreadpoolWait(void) { __asm jmp dword ptr function_ptrs[145 * 4] }
#endif
#ifndef FIX_CloseThreadpoolWork
    __declspec(naked) void __stdcall fixCloseThreadpoolWork(void) { __asm jmp dword ptr function_ptrs[146 * 4] }
#endif
#ifndef FIX_CmdBatNotification
    __declspec(naked) void __stdcall fixCmdBatNotification(void) { __asm jmp dword ptr function_ptrs[147 * 4] }
#endif
#ifndef FIX_CommConfigDialogA
    __declspec(naked) void __stdcall fixCommConfigDialogA(void) { __asm jmp dword ptr function_ptrs[148 * 4] }
#endif
#ifndef FIX_CommConfigDialogW
    __declspec(naked) void __stdcall fixCommConfigDialogW(void) { __asm jmp dword ptr function_ptrs[149 * 4] }
#endif
#ifndef FIX_CompareCalendarDates
    __declspec(naked) void __stdcall fixCompareCalendarDates(void) { __asm jmp dword ptr function_ptrs[150 * 4] }
#endif
#ifndef FIX_CompareFileTime
    __declspec(naked) void __stdcall fixCompareFileTime(void) { __asm jmp dword ptr function_ptrs[151 * 4] }
#endif
#ifndef FIX_CompareStringA
    __declspec(naked) void __stdcall fixCompareStringA(void) { __asm jmp dword ptr function_ptrs[152 * 4] }
#endif
#ifndef FIX_CompareStringEx
    __declspec(naked) void __stdcall fixCompareStringEx(void) { __asm jmp dword ptr function_ptrs[153 * 4] }
#endif
#ifndef FIX_CompareStringOrdinal
    __declspec(naked) void __stdcall fixCompareStringOrdinal(void) { __asm jmp dword ptr function_ptrs[154 * 4] }
#endif
#ifndef FIX_CompareStringW
    __declspec(naked) void __stdcall fixCompareStringW(void) { __asm jmp dword ptr function_ptrs[155 * 4] }
#endif
#ifndef FIX_ConnectNamedPipe
    __declspec(naked) void __stdcall fixConnectNamedPipe(void) { __asm jmp dword ptr function_ptrs[156 * 4] }
#endif
#ifndef FIX_ConsoleMenuControl
    __declspec(naked) void __stdcall fixConsoleMenuControl(void) { __asm jmp dword ptr function_ptrs[157 * 4] }
#endif
#ifndef FIX_ContinueDebugEvent
    __declspec(naked) void __stdcall fixContinueDebugEvent(void) { __asm jmp dword ptr function_ptrs[158 * 4] }
#endif
#ifndef FIX_ConvertCalDateTimeToSystemTime
    __declspec(naked) void __stdcall fixConvertCalDateTimeToSystemTime(void) { __asm jmp dword ptr function_ptrs[159 * 4] }
#endif
#ifndef FIX_ConvertDefaultLocale
    __declspec(naked) void __stdcall fixConvertDefaultLocale(void) { __asm jmp dword ptr function_ptrs[160 * 4] }
#endif
#ifndef FIX_ConvertFiberToThread
    __declspec(naked) void __stdcall fixConvertFiberToThread(void) { __asm jmp dword ptr function_ptrs[161 * 4] }
#endif
#ifndef FIX_ConvertNLSDayOfWeekToWin32DayOfWeek
    __declspec(naked) void __stdcall fixConvertNLSDayOfWeekToWin32DayOfWeek(void) { __asm jmp dword ptr function_ptrs[162 * 4] }
#endif
#ifndef FIX_ConvertSystemTimeToCalDateTime
    __declspec(naked) void __stdcall fixConvertSystemTimeToCalDateTime(void) { __asm jmp dword ptr function_ptrs[163 * 4] }
#endif
#ifndef FIX_ConvertThreadToFiber
    __declspec(naked) void __stdcall fixConvertThreadToFiber(void) { __asm jmp dword ptr function_ptrs[164 * 4] }
#endif
#ifndef FIX_ConvertThreadToFiberEx
    __declspec(naked) void __stdcall fixConvertThreadToFiberEx(void) { __asm jmp dword ptr function_ptrs[165 * 4] }
#endif
#ifndef FIX_CopyContext
    __declspec(naked) void __stdcall fixCopyContext(void) { __asm jmp dword ptr function_ptrs[166 * 4] }
#endif
#ifndef FIX_CopyFile2
    __declspec(naked) void __stdcall fixCopyFile2(void) { __asm jmp dword ptr function_ptrs[167 * 4] }
#endif
#ifndef FIX_CopyFileA
    __declspec(naked) void __stdcall fixCopyFileA(void) { __asm jmp dword ptr function_ptrs[168 * 4] }
#endif
#ifndef FIX_CopyFileExA
    __declspec(naked) void __stdcall fixCopyFileExA(void) { __asm jmp dword ptr function_ptrs[169 * 4] }
#endif
#ifndef FIX_CopyFileExW
    __declspec(naked) void __stdcall fixCopyFileExW(void) { __asm jmp dword ptr function_ptrs[170 * 4] }
#endif
#ifndef FIX_CopyFileTransactedA
    __declspec(naked) void __stdcall fixCopyFileTransactedA(void) { __asm jmp dword ptr function_ptrs[171 * 4] }
#endif
#ifndef FIX_CopyFileTransactedW
    __declspec(naked) void __stdcall fixCopyFileTransactedW(void) { __asm jmp dword ptr function_ptrs[172 * 4] }
#endif
#ifndef FIX_CopyFileW
    __declspec(naked) void __stdcall fixCopyFileW(void) { __asm jmp dword ptr function_ptrs[173 * 4] }
#endif
#ifndef FIX_CopyLZFile
    __declspec(naked) void __stdcall fixCopyLZFile(void) { __asm jmp dword ptr function_ptrs[174 * 4] }
#endif
#ifndef FIX_CreateActCtxA
    __declspec(naked) void __stdcall fixCreateActCtxA(void) { __asm jmp dword ptr function_ptrs[175 * 4] }
#endif
#ifndef FIX_CreateActCtxW
    __declspec(naked) void __stdcall fixCreateActCtxW(void) { __asm jmp dword ptr function_ptrs[176 * 4] }
#endif
#ifndef FIX_CreateActCtxWWorker
    __declspec(naked) void __stdcall fixCreateActCtxWWorker(void) { __asm jmp dword ptr function_ptrs[177 * 4] }
#endif
#ifndef FIX_CreateBoundaryDescriptorA
    __declspec(naked) void __stdcall fixCreateBoundaryDescriptorA(void) { __asm jmp dword ptr function_ptrs[178 * 4] }
#endif
#ifndef FIX_CreateBoundaryDescriptorW
    __declspec(naked) void __stdcall fixCreateBoundaryDescriptorW(void) { __asm jmp dword ptr function_ptrs[179 * 4] }
#endif
#ifndef FIX_CreateConsoleScreenBuffer
    __declspec(naked) void __stdcall fixCreateConsoleScreenBuffer(void) { __asm jmp dword ptr function_ptrs[180 * 4] }
#endif
#ifndef FIX_CreateDirectoryA
    __declspec(naked) void __stdcall fixCreateDirectoryA(void) { __asm jmp dword ptr function_ptrs[181 * 4] }
#endif
#ifndef FIX_CreateDirectoryExA
    __declspec(naked) void __stdcall fixCreateDirectoryExA(void) { __asm jmp dword ptr function_ptrs[182 * 4] }
#endif
#ifndef FIX_CreateDirectoryExW
    __declspec(naked) void __stdcall fixCreateDirectoryExW(void) { __asm jmp dword ptr function_ptrs[183 * 4] }
#endif
#ifndef FIX_CreateDirectoryTransactedA
    __declspec(naked) void __stdcall fixCreateDirectoryTransactedA(void) { __asm jmp dword ptr function_ptrs[184 * 4] }
#endif
#ifndef FIX_CreateDirectoryTransactedW
    __declspec(naked) void __stdcall fixCreateDirectoryTransactedW(void) { __asm jmp dword ptr function_ptrs[185 * 4] }
#endif
#ifndef FIX_CreateDirectoryW
    __declspec(naked) void __stdcall fixCreateDirectoryW(void) { __asm jmp dword ptr function_ptrs[186 * 4] }
#endif
#ifndef FIX_CreateEnclave
    __declspec(naked) void __stdcall fixCreateEnclave(void) { __asm jmp dword ptr function_ptrs[187 * 4] }
#endif
#ifndef FIX_CreateEventA
    __declspec(naked) void __stdcall fixCreateEventA(void) { __asm jmp dword ptr function_ptrs[188 * 4] }
#endif
#ifndef FIX_CreateEventExA
    __declspec(naked) void __stdcall fixCreateEventExA(void) { __asm jmp dword ptr function_ptrs[189 * 4] }
#endif
#ifndef FIX_CreateEventExW
    __declspec(naked) void __stdcall fixCreateEventExW(void) { __asm jmp dword ptr function_ptrs[190 * 4] }
#endif
#ifndef FIX_CreateEventW
    __declspec(naked) void __stdcall fixCreateEventW(void) { __asm jmp dword ptr function_ptrs[191 * 4] }
#endif
#ifndef FIX_CreateFiber
    __declspec(naked) void __stdcall fixCreateFiber(void) { __asm jmp dword ptr function_ptrs[192 * 4] }
#endif
#ifndef FIX_CreateFiberEx
    __declspec(naked) void __stdcall fixCreateFiberEx(void) { __asm jmp dword ptr function_ptrs[193 * 4] }
#endif
#ifndef FIX_CreateFile2
    __declspec(naked) void __stdcall fixCreateFile2(void) { __asm jmp dword ptr function_ptrs[194 * 4] }
#endif
#ifndef FIX_CreateFileA
    __declspec(naked) void __stdcall fixCreateFileA(void) { __asm jmp dword ptr function_ptrs[195 * 4] }
#endif
#ifndef FIX_CreateFileMappingA
    __declspec(naked) void __stdcall fixCreateFileMappingA(void) { __asm jmp dword ptr function_ptrs[196 * 4] }
#endif
#ifndef FIX_CreateFileMappingFromApp
    __declspec(naked) void __stdcall fixCreateFileMappingFromApp(void) { __asm jmp dword ptr function_ptrs[197 * 4] }
#endif
#ifndef FIX_CreateFileMappingNumaA
    __declspec(naked) void __stdcall fixCreateFileMappingNumaA(void) { __asm jmp dword ptr function_ptrs[198 * 4] }
#endif
#ifndef FIX_CreateFileMappingNumaW
    __declspec(naked) void __stdcall fixCreateFileMappingNumaW(void) { __asm jmp dword ptr function_ptrs[199 * 4] }
#endif
#ifndef FIX_CreateFileMappingW
    __declspec(naked) void __stdcall fixCreateFileMappingW(void) { __asm jmp dword ptr function_ptrs[200 * 4] }
#endif
#ifndef FIX_CreateFileTransactedA
    __declspec(naked) void __stdcall fixCreateFileTransactedA(void) { __asm jmp dword ptr function_ptrs[201 * 4] }
#endif
#ifndef FIX_CreateFileTransactedW
    __declspec(naked) void __stdcall fixCreateFileTransactedW(void) { __asm jmp dword ptr function_ptrs[202 * 4] }
#endif
#ifndef FIX_CreateFileW
    __declspec(naked) void __stdcall fixCreateFileW(void) { __asm jmp dword ptr function_ptrs[203 * 4] }
#endif
#ifndef FIX_CreateHardLinkA
    __declspec(naked) void __stdcall fixCreateHardLinkA(void) { __asm jmp dword ptr function_ptrs[204 * 4] }
#endif
#ifndef FIX_CreateHardLinkTransactedA
    __declspec(naked) void __stdcall fixCreateHardLinkTransactedA(void) { __asm jmp dword ptr function_ptrs[205 * 4] }
#endif
#ifndef FIX_CreateHardLinkTransactedW
    __declspec(naked) void __stdcall fixCreateHardLinkTransactedW(void) { __asm jmp dword ptr function_ptrs[206 * 4] }
#endif
#ifndef FIX_CreateHardLinkW
    __declspec(naked) void __stdcall fixCreateHardLinkW(void) { __asm jmp dword ptr function_ptrs[207 * 4] }
#endif
#ifndef FIX_CreateIoCompletionPort
    __declspec(naked) void __stdcall fixCreateIoCompletionPort(void) { __asm jmp dword ptr function_ptrs[208 * 4] }
#endif
#ifndef FIX_CreateJobObjectA
    __declspec(naked) void __stdcall fixCreateJobObjectA(void) { __asm jmp dword ptr function_ptrs[209 * 4] }
#endif
#ifndef FIX_CreateJobObjectW
    __declspec(naked) void __stdcall fixCreateJobObjectW(void) { __asm jmp dword ptr function_ptrs[210 * 4] }
#endif
#ifndef FIX_CreateJobSet
    __declspec(naked) void __stdcall fixCreateJobSet(void) { __asm jmp dword ptr function_ptrs[211 * 4] }
#endif
#ifndef FIX_CreateMailslotA
    __declspec(naked) void __stdcall fixCreateMailslotA(void) { __asm jmp dword ptr function_ptrs[212 * 4] }
#endif
#ifndef FIX_CreateMailslotW
    __declspec(naked) void __stdcall fixCreateMailslotW(void) { __asm jmp dword ptr function_ptrs[213 * 4] }
#endif
#ifndef FIX_CreateMemoryResourceNotification
    __declspec(naked) void __stdcall fixCreateMemoryResourceNotification(void) { __asm jmp dword ptr function_ptrs[214 * 4] }
#endif
#ifndef FIX_CreateMutexA
    __declspec(naked) void __stdcall fixCreateMutexA(void) { __asm jmp dword ptr function_ptrs[215 * 4] }
#endif
#ifndef FIX_CreateMutexExA
    __declspec(naked) void __stdcall fixCreateMutexExA(void) { __asm jmp dword ptr function_ptrs[216 * 4] }
#endif
#ifndef FIX_CreateMutexExW
    __declspec(naked) void __stdcall fixCreateMutexExW(void) { __asm jmp dword ptr function_ptrs[217 * 4] }
#endif
#ifndef FIX_CreateMutexW
    __declspec(naked) void __stdcall fixCreateMutexW(void) { __asm jmp dword ptr function_ptrs[218 * 4] }
#endif
#ifndef FIX_CreateNamedPipeA
    __declspec(naked) void __stdcall fixCreateNamedPipeA(void) { __asm jmp dword ptr function_ptrs[219 * 4] }
#endif
#ifndef FIX_CreateNamedPipeW
    __declspec(naked) void __stdcall fixCreateNamedPipeW(void) { __asm jmp dword ptr function_ptrs[220 * 4] }
#endif
#ifndef FIX_CreatePipe
    __declspec(naked) void __stdcall fixCreatePipe(void) { __asm jmp dword ptr function_ptrs[221 * 4] }
#endif
#ifndef FIX_CreatePrivateNamespaceA
    __declspec(naked) void __stdcall fixCreatePrivateNamespaceA(void) { __asm jmp dword ptr function_ptrs[222 * 4] }
#endif
#ifndef FIX_CreatePrivateNamespaceW
    __declspec(naked) void __stdcall fixCreatePrivateNamespaceW(void) { __asm jmp dword ptr function_ptrs[223 * 4] }
#endif
#ifndef FIX_CreateProcessA
    __declspec(naked) void __stdcall fixCreateProcessA(void) { __asm jmp dword ptr function_ptrs[224 * 4] }
#endif
#ifndef FIX_CreateProcessAsUserA
    __declspec(naked) void __stdcall fixCreateProcessAsUserA(void) { __asm jmp dword ptr function_ptrs[225 * 4] }
#endif
#ifndef FIX_CreateProcessAsUserW
    __declspec(naked) void __stdcall fixCreateProcessAsUserW(void) { __asm jmp dword ptr function_ptrs[226 * 4] }
#endif
#ifndef FIX_CreateProcessInternalA
    __declspec(naked) void __stdcall fixCreateProcessInternalA(void) { __asm jmp dword ptr function_ptrs[227 * 4] }
#endif
#ifndef FIX_CreateProcessInternalW
    __declspec(naked) void __stdcall fixCreateProcessInternalW(void) { __asm jmp dword ptr function_ptrs[228 * 4] }
#endif
#ifndef FIX_CreateProcessW
    __declspec(naked) void __stdcall fixCreateProcessW(void) { __asm jmp dword ptr function_ptrs[229 * 4] }
#endif
#ifndef FIX_CreatePseudoConsole
    __declspec(naked) void __stdcall fixCreatePseudoConsole(void) { __asm jmp dword ptr function_ptrs[230 * 4] }
#endif
#ifndef FIX_CreateRemoteThread
    __declspec(naked) void __stdcall fixCreateRemoteThread(void) { __asm jmp dword ptr function_ptrs[231 * 4] }
#endif
#ifndef FIX_CreateRemoteThreadEx
    __declspec(naked) void __stdcall fixCreateRemoteThreadEx(void) { __asm jmp dword ptr function_ptrs[232 * 4] }
#endif
#ifndef FIX_CreateSemaphoreA
    __declspec(naked) void __stdcall fixCreateSemaphoreA(void) { __asm jmp dword ptr function_ptrs[233 * 4] }
#endif
#ifndef FIX_CreateSemaphoreExA
    __declspec(naked) void __stdcall fixCreateSemaphoreExA(void) { __asm jmp dword ptr function_ptrs[234 * 4] }
#endif
#ifndef FIX_CreateSemaphoreExW
    __declspec(naked) void __stdcall fixCreateSemaphoreExW(void) { __asm jmp dword ptr function_ptrs[235 * 4] }
#endif
#ifndef FIX_CreateSemaphoreW
    __declspec(naked) void __stdcall fixCreateSemaphoreW(void) { __asm jmp dword ptr function_ptrs[236 * 4] }
#endif
#ifndef FIX_CreateSocketHandle
    __declspec(naked) void __stdcall fixCreateSocketHandle(void) { __asm jmp dword ptr function_ptrs[237 * 4] }
#endif
#ifndef FIX_CreateSymbolicLinkA
    __declspec(naked) void __stdcall fixCreateSymbolicLinkA(void) { __asm jmp dword ptr function_ptrs[238 * 4] }
#endif
#ifndef FIX_CreateSymbolicLinkTransactedA
    __declspec(naked) void __stdcall fixCreateSymbolicLinkTransactedA(void) { __asm jmp dword ptr function_ptrs[239 * 4] }
#endif
#ifndef FIX_CreateSymbolicLinkTransactedW
    __declspec(naked) void __stdcall fixCreateSymbolicLinkTransactedW(void) { __asm jmp dword ptr function_ptrs[240 * 4] }
#endif
#ifndef FIX_CreateSymbolicLinkW
    __declspec(naked) void __stdcall fixCreateSymbolicLinkW(void) { __asm jmp dword ptr function_ptrs[241 * 4] }
#endif
#ifndef FIX_CreateTapePartition
    __declspec(naked) void __stdcall fixCreateTapePartition(void) { __asm jmp dword ptr function_ptrs[242 * 4] }
#endif
#ifndef FIX_CreateThread
    __declspec(naked) void __stdcall fixCreateThread(void) { __asm jmp dword ptr function_ptrs[243 * 4] }
#endif
#ifndef FIX_CreateThreadpool
    __declspec(naked) void __stdcall fixCreateThreadpool(void) { __asm jmp dword ptr function_ptrs[244 * 4] }
#endif
#ifndef FIX_CreateThreadpoolCleanupGroup
    __declspec(naked) void __stdcall fixCreateThreadpoolCleanupGroup(void) { __asm jmp dword ptr function_ptrs[245 * 4] }
#endif
#ifndef FIX_CreateThreadpoolIo
    __declspec(naked) void __stdcall fixCreateThreadpoolIo(void) { __asm jmp dword ptr function_ptrs[246 * 4] }
#endif
#ifndef FIX_CreateThreadpoolTimer
    __declspec(naked) void __stdcall fixCreateThreadpoolTimer(void) { __asm jmp dword ptr function_ptrs[247 * 4] }
#endif
#ifndef FIX_CreateThreadpoolWait
    __declspec(naked) void __stdcall fixCreateThreadpoolWait(void) { __asm jmp dword ptr function_ptrs[248 * 4] }
#endif
#ifndef FIX_CreateThreadpoolWork
    __declspec(naked) void __stdcall fixCreateThreadpoolWork(void) { __asm jmp dword ptr function_ptrs[249 * 4] }
#endif
#ifndef FIX_CreateTimerQueue
    __declspec(naked) void __stdcall fixCreateTimerQueue(void) { __asm jmp dword ptr function_ptrs[250 * 4] }
#endif
#ifndef FIX_CreateTimerQueueTimer
    __declspec(naked) void __stdcall fixCreateTimerQueueTimer(void) { __asm jmp dword ptr function_ptrs[251 * 4] }
#endif
#ifndef FIX_CreateToolhelp32Snapshot
    __declspec(naked) void __stdcall fixCreateToolhelp32Snapshot(void) { __asm jmp dword ptr function_ptrs[252 * 4] }
#endif
#ifndef FIX_CreateWaitableTimerA
    __declspec(naked) void __stdcall fixCreateWaitableTimerA(void) { __asm jmp dword ptr function_ptrs[253 * 4] }
#endif
#ifndef FIX_CreateWaitableTimerExA
    __declspec(naked) void __stdcall fixCreateWaitableTimerExA(void) { __asm jmp dword ptr function_ptrs[254 * 4] }
#endif
#ifndef FIX_CreateWaitableTimerExW
    __declspec(naked) void __stdcall fixCreateWaitableTimerExW(void) { __asm jmp dword ptr function_ptrs[255 * 4] }
#endif
#ifndef FIX_CreateWaitableTimerW
    __declspec(naked) void __stdcall fixCreateWaitableTimerW(void) { __asm jmp dword ptr function_ptrs[256 * 4] }
#endif
#ifndef FIX_CtrlRoutine
    __declspec(naked) void __stdcall fixCtrlRoutine(void) { __asm jmp dword ptr function_ptrs[257 * 4] }
#endif
#ifndef FIX_DeactivateActCtx
    __declspec(naked) void __stdcall fixDeactivateActCtx(void) { __asm jmp dword ptr function_ptrs[258 * 4] }
#endif
#ifndef FIX_DeactivateActCtxWorker
    __declspec(naked) void __stdcall fixDeactivateActCtxWorker(void) { __asm jmp dword ptr function_ptrs[259 * 4] }
#endif
#ifndef FIX_DebugActiveProcess
    __declspec(naked) void __stdcall fixDebugActiveProcess(void) { __asm jmp dword ptr function_ptrs[260 * 4] }
#endif
#ifndef FIX_DebugActiveProcessStop
    __declspec(naked) void __stdcall fixDebugActiveProcessStop(void) { __asm jmp dword ptr function_ptrs[261 * 4] }
#endif
#ifndef FIX_DebugBreak
    __declspec(naked) void __stdcall fixDebugBreak(void) { __asm jmp dword ptr function_ptrs[262 * 4] }
#endif
#ifndef FIX_DebugBreakProcess
    __declspec(naked) void __stdcall fixDebugBreakProcess(void) { __asm jmp dword ptr function_ptrs[263 * 4] }
#endif
#ifndef FIX_DebugSetProcessKillOnExit
    __declspec(naked) void __stdcall fixDebugSetProcessKillOnExit(void) { __asm jmp dword ptr function_ptrs[264 * 4] }
#endif
#ifndef FIX_DecodePointer
    __declspec(naked) void __stdcall fixDecodePointer(void) { __asm jmp dword ptr function_ptrs[265 * 4] }
#endif
#ifndef FIX_DecodeSystemPointer
    __declspec(naked) void __stdcall fixDecodeSystemPointer(void) { __asm jmp dword ptr function_ptrs[266 * 4] }
#endif
#ifndef FIX_DefineDosDeviceA
    __declspec(naked) void __stdcall fixDefineDosDeviceA(void) { __asm jmp dword ptr function_ptrs[267 * 4] }
#endif
#ifndef FIX_DefineDosDeviceW
    __declspec(naked) void __stdcall fixDefineDosDeviceW(void) { __asm jmp dword ptr function_ptrs[268 * 4] }
#endif
#ifndef FIX_DelayLoadFailureHook
    __declspec(naked) void __stdcall fixDelayLoadFailureHook(void) { __asm jmp dword ptr function_ptrs[269 * 4] }
#endif
#ifndef FIX_DeleteAtom
    __declspec(naked) void __stdcall fixDeleteAtom(void) { __asm jmp dword ptr function_ptrs[270 * 4] }
#endif
#ifndef FIX_DeleteBoundaryDescriptor
    __declspec(naked) void __stdcall fixDeleteBoundaryDescriptor(void) { __asm jmp dword ptr function_ptrs[271 * 4] }
#endif
#ifndef FIX_DeleteCriticalSection
    __declspec(naked) void __stdcall fixDeleteCriticalSection(void) { __asm jmp dword ptr function_ptrs[272 * 4] }
#endif
#ifndef FIX_DeleteFiber
    __declspec(naked) void __stdcall fixDeleteFiber(void) { __asm jmp dword ptr function_ptrs[273 * 4] }
#endif
#ifndef FIX_DeleteFileA
    __declspec(naked) void __stdcall fixDeleteFileA(void) { __asm jmp dword ptr function_ptrs[274 * 4] }
#endif
#ifndef FIX_DeleteFileTransactedA
    __declspec(naked) void __stdcall fixDeleteFileTransactedA(void) { __asm jmp dword ptr function_ptrs[275 * 4] }
#endif
#ifndef FIX_DeleteFileTransactedW
    __declspec(naked) void __stdcall fixDeleteFileTransactedW(void) { __asm jmp dword ptr function_ptrs[276 * 4] }
#endif
#ifndef FIX_DeleteFileW
    __declspec(naked) void __stdcall fixDeleteFileW(void) { __asm jmp dword ptr function_ptrs[277 * 4] }
#endif
#ifndef FIX_DeleteProcThreadAttributeList
    __declspec(naked) void __stdcall fixDeleteProcThreadAttributeList(void) { __asm jmp dword ptr function_ptrs[278 * 4] }
#endif
#ifndef FIX_DeleteSynchronizationBarrier
    __declspec(naked) void __stdcall fixDeleteSynchronizationBarrier(void) { __asm jmp dword ptr function_ptrs[279 * 4] }
#endif
#ifndef FIX_DeleteTimerQueue
    __declspec(naked) void __stdcall fixDeleteTimerQueue(void) { __asm jmp dword ptr function_ptrs[280 * 4] }
#endif
#ifndef FIX_DeleteTimerQueueEx
    __declspec(naked) void __stdcall fixDeleteTimerQueueEx(void) { __asm jmp dword ptr function_ptrs[281 * 4] }
#endif
#ifndef FIX_DeleteTimerQueueTimer
    __declspec(naked) void __stdcall fixDeleteTimerQueueTimer(void) { __asm jmp dword ptr function_ptrs[282 * 4] }
#endif
#ifndef FIX_DeleteVolumeMountPointA
    __declspec(naked) void __stdcall fixDeleteVolumeMountPointA(void) { __asm jmp dword ptr function_ptrs[283 * 4] }
#endif
#ifndef FIX_DeleteVolumeMountPointW
    __declspec(naked) void __stdcall fixDeleteVolumeMountPointW(void) { __asm jmp dword ptr function_ptrs[284 * 4] }
#endif
#ifndef FIX_DeviceIoControl
    __declspec(naked) void __stdcall fixDeviceIoControl(void) { __asm jmp dword ptr function_ptrs[285 * 4] }
#endif
#ifndef FIX_DisableThreadLibraryCalls
    __declspec(naked) void __stdcall fixDisableThreadLibraryCalls(void) { __asm jmp dword ptr function_ptrs[286 * 4] }
#endif
#ifndef FIX_DisableThreadProfiling
    __declspec(naked) void __stdcall fixDisableThreadProfiling(void) { __asm jmp dword ptr function_ptrs[287 * 4] }
#endif
#ifndef FIX_DisassociateCurrentThreadFromCallback
    __declspec(naked) void __stdcall fixDisassociateCurrentThreadFromCallback(void) { __asm jmp dword ptr function_ptrs[288 * 4] }
#endif
#ifndef FIX_DiscardVirtualMemory
    __declspec(naked) void __stdcall fixDiscardVirtualMemory(void) { __asm jmp dword ptr function_ptrs[289 * 4] }
#endif
#ifndef FIX_DisconnectNamedPipe
    __declspec(naked) void __stdcall fixDisconnectNamedPipe(void) { __asm jmp dword ptr function_ptrs[290 * 4] }
#endif
#ifndef FIX_DnsHostnameToComputerNameA
    __declspec(naked) void __stdcall fixDnsHostnameToComputerNameA(void) { __asm jmp dword ptr function_ptrs[291 * 4] }
#endif
#ifndef FIX_DnsHostnameToComputerNameExW
    __declspec(naked) void __stdcall fixDnsHostnameToComputerNameExW(void) { __asm jmp dword ptr function_ptrs[292 * 4] }
#endif
#ifndef FIX_DnsHostnameToComputerNameW
    __declspec(naked) void __stdcall fixDnsHostnameToComputerNameW(void) { __asm jmp dword ptr function_ptrs[293 * 4] }
#endif
#ifndef FIX_DosDateTimeToFileTime
    __declspec(naked) void __stdcall fixDosDateTimeToFileTime(void) { __asm jmp dword ptr function_ptrs[294 * 4] }
#endif
#ifndef FIX_DosPathToSessionPathA
    __declspec(naked) void __stdcall fixDosPathToSessionPathA(void) { __asm jmp dword ptr function_ptrs[295 * 4] }
#endif
#ifndef FIX_DosPathToSessionPathW
    __declspec(naked) void __stdcall fixDosPathToSessionPathW(void) { __asm jmp dword ptr function_ptrs[296 * 4] }
#endif
#ifndef FIX_DuplicateConsoleHandle
    __declspec(naked) void __stdcall fixDuplicateConsoleHandle(void) { __asm jmp dword ptr function_ptrs[297 * 4] }
#endif
#ifndef FIX_DuplicateEncryptionInfoFileExt
    __declspec(naked) void __stdcall fixDuplicateEncryptionInfoFileExt(void) { __asm jmp dword ptr function_ptrs[298 * 4] }
#endif
#ifndef FIX_DuplicateHandle
    __declspec(naked) void __stdcall fixDuplicateHandle(void) { __asm jmp dword ptr function_ptrs[299 * 4] }
#endif
#ifndef FIX_EnableThreadProfiling
    __declspec(naked) void __stdcall fixEnableThreadProfiling(void) { __asm jmp dword ptr function_ptrs[300 * 4] }
#endif
#ifndef FIX_EncodePointer
    __declspec(naked) void __stdcall fixEncodePointer(void) { __asm jmp dword ptr function_ptrs[301 * 4] }
#endif
#ifndef FIX_EncodeSystemPointer
    __declspec(naked) void __stdcall fixEncodeSystemPointer(void) { __asm jmp dword ptr function_ptrs[302 * 4] }
#endif
#ifndef FIX_EndUpdateResourceA
    __declspec(naked) void __stdcall fixEndUpdateResourceA(void) { __asm jmp dword ptr function_ptrs[303 * 4] }
#endif
#ifndef FIX_EndUpdateResourceW
    __declspec(naked) void __stdcall fixEndUpdateResourceW(void) { __asm jmp dword ptr function_ptrs[304 * 4] }
#endif
#ifndef FIX_EnterCriticalSection
    __declspec(naked) void __stdcall fixEnterCriticalSection(void) { __asm jmp dword ptr function_ptrs[305 * 4] }
#endif
#ifndef FIX_EnterSynchronizationBarrier
    __declspec(naked) void __stdcall fixEnterSynchronizationBarrier(void) { __asm jmp dword ptr function_ptrs[306 * 4] }
#endif
#ifndef FIX_EnumCalendarInfoA
    __declspec(naked) void __stdcall fixEnumCalendarInfoA(void) { __asm jmp dword ptr function_ptrs[307 * 4] }
#endif
#ifndef FIX_EnumCalendarInfoExA
    __declspec(naked) void __stdcall fixEnumCalendarInfoExA(void) { __asm jmp dword ptr function_ptrs[308 * 4] }
#endif
#ifndef FIX_EnumCalendarInfoExEx
    __declspec(naked) void __stdcall fixEnumCalendarInfoExEx(void) { __asm jmp dword ptr function_ptrs[309 * 4] }
#endif
#ifndef FIX_EnumCalendarInfoExW
    __declspec(naked) void __stdcall fixEnumCalendarInfoExW(void) { __asm jmp dword ptr function_ptrs[310 * 4] }
#endif
#ifndef FIX_EnumCalendarInfoW
    __declspec(naked) void __stdcall fixEnumCalendarInfoW(void) { __asm jmp dword ptr function_ptrs[311 * 4] }
#endif
#ifndef FIX_EnumDateFormatsA
    __declspec(naked) void __stdcall fixEnumDateFormatsA(void) { __asm jmp dword ptr function_ptrs[312 * 4] }
#endif
#ifndef FIX_EnumDateFormatsExA
    __declspec(naked) void __stdcall fixEnumDateFormatsExA(void) { __asm jmp dword ptr function_ptrs[313 * 4] }
#endif
#ifndef FIX_EnumDateFormatsExEx
    __declspec(naked) void __stdcall fixEnumDateFormatsExEx(void) { __asm jmp dword ptr function_ptrs[314 * 4] }
#endif
#ifndef FIX_EnumDateFormatsExW
    __declspec(naked) void __stdcall fixEnumDateFormatsExW(void) { __asm jmp dword ptr function_ptrs[315 * 4] }
#endif
#ifndef FIX_EnumDateFormatsW
    __declspec(naked) void __stdcall fixEnumDateFormatsW(void) { __asm jmp dword ptr function_ptrs[316 * 4] }
#endif
#ifndef FIX_EnumLanguageGroupLocalesA
    __declspec(naked) void __stdcall fixEnumLanguageGroupLocalesA(void) { __asm jmp dword ptr function_ptrs[317 * 4] }
#endif
#ifndef FIX_EnumLanguageGroupLocalesW
    __declspec(naked) void __stdcall fixEnumLanguageGroupLocalesW(void) { __asm jmp dword ptr function_ptrs[318 * 4] }
#endif
#ifndef FIX_EnumResourceLanguagesA
    __declspec(naked) void __stdcall fixEnumResourceLanguagesA(void) { __asm jmp dword ptr function_ptrs[319 * 4] }
#endif
#ifndef FIX_EnumResourceLanguagesExA
    __declspec(naked) void __stdcall fixEnumResourceLanguagesExA(void) { __asm jmp dword ptr function_ptrs[320 * 4] }
#endif
#ifndef FIX_EnumResourceLanguagesExW
    __declspec(naked) void __stdcall fixEnumResourceLanguagesExW(void) { __asm jmp dword ptr function_ptrs[321 * 4] }
#endif
#ifndef FIX_EnumResourceLanguagesW
    __declspec(naked) void __stdcall fixEnumResourceLanguagesW(void) { __asm jmp dword ptr function_ptrs[322 * 4] }
#endif
#ifndef FIX_EnumResourceNamesA
    __declspec(naked) void __stdcall fixEnumResourceNamesA(void) { __asm jmp dword ptr function_ptrs[323 * 4] }
#endif
#ifndef FIX_EnumResourceNamesExA
    __declspec(naked) void __stdcall fixEnumResourceNamesExA(void) { __asm jmp dword ptr function_ptrs[324 * 4] }
#endif
#ifndef FIX_EnumResourceNamesExW
    __declspec(naked) void __stdcall fixEnumResourceNamesExW(void) { __asm jmp dword ptr function_ptrs[325 * 4] }
#endif
#ifndef FIX_EnumResourceNamesW
    __declspec(naked) void __stdcall fixEnumResourceNamesW(void) { __asm jmp dword ptr function_ptrs[326 * 4] }
#endif
#ifndef FIX_EnumResourceTypesA
    __declspec(naked) void __stdcall fixEnumResourceTypesA(void) { __asm jmp dword ptr function_ptrs[327 * 4] }
#endif
#ifndef FIX_EnumResourceTypesExA
    __declspec(naked) void __stdcall fixEnumResourceTypesExA(void) { __asm jmp dword ptr function_ptrs[328 * 4] }
#endif
#ifndef FIX_EnumResourceTypesExW
    __declspec(naked) void __stdcall fixEnumResourceTypesExW(void) { __asm jmp dword ptr function_ptrs[329 * 4] }
#endif
#ifndef FIX_EnumResourceTypesW
    __declspec(naked) void __stdcall fixEnumResourceTypesW(void) { __asm jmp dword ptr function_ptrs[330 * 4] }
#endif
#ifndef FIX_EnumSystemCodePagesA
    __declspec(naked) void __stdcall fixEnumSystemCodePagesA(void) { __asm jmp dword ptr function_ptrs[331 * 4] }
#endif
#ifndef FIX_EnumSystemCodePagesW
    __declspec(naked) void __stdcall fixEnumSystemCodePagesW(void) { __asm jmp dword ptr function_ptrs[332 * 4] }
#endif
#ifndef FIX_EnumSystemFirmwareTables
    __declspec(naked) void __stdcall fixEnumSystemFirmwareTables(void) { __asm jmp dword ptr function_ptrs[333 * 4] }
#endif
#ifndef FIX_EnumSystemGeoID
    __declspec(naked) void __stdcall fixEnumSystemGeoID(void) { __asm jmp dword ptr function_ptrs[334 * 4] }
#endif
#ifndef FIX_EnumSystemGeoNames
    __declspec(naked) void __stdcall fixEnumSystemGeoNames(void) { __asm jmp dword ptr function_ptrs[335 * 4] }
#endif
#ifndef FIX_EnumSystemLanguageGroupsA
    __declspec(naked) void __stdcall fixEnumSystemLanguageGroupsA(void) { __asm jmp dword ptr function_ptrs[336 * 4] }
#endif
#ifndef FIX_EnumSystemLanguageGroupsW
    __declspec(naked) void __stdcall fixEnumSystemLanguageGroupsW(void) { __asm jmp dword ptr function_ptrs[337 * 4] }
#endif
#ifndef FIX_EnumSystemLocalesA
    __declspec(naked) void __stdcall fixEnumSystemLocalesA(void) { __asm jmp dword ptr function_ptrs[338 * 4] }
#endif
#ifndef FIX_EnumSystemLocalesEx
    __declspec(naked) void __stdcall fixEnumSystemLocalesEx(void) { __asm jmp dword ptr function_ptrs[339 * 4] }
#endif
#ifndef FIX_EnumSystemLocalesW
    __declspec(naked) void __stdcall fixEnumSystemLocalesW(void) { __asm jmp dword ptr function_ptrs[340 * 4] }
#endif
#ifndef FIX_EnumTimeFormatsA
    __declspec(naked) void __stdcall fixEnumTimeFormatsA(void) { __asm jmp dword ptr function_ptrs[341 * 4] }
#endif
#ifndef FIX_EnumTimeFormatsEx
    __declspec(naked) void __stdcall fixEnumTimeFormatsEx(void) { __asm jmp dword ptr function_ptrs[342 * 4] }
#endif
#ifndef FIX_EnumTimeFormatsW
    __declspec(naked) void __stdcall fixEnumTimeFormatsW(void) { __asm jmp dword ptr function_ptrs[343 * 4] }
#endif
#ifndef FIX_EnumUILanguagesA
    __declspec(naked) void __stdcall fixEnumUILanguagesA(void) { __asm jmp dword ptr function_ptrs[344 * 4] }
#endif
#ifndef FIX_EnumUILanguagesW
    __declspec(naked) void __stdcall fixEnumUILanguagesW(void) { __asm jmp dword ptr function_ptrs[345 * 4] }
#endif
#ifndef FIX_EnumerateLocalComputerNamesA
    __declspec(naked) void __stdcall fixEnumerateLocalComputerNamesA(void) { __asm jmp dword ptr function_ptrs[346 * 4] }
#endif
#ifndef FIX_EnumerateLocalComputerNamesW
    __declspec(naked) void __stdcall fixEnumerateLocalComputerNamesW(void) { __asm jmp dword ptr function_ptrs[347 * 4] }
#endif
#ifndef FIX_EraseTape
    __declspec(naked) void __stdcall fixEraseTape(void) { __asm jmp dword ptr function_ptrs[348 * 4] }
#endif
#ifndef FIX_EscapeCommFunction
    __declspec(naked) void __stdcall fixEscapeCommFunction(void) { __asm jmp dword ptr function_ptrs[349 * 4] }
#endif
#ifndef FIX_ExitProcess
    __declspec(naked) void __stdcall fixExitProcess(void) { __asm jmp dword ptr function_ptrs[350 * 4] }
#endif
#ifndef FIX_ExitThread
    __declspec(naked) void __stdcall fixExitThread(void) { __asm jmp dword ptr function_ptrs[351 * 4] }
#endif
#ifndef FIX_ExitVDM
    __declspec(naked) void __stdcall fixExitVDM(void) { __asm jmp dword ptr function_ptrs[352 * 4] }
#endif
#ifndef FIX_ExpandEnvironmentStringsA
    __declspec(naked) void __stdcall fixExpandEnvironmentStringsA(void) { __asm jmp dword ptr function_ptrs[353 * 4] }
#endif
#ifndef FIX_ExpandEnvironmentStringsW
    __declspec(naked) void __stdcall fixExpandEnvironmentStringsW(void) { __asm jmp dword ptr function_ptrs[354 * 4] }
#endif
#ifndef FIX_ExpungeConsoleCommandHistoryA
    __declspec(naked) void __stdcall fixExpungeConsoleCommandHistoryA(void) { __asm jmp dword ptr function_ptrs[355 * 4] }
#endif
#ifndef FIX_ExpungeConsoleCommandHistoryW
    __declspec(naked) void __stdcall fixExpungeConsoleCommandHistoryW(void) { __asm jmp dword ptr function_ptrs[356 * 4] }
#endif
#ifndef FIX_FatalAppExitA
    __declspec(naked) void __stdcall fixFatalAppExitA(void) { __asm jmp dword ptr function_ptrs[357 * 4] }
#endif
#ifndef FIX_FatalAppExitW
    __declspec(naked) void __stdcall fixFatalAppExitW(void) { __asm jmp dword ptr function_ptrs[358 * 4] }
#endif
#ifndef FIX_FatalExit
    __declspec(naked) void __stdcall fixFatalExit(void) { __asm jmp dword ptr function_ptrs[359 * 4] }
#endif
#ifndef FIX_FileTimeToDosDateTime
    __declspec(naked) void __stdcall fixFileTimeToDosDateTime(void) { __asm jmp dword ptr function_ptrs[360 * 4] }
#endif
#ifndef FIX_FileTimeToLocalFileTime
    __declspec(naked) void __stdcall fixFileTimeToLocalFileTime(void) { __asm jmp dword ptr function_ptrs[361 * 4] }
#endif
#ifndef FIX_FileTimeToSystemTime
    __declspec(naked) void __stdcall fixFileTimeToSystemTime(void) { __asm jmp dword ptr function_ptrs[362 * 4] }
#endif
#ifndef FIX_FillConsoleOutputAttribute
    __declspec(naked) void __stdcall fixFillConsoleOutputAttribute(void) { __asm jmp dword ptr function_ptrs[363 * 4] }
#endif
#ifndef FIX_FillConsoleOutputCharacterA
    __declspec(naked) void __stdcall fixFillConsoleOutputCharacterA(void) { __asm jmp dword ptr function_ptrs[364 * 4] }
#endif
#ifndef FIX_FillConsoleOutputCharacterW
    __declspec(naked) void __stdcall fixFillConsoleOutputCharacterW(void) { __asm jmp dword ptr function_ptrs[365 * 4] }
#endif
#ifndef FIX_FindActCtxSectionGuid
    __declspec(naked) void __stdcall fixFindActCtxSectionGuid(void) { __asm jmp dword ptr function_ptrs[366 * 4] }
#endif
#ifndef FIX_FindActCtxSectionGuidWorker
    __declspec(naked) void __stdcall fixFindActCtxSectionGuidWorker(void) { __asm jmp dword ptr function_ptrs[367 * 4] }
#endif
#ifndef FIX_FindActCtxSectionStringA
    __declspec(naked) void __stdcall fixFindActCtxSectionStringA(void) { __asm jmp dword ptr function_ptrs[368 * 4] }
#endif
#ifndef FIX_FindActCtxSectionStringW
    __declspec(naked) void __stdcall fixFindActCtxSectionStringW(void) { __asm jmp dword ptr function_ptrs[369 * 4] }
#endif
#ifndef FIX_FindActCtxSectionStringWWorker
    __declspec(naked) void __stdcall fixFindActCtxSectionStringWWorker(void) { __asm jmp dword ptr function_ptrs[370 * 4] }
#endif
#ifndef FIX_FindAtomA
    __declspec(naked) void __stdcall fixFindAtomA(void) { __asm jmp dword ptr function_ptrs[371 * 4] }
#endif
#ifndef FIX_FindAtomW
    __declspec(naked) void __stdcall fixFindAtomW(void) { __asm jmp dword ptr function_ptrs[372 * 4] }
#endif
#ifndef FIX_FindClose
    __declspec(naked) void __stdcall fixFindClose(void) { __asm jmp dword ptr function_ptrs[373 * 4] }
#endif
#ifndef FIX_FindCloseChangeNotification
    __declspec(naked) void __stdcall fixFindCloseChangeNotification(void) { __asm jmp dword ptr function_ptrs[374 * 4] }
#endif
#ifndef FIX_FindFirstChangeNotificationA
    __declspec(naked) void __stdcall fixFindFirstChangeNotificationA(void) { __asm jmp dword ptr function_ptrs[375 * 4] }
#endif
#ifndef FIX_FindFirstChangeNotificationW
    __declspec(naked) void __stdcall fixFindFirstChangeNotificationW(void) { __asm jmp dword ptr function_ptrs[376 * 4] }
#endif
#ifndef FIX_FindFirstFileA
    __declspec(naked) void __stdcall fixFindFirstFileA(void) { __asm jmp dword ptr function_ptrs[377 * 4] }
#endif
#ifndef FIX_FindFirstFileExA
    __declspec(naked) void __stdcall fixFindFirstFileExA(void) { __asm jmp dword ptr function_ptrs[378 * 4] }
#endif
#ifndef FIX_FindFirstFileExW
    __declspec(naked) void __stdcall fixFindFirstFileExW(void) { __asm jmp dword ptr function_ptrs[379 * 4] }
#endif
#ifndef FIX_FindFirstFileNameTransactedW
    __declspec(naked) void __stdcall fixFindFirstFileNameTransactedW(void) { __asm jmp dword ptr function_ptrs[380 * 4] }
#endif
#ifndef FIX_FindFirstFileNameW
    __declspec(naked) void __stdcall fixFindFirstFileNameW(void) { __asm jmp dword ptr function_ptrs[381 * 4] }
#endif
#ifndef FIX_FindFirstFileTransactedA
    __declspec(naked) void __stdcall fixFindFirstFileTransactedA(void) { __asm jmp dword ptr function_ptrs[382 * 4] }
#endif
#ifndef FIX_FindFirstFileTransactedW
    __declspec(naked) void __stdcall fixFindFirstFileTransactedW(void) { __asm jmp dword ptr function_ptrs[383 * 4] }
#endif
#ifndef FIX_FindFirstFileW
    __declspec(naked) void __stdcall fixFindFirstFileW(void) { __asm jmp dword ptr function_ptrs[384 * 4] }
#endif
#ifndef FIX_FindFirstStreamTransactedW
    __declspec(naked) void __stdcall fixFindFirstStreamTransactedW(void) { __asm jmp dword ptr function_ptrs[385 * 4] }
#endif
#ifndef FIX_FindFirstStreamW
    __declspec(naked) void __stdcall fixFindFirstStreamW(void) { __asm jmp dword ptr function_ptrs[386 * 4] }
#endif
#ifndef FIX_FindFirstVolumeA
    __declspec(naked) void __stdcall fixFindFirstVolumeA(void) { __asm jmp dword ptr function_ptrs[387 * 4] }
#endif
#ifndef FIX_FindFirstVolumeMountPointA
    __declspec(naked) void __stdcall fixFindFirstVolumeMountPointA(void) { __asm jmp dword ptr function_ptrs[388 * 4] }
#endif
#ifndef FIX_FindFirstVolumeMountPointW
    __declspec(naked) void __stdcall fixFindFirstVolumeMountPointW(void) { __asm jmp dword ptr function_ptrs[389 * 4] }
#endif
#ifndef FIX_FindFirstVolumeW
    __declspec(naked) void __stdcall fixFindFirstVolumeW(void) { __asm jmp dword ptr function_ptrs[390 * 4] }
#endif
#ifndef FIX_FindNLSString
    __declspec(naked) void __stdcall fixFindNLSString(void) { __asm jmp dword ptr function_ptrs[391 * 4] }
#endif
#ifndef FIX_FindNLSStringEx
    __declspec(naked) void __stdcall fixFindNLSStringEx(void) { __asm jmp dword ptr function_ptrs[392 * 4] }
#endif
#ifndef FIX_FindNextChangeNotification
    __declspec(naked) void __stdcall fixFindNextChangeNotification(void) { __asm jmp dword ptr function_ptrs[393 * 4] }
#endif
#ifndef FIX_FindNextFileA
    __declspec(naked) void __stdcall fixFindNextFileA(void) { __asm jmp dword ptr function_ptrs[394 * 4] }
#endif
#ifndef FIX_FindNextFileNameW
    __declspec(naked) void __stdcall fixFindNextFileNameW(void) { __asm jmp dword ptr function_ptrs[395 * 4] }
#endif
#ifndef FIX_FindNextFileW
    __declspec(naked) void __stdcall fixFindNextFileW(void) { __asm jmp dword ptr function_ptrs[396 * 4] }
#endif
#ifndef FIX_FindNextStreamW
    __declspec(naked) void __stdcall fixFindNextStreamW(void) { __asm jmp dword ptr function_ptrs[397 * 4] }
#endif
#ifndef FIX_FindNextVolumeA
    __declspec(naked) void __stdcall fixFindNextVolumeA(void) { __asm jmp dword ptr function_ptrs[398 * 4] }
#endif
#ifndef FIX_FindNextVolumeMountPointA
    __declspec(naked) void __stdcall fixFindNextVolumeMountPointA(void) { __asm jmp dword ptr function_ptrs[399 * 4] }
#endif
#ifndef FIX_FindNextVolumeMountPointW
    __declspec(naked) void __stdcall fixFindNextVolumeMountPointW(void) { __asm jmp dword ptr function_ptrs[400 * 4] }
#endif
#ifndef FIX_FindNextVolumeW
    __declspec(naked) void __stdcall fixFindNextVolumeW(void) { __asm jmp dword ptr function_ptrs[401 * 4] }
#endif
#ifndef FIX_FindPackagesByPackageFamily
    __declspec(naked) void __stdcall fixFindPackagesByPackageFamily(void) { __asm jmp dword ptr function_ptrs[402 * 4] }
#endif
#ifndef FIX_FindResourceA
    __declspec(naked) void __stdcall fixFindResourceA(void) { __asm jmp dword ptr function_ptrs[403 * 4] }
#endif
#ifndef FIX_FindResourceExA
    __declspec(naked) void __stdcall fixFindResourceExA(void) { __asm jmp dword ptr function_ptrs[404 * 4] }
#endif
#ifndef FIX_FindResourceExW
    __declspec(naked) void __stdcall fixFindResourceExW(void) { __asm jmp dword ptr function_ptrs[405 * 4] }
#endif
#ifndef FIX_FindResourceW
    __declspec(naked) void __stdcall fixFindResourceW(void) { __asm jmp dword ptr function_ptrs[406 * 4] }
#endif
#ifndef FIX_FindStringOrdinal
    __declspec(naked) void __stdcall fixFindStringOrdinal(void) { __asm jmp dword ptr function_ptrs[407 * 4] }
#endif
#ifndef FIX_FindVolumeClose
    __declspec(naked) void __stdcall fixFindVolumeClose(void) { __asm jmp dword ptr function_ptrs[408 * 4] }
#endif
#ifndef FIX_FindVolumeMountPointClose
    __declspec(naked) void __stdcall fixFindVolumeMountPointClose(void) { __asm jmp dword ptr function_ptrs[409 * 4] }
#endif
#ifndef FIX_FlsAlloc
    __declspec(naked) void __stdcall fixFlsAlloc(void) { __asm jmp dword ptr function_ptrs[410 * 4] }
#endif
#ifndef FIX_FlsFree
    __declspec(naked) void __stdcall fixFlsFree(void) { __asm jmp dword ptr function_ptrs[411 * 4] }
#endif
#ifndef FIX_FlsGetValue
    __declspec(naked) void __stdcall fixFlsGetValue(void) { __asm jmp dword ptr function_ptrs[412 * 4] }
#endif
#ifndef FIX_FlsSetValue
    __declspec(naked) void __stdcall fixFlsSetValue(void) { __asm jmp dword ptr function_ptrs[413 * 4] }
#endif
#ifndef FIX_FlushConsoleInputBuffer
    __declspec(naked) void __stdcall fixFlushConsoleInputBuffer(void) { __asm jmp dword ptr function_ptrs[414 * 4] }
#endif
#ifndef FIX_FlushFileBuffers
    __declspec(naked) void __stdcall fixFlushFileBuffers(void) { __asm jmp dword ptr function_ptrs[415 * 4] }
#endif
#ifndef FIX_FlushInstructionCache
    __declspec(naked) void __stdcall fixFlushInstructionCache(void) { __asm jmp dword ptr function_ptrs[416 * 4] }
#endif
#ifndef FIX_FlushProcessWriteBuffers
    __declspec(naked) void __stdcall fixFlushProcessWriteBuffers(void) { __asm jmp dword ptr function_ptrs[417 * 4] }
#endif
#ifndef FIX_FlushViewOfFile
    __declspec(naked) void __stdcall fixFlushViewOfFile(void) { __asm jmp dword ptr function_ptrs[418 * 4] }
#endif
#ifndef FIX_FoldStringA
    __declspec(naked) void __stdcall fixFoldStringA(void) { __asm jmp dword ptr function_ptrs[419 * 4] }
#endif
#ifndef FIX_FoldStringW
    __declspec(naked) void __stdcall fixFoldStringW(void) { __asm jmp dword ptr function_ptrs[420 * 4] }
#endif
#ifndef FIX_FormatApplicationUserModelId
    __declspec(naked) void __stdcall fixFormatApplicationUserModelId(void) { __asm jmp dword ptr function_ptrs[421 * 4] }
#endif
#ifndef FIX_FormatMessageA
    __declspec(naked) void __stdcall fixFormatMessageA(void) { __asm jmp dword ptr function_ptrs[422 * 4] }
#endif
#ifndef FIX_FormatMessageW
    __declspec(naked) void __stdcall fixFormatMessageW(void) { __asm jmp dword ptr function_ptrs[423 * 4] }
#endif
#ifndef FIX_FreeConsole
    __declspec(naked) void __stdcall fixFreeConsole(void) { __asm jmp dword ptr function_ptrs[424 * 4] }
#endif
#ifndef FIX_FreeEnvironmentStringsA
    __declspec(naked) void __stdcall fixFreeEnvironmentStringsA(void) { __asm jmp dword ptr function_ptrs[425 * 4] }
#endif
#ifndef FIX_FreeEnvironmentStringsW
    __declspec(naked) void __stdcall fixFreeEnvironmentStringsW(void) { __asm jmp dword ptr function_ptrs[426 * 4] }
#endif
#ifndef FIX_FreeLibrary
    __declspec(naked) void __stdcall fixFreeLibrary(void) { __asm jmp dword ptr function_ptrs[427 * 4] }
#endif
#ifndef FIX_FreeLibraryAndExitThread
    __declspec(naked) void __stdcall fixFreeLibraryAndExitThread(void) { __asm jmp dword ptr function_ptrs[428 * 4] }
#endif
#ifndef FIX_FreeLibraryWhenCallbackReturns
    __declspec(naked) void __stdcall fixFreeLibraryWhenCallbackReturns(void) { __asm jmp dword ptr function_ptrs[429 * 4] }
#endif
#ifndef FIX_FreeMemoryJobObject
    __declspec(naked) void __stdcall fixFreeMemoryJobObject(void) { __asm jmp dword ptr function_ptrs[430 * 4] }
#endif
#ifndef FIX_FreeResource
    __declspec(naked) void __stdcall fixFreeResource(void) { __asm jmp dword ptr function_ptrs[431 * 4] }
#endif
#ifndef FIX_FreeUserPhysicalPages
    __declspec(naked) void __stdcall fixFreeUserPhysicalPages(void) { __asm jmp dword ptr function_ptrs[432 * 4] }
#endif
#ifndef FIX_GenerateConsoleCtrlEvent
    __declspec(naked) void __stdcall fixGenerateConsoleCtrlEvent(void) { __asm jmp dword ptr function_ptrs[433 * 4] }
#endif
#ifndef FIX_GetACP
    __declspec(naked) void __stdcall fixGetACP(void) { __asm jmp dword ptr function_ptrs[434 * 4] }
#endif
#ifndef FIX_GetActiveProcessorCount
    __declspec(naked) void __stdcall fixGetActiveProcessorCount(void) { __asm jmp dword ptr function_ptrs[435 * 4] }
#endif
#ifndef FIX_GetActiveProcessorGroupCount
    __declspec(naked) void __stdcall fixGetActiveProcessorGroupCount(void) { __asm jmp dword ptr function_ptrs[436 * 4] }
#endif
#ifndef FIX_GetAppContainerAce
    __declspec(naked) void __stdcall fixGetAppContainerAce(void) { __asm jmp dword ptr function_ptrs[437 * 4] }
#endif
#ifndef FIX_GetAppContainerNamedObjectPath
    __declspec(naked) void __stdcall fixGetAppContainerNamedObjectPath(void) { __asm jmp dword ptr function_ptrs[438 * 4] }
#endif
#ifndef FIX_GetApplicationRecoveryCallback
    __declspec(naked) void __stdcall fixGetApplicationRecoveryCallback(void) { __asm jmp dword ptr function_ptrs[439 * 4] }
#endif
#ifndef FIX_GetApplicationRecoveryCallbackWorker
    __declspec(naked) void __stdcall fixGetApplicationRecoveryCallbackWorker(void) { __asm jmp dword ptr function_ptrs[440 * 4] }
#endif
#ifndef FIX_GetApplicationRestartSettings
    __declspec(naked) void __stdcall fixGetApplicationRestartSettings(void) { __asm jmp dword ptr function_ptrs[441 * 4] }
#endif
#ifndef FIX_GetApplicationRestartSettingsWorker
    __declspec(naked) void __stdcall fixGetApplicationRestartSettingsWorker(void) { __asm jmp dword ptr function_ptrs[442 * 4] }
#endif
#ifndef FIX_GetApplicationUserModelId
    __declspec(naked) void __stdcall fixGetApplicationUserModelId(void) { __asm jmp dword ptr function_ptrs[443 * 4] }
#endif
#ifndef FIX_GetAtomNameA
    __declspec(naked) void __stdcall fixGetAtomNameA(void) { __asm jmp dword ptr function_ptrs[444 * 4] }
#endif
#ifndef FIX_GetAtomNameW
    __declspec(naked) void __stdcall fixGetAtomNameW(void) { __asm jmp dword ptr function_ptrs[445 * 4] }
#endif
#ifndef FIX_GetBinaryType
    __declspec(naked) void __stdcall fixGetBinaryType(void) { __asm jmp dword ptr function_ptrs[446 * 4] }
#endif
#ifndef FIX_GetBinaryTypeA
    __declspec(naked) void __stdcall fixGetBinaryTypeA(void) { __asm jmp dword ptr function_ptrs[447 * 4] }
#endif
#ifndef FIX_GetBinaryTypeW
    __declspec(naked) void __stdcall fixGetBinaryTypeW(void) { __asm jmp dword ptr function_ptrs[448 * 4] }
#endif
#ifndef FIX_GetCPInfo
    __declspec(naked) void __stdcall fixGetCPInfo(void) { __asm jmp dword ptr function_ptrs[449 * 4] }
#endif
#ifndef FIX_GetCPInfoExA
    __declspec(naked) void __stdcall fixGetCPInfoExA(void) { __asm jmp dword ptr function_ptrs[450 * 4] }
#endif
#ifndef FIX_GetCPInfoExW
    __declspec(naked) void __stdcall fixGetCPInfoExW(void) { __asm jmp dword ptr function_ptrs[451 * 4] }
#endif
#ifndef FIX_GetCachedSigningLevel
    __declspec(naked) void __stdcall fixGetCachedSigningLevel(void) { __asm jmp dword ptr function_ptrs[452 * 4] }
#endif
#ifndef FIX_GetCalendarDateFormat
    __declspec(naked) void __stdcall fixGetCalendarDateFormat(void) { __asm jmp dword ptr function_ptrs[453 * 4] }
#endif
#ifndef FIX_GetCalendarDateFormatEx
    __declspec(naked) void __stdcall fixGetCalendarDateFormatEx(void) { __asm jmp dword ptr function_ptrs[454 * 4] }
#endif
#ifndef FIX_GetCalendarDaysInMonth
    __declspec(naked) void __stdcall fixGetCalendarDaysInMonth(void) { __asm jmp dword ptr function_ptrs[455 * 4] }
#endif
#ifndef FIX_GetCalendarDifferenceInDays
    __declspec(naked) void __stdcall fixGetCalendarDifferenceInDays(void) { __asm jmp dword ptr function_ptrs[456 * 4] }
#endif
#ifndef FIX_GetCalendarInfoA
    __declspec(naked) void __stdcall fixGetCalendarInfoA(void) { __asm jmp dword ptr function_ptrs[457 * 4] }
#endif
#ifndef FIX_GetCalendarInfoEx
    __declspec(naked) void __stdcall fixGetCalendarInfoEx(void) { __asm jmp dword ptr function_ptrs[458 * 4] }
#endif
#ifndef FIX_GetCalendarInfoW
    __declspec(naked) void __stdcall fixGetCalendarInfoW(void) { __asm jmp dword ptr function_ptrs[459 * 4] }
#endif
#ifndef FIX_GetCalendarMonthsInYear
    __declspec(naked) void __stdcall fixGetCalendarMonthsInYear(void) { __asm jmp dword ptr function_ptrs[460 * 4] }
#endif
#ifndef FIX_GetCalendarSupportedDateRange
    __declspec(naked) void __stdcall fixGetCalendarSupportedDateRange(void) { __asm jmp dword ptr function_ptrs[461 * 4] }
#endif
#ifndef FIX_GetCalendarWeekNumber
    __declspec(naked) void __stdcall fixGetCalendarWeekNumber(void) { __asm jmp dword ptr function_ptrs[462 * 4] }
#endif
#ifndef FIX_GetComPlusPackageInstallStatus
    __declspec(naked) void __stdcall fixGetComPlusPackageInstallStatus(void) { __asm jmp dword ptr function_ptrs[463 * 4] }
#endif
#ifndef FIX_GetCommConfig
    __declspec(naked) void __stdcall fixGetCommConfig(void) { __asm jmp dword ptr function_ptrs[464 * 4] }
#endif
#ifndef FIX_GetCommMask
    __declspec(naked) void __stdcall fixGetCommMask(void) { __asm jmp dword ptr function_ptrs[465 * 4] }
#endif
#ifndef FIX_GetCommModemStatus
    __declspec(naked) void __stdcall fixGetCommModemStatus(void) { __asm jmp dword ptr function_ptrs[466 * 4] }
#endif
#ifndef FIX_GetCommProperties
    __declspec(naked) void __stdcall fixGetCommProperties(void) { __asm jmp dword ptr function_ptrs[467 * 4] }
#endif
#ifndef FIX_GetCommState
    __declspec(naked) void __stdcall fixGetCommState(void) { __asm jmp dword ptr function_ptrs[468 * 4] }
#endif
#ifndef FIX_GetCommTimeouts
    __declspec(naked) void __stdcall fixGetCommTimeouts(void) { __asm jmp dword ptr function_ptrs[469 * 4] }
#endif
#ifndef FIX_GetCommandLineA
    __declspec(naked) void __stdcall fixGetCommandLineA(void) { __asm jmp dword ptr function_ptrs[470 * 4] }
#endif
#ifndef FIX_GetCommandLineW
    __declspec(naked) void __stdcall fixGetCommandLineW(void) { __asm jmp dword ptr function_ptrs[471 * 4] }
#endif
#ifndef FIX_GetCompressedFileSizeA
    __declspec(naked) void __stdcall fixGetCompressedFileSizeA(void) { __asm jmp dword ptr function_ptrs[472 * 4] }
#endif
#ifndef FIX_GetCompressedFileSizeTransactedA
    __declspec(naked) void __stdcall fixGetCompressedFileSizeTransactedA(void) { __asm jmp dword ptr function_ptrs[473 * 4] }
#endif
#ifndef FIX_GetCompressedFileSizeTransactedW
    __declspec(naked) void __stdcall fixGetCompressedFileSizeTransactedW(void) { __asm jmp dword ptr function_ptrs[474 * 4] }
#endif
#ifndef FIX_GetCompressedFileSizeW
    __declspec(naked) void __stdcall fixGetCompressedFileSizeW(void) { __asm jmp dword ptr function_ptrs[475 * 4] }
#endif
#ifndef FIX_GetComputerNameA
    __declspec(naked) void __stdcall fixGetComputerNameA(void) { __asm jmp dword ptr function_ptrs[476 * 4] }
#endif
#ifndef FIX_GetComputerNameExA
    __declspec(naked) void __stdcall fixGetComputerNameExA(void) { __asm jmp dword ptr function_ptrs[477 * 4] }
#endif
#ifndef FIX_GetComputerNameExW
    __declspec(naked) void __stdcall fixGetComputerNameExW(void) { __asm jmp dword ptr function_ptrs[478 * 4] }
#endif
#ifndef FIX_GetComputerNameW
    __declspec(naked) void __stdcall fixGetComputerNameW(void) { __asm jmp dword ptr function_ptrs[479 * 4] }
#endif
#ifndef FIX_GetConsoleAliasA
    __declspec(naked) void __stdcall fixGetConsoleAliasA(void) { __asm jmp dword ptr function_ptrs[480 * 4] }
#endif
#ifndef FIX_GetConsoleAliasExesA
    __declspec(naked) void __stdcall fixGetConsoleAliasExesA(void) { __asm jmp dword ptr function_ptrs[481 * 4] }
#endif
#ifndef FIX_GetConsoleAliasExesLengthA
    __declspec(naked) void __stdcall fixGetConsoleAliasExesLengthA(void) { __asm jmp dword ptr function_ptrs[482 * 4] }
#endif
#ifndef FIX_GetConsoleAliasExesLengthW
    __declspec(naked) void __stdcall fixGetConsoleAliasExesLengthW(void) { __asm jmp dword ptr function_ptrs[483 * 4] }
#endif
#ifndef FIX_GetConsoleAliasExesW
    __declspec(naked) void __stdcall fixGetConsoleAliasExesW(void) { __asm jmp dword ptr function_ptrs[484 * 4] }
#endif
#ifndef FIX_GetConsoleAliasW
    __declspec(naked) void __stdcall fixGetConsoleAliasW(void) { __asm jmp dword ptr function_ptrs[485 * 4] }
#endif
#ifndef FIX_GetConsoleAliasesA
    __declspec(naked) void __stdcall fixGetConsoleAliasesA(void) { __asm jmp dword ptr function_ptrs[486 * 4] }
#endif
#ifndef FIX_GetConsoleAliasesLengthA
    __declspec(naked) void __stdcall fixGetConsoleAliasesLengthA(void) { __asm jmp dword ptr function_ptrs[487 * 4] }
#endif
#ifndef FIX_GetConsoleAliasesLengthW
    __declspec(naked) void __stdcall fixGetConsoleAliasesLengthW(void) { __asm jmp dword ptr function_ptrs[488 * 4] }
#endif
#ifndef FIX_GetConsoleAliasesW
    __declspec(naked) void __stdcall fixGetConsoleAliasesW(void) { __asm jmp dword ptr function_ptrs[489 * 4] }
#endif
#ifndef FIX_GetConsoleCP
    __declspec(naked) void __stdcall fixGetConsoleCP(void) { __asm jmp dword ptr function_ptrs[490 * 4] }
#endif
#ifndef FIX_GetConsoleCharType
    __declspec(naked) void __stdcall fixGetConsoleCharType(void) { __asm jmp dword ptr function_ptrs[491 * 4] }
#endif
#ifndef FIX_GetConsoleCommandHistoryA
    __declspec(naked) void __stdcall fixGetConsoleCommandHistoryA(void) { __asm jmp dword ptr function_ptrs[492 * 4] }
#endif
#ifndef FIX_GetConsoleCommandHistoryLengthA
    __declspec(naked) void __stdcall fixGetConsoleCommandHistoryLengthA(void) { __asm jmp dword ptr function_ptrs[493 * 4] }
#endif
#ifndef FIX_GetConsoleCommandHistoryLengthW
    __declspec(naked) void __stdcall fixGetConsoleCommandHistoryLengthW(void) { __asm jmp dword ptr function_ptrs[494 * 4] }
#endif
#ifndef FIX_GetConsoleCommandHistoryW
    __declspec(naked) void __stdcall fixGetConsoleCommandHistoryW(void) { __asm jmp dword ptr function_ptrs[495 * 4] }
#endif
#ifndef FIX_GetConsoleCursorInfo
    __declspec(naked) void __stdcall fixGetConsoleCursorInfo(void) { __asm jmp dword ptr function_ptrs[496 * 4] }
#endif
#ifndef FIX_GetConsoleCursorMode
    __declspec(naked) void __stdcall fixGetConsoleCursorMode(void) { __asm jmp dword ptr function_ptrs[497 * 4] }
#endif
#ifndef FIX_GetConsoleDisplayMode
    __declspec(naked) void __stdcall fixGetConsoleDisplayMode(void) { __asm jmp dword ptr function_ptrs[498 * 4] }
#endif
#ifndef FIX_GetConsoleFontInfo
    __declspec(naked) void __stdcall fixGetConsoleFontInfo(void) { __asm jmp dword ptr function_ptrs[499 * 4] }
#endif
#ifndef FIX_GetConsoleFontSize
    __declspec(naked) void __stdcall fixGetConsoleFontSize(void) { __asm jmp dword ptr function_ptrs[500 * 4] }
#endif
#ifndef FIX_GetConsoleHardwareState
    __declspec(naked) void __stdcall fixGetConsoleHardwareState(void) { __asm jmp dword ptr function_ptrs[501 * 4] }
#endif
#ifndef FIX_GetConsoleHistoryInfo
    __declspec(naked) void __stdcall fixGetConsoleHistoryInfo(void) { __asm jmp dword ptr function_ptrs[502 * 4] }
#endif
#ifndef FIX_GetConsoleInputExeNameA
    __declspec(naked) void __stdcall fixGetConsoleInputExeNameA(void) { __asm jmp dword ptr function_ptrs[503 * 4] }
#endif
#ifndef FIX_GetConsoleInputExeNameW
    __declspec(naked) void __stdcall fixGetConsoleInputExeNameW(void) { __asm jmp dword ptr function_ptrs[504 * 4] }
#endif
#ifndef FIX_GetConsoleInputWaitHandle
    __declspec(naked) void __stdcall fixGetConsoleInputWaitHandle(void) { __asm jmp dword ptr function_ptrs[505 * 4] }
#endif
#ifndef FIX_GetConsoleKeyboardLayoutNameA
    __declspec(naked) void __stdcall fixGetConsoleKeyboardLayoutNameA(void) { __asm jmp dword ptr function_ptrs[506 * 4] }
#endif
#ifndef FIX_GetConsoleKeyboardLayoutNameW
    __declspec(naked) void __stdcall fixGetConsoleKeyboardLayoutNameW(void) { __asm jmp dword ptr function_ptrs[507 * 4] }
#endif
#ifndef FIX_GetConsoleMode
    __declspec(naked) void __stdcall fixGetConsoleMode(void) { __asm jmp dword ptr function_ptrs[508 * 4] }
#endif
#ifndef FIX_GetConsoleNlsMode
    __declspec(naked) void __stdcall fixGetConsoleNlsMode(void) { __asm jmp dword ptr function_ptrs[509 * 4] }
#endif
#ifndef FIX_GetConsoleOriginalTitleA
    __declspec(naked) void __stdcall fixGetConsoleOriginalTitleA(void) { __asm jmp dword ptr function_ptrs[510 * 4] }
#endif
#ifndef FIX_GetConsoleOriginalTitleW
    __declspec(naked) void __stdcall fixGetConsoleOriginalTitleW(void) { __asm jmp dword ptr function_ptrs[511 * 4] }
#endif
#ifndef FIX_GetConsoleOutputCP
    __declspec(naked) void __stdcall fixGetConsoleOutputCP(void) { __asm jmp dword ptr function_ptrs[512 * 4] }
#endif
#ifndef FIX_GetConsoleProcessList
    __declspec(naked) void __stdcall fixGetConsoleProcessList(void) { __asm jmp dword ptr function_ptrs[513 * 4] }
#endif
#ifndef FIX_GetConsoleScreenBufferInfo
    __declspec(naked) void __stdcall fixGetConsoleScreenBufferInfo(void) { __asm jmp dword ptr function_ptrs[514 * 4] }
#endif
#ifndef FIX_GetConsoleScreenBufferInfoEx
    __declspec(naked) void __stdcall fixGetConsoleScreenBufferInfoEx(void) { __asm jmp dword ptr function_ptrs[515 * 4] }
#endif
#ifndef FIX_GetConsoleSelectionInfo
    __declspec(naked) void __stdcall fixGetConsoleSelectionInfo(void) { __asm jmp dword ptr function_ptrs[516 * 4] }
#endif
#ifndef FIX_GetConsoleTitleA
    __declspec(naked) void __stdcall fixGetConsoleTitleA(void) { __asm jmp dword ptr function_ptrs[517 * 4] }
#endif
#ifndef FIX_GetConsoleTitleW
    __declspec(naked) void __stdcall fixGetConsoleTitleW(void) { __asm jmp dword ptr function_ptrs[518 * 4] }
#endif
#ifndef FIX_GetConsoleWindow
    __declspec(naked) void __stdcall fixGetConsoleWindow(void) { __asm jmp dword ptr function_ptrs[519 * 4] }
#endif
#ifndef FIX_GetCurrencyFormatA
    __declspec(naked) void __stdcall fixGetCurrencyFormatA(void) { __asm jmp dword ptr function_ptrs[520 * 4] }
#endif
#ifndef FIX_GetCurrencyFormatEx
    __declspec(naked) void __stdcall fixGetCurrencyFormatEx(void) { __asm jmp dword ptr function_ptrs[521 * 4] }
#endif
#ifndef FIX_GetCurrencyFormatW
    __declspec(naked) void __stdcall fixGetCurrencyFormatW(void) { __asm jmp dword ptr function_ptrs[522 * 4] }
#endif
#ifndef FIX_GetCurrentActCtx
    __declspec(naked) void __stdcall fixGetCurrentActCtx(void) { __asm jmp dword ptr function_ptrs[523 * 4] }
#endif
#ifndef FIX_GetCurrentActCtxWorker
    __declspec(naked) void __stdcall fixGetCurrentActCtxWorker(void) { __asm jmp dword ptr function_ptrs[524 * 4] }
#endif
#ifndef FIX_GetCurrentApplicationUserModelId
    __declspec(naked) void __stdcall fixGetCurrentApplicationUserModelId(void) { __asm jmp dword ptr function_ptrs[525 * 4] }
#endif
#ifndef FIX_GetCurrentConsoleFont
    __declspec(naked) void __stdcall fixGetCurrentConsoleFont(void) { __asm jmp dword ptr function_ptrs[526 * 4] }
#endif
#ifndef FIX_GetCurrentConsoleFontEx
    __declspec(naked) void __stdcall fixGetCurrentConsoleFontEx(void) { __asm jmp dword ptr function_ptrs[527 * 4] }
#endif
#ifndef FIX_GetCurrentDirectoryA
    __declspec(naked) void __stdcall fixGetCurrentDirectoryA(void) { __asm jmp dword ptr function_ptrs[528 * 4] }
#endif
#ifndef FIX_GetCurrentDirectoryW
    __declspec(naked) void __stdcall fixGetCurrentDirectoryW(void) { __asm jmp dword ptr function_ptrs[529 * 4] }
#endif
#ifndef FIX_GetCurrentPackageFamilyName
    __declspec(naked) void __stdcall fixGetCurrentPackageFamilyName(void) { __asm jmp dword ptr function_ptrs[530 * 4] }
#endif
#ifndef FIX_GetCurrentPackageFullName
    __declspec(naked) void __stdcall fixGetCurrentPackageFullName(void) { __asm jmp dword ptr function_ptrs[531 * 4] }
#endif
#ifndef FIX_GetCurrentPackageId
    __declspec(naked) void __stdcall fixGetCurrentPackageId(void) { __asm jmp dword ptr function_ptrs[532 * 4] }
#endif
#ifndef FIX_GetCurrentPackageInfo
    __declspec(naked) void __stdcall fixGetCurrentPackageInfo(void) { __asm jmp dword ptr function_ptrs[533 * 4] }
#endif
#ifndef FIX_GetCurrentPackagePath
    __declspec(naked) void __stdcall fixGetCurrentPackagePath(void) { __asm jmp dword ptr function_ptrs[534 * 4] }
#endif
#ifndef FIX_GetCurrentProcess
    __declspec(naked) void __stdcall fixGetCurrentProcess(void) { __asm jmp dword ptr function_ptrs[535 * 4] }
#endif
#ifndef FIX_GetCurrentProcessId
    __declspec(naked) void __stdcall fixGetCurrentProcessId(void) { __asm jmp dword ptr function_ptrs[536 * 4] }
#endif
#ifndef FIX_GetCurrentProcessorNumber
    __declspec(naked) void __stdcall fixGetCurrentProcessorNumber(void) { __asm jmp dword ptr function_ptrs[537 * 4] }
#endif
#ifndef FIX_GetCurrentProcessorNumberEx
    __declspec(naked) void __stdcall fixGetCurrentProcessorNumberEx(void) { __asm jmp dword ptr function_ptrs[538 * 4] }
#endif
#ifndef FIX_GetCurrentThread
    __declspec(naked) void __stdcall fixGetCurrentThread(void) { __asm jmp dword ptr function_ptrs[539 * 4] }
#endif
#ifndef FIX_GetCurrentThreadId
    __declspec(naked) void __stdcall fixGetCurrentThreadId(void) { __asm jmp dword ptr function_ptrs[540 * 4] }
#endif
#ifndef FIX_GetCurrentThreadStackLimits
    __declspec(naked) void __stdcall fixGetCurrentThreadStackLimits(void) { __asm jmp dword ptr function_ptrs[541 * 4] }
#endif
#ifndef FIX_GetDateFormatA
    __declspec(naked) void __stdcall fixGetDateFormatA(void) { __asm jmp dword ptr function_ptrs[542 * 4] }
#endif
#ifndef FIX_GetDateFormatAWorker
    __declspec(naked) void __stdcall fixGetDateFormatAWorker(void) { __asm jmp dword ptr function_ptrs[543 * 4] }
#endif
#ifndef FIX_GetDateFormatEx
    __declspec(naked) void __stdcall fixGetDateFormatEx(void) { __asm jmp dword ptr function_ptrs[544 * 4] }
#endif
#ifndef FIX_GetDateFormatW
    __declspec(naked) void __stdcall fixGetDateFormatW(void) { __asm jmp dword ptr function_ptrs[545 * 4] }
#endif
#ifndef FIX_GetDateFormatWWorker
    __declspec(naked) void __stdcall fixGetDateFormatWWorker(void) { __asm jmp dword ptr function_ptrs[546 * 4] }
#endif
#ifndef FIX_GetDefaultCommConfigA
    __declspec(naked) void __stdcall fixGetDefaultCommConfigA(void) { __asm jmp dword ptr function_ptrs[547 * 4] }
#endif
#ifndef FIX_GetDefaultCommConfigW
    __declspec(naked) void __stdcall fixGetDefaultCommConfigW(void) { __asm jmp dword ptr function_ptrs[548 * 4] }
#endif
#ifndef FIX_GetDevicePowerState
    __declspec(naked) void __stdcall fixGetDevicePowerState(void) { __asm jmp dword ptr function_ptrs[549 * 4] }
#endif
#ifndef FIX_GetDiskFreeSpaceA
    __declspec(naked) void __stdcall fixGetDiskFreeSpaceA(void) { __asm jmp dword ptr function_ptrs[550 * 4] }
#endif
#ifndef FIX_GetDiskFreeSpaceExA
    __declspec(naked) void __stdcall fixGetDiskFreeSpaceExA(void) { __asm jmp dword ptr function_ptrs[551 * 4] }
#endif
#ifndef FIX_GetDiskFreeSpaceExW
    __declspec(naked) void __stdcall fixGetDiskFreeSpaceExW(void) { __asm jmp dword ptr function_ptrs[552 * 4] }
#endif
#ifndef FIX_GetDiskFreeSpaceW
    __declspec(naked) void __stdcall fixGetDiskFreeSpaceW(void) { __asm jmp dword ptr function_ptrs[553 * 4] }
#endif
#ifndef FIX_GetDiskSpaceInformationA
    __declspec(naked) void __stdcall fixGetDiskSpaceInformationA(void) { __asm jmp dword ptr function_ptrs[554 * 4] }
#endif
#ifndef FIX_GetDiskSpaceInformationW
    __declspec(naked) void __stdcall fixGetDiskSpaceInformationW(void) { __asm jmp dword ptr function_ptrs[555 * 4] }
#endif
#ifndef FIX_GetDllDirectoryA
    __declspec(naked) void __stdcall fixGetDllDirectoryA(void) { __asm jmp dword ptr function_ptrs[556 * 4] }
#endif
#ifndef FIX_GetDllDirectoryW
    __declspec(naked) void __stdcall fixGetDllDirectoryW(void) { __asm jmp dword ptr function_ptrs[557 * 4] }
#endif
#ifndef FIX_GetDriveTypeA
    __declspec(naked) void __stdcall fixGetDriveTypeA(void) { __asm jmp dword ptr function_ptrs[558 * 4] }
#endif
#ifndef FIX_GetDriveTypeW
    __declspec(naked) void __stdcall fixGetDriveTypeW(void) { __asm jmp dword ptr function_ptrs[559 * 4] }
#endif
#ifndef FIX_GetDurationFormat
    __declspec(naked) void __stdcall fixGetDurationFormat(void) { __asm jmp dword ptr function_ptrs[560 * 4] }
#endif
#ifndef FIX_GetDurationFormatEx
    __declspec(naked) void __stdcall fixGetDurationFormatEx(void) { __asm jmp dword ptr function_ptrs[561 * 4] }
#endif
#ifndef FIX_GetDynamicTimeZoneInformation
    __declspec(naked) void __stdcall fixGetDynamicTimeZoneInformation(void) { __asm jmp dword ptr function_ptrs[562 * 4] }
#endif
#ifndef FIX_GetEnabledXStateFeatures
    __declspec(naked) void __stdcall fixGetEnabledXStateFeatures(void) { __asm jmp dword ptr function_ptrs[563 * 4] }
#endif
#ifndef FIX_GetEncryptedFileVersionExt
    __declspec(naked) void __stdcall fixGetEncryptedFileVersionExt(void) { __asm jmp dword ptr function_ptrs[564 * 4] }
#endif
#ifndef FIX_GetEnvironmentStrings
    __declspec(naked) void __stdcall fixGetEnvironmentStrings(void) { __asm jmp dword ptr function_ptrs[565 * 4] }
#endif
#ifndef FIX_GetEnvironmentStringsA
    __declspec(naked) void __stdcall fixGetEnvironmentStringsA(void) { __asm jmp dword ptr function_ptrs[566 * 4] }
#endif
#ifndef FIX_GetEnvironmentStringsW
    __declspec(naked) void __stdcall fixGetEnvironmentStringsW(void) { __asm jmp dword ptr function_ptrs[567 * 4] }
#endif
#ifndef FIX_GetEnvironmentVariableA
    __declspec(naked) void __stdcall fixGetEnvironmentVariableA(void) { __asm jmp dword ptr function_ptrs[568 * 4] }
#endif
#ifndef FIX_GetEnvironmentVariableW
    __declspec(naked) void __stdcall fixGetEnvironmentVariableW(void) { __asm jmp dword ptr function_ptrs[569 * 4] }
#endif
#ifndef FIX_GetEraNameCountedString
    __declspec(naked) void __stdcall fixGetEraNameCountedString(void) { __asm jmp dword ptr function_ptrs[570 * 4] }
#endif
#ifndef FIX_GetErrorMode
    __declspec(naked) void __stdcall fixGetErrorMode(void) { __asm jmp dword ptr function_ptrs[571 * 4] }
#endif
#ifndef FIX_GetExitCodeProcess
    __declspec(naked) void __stdcall fixGetExitCodeProcess(void) { __asm jmp dword ptr function_ptrs[572 * 4] }
#endif
#ifndef FIX_GetExitCodeThread
    __declspec(naked) void __stdcall fixGetExitCodeThread(void) { __asm jmp dword ptr function_ptrs[573 * 4] }
#endif
#ifndef FIX_GetExpandedNameA
    __declspec(naked) void __stdcall fixGetExpandedNameA(void) { __asm jmp dword ptr function_ptrs[574 * 4] }
#endif
#ifndef FIX_GetExpandedNameW
    __declspec(naked) void __stdcall fixGetExpandedNameW(void) { __asm jmp dword ptr function_ptrs[575 * 4] }
#endif
#ifndef FIX_GetFileAttributesA
    __declspec(naked) void __stdcall fixGetFileAttributesA(void) { __asm jmp dword ptr function_ptrs[576 * 4] }
#endif
#ifndef FIX_GetFileAttributesExA
    __declspec(naked) void __stdcall fixGetFileAttributesExA(void) { __asm jmp dword ptr function_ptrs[577 * 4] }
#endif
#ifndef FIX_GetFileAttributesExW
    __declspec(naked) void __stdcall fixGetFileAttributesExW(void) { __asm jmp dword ptr function_ptrs[578 * 4] }
#endif
#ifndef FIX_GetFileAttributesTransactedA
    __declspec(naked) void __stdcall fixGetFileAttributesTransactedA(void) { __asm jmp dword ptr function_ptrs[579 * 4] }
#endif
#ifndef FIX_GetFileAttributesTransactedW
    __declspec(naked) void __stdcall fixGetFileAttributesTransactedW(void) { __asm jmp dword ptr function_ptrs[580 * 4] }
#endif
#ifndef FIX_GetFileAttributesW
    __declspec(naked) void __stdcall fixGetFileAttributesW(void) { __asm jmp dword ptr function_ptrs[581 * 4] }
#endif
#ifndef FIX_GetFileBandwidthReservation
    __declspec(naked) void __stdcall fixGetFileBandwidthReservation(void) { __asm jmp dword ptr function_ptrs[582 * 4] }
#endif
#ifndef FIX_GetFileInformationByHandle
    __declspec(naked) void __stdcall fixGetFileInformationByHandle(void) { __asm jmp dword ptr function_ptrs[583 * 4] }
#endif
#ifndef FIX_GetFileInformationByHandleEx
    __declspec(naked) void __stdcall fixGetFileInformationByHandleEx(void) { __asm jmp dword ptr function_ptrs[584 * 4] }
#endif
#ifndef FIX_GetFileMUIInfo
    __declspec(naked) void __stdcall fixGetFileMUIInfo(void) { __asm jmp dword ptr function_ptrs[585 * 4] }
#endif
#ifndef FIX_GetFileMUIPath
    __declspec(naked) void __stdcall fixGetFileMUIPath(void) { __asm jmp dword ptr function_ptrs[586 * 4] }
#endif
#ifndef FIX_GetFileSize
    __declspec(naked) void __stdcall fixGetFileSize(void) { __asm jmp dword ptr function_ptrs[587 * 4] }
#endif
#ifndef FIX_GetFileSizeEx
    __declspec(naked) void __stdcall fixGetFileSizeEx(void) { __asm jmp dword ptr function_ptrs[588 * 4] }
#endif
#ifndef FIX_GetFileTime
    __declspec(naked) void __stdcall fixGetFileTime(void) { __asm jmp dword ptr function_ptrs[589 * 4] }
#endif
#ifndef FIX_GetFileType
    __declspec(naked) void __stdcall fixGetFileType(void) { __asm jmp dword ptr function_ptrs[590 * 4] }
#endif
#ifndef FIX_GetFinalPathNameByHandleA
    __declspec(naked) void __stdcall fixGetFinalPathNameByHandleA(void) { __asm jmp dword ptr function_ptrs[591 * 4] }
#endif
#ifndef FIX_GetFinalPathNameByHandleW
    __declspec(naked) void __stdcall fixGetFinalPathNameByHandleW(void) { __asm jmp dword ptr function_ptrs[592 * 4] }
#endif
#ifndef FIX_GetFirmwareEnvironmentVariableA
    __declspec(naked) void __stdcall fixGetFirmwareEnvironmentVariableA(void) { __asm jmp dword ptr function_ptrs[593 * 4] }
#endif
#ifndef FIX_GetFirmwareEnvironmentVariableExA
    __declspec(naked) void __stdcall fixGetFirmwareEnvironmentVariableExA(void) { __asm jmp dword ptr function_ptrs[594 * 4] }
#endif
#ifndef FIX_GetFirmwareEnvironmentVariableExW
    __declspec(naked) void __stdcall fixGetFirmwareEnvironmentVariableExW(void) { __asm jmp dword ptr function_ptrs[595 * 4] }
#endif
#ifndef FIX_GetFirmwareEnvironmentVariableW
    __declspec(naked) void __stdcall fixGetFirmwareEnvironmentVariableW(void) { __asm jmp dword ptr function_ptrs[596 * 4] }
#endif
#ifndef FIX_GetFirmwareType
    __declspec(naked) void __stdcall fixGetFirmwareType(void) { __asm jmp dword ptr function_ptrs[597 * 4] }
#endif
#ifndef FIX_GetFullPathNameA
    __declspec(naked) void __stdcall fixGetFullPathNameA(void) { __asm jmp dword ptr function_ptrs[598 * 4] }
#endif
#ifndef FIX_GetFullPathNameTransactedA
    __declspec(naked) void __stdcall fixGetFullPathNameTransactedA(void) { __asm jmp dword ptr function_ptrs[599 * 4] }
#endif
#ifndef FIX_GetFullPathNameTransactedW
    __declspec(naked) void __stdcall fixGetFullPathNameTransactedW(void) { __asm jmp dword ptr function_ptrs[600 * 4] }
#endif
#ifndef FIX_GetFullPathNameW
    __declspec(naked) void __stdcall fixGetFullPathNameW(void) { __asm jmp dword ptr function_ptrs[601 * 4] }
#endif
#ifndef FIX_GetGeoInfoA
    __declspec(naked) void __stdcall fixGetGeoInfoA(void) { __asm jmp dword ptr function_ptrs[602 * 4] }
#endif
#ifndef FIX_GetGeoInfoEx
    __declspec(naked) void __stdcall fixGetGeoInfoEx(void) { __asm jmp dword ptr function_ptrs[603 * 4] }
#endif
#ifndef FIX_GetGeoInfoW
    __declspec(naked) void __stdcall fixGetGeoInfoW(void) { __asm jmp dword ptr function_ptrs[604 * 4] }
#endif
#ifndef FIX_GetHandleContext
    __declspec(naked) void __stdcall fixGetHandleContext(void) { __asm jmp dword ptr function_ptrs[605 * 4] }
#endif
#ifndef FIX_GetHandleInformation
    __declspec(naked) void __stdcall fixGetHandleInformation(void) { __asm jmp dword ptr function_ptrs[606 * 4] }
#endif
#ifndef FIX_GetLargePageMinimum
    __declspec(naked) void __stdcall fixGetLargePageMinimum(void) { __asm jmp dword ptr function_ptrs[607 * 4] }
#endif
#ifndef FIX_GetLargestConsoleWindowSize
    __declspec(naked) void __stdcall fixGetLargestConsoleWindowSize(void) { __asm jmp dword ptr function_ptrs[608 * 4] }
#endif
#ifndef FIX_GetLastError
    __declspec(naked) void __stdcall fixGetLastError(void) { __asm jmp dword ptr function_ptrs[609 * 4] }
#endif
#ifndef FIX_GetLocalTime
    __declspec(naked) void __stdcall fixGetLocalTime(void) { __asm jmp dword ptr function_ptrs[610 * 4] }
#endif
#ifndef FIX_GetLocaleInfoA
    __declspec(naked) void __stdcall fixGetLocaleInfoA(void) { __asm jmp dword ptr function_ptrs[611 * 4] }
#endif
#ifndef FIX_GetLocaleInfoEx
    __declspec(naked) void __stdcall fixGetLocaleInfoEx(void) { __asm jmp dword ptr function_ptrs[612 * 4] }
#endif
#ifndef FIX_GetLocaleInfoW
    __declspec(naked) void __stdcall fixGetLocaleInfoW(void) { __asm jmp dword ptr function_ptrs[613 * 4] }
#endif
#ifndef FIX_GetLogicalDriveStringsA
    __declspec(naked) void __stdcall fixGetLogicalDriveStringsA(void) { __asm jmp dword ptr function_ptrs[614 * 4] }
#endif
#ifndef FIX_GetLogicalDriveStringsW
    __declspec(naked) void __stdcall fixGetLogicalDriveStringsW(void) { __asm jmp dword ptr function_ptrs[615 * 4] }
#endif
#ifndef FIX_GetLogicalDrives
    __declspec(naked) void __stdcall fixGetLogicalDrives(void) { __asm jmp dword ptr function_ptrs[616 * 4] }
#endif
#ifndef FIX_GetLogicalProcessorInformation
    __declspec(naked) void __stdcall fixGetLogicalProcessorInformation(void) { __asm jmp dword ptr function_ptrs[617 * 4] }
#endif
#ifndef FIX_GetLogicalProcessorInformationEx
    __declspec(naked) void __stdcall fixGetLogicalProcessorInformationEx(void) { __asm jmp dword ptr function_ptrs[618 * 4] }
#endif
#ifndef FIX_GetLongPathNameA
    __declspec(naked) void __stdcall fixGetLongPathNameA(void) { __asm jmp dword ptr function_ptrs[619 * 4] }
#endif
#ifndef FIX_GetLongPathNameTransactedA
    __declspec(naked) void __stdcall fixGetLongPathNameTransactedA(void) { __asm jmp dword ptr function_ptrs[620 * 4] }
#endif
#ifndef FIX_GetLongPathNameTransactedW
    __declspec(naked) void __stdcall fixGetLongPathNameTransactedW(void) { __asm jmp dword ptr function_ptrs[621 * 4] }
#endif
#ifndef FIX_GetLongPathNameW
    __declspec(naked) void __stdcall fixGetLongPathNameW(void) { __asm jmp dword ptr function_ptrs[622 * 4] }
#endif
#ifndef FIX_GetMailslotInfo
    __declspec(naked) void __stdcall fixGetMailslotInfo(void) { __asm jmp dword ptr function_ptrs[623 * 4] }
#endif
#ifndef FIX_GetMaximumProcessorCount
    __declspec(naked) void __stdcall fixGetMaximumProcessorCount(void) { __asm jmp dword ptr function_ptrs[624 * 4] }
#endif
#ifndef FIX_GetMaximumProcessorGroupCount
    __declspec(naked) void __stdcall fixGetMaximumProcessorGroupCount(void) { __asm jmp dword ptr function_ptrs[625 * 4] }
#endif
#ifndef FIX_GetMemoryErrorHandlingCapabilities
    __declspec(naked) void __stdcall fixGetMemoryErrorHandlingCapabilities(void) { __asm jmp dword ptr function_ptrs[626 * 4] }
#endif
#ifndef FIX_GetModuleFileNameA
    __declspec(naked) void __stdcall fixGetModuleFileNameA(void) { __asm jmp dword ptr function_ptrs[627 * 4] }
#endif
#ifndef FIX_GetModuleFileNameW
    __declspec(naked) void __stdcall fixGetModuleFileNameW(void) { __asm jmp dword ptr function_ptrs[628 * 4] }
#endif
#ifndef FIX_GetModuleHandleA
    __declspec(naked) void __stdcall fixGetModuleHandleA(void) { __asm jmp dword ptr function_ptrs[629 * 4] }
#endif
#ifndef FIX_GetModuleHandleExA
    __declspec(naked) void __stdcall fixGetModuleHandleExA(void) { __asm jmp dword ptr function_ptrs[630 * 4] }
#endif
#ifndef FIX_GetModuleHandleExW
    __declspec(naked) void __stdcall fixGetModuleHandleExW(void) { __asm jmp dword ptr function_ptrs[631 * 4] }
#endif
#ifndef FIX_GetModuleHandleW
    __declspec(naked) void __stdcall fixGetModuleHandleW(void) { __asm jmp dword ptr function_ptrs[632 * 4] }
#endif
#ifndef FIX_GetNLSVersion
    __declspec(naked) void __stdcall fixGetNLSVersion(void) { __asm jmp dword ptr function_ptrs[633 * 4] }
#endif
#ifndef FIX_GetNLSVersionEx
    __declspec(naked) void __stdcall fixGetNLSVersionEx(void) { __asm jmp dword ptr function_ptrs[634 * 4] }
#endif
#ifndef FIX_GetNamedPipeAttribute
    __declspec(naked) void __stdcall fixGetNamedPipeAttribute(void) { __asm jmp dword ptr function_ptrs[635 * 4] }
#endif
#ifndef FIX_GetNamedPipeClientComputerNameA
    __declspec(naked) void __stdcall fixGetNamedPipeClientComputerNameA(void) { __asm jmp dword ptr function_ptrs[636 * 4] }
#endif
#ifndef FIX_GetNamedPipeClientComputerNameW
    __declspec(naked) void __stdcall fixGetNamedPipeClientComputerNameW(void) { __asm jmp dword ptr function_ptrs[637 * 4] }
#endif
#ifndef FIX_GetNamedPipeClientProcessId
    __declspec(naked) void __stdcall fixGetNamedPipeClientProcessId(void) { __asm jmp dword ptr function_ptrs[638 * 4] }
#endif
#ifndef FIX_GetNamedPipeClientSessionId
    __declspec(naked) void __stdcall fixGetNamedPipeClientSessionId(void) { __asm jmp dword ptr function_ptrs[639 * 4] }
#endif
#ifndef FIX_GetNamedPipeHandleStateA
    __declspec(naked) void __stdcall fixGetNamedPipeHandleStateA(void) { __asm jmp dword ptr function_ptrs[640 * 4] }
#endif
#ifndef FIX_GetNamedPipeHandleStateW
    __declspec(naked) void __stdcall fixGetNamedPipeHandleStateW(void) { __asm jmp dword ptr function_ptrs[641 * 4] }
#endif
#ifndef FIX_GetNamedPipeInfo
    __declspec(naked) void __stdcall fixGetNamedPipeInfo(void) { __asm jmp dword ptr function_ptrs[642 * 4] }
#endif
#ifndef FIX_GetNamedPipeServerProcessId
    __declspec(naked) void __stdcall fixGetNamedPipeServerProcessId(void) { __asm jmp dword ptr function_ptrs[643 * 4] }
#endif
#ifndef FIX_GetNamedPipeServerSessionId
    __declspec(naked) void __stdcall fixGetNamedPipeServerSessionId(void) { __asm jmp dword ptr function_ptrs[644 * 4] }
#endif
#ifndef FIX_GetNativeSystemInfo
    __declspec(naked) void __stdcall fixGetNativeSystemInfo(void) { __asm jmp dword ptr function_ptrs[645 * 4] }
#endif
#ifndef FIX_GetNextVDMCommand
    __declspec(naked) void __stdcall fixGetNextVDMCommand(void) { __asm jmp dword ptr function_ptrs[646 * 4] }
#endif
#ifndef FIX_GetNumaAvailableMemoryNode
    __declspec(naked) void __stdcall fixGetNumaAvailableMemoryNode(void) { __asm jmp dword ptr function_ptrs[647 * 4] }
#endif
#ifndef FIX_GetNumaAvailableMemoryNodeEx
    __declspec(naked) void __stdcall fixGetNumaAvailableMemoryNodeEx(void) { __asm jmp dword ptr function_ptrs[648 * 4] }
#endif
#ifndef FIX_GetNumaHighestNodeNumber
    __declspec(naked) void __stdcall fixGetNumaHighestNodeNumber(void) { __asm jmp dword ptr function_ptrs[649 * 4] }
#endif
#ifndef FIX_GetNumaNodeNumberFromHandle
    __declspec(naked) void __stdcall fixGetNumaNodeNumberFromHandle(void) { __asm jmp dword ptr function_ptrs[650 * 4] }
#endif
#ifndef FIX_GetNumaNodeProcessorMask
    __declspec(naked) void __stdcall fixGetNumaNodeProcessorMask(void) { __asm jmp dword ptr function_ptrs[651 * 4] }
#endif
#ifndef FIX_GetNumaNodeProcessorMaskEx
    __declspec(naked) void __stdcall fixGetNumaNodeProcessorMaskEx(void) { __asm jmp dword ptr function_ptrs[652 * 4] }
#endif
#ifndef FIX_GetNumaProcessorNode
    __declspec(naked) void __stdcall fixGetNumaProcessorNode(void) { __asm jmp dword ptr function_ptrs[653 * 4] }
#endif
#ifndef FIX_GetNumaProcessorNodeEx
    __declspec(naked) void __stdcall fixGetNumaProcessorNodeEx(void) { __asm jmp dword ptr function_ptrs[654 * 4] }
#endif
#ifndef FIX_GetNumaProximityNode
    __declspec(naked) void __stdcall fixGetNumaProximityNode(void) { __asm jmp dword ptr function_ptrs[655 * 4] }
#endif
#ifndef FIX_GetNumaProximityNodeEx
    __declspec(naked) void __stdcall fixGetNumaProximityNodeEx(void) { __asm jmp dword ptr function_ptrs[656 * 4] }
#endif
#ifndef FIX_GetNumberFormatA
    __declspec(naked) void __stdcall fixGetNumberFormatA(void) { __asm jmp dword ptr function_ptrs[657 * 4] }
#endif
#ifndef FIX_GetNumberFormatEx
    __declspec(naked) void __stdcall fixGetNumberFormatEx(void) { __asm jmp dword ptr function_ptrs[658 * 4] }
#endif
#ifndef FIX_GetNumberFormatW
    __declspec(naked) void __stdcall fixGetNumberFormatW(void) { __asm jmp dword ptr function_ptrs[659 * 4] }
#endif
#ifndef FIX_GetNumberOfConsoleFonts
    __declspec(naked) void __stdcall fixGetNumberOfConsoleFonts(void) { __asm jmp dword ptr function_ptrs[660 * 4] }
#endif
#ifndef FIX_GetNumberOfConsoleInputEvents
    __declspec(naked) void __stdcall fixGetNumberOfConsoleInputEvents(void) { __asm jmp dword ptr function_ptrs[661 * 4] }
#endif
#ifndef FIX_GetNumberOfConsoleMouseButtons
    __declspec(naked) void __stdcall fixGetNumberOfConsoleMouseButtons(void) { __asm jmp dword ptr function_ptrs[662 * 4] }
#endif
#ifndef FIX_GetOEMCP
    __declspec(naked) void __stdcall fixGetOEMCP(void) { __asm jmp dword ptr function_ptrs[663 * 4] }
#endif
#ifndef FIX_GetOverlappedResult
    __declspec(naked) void __stdcall fixGetOverlappedResult(void) { __asm jmp dword ptr function_ptrs[664 * 4] }
#endif
#ifndef FIX_GetOverlappedResultEx
    __declspec(naked) void __stdcall fixGetOverlappedResultEx(void) { __asm jmp dword ptr function_ptrs[665 * 4] }
#endif
#ifndef FIX_GetPackageApplicationIds
    __declspec(naked) void __stdcall fixGetPackageApplicationIds(void) { __asm jmp dword ptr function_ptrs[666 * 4] }
#endif
#ifndef FIX_GetPackageFamilyName
    __declspec(naked) void __stdcall fixGetPackageFamilyName(void) { __asm jmp dword ptr function_ptrs[667 * 4] }
#endif
#ifndef FIX_GetPackageFullName
    __declspec(naked) void __stdcall fixGetPackageFullName(void) { __asm jmp dword ptr function_ptrs[668 * 4] }
#endif
#ifndef FIX_GetPackageId
    __declspec(naked) void __stdcall fixGetPackageId(void) { __asm jmp dword ptr function_ptrs[669 * 4] }
#endif
#ifndef FIX_GetPackageInfo
    __declspec(naked) void __stdcall fixGetPackageInfo(void) { __asm jmp dword ptr function_ptrs[670 * 4] }
#endif
#ifndef FIX_GetPackagePath
    __declspec(naked) void __stdcall fixGetPackagePath(void) { __asm jmp dword ptr function_ptrs[671 * 4] }
#endif
#ifndef FIX_GetPackagePathByFullName
    __declspec(naked) void __stdcall fixGetPackagePathByFullName(void) { __asm jmp dword ptr function_ptrs[672 * 4] }
#endif
#ifndef FIX_GetPackagesByPackageFamily
    __declspec(naked) void __stdcall fixGetPackagesByPackageFamily(void) { __asm jmp dword ptr function_ptrs[673 * 4] }
#endif
#ifndef FIX_GetPhysicallyInstalledSystemMemory
    __declspec(naked) void __stdcall fixGetPhysicallyInstalledSystemMemory(void) { __asm jmp dword ptr function_ptrs[674 * 4] }
#endif
#ifndef FIX_GetPriorityClass
    __declspec(naked) void __stdcall fixGetPriorityClass(void) { __asm jmp dword ptr function_ptrs[675 * 4] }
#endif
#ifndef FIX_GetPrivateProfileIntA
    __declspec(naked) void __stdcall fixGetPrivateProfileIntA(void) { __asm jmp dword ptr function_ptrs[676 * 4] }
#endif
#ifndef FIX_GetPrivateProfileIntW
    __declspec(naked) void __stdcall fixGetPrivateProfileIntW(void) { __asm jmp dword ptr function_ptrs[677 * 4] }
#endif
#ifndef FIX_GetPrivateProfileSectionA
    __declspec(naked) void __stdcall fixGetPrivateProfileSectionA(void) { __asm jmp dword ptr function_ptrs[678 * 4] }
#endif
#ifndef FIX_GetPrivateProfileSectionNamesA
    __declspec(naked) void __stdcall fixGetPrivateProfileSectionNamesA(void) { __asm jmp dword ptr function_ptrs[679 * 4] }
#endif
#ifndef FIX_GetPrivateProfileSectionNamesW
    __declspec(naked) void __stdcall fixGetPrivateProfileSectionNamesW(void) { __asm jmp dword ptr function_ptrs[680 * 4] }
#endif
#ifndef FIX_GetPrivateProfileSectionW
    __declspec(naked) void __stdcall fixGetPrivateProfileSectionW(void) { __asm jmp dword ptr function_ptrs[681 * 4] }
#endif
#ifndef FIX_GetPrivateProfileStringA
    __declspec(naked) void __stdcall fixGetPrivateProfileStringA(void) { __asm jmp dword ptr function_ptrs[682 * 4] }
#endif
#ifndef FIX_GetPrivateProfileStringW
    __declspec(naked) void __stdcall fixGetPrivateProfileStringW(void) { __asm jmp dword ptr function_ptrs[683 * 4] }
#endif
#ifndef FIX_GetPrivateProfileStructA
    __declspec(naked) void __stdcall fixGetPrivateProfileStructA(void) { __asm jmp dword ptr function_ptrs[684 * 4] }
#endif
#ifndef FIX_GetPrivateProfileStructW
    __declspec(naked) void __stdcall fixGetPrivateProfileStructW(void) { __asm jmp dword ptr function_ptrs[685 * 4] }
#endif
#ifndef FIX_GetProcAddress
    __declspec(naked) void __stdcall fixGetProcAddress(void) { __asm jmp dword ptr function_ptrs[686 * 4] }
#endif
#ifndef FIX_GetProcessAffinityMask
    __declspec(naked) void __stdcall fixGetProcessAffinityMask(void) { __asm jmp dword ptr function_ptrs[687 * 4] }
#endif
#ifndef FIX_GetProcessDEPPolicy
    __declspec(naked) void __stdcall fixGetProcessDEPPolicy(void) { __asm jmp dword ptr function_ptrs[688 * 4] }
#endif
#ifndef FIX_GetProcessDefaultCpuSets
    __declspec(naked) void __stdcall fixGetProcessDefaultCpuSets(void) { __asm jmp dword ptr function_ptrs[689 * 4] }
#endif
#ifndef FIX_GetProcessGroupAffinity
    __declspec(naked) void __stdcall fixGetProcessGroupAffinity(void) { __asm jmp dword ptr function_ptrs[690 * 4] }
#endif
#ifndef FIX_GetProcessHandleCount
    __declspec(naked) void __stdcall fixGetProcessHandleCount(void) { __asm jmp dword ptr function_ptrs[691 * 4] }
#endif
#ifndef FIX_GetProcessHeap
    __declspec(naked) void __stdcall fixGetProcessHeap(void) { __asm jmp dword ptr function_ptrs[692 * 4] }
#endif
#ifndef FIX_GetProcessHeaps
    __declspec(naked) void __stdcall fixGetProcessHeaps(void) { __asm jmp dword ptr function_ptrs[693 * 4] }
#endif
#ifndef FIX_GetProcessId
    __declspec(naked) void __stdcall fixGetProcessId(void) { __asm jmp dword ptr function_ptrs[694 * 4] }
#endif
#ifndef FIX_GetProcessIdOfThread
    __declspec(naked) void __stdcall fixGetProcessIdOfThread(void) { __asm jmp dword ptr function_ptrs[695 * 4] }
#endif
#ifndef FIX_GetProcessInformation
    __declspec(naked) void __stdcall fixGetProcessInformation(void) { __asm jmp dword ptr function_ptrs[696 * 4] }
#endif
#ifndef FIX_GetProcessIoCounters
    __declspec(naked) void __stdcall fixGetProcessIoCounters(void) { __asm jmp dword ptr function_ptrs[697 * 4] }
#endif
#ifndef FIX_GetProcessMitigationPolicy
    __declspec(naked) void __stdcall fixGetProcessMitigationPolicy(void) { __asm jmp dword ptr function_ptrs[698 * 4] }
#endif
#ifndef FIX_GetProcessPreferredUILanguages
    __declspec(naked) void __stdcall fixGetProcessPreferredUILanguages(void) { __asm jmp dword ptr function_ptrs[699 * 4] }
#endif
#ifndef FIX_GetProcessPriorityBoost
    __declspec(naked) void __stdcall fixGetProcessPriorityBoost(void) { __asm jmp dword ptr function_ptrs[700 * 4] }
#endif
#ifndef FIX_GetProcessShutdownParameters
    __declspec(naked) void __stdcall fixGetProcessShutdownParameters(void) { __asm jmp dword ptr function_ptrs[701 * 4] }
#endif
#ifndef FIX_GetProcessTimes
    __declspec(naked) void __stdcall fixGetProcessTimes(void) { __asm jmp dword ptr function_ptrs[702 * 4] }
#endif
#ifndef FIX_GetProcessVersion
    __declspec(naked) void __stdcall fixGetProcessVersion(void) { __asm jmp dword ptr function_ptrs[703 * 4] }
#endif
#ifndef FIX_GetProcessWorkingSetSize
    __declspec(naked) void __stdcall fixGetProcessWorkingSetSize(void) { __asm jmp dword ptr function_ptrs[704 * 4] }
#endif
#ifndef FIX_GetProcessWorkingSetSizeEx
    __declspec(naked) void __stdcall fixGetProcessWorkingSetSizeEx(void) { __asm jmp dword ptr function_ptrs[705 * 4] }
#endif
#ifndef FIX_GetProcessorSystemCycleTime
    __declspec(naked) void __stdcall fixGetProcessorSystemCycleTime(void) { __asm jmp dword ptr function_ptrs[706 * 4] }
#endif
#ifndef FIX_GetProductInfo
    __declspec(naked) void __stdcall fixGetProductInfo(void) { __asm jmp dword ptr function_ptrs[707 * 4] }
#endif
#ifndef FIX_GetProfileIntA
    __declspec(naked) void __stdcall fixGetProfileIntA(void) { __asm jmp dword ptr function_ptrs[708 * 4] }
#endif
#ifndef FIX_GetProfileIntW
    __declspec(naked) void __stdcall fixGetProfileIntW(void) { __asm jmp dword ptr function_ptrs[709 * 4] }
#endif
#ifndef FIX_GetProfileSectionA
    __declspec(naked) void __stdcall fixGetProfileSectionA(void) { __asm jmp dword ptr function_ptrs[710 * 4] }
#endif
#ifndef FIX_GetProfileSectionW
    __declspec(naked) void __stdcall fixGetProfileSectionW(void) { __asm jmp dword ptr function_ptrs[711 * 4] }
#endif
#ifndef FIX_GetProfileStringA
    __declspec(naked) void __stdcall fixGetProfileStringA(void) { __asm jmp dword ptr function_ptrs[712 * 4] }
#endif
#ifndef FIX_GetProfileStringW
    __declspec(naked) void __stdcall fixGetProfileStringW(void) { __asm jmp dword ptr function_ptrs[713 * 4] }
#endif
#ifndef FIX_GetQueuedCompletionStatus
    __declspec(naked) void __stdcall fixGetQueuedCompletionStatus(void) { __asm jmp dword ptr function_ptrs[714 * 4] }
#endif
#ifndef FIX_GetQueuedCompletionStatusEx
    __declspec(naked) void __stdcall fixGetQueuedCompletionStatusEx(void) { __asm jmp dword ptr function_ptrs[715 * 4] }
#endif
#ifndef FIX_GetShortPathNameA
    __declspec(naked) void __stdcall fixGetShortPathNameA(void) { __asm jmp dword ptr function_ptrs[716 * 4] }
#endif
#ifndef FIX_GetShortPathNameW
    __declspec(naked) void __stdcall fixGetShortPathNameW(void) { __asm jmp dword ptr function_ptrs[717 * 4] }
#endif
#ifndef FIX_GetStagedPackagePathByFullName
    __declspec(naked) void __stdcall fixGetStagedPackagePathByFullName(void) { __asm jmp dword ptr function_ptrs[718 * 4] }
#endif
#ifndef FIX_GetStartupInfoA
    __declspec(naked) void __stdcall fixGetStartupInfoA(void) { __asm jmp dword ptr function_ptrs[719 * 4] }
#endif
#ifndef FIX_GetStartupInfoW
    __declspec(naked) void __stdcall fixGetStartupInfoW(void) { __asm jmp dword ptr function_ptrs[720 * 4] }
#endif
#ifndef FIX_GetStateFolder
    __declspec(naked) void __stdcall fixGetStateFolder(void) { __asm jmp dword ptr function_ptrs[721 * 4] }
#endif
#ifndef FIX_GetStdHandle
    __declspec(naked) void __stdcall fixGetStdHandle(void) { __asm jmp dword ptr function_ptrs[722 * 4] }
#endif
#ifndef FIX_GetStringScripts
    __declspec(naked) void __stdcall fixGetStringScripts(void) { __asm jmp dword ptr function_ptrs[723 * 4] }
#endif
#ifndef FIX_GetStringTypeA
    __declspec(naked) void __stdcall fixGetStringTypeA(void) { __asm jmp dword ptr function_ptrs[724 * 4] }
#endif
#ifndef FIX_GetStringTypeExA
    __declspec(naked) void __stdcall fixGetStringTypeExA(void) { __asm jmp dword ptr function_ptrs[725 * 4] }
#endif
#ifndef FIX_GetStringTypeExW
    __declspec(naked) void __stdcall fixGetStringTypeExW(void) { __asm jmp dword ptr function_ptrs[726 * 4] }
#endif
#ifndef FIX_GetStringTypeW
    __declspec(naked) void __stdcall fixGetStringTypeW(void) { __asm jmp dword ptr function_ptrs[727 * 4] }
#endif
#ifndef FIX_GetSystemAppDataKey
    __declspec(naked) void __stdcall fixGetSystemAppDataKey(void) { __asm jmp dword ptr function_ptrs[728 * 4] }
#endif
#ifndef FIX_GetSystemCpuSetInformation
    __declspec(naked) void __stdcall fixGetSystemCpuSetInformation(void) { __asm jmp dword ptr function_ptrs[729 * 4] }
#endif
#ifndef FIX_GetSystemDEPPolicy
    __declspec(naked) void __stdcall fixGetSystemDEPPolicy(void) { __asm jmp dword ptr function_ptrs[730 * 4] }
#endif
#ifndef FIX_GetSystemDefaultLCID
    __declspec(naked) void __stdcall fixGetSystemDefaultLCID(void) { __asm jmp dword ptr function_ptrs[731 * 4] }
#endif
#ifndef FIX_GetSystemDefaultLangID
    __declspec(naked) void __stdcall fixGetSystemDefaultLangID(void) { __asm jmp dword ptr function_ptrs[732 * 4] }
#endif
#ifndef FIX_GetSystemDefaultLocaleName
    __declspec(naked) void __stdcall fixGetSystemDefaultLocaleName(void) { __asm jmp dword ptr function_ptrs[733 * 4] }
#endif
#ifndef FIX_GetSystemDefaultUILanguage
    __declspec(naked) void __stdcall fixGetSystemDefaultUILanguage(void) { __asm jmp dword ptr function_ptrs[734 * 4] }
#endif
#ifndef FIX_GetSystemDirectoryA
    __declspec(naked) void __stdcall fixGetSystemDirectoryA(void) { __asm jmp dword ptr function_ptrs[735 * 4] }
#endif
#ifndef FIX_GetSystemDirectoryW
    __declspec(naked) void __stdcall fixGetSystemDirectoryW(void) { __asm jmp dword ptr function_ptrs[736 * 4] }
#endif
#ifndef FIX_GetSystemFileCacheSize
    __declspec(naked) void __stdcall fixGetSystemFileCacheSize(void) { __asm jmp dword ptr function_ptrs[737 * 4] }
#endif
#ifndef FIX_GetSystemFirmwareTable
    __declspec(naked) void __stdcall fixGetSystemFirmwareTable(void) { __asm jmp dword ptr function_ptrs[738 * 4] }
#endif
#ifndef FIX_GetSystemInfo
    __declspec(naked) void __stdcall fixGetSystemInfo(void) { __asm jmp dword ptr function_ptrs[739 * 4] }
#endif
#ifndef FIX_GetSystemPowerStatus
    __declspec(naked) void __stdcall fixGetSystemPowerStatus(void) { __asm jmp dword ptr function_ptrs[740 * 4] }
#endif
#ifndef FIX_GetSystemPreferredUILanguages
    __declspec(naked) void __stdcall fixGetSystemPreferredUILanguages(void) { __asm jmp dword ptr function_ptrs[741 * 4] }
#endif
#ifndef FIX_GetSystemRegistryQuota
    __declspec(naked) void __stdcall fixGetSystemRegistryQuota(void) { __asm jmp dword ptr function_ptrs[742 * 4] }
#endif
#ifndef FIX_GetSystemTime
    __declspec(naked) void __stdcall fixGetSystemTime(void) { __asm jmp dword ptr function_ptrs[743 * 4] }
#endif
#ifndef FIX_GetSystemTimeAdjustment
    __declspec(naked) void __stdcall fixGetSystemTimeAdjustment(void) { __asm jmp dword ptr function_ptrs[744 * 4] }
#endif
#ifndef FIX_GetSystemTimeAsFileTime
    __declspec(naked) void __stdcall fixGetSystemTimeAsFileTime(void) { __asm jmp dword ptr function_ptrs[745 * 4] }
#endif
#ifndef FIX_GetSystemTimePreciseAsFileTime
    __declspec(naked) void __stdcall fixGetSystemTimePreciseAsFileTime(void) { __asm jmp dword ptr function_ptrs[746 * 4] }
#endif
#ifndef FIX_GetSystemTimes
    __declspec(naked) void __stdcall fixGetSystemTimes(void) { __asm jmp dword ptr function_ptrs[747 * 4] }
#endif
#ifndef FIX_GetSystemWindowsDirectoryA
    __declspec(naked) void __stdcall fixGetSystemWindowsDirectoryA(void) { __asm jmp dword ptr function_ptrs[748 * 4] }
#endif
#ifndef FIX_GetSystemWindowsDirectoryW
    __declspec(naked) void __stdcall fixGetSystemWindowsDirectoryW(void) { __asm jmp dword ptr function_ptrs[749 * 4] }
#endif
#ifndef FIX_GetSystemWow64DirectoryA
    __declspec(naked) void __stdcall fixGetSystemWow64DirectoryA(void) { __asm jmp dword ptr function_ptrs[750 * 4] }
#endif
#ifndef FIX_GetSystemWow64DirectoryW
    __declspec(naked) void __stdcall fixGetSystemWow64DirectoryW(void) { __asm jmp dword ptr function_ptrs[751 * 4] }
#endif
#ifndef FIX_GetTapeParameters
    __declspec(naked) void __stdcall fixGetTapeParameters(void) { __asm jmp dword ptr function_ptrs[752 * 4] }
#endif
#ifndef FIX_GetTapePosition
    __declspec(naked) void __stdcall fixGetTapePosition(void) { __asm jmp dword ptr function_ptrs[753 * 4] }
#endif
#ifndef FIX_GetTapeStatus
    __declspec(naked) void __stdcall fixGetTapeStatus(void) { __asm jmp dword ptr function_ptrs[754 * 4] }
#endif
#ifndef FIX_GetTempFileNameA
    __declspec(naked) void __stdcall fixGetTempFileNameA(void) { __asm jmp dword ptr function_ptrs[755 * 4] }
#endif
#ifndef FIX_GetTempFileNameW
    __declspec(naked) void __stdcall fixGetTempFileNameW(void) { __asm jmp dword ptr function_ptrs[756 * 4] }
#endif
#ifndef FIX_GetTempPathA
    __declspec(naked) void __stdcall fixGetTempPathA(void) { __asm jmp dword ptr function_ptrs[757 * 4] }
#endif
#ifndef FIX_GetTempPathW
    __declspec(naked) void __stdcall fixGetTempPathW(void) { __asm jmp dword ptr function_ptrs[758 * 4] }
#endif
#ifndef FIX_GetThreadContext
    __declspec(naked) void __stdcall fixGetThreadContext(void) { __asm jmp dword ptr function_ptrs[759 * 4] }
#endif
#ifndef FIX_GetThreadDescription
    __declspec(naked) void __stdcall fixGetThreadDescription(void) { __asm jmp dword ptr function_ptrs[760 * 4] }
#endif
#ifndef FIX_GetThreadErrorMode
    __declspec(naked) void __stdcall fixGetThreadErrorMode(void) { __asm jmp dword ptr function_ptrs[761 * 4] }
#endif
#ifndef FIX_GetThreadGroupAffinity
    __declspec(naked) void __stdcall fixGetThreadGroupAffinity(void) { __asm jmp dword ptr function_ptrs[762 * 4] }
#endif
#ifndef FIX_GetThreadIOPendingFlag
    __declspec(naked) void __stdcall fixGetThreadIOPendingFlag(void) { __asm jmp dword ptr function_ptrs[763 * 4] }
#endif
#ifndef FIX_GetThreadId
    __declspec(naked) void __stdcall fixGetThreadId(void) { __asm jmp dword ptr function_ptrs[764 * 4] }
#endif
#ifndef FIX_GetThreadIdealProcessorEx
    __declspec(naked) void __stdcall fixGetThreadIdealProcessorEx(void) { __asm jmp dword ptr function_ptrs[765 * 4] }
#endif
#ifndef FIX_GetThreadInformation
    __declspec(naked) void __stdcall fixGetThreadInformation(void) { __asm jmp dword ptr function_ptrs[766 * 4] }
#endif
#ifndef FIX_GetThreadLocale
    __declspec(naked) void __stdcall fixGetThreadLocale(void) { __asm jmp dword ptr function_ptrs[767 * 4] }
#endif
#ifndef FIX_GetThreadPreferredUILanguages
    __declspec(naked) void __stdcall fixGetThreadPreferredUILanguages(void) { __asm jmp dword ptr function_ptrs[768 * 4] }
#endif
#ifndef FIX_GetThreadPriority
    __declspec(naked) void __stdcall fixGetThreadPriority(void) { __asm jmp dword ptr function_ptrs[769 * 4] }
#endif
#ifndef FIX_GetThreadPriorityBoost
    __declspec(naked) void __stdcall fixGetThreadPriorityBoost(void) { __asm jmp dword ptr function_ptrs[770 * 4] }
#endif
#ifndef FIX_GetThreadSelectedCpuSets
    __declspec(naked) void __stdcall fixGetThreadSelectedCpuSets(void) { __asm jmp dword ptr function_ptrs[771 * 4] }
#endif
#ifndef FIX_GetThreadSelectorEntry
    __declspec(naked) void __stdcall fixGetThreadSelectorEntry(void) { __asm jmp dword ptr function_ptrs[772 * 4] }
#endif
#ifndef FIX_GetThreadTimes
    __declspec(naked) void __stdcall fixGetThreadTimes(void) { __asm jmp dword ptr function_ptrs[773 * 4] }
#endif
#ifndef FIX_GetThreadUILanguage
    __declspec(naked) void __stdcall fixGetThreadUILanguage(void) { __asm jmp dword ptr function_ptrs[774 * 4] }
#endif
#ifndef FIX_GetTickCount
    __declspec(naked) void __stdcall fixGetTickCount(void) { __asm jmp dword ptr function_ptrs[775 * 4] }
#endif
#ifndef FIX_GetTickCount64
    __declspec(naked) void __stdcall fixGetTickCount64(void) { __asm jmp dword ptr function_ptrs[776 * 4] }
#endif
#ifndef FIX_GetTimeFormatA
    __declspec(naked) void __stdcall fixGetTimeFormatA(void) { __asm jmp dword ptr function_ptrs[777 * 4] }
#endif
#ifndef FIX_GetTimeFormatAWorker
    __declspec(naked) void __stdcall fixGetTimeFormatAWorker(void) { __asm jmp dword ptr function_ptrs[778 * 4] }
#endif
#ifndef FIX_GetTimeFormatEx
    __declspec(naked) void __stdcall fixGetTimeFormatEx(void) { __asm jmp dword ptr function_ptrs[779 * 4] }
#endif
#ifndef FIX_GetTimeFormatW
    __declspec(naked) void __stdcall fixGetTimeFormatW(void) { __asm jmp dword ptr function_ptrs[780 * 4] }
#endif
#ifndef FIX_GetTimeFormatWWorker
    __declspec(naked) void __stdcall fixGetTimeFormatWWorker(void) { __asm jmp dword ptr function_ptrs[781 * 4] }
#endif
#ifndef FIX_GetTimeZoneInformation
    __declspec(naked) void __stdcall fixGetTimeZoneInformation(void) { __asm jmp dword ptr function_ptrs[782 * 4] }
#endif
#ifndef FIX_GetTimeZoneInformationForYear
    __declspec(naked) void __stdcall fixGetTimeZoneInformationForYear(void) { __asm jmp dword ptr function_ptrs[783 * 4] }
#endif
#ifndef FIX_GetUILanguageInfo
    __declspec(naked) void __stdcall fixGetUILanguageInfo(void) { __asm jmp dword ptr function_ptrs[784 * 4] }
#endif
#ifndef FIX_GetUserDefaultGeoName
    __declspec(naked) void __stdcall fixGetUserDefaultGeoName(void) { __asm jmp dword ptr function_ptrs[785 * 4] }
#endif
#ifndef FIX_GetUserDefaultLCID
    __declspec(naked) void __stdcall fixGetUserDefaultLCID(void) { __asm jmp dword ptr function_ptrs[786 * 4] }
#endif
#ifndef FIX_GetUserDefaultLangID
    __declspec(naked) void __stdcall fixGetUserDefaultLangID(void) { __asm jmp dword ptr function_ptrs[787 * 4] }
#endif
#ifndef FIX_GetUserDefaultLocaleName
    __declspec(naked) void __stdcall fixGetUserDefaultLocaleName(void) { __asm jmp dword ptr function_ptrs[788 * 4] }
#endif
#ifndef FIX_GetUserDefaultUILanguage
    __declspec(naked) void __stdcall fixGetUserDefaultUILanguage(void) { __asm jmp dword ptr function_ptrs[789 * 4] }
#endif
#ifndef FIX_GetUserGeoID
    __declspec(naked) void __stdcall fixGetUserGeoID(void) { __asm jmp dword ptr function_ptrs[790 * 4] }
#endif
#ifndef FIX_GetUserPreferredUILanguages
    __declspec(naked) void __stdcall fixGetUserPreferredUILanguages(void) { __asm jmp dword ptr function_ptrs[791 * 4] }
#endif
#ifndef FIX_GetVDMCurrentDirectories
    __declspec(naked) void __stdcall fixGetVDMCurrentDirectories(void) { __asm jmp dword ptr function_ptrs[792 * 4] }
#endif
#ifndef FIX_GetVersion
    __declspec(naked) void __stdcall fixGetVersion(void) { __asm jmp dword ptr function_ptrs[793 * 4] }
#endif
#ifndef FIX_GetVersionExA
    __declspec(naked) void __stdcall fixGetVersionExA(void) { __asm jmp dword ptr function_ptrs[794 * 4] }
#endif
#ifndef FIX_GetVersionExW
    __declspec(naked) void __stdcall fixGetVersionExW(void) { __asm jmp dword ptr function_ptrs[795 * 4] }
#endif
#ifndef FIX_GetVolumeInformationA
    __declspec(naked) void __stdcall fixGetVolumeInformationA(void) { __asm jmp dword ptr function_ptrs[796 * 4] }
#endif
#ifndef FIX_GetVolumeInformationByHandleW
    __declspec(naked) void __stdcall fixGetVolumeInformationByHandleW(void) { __asm jmp dword ptr function_ptrs[797 * 4] }
#endif
#ifndef FIX_GetVolumeInformationW
    __declspec(naked) void __stdcall fixGetVolumeInformationW(void) { __asm jmp dword ptr function_ptrs[798 * 4] }
#endif
#ifndef FIX_GetVolumeNameForVolumeMountPointA
    __declspec(naked) void __stdcall fixGetVolumeNameForVolumeMountPointA(void) { __asm jmp dword ptr function_ptrs[799 * 4] }
#endif
#ifndef FIX_GetVolumeNameForVolumeMountPointW
    __declspec(naked) void __stdcall fixGetVolumeNameForVolumeMountPointW(void) { __asm jmp dword ptr function_ptrs[800 * 4] }
#endif
#ifndef FIX_GetVolumePathNameA
    __declspec(naked) void __stdcall fixGetVolumePathNameA(void) { __asm jmp dword ptr function_ptrs[801 * 4] }
#endif
#ifndef FIX_GetVolumePathNameW
    __declspec(naked) void __stdcall fixGetVolumePathNameW(void) { __asm jmp dword ptr function_ptrs[802 * 4] }
#endif
#ifndef FIX_GetVolumePathNamesForVolumeNameA
    __declspec(naked) void __stdcall fixGetVolumePathNamesForVolumeNameA(void) { __asm jmp dword ptr function_ptrs[803 * 4] }
#endif
#ifndef FIX_GetVolumePathNamesForVolumeNameW
    __declspec(naked) void __stdcall fixGetVolumePathNamesForVolumeNameW(void) { __asm jmp dword ptr function_ptrs[804 * 4] }
#endif
#ifndef FIX_GetWindowsDirectoryA
    __declspec(naked) void __stdcall fixGetWindowsDirectoryA(void) { __asm jmp dword ptr function_ptrs[805 * 4] }
#endif
#ifndef FIX_GetWindowsDirectoryW
    __declspec(naked) void __stdcall fixGetWindowsDirectoryW(void) { __asm jmp dword ptr function_ptrs[806 * 4] }
#endif
#ifndef FIX_GetWriteWatch
    __declspec(naked) void __stdcall fixGetWriteWatch(void) { __asm jmp dword ptr function_ptrs[807 * 4] }
#endif
#ifndef FIX_GetXStateFeaturesMask
    __declspec(naked) void __stdcall fixGetXStateFeaturesMask(void) { __asm jmp dword ptr function_ptrs[808 * 4] }
#endif
#ifndef FIX_GlobalAddAtomA
    __declspec(naked) void __stdcall fixGlobalAddAtomA(void) { __asm jmp dword ptr function_ptrs[809 * 4] }
#endif
#ifndef FIX_GlobalAddAtomExA
    __declspec(naked) void __stdcall fixGlobalAddAtomExA(void) { __asm jmp dword ptr function_ptrs[810 * 4] }
#endif
#ifndef FIX_GlobalAddAtomExW
    __declspec(naked) void __stdcall fixGlobalAddAtomExW(void) { __asm jmp dword ptr function_ptrs[811 * 4] }
#endif
#ifndef FIX_GlobalAddAtomW
    __declspec(naked) void __stdcall fixGlobalAddAtomW(void) { __asm jmp dword ptr function_ptrs[812 * 4] }
#endif
#ifndef FIX_GlobalAlloc
    __declspec(naked) void __stdcall fixGlobalAlloc(void) { __asm jmp dword ptr function_ptrs[813 * 4] }
#endif
#ifndef FIX_GlobalCompact
    __declspec(naked) void __stdcall fixGlobalCompact(void) { __asm jmp dword ptr function_ptrs[814 * 4] }
#endif
#ifndef FIX_GlobalDeleteAtom
    __declspec(naked) void __stdcall fixGlobalDeleteAtom(void) { __asm jmp dword ptr function_ptrs[815 * 4] }
#endif
#ifndef FIX_GlobalFindAtomA
    __declspec(naked) void __stdcall fixGlobalFindAtomA(void) { __asm jmp dword ptr function_ptrs[816 * 4] }
#endif
#ifndef FIX_GlobalFindAtomW
    __declspec(naked) void __stdcall fixGlobalFindAtomW(void) { __asm jmp dword ptr function_ptrs[817 * 4] }
#endif
#ifndef FIX_GlobalFix
    __declspec(naked) void __stdcall fixGlobalFix(void) { __asm jmp dword ptr function_ptrs[818 * 4] }
#endif
#ifndef FIX_GlobalFlags
    __declspec(naked) void __stdcall fixGlobalFlags(void) { __asm jmp dword ptr function_ptrs[819 * 4] }
#endif
#ifndef FIX_GlobalFree
    __declspec(naked) void __stdcall fixGlobalFree(void) { __asm jmp dword ptr function_ptrs[820 * 4] }
#endif
#ifndef FIX_GlobalGetAtomNameA
    __declspec(naked) void __stdcall fixGlobalGetAtomNameA(void) { __asm jmp dword ptr function_ptrs[821 * 4] }
#endif
#ifndef FIX_GlobalGetAtomNameW
    __declspec(naked) void __stdcall fixGlobalGetAtomNameW(void) { __asm jmp dword ptr function_ptrs[822 * 4] }
#endif
#ifndef FIX_GlobalHandle
    __declspec(naked) void __stdcall fixGlobalHandle(void) { __asm jmp dword ptr function_ptrs[823 * 4] }
#endif
#ifndef FIX_GlobalLock
    __declspec(naked) void __stdcall fixGlobalLock(void) { __asm jmp dword ptr function_ptrs[824 * 4] }
#endif
#ifndef FIX_GlobalMemoryStatus
    __declspec(naked) void __stdcall fixGlobalMemoryStatus(void) { __asm jmp dword ptr function_ptrs[825 * 4] }
#endif
#ifndef FIX_GlobalMemoryStatusEx
    __declspec(naked) void __stdcall fixGlobalMemoryStatusEx(void) { __asm jmp dword ptr function_ptrs[826 * 4] }
#endif
#ifndef FIX_GlobalReAlloc
    __declspec(naked) void __stdcall fixGlobalReAlloc(void) { __asm jmp dword ptr function_ptrs[827 * 4] }
#endif
#ifndef FIX_GlobalSize
    __declspec(naked) void __stdcall fixGlobalSize(void) { __asm jmp dword ptr function_ptrs[828 * 4] }
#endif
#ifndef FIX_GlobalUnWire
    __declspec(naked) void __stdcall fixGlobalUnWire(void) { __asm jmp dword ptr function_ptrs[829 * 4] }
#endif
#ifndef FIX_GlobalUnfix
    __declspec(naked) void __stdcall fixGlobalUnfix(void) { __asm jmp dword ptr function_ptrs[830 * 4] }
#endif
#ifndef FIX_GlobalUnlock
    __declspec(naked) void __stdcall fixGlobalUnlock(void) { __asm jmp dword ptr function_ptrs[831 * 4] }
#endif
#ifndef FIX_GlobalWire
    __declspec(naked) void __stdcall fixGlobalWire(void) { __asm jmp dword ptr function_ptrs[832 * 4] }
#endif
#ifndef FIX_Heap32First
    __declspec(naked) void __stdcall fixHeap32First(void) { __asm jmp dword ptr function_ptrs[833 * 4] }
#endif
#ifndef FIX_Heap32ListFirst
    __declspec(naked) void __stdcall fixHeap32ListFirst(void) { __asm jmp dword ptr function_ptrs[834 * 4] }
#endif
#ifndef FIX_Heap32ListNext
    __declspec(naked) void __stdcall fixHeap32ListNext(void) { __asm jmp dword ptr function_ptrs[835 * 4] }
#endif
#ifndef FIX_Heap32Next
    __declspec(naked) void __stdcall fixHeap32Next(void) { __asm jmp dword ptr function_ptrs[836 * 4] }
#endif
#ifndef FIX_HeapAlloc
    __declspec(naked) void __stdcall fixHeapAlloc(void) { __asm jmp dword ptr function_ptrs[837 * 4] }
#endif
#ifndef FIX_HeapCompact
    __declspec(naked) void __stdcall fixHeapCompact(void) { __asm jmp dword ptr function_ptrs[838 * 4] }
#endif
#ifndef FIX_HeapCreate
    __declspec(naked) void __stdcall fixHeapCreate(void) { __asm jmp dword ptr function_ptrs[839 * 4] }
#endif
#ifndef FIX_HeapDestroy
    __declspec(naked) void __stdcall fixHeapDestroy(void) { __asm jmp dword ptr function_ptrs[840 * 4] }
#endif
#ifndef FIX_HeapFree
    __declspec(naked) void __stdcall fixHeapFree(void) { __asm jmp dword ptr function_ptrs[841 * 4] }
#endif
#ifndef FIX_HeapLock
    __declspec(naked) void __stdcall fixHeapLock(void) { __asm jmp dword ptr function_ptrs[842 * 4] }
#endif
#ifndef FIX_HeapQueryInformation
    __declspec(naked) void __stdcall fixHeapQueryInformation(void) { __asm jmp dword ptr function_ptrs[843 * 4] }
#endif
#ifndef FIX_HeapReAlloc
    __declspec(naked) void __stdcall fixHeapReAlloc(void) { __asm jmp dword ptr function_ptrs[844 * 4] }
#endif
#ifndef FIX_HeapSetInformation
    __declspec(naked) void __stdcall fixHeapSetInformation(void) { __asm jmp dword ptr function_ptrs[845 * 4] }
#endif
#ifndef FIX_HeapSize
    __declspec(naked) void __stdcall fixHeapSize(void) { __asm jmp dword ptr function_ptrs[846 * 4] }
#endif
#ifndef FIX_HeapSummary
    __declspec(naked) void __stdcall fixHeapSummary(void) { __asm jmp dword ptr function_ptrs[847 * 4] }
#endif
#ifndef FIX_HeapUnlock
    __declspec(naked) void __stdcall fixHeapUnlock(void) { __asm jmp dword ptr function_ptrs[848 * 4] }
#endif
#ifndef FIX_HeapValidate
    __declspec(naked) void __stdcall fixHeapValidate(void) { __asm jmp dword ptr function_ptrs[849 * 4] }
#endif
#ifndef FIX_HeapWalk
    __declspec(naked) void __stdcall fixHeapWalk(void) { __asm jmp dword ptr function_ptrs[850 * 4] }
#endif
#ifndef FIX_IdnToAscii
    __declspec(naked) void __stdcall fixIdnToAscii(void) { __asm jmp dword ptr function_ptrs[851 * 4] }
#endif
#ifndef FIX_IdnToNameprepUnicode
    __declspec(naked) void __stdcall fixIdnToNameprepUnicode(void) { __asm jmp dword ptr function_ptrs[852 * 4] }
#endif
#ifndef FIX_IdnToUnicode
    __declspec(naked) void __stdcall fixIdnToUnicode(void) { __asm jmp dword ptr function_ptrs[853 * 4] }
#endif
#ifndef FIX_InitAtomTable
    __declspec(naked) void __stdcall fixInitAtomTable(void) { __asm jmp dword ptr function_ptrs[854 * 4] }
#endif
#ifndef FIX_InitOnceBeginInitialize
    __declspec(naked) void __stdcall fixInitOnceBeginInitialize(void) { __asm jmp dword ptr function_ptrs[855 * 4] }
#endif
#ifndef FIX_InitOnceComplete
    __declspec(naked) void __stdcall fixInitOnceComplete(void) { __asm jmp dword ptr function_ptrs[856 * 4] }
#endif
#ifndef FIX_InitOnceExecuteOnce
    __declspec(naked) void __stdcall fixInitOnceExecuteOnce(void) { __asm jmp dword ptr function_ptrs[857 * 4] }
#endif
#ifndef FIX_InitOnceInitialize
    __declspec(naked) void __stdcall fixInitOnceInitialize(void) { __asm jmp dword ptr function_ptrs[858 * 4] }
#endif
#ifndef FIX_InitializeConditionVariable
    __declspec(naked) void __stdcall fixInitializeConditionVariable(void) { __asm jmp dword ptr function_ptrs[859 * 4] }
#endif
#ifndef FIX_InitializeContext
    __declspec(naked) void __stdcall fixInitializeContext(void) { __asm jmp dword ptr function_ptrs[860 * 4] }
#endif
#ifndef FIX_InitializeContext2
    __declspec(naked) void __stdcall fixInitializeContext2(void) { __asm jmp dword ptr function_ptrs[861 * 4] }
#endif
#ifndef FIX_InitializeCriticalSection
    __declspec(naked) void __stdcall fixInitializeCriticalSection(void) { __asm jmp dword ptr function_ptrs[862 * 4] }
#endif
#ifndef FIX_InitializeCriticalSectionAndSpinCount
    __declspec(naked) void __stdcall fixInitializeCriticalSectionAndSpinCount(void) { __asm jmp dword ptr function_ptrs[863 * 4] }
#endif
#ifndef FIX_InitializeCriticalSectionEx
    __declspec(naked) void __stdcall fixInitializeCriticalSectionEx(void) { __asm jmp dword ptr function_ptrs[864 * 4] }
#endif
#ifndef FIX_InitializeEnclave
    __declspec(naked) void __stdcall fixInitializeEnclave(void) { __asm jmp dword ptr function_ptrs[865 * 4] }
#endif
#ifndef FIX_InitializeProcThreadAttributeList
    __declspec(naked) void __stdcall fixInitializeProcThreadAttributeList(void) { __asm jmp dword ptr function_ptrs[866 * 4] }
#endif
#ifndef FIX_InitializeSListHead
    __declspec(naked) void __stdcall fixInitializeSListHead(void) { __asm jmp dword ptr function_ptrs[867 * 4] }
#endif
#ifndef FIX_InitializeSRWLock
    __declspec(naked) void __stdcall fixInitializeSRWLock(void) { __asm jmp dword ptr function_ptrs[868 * 4] }
#endif
#ifndef FIX_InitializeSynchronizationBarrier
    __declspec(naked) void __stdcall fixInitializeSynchronizationBarrier(void) { __asm jmp dword ptr function_ptrs[869 * 4] }
#endif
#ifndef FIX_InstallELAMCertificateInfo
    __declspec(naked) void __stdcall fixInstallELAMCertificateInfo(void) { __asm jmp dword ptr function_ptrs[870 * 4] }
#endif
#ifndef FIX_InterlockedCompareExchange
    __declspec(naked) void __stdcall fixInterlockedCompareExchange(void) { __asm jmp dword ptr function_ptrs[871 * 4] }
#endif
#ifndef FIX_InterlockedCompareExchange64
    __declspec(naked) void __stdcall fixInterlockedCompareExchange64(void) { __asm jmp dword ptr function_ptrs[872 * 4] }
#endif
#ifndef FIX_InterlockedDecrement
    __declspec(naked) void __stdcall fixInterlockedDecrement(void) { __asm jmp dword ptr function_ptrs[873 * 4] }
#endif
#ifndef FIX_InterlockedExchange
    __declspec(naked) void __stdcall fixInterlockedExchange(void) { __asm jmp dword ptr function_ptrs[874 * 4] }
#endif
#ifndef FIX_InterlockedExchangeAdd
    __declspec(naked) void __stdcall fixInterlockedExchangeAdd(void) { __asm jmp dword ptr function_ptrs[875 * 4] }
#endif
#ifndef FIX_InterlockedFlushSList
    __declspec(naked) void __stdcall fixInterlockedFlushSList(void) { __asm jmp dword ptr function_ptrs[876 * 4] }
#endif
#ifndef FIX_InterlockedIncrement
    __declspec(naked) void __stdcall fixInterlockedIncrement(void) { __asm jmp dword ptr function_ptrs[877 * 4] }
#endif
#ifndef FIX_InterlockedPopEntrySList
    __declspec(naked) void __stdcall fixInterlockedPopEntrySList(void) { __asm jmp dword ptr function_ptrs[878 * 4] }
#endif
#ifndef FIX_InterlockedPushEntrySList
    __declspec(naked) void __stdcall fixInterlockedPushEntrySList(void) { __asm jmp dword ptr function_ptrs[879 * 4] }
#endif
#ifndef FIX_InterlockedPushListSList
    __declspec(naked) void __stdcall fixInterlockedPushListSList(void) { __asm jmp dword ptr function_ptrs[880 * 4] }
#endif
#ifndef FIX_InterlockedPushListSListEx
    __declspec(naked) void __stdcall fixInterlockedPushListSListEx(void) { __asm jmp dword ptr function_ptrs[881 * 4] }
#endif
#ifndef FIX_InvalidateConsoleDIBits
    __declspec(naked) void __stdcall fixInvalidateConsoleDIBits(void) { __asm jmp dword ptr function_ptrs[882 * 4] }
#endif
#ifndef FIX_IsBadCodePtr
    __declspec(naked) void __stdcall fixIsBadCodePtr(void) { __asm jmp dword ptr function_ptrs[883 * 4] }
#endif
#ifndef FIX_IsBadHugeReadPtr
    __declspec(naked) void __stdcall fixIsBadHugeReadPtr(void) { __asm jmp dword ptr function_ptrs[884 * 4] }
#endif
#ifndef FIX_IsBadHugeWritePtr
    __declspec(naked) void __stdcall fixIsBadHugeWritePtr(void) { __asm jmp dword ptr function_ptrs[885 * 4] }
#endif
#ifndef FIX_IsBadReadPtr
    __declspec(naked) void __stdcall fixIsBadReadPtr(void) { __asm jmp dword ptr function_ptrs[886 * 4] }
#endif
#ifndef FIX_IsBadStringPtrA
    __declspec(naked) void __stdcall fixIsBadStringPtrA(void) { __asm jmp dword ptr function_ptrs[887 * 4] }
#endif
#ifndef FIX_IsBadStringPtrW
    __declspec(naked) void __stdcall fixIsBadStringPtrW(void) { __asm jmp dword ptr function_ptrs[888 * 4] }
#endif
#ifndef FIX_IsBadWritePtr
    __declspec(naked) void __stdcall fixIsBadWritePtr(void) { __asm jmp dword ptr function_ptrs[889 * 4] }
#endif
#ifndef FIX_IsCalendarLeapDay
    __declspec(naked) void __stdcall fixIsCalendarLeapDay(void) { __asm jmp dword ptr function_ptrs[890 * 4] }
#endif
#ifndef FIX_IsCalendarLeapMonth
    __declspec(naked) void __stdcall fixIsCalendarLeapMonth(void) { __asm jmp dword ptr function_ptrs[891 * 4] }
#endif
#ifndef FIX_IsCalendarLeapYear
    __declspec(naked) void __stdcall fixIsCalendarLeapYear(void) { __asm jmp dword ptr function_ptrs[892 * 4] }
#endif
#ifndef FIX_IsDBCSLeadByte
    __declspec(naked) void __stdcall fixIsDBCSLeadByte(void) { __asm jmp dword ptr function_ptrs[893 * 4] }
#endif
#ifndef FIX_IsDBCSLeadByteEx
    __declspec(naked) void __stdcall fixIsDBCSLeadByteEx(void) { __asm jmp dword ptr function_ptrs[894 * 4] }
#endif
#ifndef FIX_IsDebuggerPresent
    __declspec(naked) void __stdcall fixIsDebuggerPresent(void) { __asm jmp dword ptr function_ptrs[895 * 4] }
#endif
#ifndef FIX_IsEnclaveTypeSupported
    __declspec(naked) void __stdcall fixIsEnclaveTypeSupported(void) { __asm jmp dword ptr function_ptrs[896 * 4] }
#endif
#ifndef FIX_IsNLSDefinedString
    __declspec(naked) void __stdcall fixIsNLSDefinedString(void) { __asm jmp dword ptr function_ptrs[897 * 4] }
#endif
#ifndef FIX_IsNativeVhdBoot
    __declspec(naked) void __stdcall fixIsNativeVhdBoot(void) { __asm jmp dword ptr function_ptrs[898 * 4] }
#endif
#ifndef FIX_IsNormalizedString
    __declspec(naked) void __stdcall fixIsNormalizedString(void) { __asm jmp dword ptr function_ptrs[899 * 4] }
#endif
#ifndef FIX_IsProcessCritical
    __declspec(naked) void __stdcall fixIsProcessCritical(void) { __asm jmp dword ptr function_ptrs[900 * 4] }
#endif
#ifndef FIX_IsProcessInJob
    __declspec(naked) void __stdcall fixIsProcessInJob(void) { __asm jmp dword ptr function_ptrs[901 * 4] }
#endif
#ifndef FIX_IsProcessorFeaturePresent
    __declspec(naked) void __stdcall fixIsProcessorFeaturePresent(void) { __asm jmp dword ptr function_ptrs[902 * 4] }
#endif
#ifndef FIX_IsSystemResumeAutomatic
    __declspec(naked) void __stdcall fixIsSystemResumeAutomatic(void) { __asm jmp dword ptr function_ptrs[903 * 4] }
#endif
#ifndef FIX_IsThreadAFiber
    __declspec(naked) void __stdcall fixIsThreadAFiber(void) { __asm jmp dword ptr function_ptrs[904 * 4] }
#endif
#ifndef FIX_IsThreadpoolTimerSet
    __declspec(naked) void __stdcall fixIsThreadpoolTimerSet(void) { __asm jmp dword ptr function_ptrs[905 * 4] }
#endif
#ifndef FIX_IsValidCalDateTime
    __declspec(naked) void __stdcall fixIsValidCalDateTime(void) { __asm jmp dword ptr function_ptrs[906 * 4] }
#endif
#ifndef FIX_IsValidCodePage
    __declspec(naked) void __stdcall fixIsValidCodePage(void) { __asm jmp dword ptr function_ptrs[907 * 4] }
#endif
#ifndef FIX_IsValidLanguageGroup
    __declspec(naked) void __stdcall fixIsValidLanguageGroup(void) { __asm jmp dword ptr function_ptrs[908 * 4] }
#endif
#ifndef FIX_IsValidLocale
    __declspec(naked) void __stdcall fixIsValidLocale(void) { __asm jmp dword ptr function_ptrs[909 * 4] }
#endif
#ifndef FIX_IsValidLocaleName
    __declspec(naked) void __stdcall fixIsValidLocaleName(void) { __asm jmp dword ptr function_ptrs[910 * 4] }
#endif
#ifndef FIX_IsValidNLSVersion
    __declspec(naked) void __stdcall fixIsValidNLSVersion(void) { __asm jmp dword ptr function_ptrs[911 * 4] }
#endif
#ifndef FIX_IsWow64GuestMachineSupported
    __declspec(naked) void __stdcall fixIsWow64GuestMachineSupported(void) { __asm jmp dword ptr function_ptrs[912 * 4] }
#endif
#ifndef FIX_IsWow64Process
    __declspec(naked) void __stdcall fixIsWow64Process(void) { __asm jmp dword ptr function_ptrs[913 * 4] }
#endif
#ifndef FIX_IsWow64Process2
    __declspec(naked) void __stdcall fixIsWow64Process2(void) { __asm jmp dword ptr function_ptrs[914 * 4] }
#endif
#ifndef FIX_K32EmptyWorkingSet
    __declspec(naked) void __stdcall fixK32EmptyWorkingSet(void) { __asm jmp dword ptr function_ptrs[915 * 4] }
#endif
#ifndef FIX_K32EnumDeviceDrivers
    __declspec(naked) void __stdcall fixK32EnumDeviceDrivers(void) { __asm jmp dword ptr function_ptrs[916 * 4] }
#endif
#ifndef FIX_K32EnumPageFilesA
    __declspec(naked) void __stdcall fixK32EnumPageFilesA(void) { __asm jmp dword ptr function_ptrs[917 * 4] }
#endif
#ifndef FIX_K32EnumPageFilesW
    __declspec(naked) void __stdcall fixK32EnumPageFilesW(void) { __asm jmp dword ptr function_ptrs[918 * 4] }
#endif
#ifndef FIX_K32EnumProcessModules
    __declspec(naked) void __stdcall fixK32EnumProcessModules(void) { __asm jmp dword ptr function_ptrs[919 * 4] }
#endif
#ifndef FIX_K32EnumProcessModulesEx
    __declspec(naked) void __stdcall fixK32EnumProcessModulesEx(void) { __asm jmp dword ptr function_ptrs[920 * 4] }
#endif
#ifndef FIX_K32EnumProcesses
    __declspec(naked) void __stdcall fixK32EnumProcesses(void) { __asm jmp dword ptr function_ptrs[921 * 4] }
#endif
#ifndef FIX_K32GetDeviceDriverBaseNameA
    __declspec(naked) void __stdcall fixK32GetDeviceDriverBaseNameA(void) { __asm jmp dword ptr function_ptrs[922 * 4] }
#endif
#ifndef FIX_K32GetDeviceDriverBaseNameW
    __declspec(naked) void __stdcall fixK32GetDeviceDriverBaseNameW(void) { __asm jmp dword ptr function_ptrs[923 * 4] }
#endif
#ifndef FIX_K32GetDeviceDriverFileNameA
    __declspec(naked) void __stdcall fixK32GetDeviceDriverFileNameA(void) { __asm jmp dword ptr function_ptrs[924 * 4] }
#endif
#ifndef FIX_K32GetDeviceDriverFileNameW
    __declspec(naked) void __stdcall fixK32GetDeviceDriverFileNameW(void) { __asm jmp dword ptr function_ptrs[925 * 4] }
#endif
#ifndef FIX_K32GetMappedFileNameA
    __declspec(naked) void __stdcall fixK32GetMappedFileNameA(void) { __asm jmp dword ptr function_ptrs[926 * 4] }
#endif
#ifndef FIX_K32GetMappedFileNameW
    __declspec(naked) void __stdcall fixK32GetMappedFileNameW(void) { __asm jmp dword ptr function_ptrs[927 * 4] }
#endif
#ifndef FIX_K32GetModuleBaseNameA
    __declspec(naked) void __stdcall fixK32GetModuleBaseNameA(void) { __asm jmp dword ptr function_ptrs[928 * 4] }
#endif
#ifndef FIX_K32GetModuleBaseNameW
    __declspec(naked) void __stdcall fixK32GetModuleBaseNameW(void) { __asm jmp dword ptr function_ptrs[929 * 4] }
#endif
#ifndef FIX_K32GetModuleFileNameExA
    __declspec(naked) void __stdcall fixK32GetModuleFileNameExA(void) { __asm jmp dword ptr function_ptrs[930 * 4] }
#endif
#ifndef FIX_K32GetModuleFileNameExW
    __declspec(naked) void __stdcall fixK32GetModuleFileNameExW(void) { __asm jmp dword ptr function_ptrs[931 * 4] }
#endif
#ifndef FIX_K32GetModuleInformation
    __declspec(naked) void __stdcall fixK32GetModuleInformation(void) { __asm jmp dword ptr function_ptrs[932 * 4] }
#endif
#ifndef FIX_K32GetPerformanceInfo
    __declspec(naked) void __stdcall fixK32GetPerformanceInfo(void) { __asm jmp dword ptr function_ptrs[933 * 4] }
#endif
#ifndef FIX_K32GetProcessImageFileNameA
    __declspec(naked) void __stdcall fixK32GetProcessImageFileNameA(void) { __asm jmp dword ptr function_ptrs[934 * 4] }
#endif
#ifndef FIX_K32GetProcessImageFileNameW
    __declspec(naked) void __stdcall fixK32GetProcessImageFileNameW(void) { __asm jmp dword ptr function_ptrs[935 * 4] }
#endif
#ifndef FIX_K32GetProcessMemoryInfo
    __declspec(naked) void __stdcall fixK32GetProcessMemoryInfo(void) { __asm jmp dword ptr function_ptrs[936 * 4] }
#endif
#ifndef FIX_K32GetWsChanges
    __declspec(naked) void __stdcall fixK32GetWsChanges(void) { __asm jmp dword ptr function_ptrs[937 * 4] }
#endif
#ifndef FIX_K32GetWsChangesEx
    __declspec(naked) void __stdcall fixK32GetWsChangesEx(void) { __asm jmp dword ptr function_ptrs[938 * 4] }
#endif
#ifndef FIX_K32InitializeProcessForWsWatch
    __declspec(naked) void __stdcall fixK32InitializeProcessForWsWatch(void) { __asm jmp dword ptr function_ptrs[939 * 4] }
#endif
#ifndef FIX_K32QueryWorkingSet
    __declspec(naked) void __stdcall fixK32QueryWorkingSet(void) { __asm jmp dword ptr function_ptrs[940 * 4] }
#endif
#ifndef FIX_K32QueryWorkingSetEx
    __declspec(naked) void __stdcall fixK32QueryWorkingSetEx(void) { __asm jmp dword ptr function_ptrs[941 * 4] }
#endif
#ifndef FIX_LCIDToLocaleName
    __declspec(naked) void __stdcall fixLCIDToLocaleName(void) { __asm jmp dword ptr function_ptrs[942 * 4] }
#endif
#ifndef FIX_LCMapStringA
    __declspec(naked) void __stdcall fixLCMapStringA(void) { __asm jmp dword ptr function_ptrs[943 * 4] }
#endif
#ifndef FIX_LCMapStringEx
    __declspec(naked) void __stdcall fixLCMapStringEx(void) { __asm jmp dword ptr function_ptrs[944 * 4] }
#endif
#ifndef FIX_LCMapStringW
    __declspec(naked) void __stdcall fixLCMapStringW(void) { __asm jmp dword ptr function_ptrs[945 * 4] }
#endif
#ifndef FIX_LZClose
    __declspec(naked) void __stdcall fixLZClose(void) { __asm jmp dword ptr function_ptrs[946 * 4] }
#endif
#ifndef FIX_LZCloseFile
    __declspec(naked) void __stdcall fixLZCloseFile(void) { __asm jmp dword ptr function_ptrs[947 * 4] }
#endif
#ifndef FIX_LZCopy
    __declspec(naked) void __stdcall fixLZCopy(void) { __asm jmp dword ptr function_ptrs[948 * 4] }
#endif
#ifndef FIX_LZCreateFileW
    __declspec(naked) void __stdcall fixLZCreateFileW(void) { __asm jmp dword ptr function_ptrs[949 * 4] }
#endif
#ifndef FIX_LZDone
    __declspec(naked) void __stdcall fixLZDone(void) { __asm jmp dword ptr function_ptrs[950 * 4] }
#endif
#ifndef FIX_LZInit
    __declspec(naked) void __stdcall fixLZInit(void) { __asm jmp dword ptr function_ptrs[951 * 4] }
#endif
#ifndef FIX_LZOpenFileA
    __declspec(naked) void __stdcall fixLZOpenFileA(void) { __asm jmp dword ptr function_ptrs[952 * 4] }
#endif
#ifndef FIX_LZOpenFileW
    __declspec(naked) void __stdcall fixLZOpenFileW(void) { __asm jmp dword ptr function_ptrs[953 * 4] }
#endif
#ifndef FIX_LZRead
    __declspec(naked) void __stdcall fixLZRead(void) { __asm jmp dword ptr function_ptrs[954 * 4] }
#endif
#ifndef FIX_LZSeek
    __declspec(naked) void __stdcall fixLZSeek(void) { __asm jmp dword ptr function_ptrs[955 * 4] }
#endif
#ifndef FIX_LZStart
    __declspec(naked) void __stdcall fixLZStart(void) { __asm jmp dword ptr function_ptrs[956 * 4] }
#endif
#ifndef FIX_LeaveCriticalSection
    __declspec(naked) void __stdcall fixLeaveCriticalSection(void) { __asm jmp dword ptr function_ptrs[957 * 4] }
#endif
#ifndef FIX_LeaveCriticalSectionWhenCallbackReturns
    __declspec(naked) void __stdcall fixLeaveCriticalSectionWhenCallbackReturns(void) { __asm jmp dword ptr function_ptrs[958 * 4] }
#endif
#ifndef FIX_LoadAppInitDlls
    __declspec(naked) void __stdcall fixLoadAppInitDlls(void) { __asm jmp dword ptr function_ptrs[959 * 4] }
#endif
#ifndef FIX_LoadEnclaveData
    __declspec(naked) void __stdcall fixLoadEnclaveData(void) { __asm jmp dword ptr function_ptrs[960 * 4] }
#endif
#ifndef FIX_LoadLibraryA
    __declspec(naked) void __stdcall fixLoadLibraryA(void) { __asm jmp dword ptr function_ptrs[961 * 4] }
#endif
#ifndef FIX_LoadLibraryExA
    __declspec(naked) void __stdcall fixLoadLibraryExA(void) { __asm jmp dword ptr function_ptrs[962 * 4] }
#endif
#ifndef FIX_LoadLibraryExW
    __declspec(naked) void __stdcall fixLoadLibraryExW(void) { __asm jmp dword ptr function_ptrs[963 * 4] }
#endif
#ifndef FIX_LoadLibraryW
    __declspec(naked) void __stdcall fixLoadLibraryW(void) { __asm jmp dword ptr function_ptrs[964 * 4] }
#endif
#ifndef FIX_LoadModule
    __declspec(naked) void __stdcall fixLoadModule(void) { __asm jmp dword ptr function_ptrs[965 * 4] }
#endif
#ifndef FIX_LoadPackagedLibrary
    __declspec(naked) void __stdcall fixLoadPackagedLibrary(void) { __asm jmp dword ptr function_ptrs[966 * 4] }
#endif
#ifndef FIX_LoadResource
    __declspec(naked) void __stdcall fixLoadResource(void) { __asm jmp dword ptr function_ptrs[967 * 4] }
#endif
#ifndef FIX_LoadStringBaseExW
    __declspec(naked) void __stdcall fixLoadStringBaseExW(void) { __asm jmp dword ptr function_ptrs[968 * 4] }
#endif
#ifndef FIX_LoadStringBaseW
    __declspec(naked) void __stdcall fixLoadStringBaseW(void) { __asm jmp dword ptr function_ptrs[969 * 4] }
#endif
#ifndef FIX_LocalAlloc
    __declspec(naked) void __stdcall fixLocalAlloc(void) { __asm jmp dword ptr function_ptrs[970 * 4] }
#endif
#ifndef FIX_LocalCompact
    __declspec(naked) void __stdcall fixLocalCompact(void) { __asm jmp dword ptr function_ptrs[971 * 4] }
#endif
#ifndef FIX_LocalFileTimeToFileTime
    __declspec(naked) void __stdcall fixLocalFileTimeToFileTime(void) { __asm jmp dword ptr function_ptrs[972 * 4] }
#endif
#ifndef FIX_LocalFileTimeToLocalSystemTime
    __declspec(naked) void __stdcall fixLocalFileTimeToLocalSystemTime(void) { __asm jmp dword ptr function_ptrs[973 * 4] }
#endif
#ifndef FIX_LocalFlags
    __declspec(naked) void __stdcall fixLocalFlags(void) { __asm jmp dword ptr function_ptrs[974 * 4] }
#endif
#ifndef FIX_LocalFree
    __declspec(naked) void __stdcall fixLocalFree(void) { __asm jmp dword ptr function_ptrs[975 * 4] }
#endif
#ifndef FIX_LocalHandle
    __declspec(naked) void __stdcall fixLocalHandle(void) { __asm jmp dword ptr function_ptrs[976 * 4] }
#endif
#ifndef FIX_LocalLock
    __declspec(naked) void __stdcall fixLocalLock(void) { __asm jmp dword ptr function_ptrs[977 * 4] }
#endif
#ifndef FIX_LocalReAlloc
    __declspec(naked) void __stdcall fixLocalReAlloc(void) { __asm jmp dword ptr function_ptrs[978 * 4] }
#endif
#ifndef FIX_LocalShrink
    __declspec(naked) void __stdcall fixLocalShrink(void) { __asm jmp dword ptr function_ptrs[979 * 4] }
#endif
#ifndef FIX_LocalSize
    __declspec(naked) void __stdcall fixLocalSize(void) { __asm jmp dword ptr function_ptrs[980 * 4] }
#endif
#ifndef FIX_LocalSystemTimeToLocalFileTime
    __declspec(naked) void __stdcall fixLocalSystemTimeToLocalFileTime(void) { __asm jmp dword ptr function_ptrs[981 * 4] }
#endif
#ifndef FIX_LocalUnlock
    __declspec(naked) void __stdcall fixLocalUnlock(void) { __asm jmp dword ptr function_ptrs[982 * 4] }
#endif
#ifndef FIX_LocaleNameToLCID
    __declspec(naked) void __stdcall fixLocaleNameToLCID(void) { __asm jmp dword ptr function_ptrs[983 * 4] }
#endif
#ifndef FIX_LocateXStateFeature
    __declspec(naked) void __stdcall fixLocateXStateFeature(void) { __asm jmp dword ptr function_ptrs[984 * 4] }
#endif
#ifndef FIX_LockFile
    __declspec(naked) void __stdcall fixLockFile(void) { __asm jmp dword ptr function_ptrs[985 * 4] }
#endif
#ifndef FIX_LockFileEx
    __declspec(naked) void __stdcall fixLockFileEx(void) { __asm jmp dword ptr function_ptrs[986 * 4] }
#endif
#ifndef FIX_LockResource
    __declspec(naked) void __stdcall fixLockResource(void) { __asm jmp dword ptr function_ptrs[987 * 4] }
#endif
#ifndef FIX_MapUserPhysicalPages
    __declspec(naked) void __stdcall fixMapUserPhysicalPages(void) { __asm jmp dword ptr function_ptrs[988 * 4] }
#endif
#ifndef FIX_MapUserPhysicalPagesScatter
    __declspec(naked) void __stdcall fixMapUserPhysicalPagesScatter(void) { __asm jmp dword ptr function_ptrs[989 * 4] }
#endif
#ifndef FIX_MapViewOfFile
    __declspec(naked) void __stdcall fixMapViewOfFile(void) { __asm jmp dword ptr function_ptrs[990 * 4] }
#endif
#ifndef FIX_MapViewOfFileEx
    __declspec(naked) void __stdcall fixMapViewOfFileEx(void) { __asm jmp dword ptr function_ptrs[991 * 4] }
#endif
#ifndef FIX_MapViewOfFileExNuma
    __declspec(naked) void __stdcall fixMapViewOfFileExNuma(void) { __asm jmp dword ptr function_ptrs[992 * 4] }
#endif
#ifndef FIX_MapViewOfFileFromApp
    __declspec(naked) void __stdcall fixMapViewOfFileFromApp(void) { __asm jmp dword ptr function_ptrs[993 * 4] }
#endif
#ifndef FIX_Module32First
    __declspec(naked) void __stdcall fixModule32First(void) { __asm jmp dword ptr function_ptrs[994 * 4] }
#endif
#ifndef FIX_Module32FirstW
    __declspec(naked) void __stdcall fixModule32FirstW(void) { __asm jmp dword ptr function_ptrs[995 * 4] }
#endif
#ifndef FIX_Module32Next
    __declspec(naked) void __stdcall fixModule32Next(void) { __asm jmp dword ptr function_ptrs[996 * 4] }
#endif
#ifndef FIX_Module32NextW
    __declspec(naked) void __stdcall fixModule32NextW(void) { __asm jmp dword ptr function_ptrs[997 * 4] }
#endif
#ifndef FIX_MoveFileA
    __declspec(naked) void __stdcall fixMoveFileA(void) { __asm jmp dword ptr function_ptrs[998 * 4] }
#endif
#ifndef FIX_MoveFileExA
    __declspec(naked) void __stdcall fixMoveFileExA(void) { __asm jmp dword ptr function_ptrs[999 * 4] }
#endif
#ifndef FIX_MoveFileExW
    __declspec(naked) void __stdcall fixMoveFileExW(void) { __asm jmp dword ptr function_ptrs[1000 * 4] }
#endif
#ifndef FIX_MoveFileTransactedA
    __declspec(naked) void __stdcall fixMoveFileTransactedA(void) { __asm jmp dword ptr function_ptrs[1001 * 4] }
#endif
#ifndef FIX_MoveFileTransactedW
    __declspec(naked) void __stdcall fixMoveFileTransactedW(void) { __asm jmp dword ptr function_ptrs[1002 * 4] }
#endif
#ifndef FIX_MoveFileW
    __declspec(naked) void __stdcall fixMoveFileW(void) { __asm jmp dword ptr function_ptrs[1003 * 4] }
#endif
#ifndef FIX_MoveFileWithProgressA
    __declspec(naked) void __stdcall fixMoveFileWithProgressA(void) { __asm jmp dword ptr function_ptrs[1004 * 4] }
#endif
#ifndef FIX_MoveFileWithProgressW
    __declspec(naked) void __stdcall fixMoveFileWithProgressW(void) { __asm jmp dword ptr function_ptrs[1005 * 4] }
#endif
#ifndef FIX_MulDiv
    __declspec(naked) void __stdcall fixMulDiv(void) { __asm jmp dword ptr function_ptrs[1006 * 4] }
#endif
#ifndef FIX_MultiByteToWideChar
    __declspec(naked) void __stdcall fixMultiByteToWideChar(void) { __asm jmp dword ptr function_ptrs[1007 * 4] }
#endif
#ifndef FIX_NeedCurrentDirectoryForExePathA
    __declspec(naked) void __stdcall fixNeedCurrentDirectoryForExePathA(void) { __asm jmp dword ptr function_ptrs[1008 * 4] }
#endif
#ifndef FIX_NeedCurrentDirectoryForExePathW
    __declspec(naked) void __stdcall fixNeedCurrentDirectoryForExePathW(void) { __asm jmp dword ptr function_ptrs[1009 * 4] }
#endif
#ifndef FIX_NlsCheckPolicy
    __declspec(naked) void __stdcall fixNlsCheckPolicy(void) { __asm jmp dword ptr function_ptrs[1010 * 4] }
#endif
#ifndef FIX_NlsEventDataDescCreate
    __declspec(naked) void __stdcall fixNlsEventDataDescCreate(void) { __asm jmp dword ptr function_ptrs[1011 * 4] }
#endif
#ifndef FIX_NlsGetCacheUpdateCount
    __declspec(naked) void __stdcall fixNlsGetCacheUpdateCount(void) { __asm jmp dword ptr function_ptrs[1012 * 4] }
#endif
#ifndef FIX_NlsUpdateLocale
    __declspec(naked) void __stdcall fixNlsUpdateLocale(void) { __asm jmp dword ptr function_ptrs[1013 * 4] }
#endif
#ifndef FIX_NlsUpdateSystemLocale
    __declspec(naked) void __stdcall fixNlsUpdateSystemLocale(void) { __asm jmp dword ptr function_ptrs[1014 * 4] }
#endif
#ifndef FIX_NlsWriteEtwEvent
    __declspec(naked) void __stdcall fixNlsWriteEtwEvent(void) { __asm jmp dword ptr function_ptrs[1015 * 4] }
#endif
#ifndef FIX_NormalizeString
    __declspec(naked) void __stdcall fixNormalizeString(void) { __asm jmp dword ptr function_ptrs[1016 * 4] }
#endif
#ifndef FIX_NotifyMountMgr
    __declspec(naked) void __stdcall fixNotifyMountMgr(void) { __asm jmp dword ptr function_ptrs[1017 * 4] }
#endif
#ifndef FIX_NotifyUILanguageChange
    __declspec(naked) void __stdcall fixNotifyUILanguageChange(void) { __asm jmp dword ptr function_ptrs[1018 * 4] }
#endif
#ifndef FIX_NtVdm64CreateProcessInternalW
    __declspec(naked) void __stdcall fixNtVdm64CreateProcessInternalW(void) { __asm jmp dword ptr function_ptrs[1019 * 4] }
#endif
#ifndef FIX_OOBEComplete
    __declspec(naked) void __stdcall fixOOBEComplete(void) { __asm jmp dword ptr function_ptrs[1020 * 4] }
#endif
#ifndef FIX_OfferVirtualMemory
    __declspec(naked) void __stdcall fixOfferVirtualMemory(void) { __asm jmp dword ptr function_ptrs[1021 * 4] }
#endif
#ifndef FIX_OpenConsoleW
    __declspec(naked) void __stdcall fixOpenConsoleW(void) { __asm jmp dword ptr function_ptrs[1022 * 4] }
#endif
#ifndef FIX_OpenConsoleWStub
    __declspec(naked) void __stdcall fixOpenConsoleWStub(void) { __asm jmp dword ptr function_ptrs[1023 * 4] }
#endif
#ifndef FIX_OpenEventA
    __declspec(naked) void __stdcall fixOpenEventA(void) { __asm jmp dword ptr function_ptrs[1024 * 4] }
#endif
#ifndef FIX_OpenEventW
    __declspec(naked) void __stdcall fixOpenEventW(void) { __asm jmp dword ptr function_ptrs[1025 * 4] }
#endif
#ifndef FIX_OpenFile
    __declspec(naked) void __stdcall fixOpenFile(void) { __asm jmp dword ptr function_ptrs[1026 * 4] }
#endif
#ifndef FIX_OpenFileById
    __declspec(naked) void __stdcall fixOpenFileById(void) { __asm jmp dword ptr function_ptrs[1027 * 4] }
#endif
#ifndef FIX_OpenFileMappingA
    __declspec(naked) void __stdcall fixOpenFileMappingA(void) { __asm jmp dword ptr function_ptrs[1028 * 4] }
#endif
#ifndef FIX_OpenFileMappingW
    __declspec(naked) void __stdcall fixOpenFileMappingW(void) { __asm jmp dword ptr function_ptrs[1029 * 4] }
#endif
#ifndef FIX_OpenJobObjectA
    __declspec(naked) void __stdcall fixOpenJobObjectA(void) { __asm jmp dword ptr function_ptrs[1030 * 4] }
#endif
#ifndef FIX_OpenJobObjectW
    __declspec(naked) void __stdcall fixOpenJobObjectW(void) { __asm jmp dword ptr function_ptrs[1031 * 4] }
#endif
#ifndef FIX_OpenMutexA
    __declspec(naked) void __stdcall fixOpenMutexA(void) { __asm jmp dword ptr function_ptrs[1032 * 4] }
#endif
#ifndef FIX_OpenMutexW
    __declspec(naked) void __stdcall fixOpenMutexW(void) { __asm jmp dword ptr function_ptrs[1033 * 4] }
#endif
#ifndef FIX_OpenPackageInfoByFullName
    __declspec(naked) void __stdcall fixOpenPackageInfoByFullName(void) { __asm jmp dword ptr function_ptrs[1034 * 4] }
#endif
#ifndef FIX_OpenPrivateNamespaceA
    __declspec(naked) void __stdcall fixOpenPrivateNamespaceA(void) { __asm jmp dword ptr function_ptrs[1035 * 4] }
#endif
#ifndef FIX_OpenPrivateNamespaceW
    __declspec(naked) void __stdcall fixOpenPrivateNamespaceW(void) { __asm jmp dword ptr function_ptrs[1036 * 4] }
#endif
#ifndef FIX_OpenProcess
    __declspec(naked) void __stdcall fixOpenProcess(void) { __asm jmp dword ptr function_ptrs[1037 * 4] }
#endif
#ifndef FIX_OpenProcessToken
    __declspec(naked) void __stdcall fixOpenProcessToken(void) { __asm jmp dword ptr function_ptrs[1038 * 4] }
#endif
#ifndef FIX_OpenProfileUserMapping
    __declspec(naked) void __stdcall fixOpenProfileUserMapping(void) { __asm jmp dword ptr function_ptrs[1039 * 4] }
#endif
#ifndef FIX_OpenSemaphoreA
    __declspec(naked) void __stdcall fixOpenSemaphoreA(void) { __asm jmp dword ptr function_ptrs[1040 * 4] }
#endif
#ifndef FIX_OpenSemaphoreW
    __declspec(naked) void __stdcall fixOpenSemaphoreW(void) { __asm jmp dword ptr function_ptrs[1041 * 4] }
#endif
#ifndef FIX_OpenState
    __declspec(naked) void __stdcall fixOpenState(void) { __asm jmp dword ptr function_ptrs[1042 * 4] }
#endif
#ifndef FIX_OpenStateExplicit
    __declspec(naked) void __stdcall fixOpenStateExplicit(void) { __asm jmp dword ptr function_ptrs[1043 * 4] }
#endif
#ifndef FIX_OpenThread
    __declspec(naked) void __stdcall fixOpenThread(void) { __asm jmp dword ptr function_ptrs[1044 * 4] }
#endif
#ifndef FIX_OpenThreadToken
    __declspec(naked) void __stdcall fixOpenThreadToken(void) { __asm jmp dword ptr function_ptrs[1045 * 4] }
#endif
#ifndef FIX_OpenWaitableTimerA
    __declspec(naked) void __stdcall fixOpenWaitableTimerA(void) { __asm jmp dword ptr function_ptrs[1046 * 4] }
#endif
#ifndef FIX_OpenWaitableTimerW
    __declspec(naked) void __stdcall fixOpenWaitableTimerW(void) { __asm jmp dword ptr function_ptrs[1047 * 4] }
#endif
#ifndef FIX_OutputDebugStringA
    __declspec(naked) void __stdcall fixOutputDebugStringA(void) { __asm jmp dword ptr function_ptrs[1048 * 4] }
#endif
#ifndef FIX_OutputDebugStringW
    __declspec(naked) void __stdcall fixOutputDebugStringW(void) { __asm jmp dword ptr function_ptrs[1049 * 4] }
#endif
#ifndef FIX_PackageFamilyNameFromFullName
    __declspec(naked) void __stdcall fixPackageFamilyNameFromFullName(void) { __asm jmp dword ptr function_ptrs[1050 * 4] }
#endif
#ifndef FIX_PackageFamilyNameFromId
    __declspec(naked) void __stdcall fixPackageFamilyNameFromId(void) { __asm jmp dword ptr function_ptrs[1051 * 4] }
#endif
#ifndef FIX_PackageFullNameFromId
    __declspec(naked) void __stdcall fixPackageFullNameFromId(void) { __asm jmp dword ptr function_ptrs[1052 * 4] }
#endif
#ifndef FIX_PackageIdFromFullName
    __declspec(naked) void __stdcall fixPackageIdFromFullName(void) { __asm jmp dword ptr function_ptrs[1053 * 4] }
#endif
#ifndef FIX_PackageNameAndPublisherIdFromFamilyName
    __declspec(naked) void __stdcall fixPackageNameAndPublisherIdFromFamilyName(void) { __asm jmp dword ptr function_ptrs[1054 * 4] }
#endif
#ifndef FIX_ParseApplicationUserModelId
    __declspec(naked) void __stdcall fixParseApplicationUserModelId(void) { __asm jmp dword ptr function_ptrs[1055 * 4] }
#endif
#ifndef FIX_PeekConsoleInputA
    __declspec(naked) void __stdcall fixPeekConsoleInputA(void) { __asm jmp dword ptr function_ptrs[1056 * 4] }
#endif
#ifndef FIX_PeekConsoleInputW
    __declspec(naked) void __stdcall fixPeekConsoleInputW(void) { __asm jmp dword ptr function_ptrs[1057 * 4] }
#endif
#ifndef FIX_PeekNamedPipe
    __declspec(naked) void __stdcall fixPeekNamedPipe(void) { __asm jmp dword ptr function_ptrs[1058 * 4] }
#endif
#ifndef FIX_PostQueuedCompletionStatus
    __declspec(naked) void __stdcall fixPostQueuedCompletionStatus(void) { __asm jmp dword ptr function_ptrs[1059 * 4] }
#endif
#ifndef FIX_PowerClearRequest
    __declspec(naked) void __stdcall fixPowerClearRequest(void) { __asm jmp dword ptr function_ptrs[1060 * 4] }
#endif
#ifndef FIX_PowerCreateRequest
    __declspec(naked) void __stdcall fixPowerCreateRequest(void) { __asm jmp dword ptr function_ptrs[1061 * 4] }
#endif
#ifndef FIX_PowerSetRequest
    __declspec(naked) void __stdcall fixPowerSetRequest(void) { __asm jmp dword ptr function_ptrs[1062 * 4] }
#endif
#ifndef FIX_PrefetchVirtualMemory
    __declspec(naked) void __stdcall fixPrefetchVirtualMemory(void) { __asm jmp dword ptr function_ptrs[1063 * 4] }
#endif
#ifndef FIX_PrepareTape
    __declspec(naked) void __stdcall fixPrepareTape(void) { __asm jmp dword ptr function_ptrs[1064 * 4] }
#endif
#ifndef FIX_PrivCopyFileExW
    __declspec(naked) void __stdcall fixPrivCopyFileExW(void) { __asm jmp dword ptr function_ptrs[1065 * 4] }
#endif
#ifndef FIX_PrivMoveFileIdentityW
    __declspec(naked) void __stdcall fixPrivMoveFileIdentityW(void) { __asm jmp dword ptr function_ptrs[1066 * 4] }
#endif
#ifndef FIX_Process32First
    __declspec(naked) void __stdcall fixProcess32First(void) { __asm jmp dword ptr function_ptrs[1067 * 4] }
#endif
#ifndef FIX_Process32FirstW
    __declspec(naked) void __stdcall fixProcess32FirstW(void) { __asm jmp dword ptr function_ptrs[1068 * 4] }
#endif
#ifndef FIX_Process32Next
    __declspec(naked) void __stdcall fixProcess32Next(void) { __asm jmp dword ptr function_ptrs[1069 * 4] }
#endif
#ifndef FIX_Process32NextW
    __declspec(naked) void __stdcall fixProcess32NextW(void) { __asm jmp dword ptr function_ptrs[1070 * 4] }
#endif
#ifndef FIX_ProcessIdToSessionId
    __declspec(naked) void __stdcall fixProcessIdToSessionId(void) { __asm jmp dword ptr function_ptrs[1071 * 4] }
#endif
#ifndef FIX_PssCaptureSnapshot
    __declspec(naked) void __stdcall fixPssCaptureSnapshot(void) { __asm jmp dword ptr function_ptrs[1072 * 4] }
#endif
#ifndef FIX_PssDuplicateSnapshot
    __declspec(naked) void __stdcall fixPssDuplicateSnapshot(void) { __asm jmp dword ptr function_ptrs[1073 * 4] }
#endif
#ifndef FIX_PssFreeSnapshot
    __declspec(naked) void __stdcall fixPssFreeSnapshot(void) { __asm jmp dword ptr function_ptrs[1074 * 4] }
#endif
#ifndef FIX_PssQuerySnapshot
    __declspec(naked) void __stdcall fixPssQuerySnapshot(void) { __asm jmp dword ptr function_ptrs[1075 * 4] }
#endif
#ifndef FIX_PssWalkMarkerCreate
    __declspec(naked) void __stdcall fixPssWalkMarkerCreate(void) { __asm jmp dword ptr function_ptrs[1076 * 4] }
#endif
#ifndef FIX_PssWalkMarkerFree
    __declspec(naked) void __stdcall fixPssWalkMarkerFree(void) { __asm jmp dword ptr function_ptrs[1077 * 4] }
#endif
#ifndef FIX_PssWalkMarkerGetPosition
    __declspec(naked) void __stdcall fixPssWalkMarkerGetPosition(void) { __asm jmp dword ptr function_ptrs[1078 * 4] }
#endif
#ifndef FIX_PssWalkMarkerRewind
    __declspec(naked) void __stdcall fixPssWalkMarkerRewind(void) { __asm jmp dword ptr function_ptrs[1079 * 4] }
#endif
#ifndef FIX_PssWalkMarkerSeek
    __declspec(naked) void __stdcall fixPssWalkMarkerSeek(void) { __asm jmp dword ptr function_ptrs[1080 * 4] }
#endif
#ifndef FIX_PssWalkMarkerSeekToBeginning
    __declspec(naked) void __stdcall fixPssWalkMarkerSeekToBeginning(void) { __asm jmp dword ptr function_ptrs[1081 * 4] }
#endif
#ifndef FIX_PssWalkMarkerSetPosition
    __declspec(naked) void __stdcall fixPssWalkMarkerSetPosition(void) { __asm jmp dword ptr function_ptrs[1082 * 4] }
#endif
#ifndef FIX_PssWalkMarkerTell
    __declspec(naked) void __stdcall fixPssWalkMarkerTell(void) { __asm jmp dword ptr function_ptrs[1083 * 4] }
#endif
#ifndef FIX_PssWalkSnapshot
    __declspec(naked) void __stdcall fixPssWalkSnapshot(void) { __asm jmp dword ptr function_ptrs[1084 * 4] }
#endif
#ifndef FIX_PulseEvent
    __declspec(naked) void __stdcall fixPulseEvent(void) { __asm jmp dword ptr function_ptrs[1085 * 4] }
#endif
#ifndef FIX_PurgeComm
    __declspec(naked) void __stdcall fixPurgeComm(void) { __asm jmp dword ptr function_ptrs[1086 * 4] }
#endif
#ifndef FIX_QueryActCtxSettingsW
    __declspec(naked) void __stdcall fixQueryActCtxSettingsW(void) { __asm jmp dword ptr function_ptrs[1087 * 4] }
#endif
#ifndef FIX_QueryActCtxSettingsWWorker
    __declspec(naked) void __stdcall fixQueryActCtxSettingsWWorker(void) { __asm jmp dword ptr function_ptrs[1088 * 4] }
#endif
#ifndef FIX_QueryActCtxW
    __declspec(naked) void __stdcall fixQueryActCtxW(void) { __asm jmp dword ptr function_ptrs[1089 * 4] }
#endif
#ifndef FIX_QueryActCtxWWorker
    __declspec(naked) void __stdcall fixQueryActCtxWWorker(void) { __asm jmp dword ptr function_ptrs[1090 * 4] }
#endif
#ifndef FIX_QueryDepthSList
    __declspec(naked) void __stdcall fixQueryDepthSList(void) { __asm jmp dword ptr function_ptrs[1091 * 4] }
#endif
#ifndef FIX_QueryDosDeviceA
    __declspec(naked) void __stdcall fixQueryDosDeviceA(void) { __asm jmp dword ptr function_ptrs[1092 * 4] }
#endif
#ifndef FIX_QueryDosDeviceW
    __declspec(naked) void __stdcall fixQueryDosDeviceW(void) { __asm jmp dword ptr function_ptrs[1093 * 4] }
#endif
#ifndef FIX_QueryFullProcessImageNameA
    __declspec(naked) void __stdcall fixQueryFullProcessImageNameA(void) { __asm jmp dword ptr function_ptrs[1094 * 4] }
#endif
#ifndef FIX_QueryFullProcessImageNameW
    __declspec(naked) void __stdcall fixQueryFullProcessImageNameW(void) { __asm jmp dword ptr function_ptrs[1095 * 4] }
#endif
#ifndef FIX_QueryIdleProcessorCycleTime
    __declspec(naked) void __stdcall fixQueryIdleProcessorCycleTime(void) { __asm jmp dword ptr function_ptrs[1096 * 4] }
#endif
#ifndef FIX_QueryIdleProcessorCycleTimeEx
    __declspec(naked) void __stdcall fixQueryIdleProcessorCycleTimeEx(void) { __asm jmp dword ptr function_ptrs[1097 * 4] }
#endif
#ifndef FIX_QueryInformationJobObject
    __declspec(naked) void __stdcall fixQueryInformationJobObject(void) { __asm jmp dword ptr function_ptrs[1098 * 4] }
#endif
#ifndef FIX_QueryIoRateControlInformationJobObject
    __declspec(naked) void __stdcall fixQueryIoRateControlInformationJobObject(void) { __asm jmp dword ptr function_ptrs[1099 * 4] }
#endif
#ifndef FIX_QueryMemoryResourceNotification
    __declspec(naked) void __stdcall fixQueryMemoryResourceNotification(void) { __asm jmp dword ptr function_ptrs[1100 * 4] }
#endif
#ifndef FIX_QueryPerformanceCounter
    __declspec(naked) void __stdcall fixQueryPerformanceCounter(void) { __asm jmp dword ptr function_ptrs[1101 * 4] }
#endif
#ifndef FIX_QueryPerformanceFrequency
    __declspec(naked) void __stdcall fixQueryPerformanceFrequency(void) { __asm jmp dword ptr function_ptrs[1102 * 4] }
#endif
#ifndef FIX_QueryProcessAffinityUpdateMode
    __declspec(naked) void __stdcall fixQueryProcessAffinityUpdateMode(void) { __asm jmp dword ptr function_ptrs[1103 * 4] }
#endif
#ifndef FIX_QueryProcessCycleTime
    __declspec(naked) void __stdcall fixQueryProcessCycleTime(void) { __asm jmp dword ptr function_ptrs[1104 * 4] }
#endif
#ifndef FIX_QueryProtectedPolicy
    __declspec(naked) void __stdcall fixQueryProtectedPolicy(void) { __asm jmp dword ptr function_ptrs[1105 * 4] }
#endif
#ifndef FIX_QueryThreadCycleTime
    __declspec(naked) void __stdcall fixQueryThreadCycleTime(void) { __asm jmp dword ptr function_ptrs[1106 * 4] }
#endif
#ifndef FIX_QueryThreadProfiling
    __declspec(naked) void __stdcall fixQueryThreadProfiling(void) { __asm jmp dword ptr function_ptrs[1107 * 4] }
#endif
#ifndef FIX_QueryThreadpoolStackInformation
    __declspec(naked) void __stdcall fixQueryThreadpoolStackInformation(void) { __asm jmp dword ptr function_ptrs[1108 * 4] }
#endif
#ifndef FIX_QueryUnbiasedInterruptTime
    __declspec(naked) void __stdcall fixQueryUnbiasedInterruptTime(void) { __asm jmp dword ptr function_ptrs[1109 * 4] }
#endif
#ifndef FIX_QueueUserAPC
    __declspec(naked) void __stdcall fixQueueUserAPC(void) { __asm jmp dword ptr function_ptrs[1110 * 4] }
#endif
#ifndef FIX_QueueUserWorkItem
    __declspec(naked) void __stdcall fixQueueUserWorkItem(void) { __asm jmp dword ptr function_ptrs[1111 * 4] }
#endif
#ifndef FIX_QuirkGetData2Worker
    __declspec(naked) void __stdcall fixQuirkGetData2Worker(void) { __asm jmp dword ptr function_ptrs[1112 * 4] }
#endif
#ifndef FIX_QuirkGetDataWorker
    __declspec(naked) void __stdcall fixQuirkGetDataWorker(void) { __asm jmp dword ptr function_ptrs[1113 * 4] }
#endif
#ifndef FIX_QuirkIsEnabled2Worker
    __declspec(naked) void __stdcall fixQuirkIsEnabled2Worker(void) { __asm jmp dword ptr function_ptrs[1114 * 4] }
#endif
#ifndef FIX_QuirkIsEnabled3Worker
    __declspec(naked) void __stdcall fixQuirkIsEnabled3Worker(void) { __asm jmp dword ptr function_ptrs[1115 * 4] }
#endif
#ifndef FIX_QuirkIsEnabledForPackage2Worker
    __declspec(naked) void __stdcall fixQuirkIsEnabledForPackage2Worker(void) { __asm jmp dword ptr function_ptrs[1116 * 4] }
#endif
#ifndef FIX_QuirkIsEnabledForPackage3Worker
    __declspec(naked) void __stdcall fixQuirkIsEnabledForPackage3Worker(void) { __asm jmp dword ptr function_ptrs[1117 * 4] }
#endif
#ifndef FIX_QuirkIsEnabledForPackage4Worker
    __declspec(naked) void __stdcall fixQuirkIsEnabledForPackage4Worker(void) { __asm jmp dword ptr function_ptrs[1118 * 4] }
#endif
#ifndef FIX_QuirkIsEnabledForPackageWorker
    __declspec(naked) void __stdcall fixQuirkIsEnabledForPackageWorker(void) { __asm jmp dword ptr function_ptrs[1119 * 4] }
#endif
#ifndef FIX_QuirkIsEnabledForProcessWorker
    __declspec(naked) void __stdcall fixQuirkIsEnabledForProcessWorker(void) { __asm jmp dword ptr function_ptrs[1120 * 4] }
#endif
#ifndef FIX_QuirkIsEnabledWorker
    __declspec(naked) void __stdcall fixQuirkIsEnabledWorker(void) { __asm jmp dword ptr function_ptrs[1121 * 4] }
#endif
#ifndef FIX_RaiseException
    __declspec(naked) void __stdcall fixRaiseException(void) { __asm jmp dword ptr function_ptrs[1122 * 4] }
#endif
#ifndef FIX_RaiseFailFastException
    __declspec(naked) void __stdcall fixRaiseFailFastException(void) { __asm jmp dword ptr function_ptrs[1123 * 4] }
#endif
#ifndef FIX_RaiseInvalid16BitExeError
    __declspec(naked) void __stdcall fixRaiseInvalid16BitExeError(void) { __asm jmp dword ptr function_ptrs[1124 * 4] }
#endif
#ifndef FIX_ReOpenFile
    __declspec(naked) void __stdcall fixReOpenFile(void) { __asm jmp dword ptr function_ptrs[1125 * 4] }
#endif
#ifndef FIX_ReadConsoleA
    __declspec(naked) void __stdcall fixReadConsoleA(void) { __asm jmp dword ptr function_ptrs[1126 * 4] }
#endif
#ifndef FIX_ReadConsoleInputA
    __declspec(naked) void __stdcall fixReadConsoleInputA(void) { __asm jmp dword ptr function_ptrs[1127 * 4] }
#endif
#ifndef FIX_ReadConsoleInputExA
    __declspec(naked) void __stdcall fixReadConsoleInputExA(void) { __asm jmp dword ptr function_ptrs[1128 * 4] }
#endif
#ifndef FIX_ReadConsoleInputExW
    __declspec(naked) void __stdcall fixReadConsoleInputExW(void) { __asm jmp dword ptr function_ptrs[1129 * 4] }
#endif
#ifndef FIX_ReadConsoleInputW
    __declspec(naked) void __stdcall fixReadConsoleInputW(void) { __asm jmp dword ptr function_ptrs[1130 * 4] }
#endif
#ifndef FIX_ReadConsoleOutputA
    __declspec(naked) void __stdcall fixReadConsoleOutputA(void) { __asm jmp dword ptr function_ptrs[1131 * 4] }
#endif
#ifndef FIX_ReadConsoleOutputAttribute
    __declspec(naked) void __stdcall fixReadConsoleOutputAttribute(void) { __asm jmp dword ptr function_ptrs[1132 * 4] }
#endif
#ifndef FIX_ReadConsoleOutputCharacterA
    __declspec(naked) void __stdcall fixReadConsoleOutputCharacterA(void) { __asm jmp dword ptr function_ptrs[1133 * 4] }
#endif
#ifndef FIX_ReadConsoleOutputCharacterW
    __declspec(naked) void __stdcall fixReadConsoleOutputCharacterW(void) { __asm jmp dword ptr function_ptrs[1134 * 4] }
#endif
#ifndef FIX_ReadConsoleOutputW
    __declspec(naked) void __stdcall fixReadConsoleOutputW(void) { __asm jmp dword ptr function_ptrs[1135 * 4] }
#endif
#ifndef FIX_ReadConsoleW
    __declspec(naked) void __stdcall fixReadConsoleW(void) { __asm jmp dword ptr function_ptrs[1136 * 4] }
#endif
#ifndef FIX_ReadDirectoryChangesExW
    __declspec(naked) void __stdcall fixReadDirectoryChangesExW(void) { __asm jmp dword ptr function_ptrs[1137 * 4] }
#endif
#ifndef FIX_ReadDirectoryChangesW
    __declspec(naked) void __stdcall fixReadDirectoryChangesW(void) { __asm jmp dword ptr function_ptrs[1138 * 4] }
#endif
#ifndef FIX_ReadFile
    __declspec(naked) void __stdcall fixReadFile(void) { __asm jmp dword ptr function_ptrs[1139 * 4] }
#endif
#ifndef FIX_ReadFileEx
    __declspec(naked) void __stdcall fixReadFileEx(void) { __asm jmp dword ptr function_ptrs[1140 * 4] }
#endif
#ifndef FIX_ReadFileScatter
    __declspec(naked) void __stdcall fixReadFileScatter(void) { __asm jmp dword ptr function_ptrs[1141 * 4] }
#endif
#ifndef FIX_ReadProcessMemory
    __declspec(naked) void __stdcall fixReadProcessMemory(void) { __asm jmp dword ptr function_ptrs[1142 * 4] }
#endif
#ifndef FIX_ReadThreadProfilingData
    __declspec(naked) void __stdcall fixReadThreadProfilingData(void) { __asm jmp dword ptr function_ptrs[1143 * 4] }
#endif
#ifndef FIX_ReclaimVirtualMemory
    __declspec(naked) void __stdcall fixReclaimVirtualMemory(void) { __asm jmp dword ptr function_ptrs[1144 * 4] }
#endif
#ifndef FIX_RegCloseKey
    __declspec(naked) void __stdcall fixRegCloseKey(void) { __asm jmp dword ptr function_ptrs[1145 * 4] }
#endif
#ifndef FIX_RegCopyTreeW
    __declspec(naked) void __stdcall fixRegCopyTreeW(void) { __asm jmp dword ptr function_ptrs[1146 * 4] }
#endif
#ifndef FIX_RegCreateKeyExA
    __declspec(naked) void __stdcall fixRegCreateKeyExA(void) { __asm jmp dword ptr function_ptrs[1147 * 4] }
#endif
#ifndef FIX_RegCreateKeyExW
    __declspec(naked) void __stdcall fixRegCreateKeyExW(void) { __asm jmp dword ptr function_ptrs[1148 * 4] }
#endif
#ifndef FIX_RegDeleteKeyExA
    __declspec(naked) void __stdcall fixRegDeleteKeyExA(void) { __asm jmp dword ptr function_ptrs[1149 * 4] }
#endif
#ifndef FIX_RegDeleteKeyExW
    __declspec(naked) void __stdcall fixRegDeleteKeyExW(void) { __asm jmp dword ptr function_ptrs[1150 * 4] }
#endif
#ifndef FIX_RegDeleteTreeA
    __declspec(naked) void __stdcall fixRegDeleteTreeA(void) { __asm jmp dword ptr function_ptrs[1151 * 4] }
#endif
#ifndef FIX_RegDeleteTreeW
    __declspec(naked) void __stdcall fixRegDeleteTreeW(void) { __asm jmp dword ptr function_ptrs[1152 * 4] }
#endif
#ifndef FIX_RegDeleteValueA
    __declspec(naked) void __stdcall fixRegDeleteValueA(void) { __asm jmp dword ptr function_ptrs[1153 * 4] }
#endif
#ifndef FIX_RegDeleteValueW
    __declspec(naked) void __stdcall fixRegDeleteValueW(void) { __asm jmp dword ptr function_ptrs[1154 * 4] }
#endif
#ifndef FIX_RegDisablePredefinedCacheEx
    __declspec(naked) void __stdcall fixRegDisablePredefinedCacheEx(void) { __asm jmp dword ptr function_ptrs[1155 * 4] }
#endif
#ifndef FIX_RegEnumKeyExA
    __declspec(naked) void __stdcall fixRegEnumKeyExA(void) { __asm jmp dword ptr function_ptrs[1156 * 4] }
#endif
#ifndef FIX_RegEnumKeyExW
    __declspec(naked) void __stdcall fixRegEnumKeyExW(void) { __asm jmp dword ptr function_ptrs[1157 * 4] }
#endif
#ifndef FIX_RegEnumValueA
    __declspec(naked) void __stdcall fixRegEnumValueA(void) { __asm jmp dword ptr function_ptrs[1158 * 4] }
#endif
#ifndef FIX_RegEnumValueW
    __declspec(naked) void __stdcall fixRegEnumValueW(void) { __asm jmp dword ptr function_ptrs[1159 * 4] }
#endif
#ifndef FIX_RegFlushKey
    __declspec(naked) void __stdcall fixRegFlushKey(void) { __asm jmp dword ptr function_ptrs[1160 * 4] }
#endif
#ifndef FIX_RegGetKeySecurity
    __declspec(naked) void __stdcall fixRegGetKeySecurity(void) { __asm jmp dword ptr function_ptrs[1161 * 4] }
#endif
#ifndef FIX_RegGetValueA
    __declspec(naked) void __stdcall fixRegGetValueA(void) { __asm jmp dword ptr function_ptrs[1162 * 4] }
#endif
#ifndef FIX_RegGetValueW
    __declspec(naked) void __stdcall fixRegGetValueW(void) { __asm jmp dword ptr function_ptrs[1163 * 4] }
#endif
#ifndef FIX_RegLoadKeyA
    __declspec(naked) void __stdcall fixRegLoadKeyA(void) { __asm jmp dword ptr function_ptrs[1164 * 4] }
#endif
#ifndef FIX_RegLoadKeyW
    __declspec(naked) void __stdcall fixRegLoadKeyW(void) { __asm jmp dword ptr function_ptrs[1165 * 4] }
#endif
#ifndef FIX_RegLoadMUIStringA
    __declspec(naked) void __stdcall fixRegLoadMUIStringA(void) { __asm jmp dword ptr function_ptrs[1166 * 4] }
#endif
#ifndef FIX_RegLoadMUIStringW
    __declspec(naked) void __stdcall fixRegLoadMUIStringW(void) { __asm jmp dword ptr function_ptrs[1167 * 4] }
#endif
#ifndef FIX_RegNotifyChangeKeyValue
    __declspec(naked) void __stdcall fixRegNotifyChangeKeyValue(void) { __asm jmp dword ptr function_ptrs[1168 * 4] }
#endif
#ifndef FIX_RegOpenCurrentUser
    __declspec(naked) void __stdcall fixRegOpenCurrentUser(void) { __asm jmp dword ptr function_ptrs[1169 * 4] }
#endif
#ifndef FIX_RegOpenKeyExA
    __declspec(naked) void __stdcall fixRegOpenKeyExA(void) { __asm jmp dword ptr function_ptrs[1170 * 4] }
#endif
#ifndef FIX_RegOpenKeyExW
    __declspec(naked) void __stdcall fixRegOpenKeyExW(void) { __asm jmp dword ptr function_ptrs[1171 * 4] }
#endif
#ifndef FIX_RegOpenUserClassesRoot
    __declspec(naked) void __stdcall fixRegOpenUserClassesRoot(void) { __asm jmp dword ptr function_ptrs[1172 * 4] }
#endif
#ifndef FIX_RegQueryInfoKeyA
    __declspec(naked) void __stdcall fixRegQueryInfoKeyA(void) { __asm jmp dword ptr function_ptrs[1173 * 4] }
#endif
#ifndef FIX_RegQueryInfoKeyW
    __declspec(naked) void __stdcall fixRegQueryInfoKeyW(void) { __asm jmp dword ptr function_ptrs[1174 * 4] }
#endif
#ifndef FIX_RegQueryValueExA
    __declspec(naked) void __stdcall fixRegQueryValueExA(void) { __asm jmp dword ptr function_ptrs[1175 * 4] }
#endif
#ifndef FIX_RegQueryValueExW
    __declspec(naked) void __stdcall fixRegQueryValueExW(void) { __asm jmp dword ptr function_ptrs[1176 * 4] }
#endif
#ifndef FIX_RegRestoreKeyA
    __declspec(naked) void __stdcall fixRegRestoreKeyA(void) { __asm jmp dword ptr function_ptrs[1177 * 4] }
#endif
#ifndef FIX_RegRestoreKeyW
    __declspec(naked) void __stdcall fixRegRestoreKeyW(void) { __asm jmp dword ptr function_ptrs[1178 * 4] }
#endif
#ifndef FIX_RegSaveKeyExA
    __declspec(naked) void __stdcall fixRegSaveKeyExA(void) { __asm jmp dword ptr function_ptrs[1179 * 4] }
#endif
#ifndef FIX_RegSaveKeyExW
    __declspec(naked) void __stdcall fixRegSaveKeyExW(void) { __asm jmp dword ptr function_ptrs[1180 * 4] }
#endif
#ifndef FIX_RegSetKeySecurity
    __declspec(naked) void __stdcall fixRegSetKeySecurity(void) { __asm jmp dword ptr function_ptrs[1181 * 4] }
#endif
#ifndef FIX_RegSetValueExA
    __declspec(naked) void __stdcall fixRegSetValueExA(void) { __asm jmp dword ptr function_ptrs[1182 * 4] }
#endif
#ifndef FIX_RegSetValueExW
    __declspec(naked) void __stdcall fixRegSetValueExW(void) { __asm jmp dword ptr function_ptrs[1183 * 4] }
#endif
#ifndef FIX_RegUnLoadKeyA
    __declspec(naked) void __stdcall fixRegUnLoadKeyA(void) { __asm jmp dword ptr function_ptrs[1184 * 4] }
#endif
#ifndef FIX_RegUnLoadKeyW
    __declspec(naked) void __stdcall fixRegUnLoadKeyW(void) { __asm jmp dword ptr function_ptrs[1185 * 4] }
#endif
#ifndef FIX_RegisterApplicationRecoveryCallback
    __declspec(naked) void __stdcall fixRegisterApplicationRecoveryCallback(void) { __asm jmp dword ptr function_ptrs[1186 * 4] }
#endif
#ifndef FIX_RegisterApplicationRestart
    __declspec(naked) void __stdcall fixRegisterApplicationRestart(void) { __asm jmp dword ptr function_ptrs[1187 * 4] }
#endif
#ifndef FIX_RegisterBadMemoryNotification
    __declspec(naked) void __stdcall fixRegisterBadMemoryNotification(void) { __asm jmp dword ptr function_ptrs[1188 * 4] }
#endif
#ifndef FIX_RegisterConsoleIME
    __declspec(naked) void __stdcall fixRegisterConsoleIME(void) { __asm jmp dword ptr function_ptrs[1189 * 4] }
#endif
#ifndef FIX_RegisterConsoleOS2
    __declspec(naked) void __stdcall fixRegisterConsoleOS2(void) { __asm jmp dword ptr function_ptrs[1190 * 4] }
#endif
#ifndef FIX_RegisterConsoleVDM
    __declspec(naked) void __stdcall fixRegisterConsoleVDM(void) { __asm jmp dword ptr function_ptrs[1191 * 4] }
#endif
#ifndef FIX_RegisterWaitForInputIdle
    __declspec(naked) void __stdcall fixRegisterWaitForInputIdle(void) { __asm jmp dword ptr function_ptrs[1192 * 4] }
#endif
#ifndef FIX_RegisterWaitForSingleObject
    __declspec(naked) void __stdcall fixRegisterWaitForSingleObject(void) { __asm jmp dword ptr function_ptrs[1193 * 4] }
#endif
#ifndef FIX_RegisterWaitForSingleObjectEx
    __declspec(naked) void __stdcall fixRegisterWaitForSingleObjectEx(void) { __asm jmp dword ptr function_ptrs[1194 * 4] }
#endif
#ifndef FIX_RegisterWaitUntilOOBECompleted
    __declspec(naked) void __stdcall fixRegisterWaitUntilOOBECompleted(void) { __asm jmp dword ptr function_ptrs[1195 * 4] }
#endif
#ifndef FIX_RegisterWowBaseHandlers
    __declspec(naked) void __stdcall fixRegisterWowBaseHandlers(void) { __asm jmp dword ptr function_ptrs[1196 * 4] }
#endif
#ifndef FIX_RegisterWowExec
    __declspec(naked) void __stdcall fixRegisterWowExec(void) { __asm jmp dword ptr function_ptrs[1197 * 4] }
#endif
#ifndef FIX_ReleaseActCtx
    __declspec(naked) void __stdcall fixReleaseActCtx(void) { __asm jmp dword ptr function_ptrs[1198 * 4] }
#endif
#ifndef FIX_ReleaseActCtxWorker
    __declspec(naked) void __stdcall fixReleaseActCtxWorker(void) { __asm jmp dword ptr function_ptrs[1199 * 4] }
#endif
#ifndef FIX_ReleaseMutex
    __declspec(naked) void __stdcall fixReleaseMutex(void) { __asm jmp dword ptr function_ptrs[1200 * 4] }
#endif
#ifndef FIX_ReleaseMutexWhenCallbackReturns
    __declspec(naked) void __stdcall fixReleaseMutexWhenCallbackReturns(void) { __asm jmp dword ptr function_ptrs[1201 * 4] }
#endif
#ifndef FIX_ReleaseSRWLockExclusive
    __declspec(naked) void __stdcall fixReleaseSRWLockExclusive(void) { __asm jmp dword ptr function_ptrs[1202 * 4] }
#endif
#ifndef FIX_ReleaseSRWLockShared
    __declspec(naked) void __stdcall fixReleaseSRWLockShared(void) { __asm jmp dword ptr function_ptrs[1203 * 4] }
#endif
#ifndef FIX_ReleaseSemaphore
    __declspec(naked) void __stdcall fixReleaseSemaphore(void) { __asm jmp dword ptr function_ptrs[1204 * 4] }
#endif
#ifndef FIX_ReleaseSemaphoreWhenCallbackReturns
    __declspec(naked) void __stdcall fixReleaseSemaphoreWhenCallbackReturns(void) { __asm jmp dword ptr function_ptrs[1205 * 4] }
#endif
#ifndef FIX_RemoveDirectoryA
    __declspec(naked) void __stdcall fixRemoveDirectoryA(void) { __asm jmp dword ptr function_ptrs[1206 * 4] }
#endif
#ifndef FIX_RemoveDirectoryTransactedA
    __declspec(naked) void __stdcall fixRemoveDirectoryTransactedA(void) { __asm jmp dword ptr function_ptrs[1207 * 4] }
#endif
#ifndef FIX_RemoveDirectoryTransactedW
    __declspec(naked) void __stdcall fixRemoveDirectoryTransactedW(void) { __asm jmp dword ptr function_ptrs[1208 * 4] }
#endif
#ifndef FIX_RemoveDirectoryW
    __declspec(naked) void __stdcall fixRemoveDirectoryW(void) { __asm jmp dword ptr function_ptrs[1209 * 4] }
#endif
#ifndef FIX_RemoveDllDirectory
    __declspec(naked) void __stdcall fixRemoveDllDirectory(void) { __asm jmp dword ptr function_ptrs[1210 * 4] }
#endif
#ifndef FIX_RemoveLocalAlternateComputerNameA
    __declspec(naked) void __stdcall fixRemoveLocalAlternateComputerNameA(void) { __asm jmp dword ptr function_ptrs[1211 * 4] }
#endif
#ifndef FIX_RemoveLocalAlternateComputerNameW
    __declspec(naked) void __stdcall fixRemoveLocalAlternateComputerNameW(void) { __asm jmp dword ptr function_ptrs[1212 * 4] }
#endif
#ifndef FIX_RemoveSecureMemoryCacheCallback
    __declspec(naked) void __stdcall fixRemoveSecureMemoryCacheCallback(void) { __asm jmp dword ptr function_ptrs[1213 * 4] }
#endif
#ifndef FIX_RemoveVectoredContinueHandler
    __declspec(naked) void __stdcall fixRemoveVectoredContinueHandler(void) { __asm jmp dword ptr function_ptrs[1214 * 4] }
#endif
#ifndef FIX_RemoveVectoredExceptionHandler
    __declspec(naked) void __stdcall fixRemoveVectoredExceptionHandler(void) { __asm jmp dword ptr function_ptrs[1215 * 4] }
#endif
#ifndef FIX_ReplaceFile
    __declspec(naked) void __stdcall fixReplaceFile(void) { __asm jmp dword ptr function_ptrs[1216 * 4] }
#endif
#ifndef FIX_ReplaceFileA
    __declspec(naked) void __stdcall fixReplaceFileA(void) { __asm jmp dword ptr function_ptrs[1217 * 4] }
#endif
#ifndef FIX_ReplaceFileW
    __declspec(naked) void __stdcall fixReplaceFileW(void) { __asm jmp dword ptr function_ptrs[1218 * 4] }
#endif
#ifndef FIX_ReplacePartitionUnit
    __declspec(naked) void __stdcall fixReplacePartitionUnit(void) { __asm jmp dword ptr function_ptrs[1219 * 4] }
#endif
#ifndef FIX_RequestDeviceWakeup
    __declspec(naked) void __stdcall fixRequestDeviceWakeup(void) { __asm jmp dword ptr function_ptrs[1220 * 4] }
#endif
#ifndef FIX_RequestWakeupLatency
    __declspec(naked) void __stdcall fixRequestWakeupLatency(void) { __asm jmp dword ptr function_ptrs[1221 * 4] }
#endif
#ifndef FIX_ResetEvent
    __declspec(naked) void __stdcall fixResetEvent(void) { __asm jmp dword ptr function_ptrs[1222 * 4] }
#endif
#ifndef FIX_ResetWriteWatch
    __declspec(naked) void __stdcall fixResetWriteWatch(void) { __asm jmp dword ptr function_ptrs[1223 * 4] }
#endif
#ifndef FIX_ResizePseudoConsole
    __declspec(naked) void __stdcall fixResizePseudoConsole(void) { __asm jmp dword ptr function_ptrs[1224 * 4] }
#endif
#ifndef FIX_ResolveDelayLoadedAPI
    __declspec(naked) void __stdcall fixResolveDelayLoadedAPI(void) { __asm jmp dword ptr function_ptrs[1225 * 4] }
#endif
#ifndef FIX_ResolveDelayLoadsFromDll
    __declspec(naked) void __stdcall fixResolveDelayLoadsFromDll(void) { __asm jmp dword ptr function_ptrs[1226 * 4] }
#endif
#ifndef FIX_ResolveLocaleName
    __declspec(naked) void __stdcall fixResolveLocaleName(void) { __asm jmp dword ptr function_ptrs[1227 * 4] }
#endif
#ifndef FIX_RestoreLastError
    __declspec(naked) void __stdcall fixRestoreLastError(void) { __asm jmp dword ptr function_ptrs[1228 * 4] }
#endif
#ifndef FIX_ResumeThread
    __declspec(naked) void __stdcall fixResumeThread(void) { __asm jmp dword ptr function_ptrs[1229 * 4] }
#endif
#ifndef FIX_RtlCaptureContext
    __declspec(naked) void __stdcall fixRtlCaptureContext(void) { __asm jmp dword ptr function_ptrs[1230 * 4] }
#endif
#ifndef FIX_RtlCaptureStackBackTrace
    __declspec(naked) void __stdcall fixRtlCaptureStackBackTrace(void) { __asm jmp dword ptr function_ptrs[1231 * 4] }
#endif
#ifndef FIX_RtlFillMemory
    __declspec(naked) void __stdcall fixRtlFillMemory(void) { __asm jmp dword ptr function_ptrs[1232 * 4] }
#endif
#ifndef FIX_RtlMoveMemory
    __declspec(naked) void __stdcall fixRtlMoveMemory(void) { __asm jmp dword ptr function_ptrs[1233 * 4] }
#endif
#ifndef FIX_RtlPcToFileHeader
    __declspec(naked) void __stdcall fixRtlPcToFileHeader(void) { __asm jmp dword ptr function_ptrs[1234 * 4] }
#endif
#ifndef FIX_RtlUnwind
    __declspec(naked) void __stdcall fixRtlUnwind(void) { __asm jmp dword ptr function_ptrs[1235 * 4] }
#endif
#ifndef FIX_RtlZeroMemory
    __declspec(naked) void __stdcall fixRtlZeroMemory(void) { __asm jmp dword ptr function_ptrs[1236 * 4] }
#endif
#ifndef FIX_ScrollConsoleScreenBufferA
    __declspec(naked) void __stdcall fixScrollConsoleScreenBufferA(void) { __asm jmp dword ptr function_ptrs[1237 * 4] }
#endif
#ifndef FIX_ScrollConsoleScreenBufferW
    __declspec(naked) void __stdcall fixScrollConsoleScreenBufferW(void) { __asm jmp dword ptr function_ptrs[1238 * 4] }
#endif
#ifndef FIX_SearchPathA
    __declspec(naked) void __stdcall fixSearchPathA(void) { __asm jmp dword ptr function_ptrs[1239 * 4] }
#endif
#ifndef FIX_SearchPathW
    __declspec(naked) void __stdcall fixSearchPathW(void) { __asm jmp dword ptr function_ptrs[1240 * 4] }
#endif
#ifndef FIX_SetCachedSigningLevel
    __declspec(naked) void __stdcall fixSetCachedSigningLevel(void) { __asm jmp dword ptr function_ptrs[1241 * 4] }
#endif
#ifndef FIX_SetCalendarInfoA
    __declspec(naked) void __stdcall fixSetCalendarInfoA(void) { __asm jmp dword ptr function_ptrs[1242 * 4] }
#endif
#ifndef FIX_SetCalendarInfoW
    __declspec(naked) void __stdcall fixSetCalendarInfoW(void) { __asm jmp dword ptr function_ptrs[1243 * 4] }
#endif
#ifndef FIX_SetComPlusPackageInstallStatus
    __declspec(naked) void __stdcall fixSetComPlusPackageInstallStatus(void) { __asm jmp dword ptr function_ptrs[1244 * 4] }
#endif
#ifndef FIX_SetCommBreak
    __declspec(naked) void __stdcall fixSetCommBreak(void) { __asm jmp dword ptr function_ptrs[1245 * 4] }
#endif
#ifndef FIX_SetCommConfig
    __declspec(naked) void __stdcall fixSetCommConfig(void) { __asm jmp dword ptr function_ptrs[1246 * 4] }
#endif
#ifndef FIX_SetCommMask
    __declspec(naked) void __stdcall fixSetCommMask(void) { __asm jmp dword ptr function_ptrs[1247 * 4] }
#endif
#ifndef FIX_SetCommState
    __declspec(naked) void __stdcall fixSetCommState(void) { __asm jmp dword ptr function_ptrs[1248 * 4] }
#endif
#ifndef FIX_SetCommTimeouts
    __declspec(naked) void __stdcall fixSetCommTimeouts(void) { __asm jmp dword ptr function_ptrs[1249 * 4] }
#endif
#ifndef FIX_SetComputerNameA
    __declspec(naked) void __stdcall fixSetComputerNameA(void) { __asm jmp dword ptr function_ptrs[1250 * 4] }
#endif
#ifndef FIX_SetComputerNameEx2W
    __declspec(naked) void __stdcall fixSetComputerNameEx2W(void) { __asm jmp dword ptr function_ptrs[1251 * 4] }
#endif
#ifndef FIX_SetComputerNameExA
    __declspec(naked) void __stdcall fixSetComputerNameExA(void) { __asm jmp dword ptr function_ptrs[1252 * 4] }
#endif
#ifndef FIX_SetComputerNameExW
    __declspec(naked) void __stdcall fixSetComputerNameExW(void) { __asm jmp dword ptr function_ptrs[1253 * 4] }
#endif
#ifndef FIX_SetComputerNameW
    __declspec(naked) void __stdcall fixSetComputerNameW(void) { __asm jmp dword ptr function_ptrs[1254 * 4] }
#endif
#ifndef FIX_SetConsoleActiveScreenBuffer
    __declspec(naked) void __stdcall fixSetConsoleActiveScreenBuffer(void) { __asm jmp dword ptr function_ptrs[1255 * 4] }
#endif
#ifndef FIX_SetConsoleCP
    __declspec(naked) void __stdcall fixSetConsoleCP(void) { __asm jmp dword ptr function_ptrs[1256 * 4] }
#endif
#ifndef FIX_SetConsoleCtrlHandler
    __declspec(naked) void __stdcall fixSetConsoleCtrlHandler(void) { __asm jmp dword ptr function_ptrs[1257 * 4] }
#endif
#ifndef FIX_SetConsoleCursor
    __declspec(naked) void __stdcall fixSetConsoleCursor(void) { __asm jmp dword ptr function_ptrs[1258 * 4] }
#endif
#ifndef FIX_SetConsoleCursorInfo
    __declspec(naked) void __stdcall fixSetConsoleCursorInfo(void) { __asm jmp dword ptr function_ptrs[1259 * 4] }
#endif
#ifndef FIX_SetConsoleCursorMode
    __declspec(naked) void __stdcall fixSetConsoleCursorMode(void) { __asm jmp dword ptr function_ptrs[1260 * 4] }
#endif
#ifndef FIX_SetConsoleCursorPosition
    __declspec(naked) void __stdcall fixSetConsoleCursorPosition(void) { __asm jmp dword ptr function_ptrs[1261 * 4] }
#endif
#ifndef FIX_SetConsoleDisplayMode
    __declspec(naked) void __stdcall fixSetConsoleDisplayMode(void) { __asm jmp dword ptr function_ptrs[1262 * 4] }
#endif
#ifndef FIX_SetConsoleFont
    __declspec(naked) void __stdcall fixSetConsoleFont(void) { __asm jmp dword ptr function_ptrs[1263 * 4] }
#endif
#ifndef FIX_SetConsoleHardwareState
    __declspec(naked) void __stdcall fixSetConsoleHardwareState(void) { __asm jmp dword ptr function_ptrs[1264 * 4] }
#endif
#ifndef FIX_SetConsoleHistoryInfo
    __declspec(naked) void __stdcall fixSetConsoleHistoryInfo(void) { __asm jmp dword ptr function_ptrs[1265 * 4] }
#endif
#ifndef FIX_SetConsoleIcon
    __declspec(naked) void __stdcall fixSetConsoleIcon(void) { __asm jmp dword ptr function_ptrs[1266 * 4] }
#endif
#ifndef FIX_SetConsoleInputExeNameA
    __declspec(naked) void __stdcall fixSetConsoleInputExeNameA(void) { __asm jmp dword ptr function_ptrs[1267 * 4] }
#endif
#ifndef FIX_SetConsoleInputExeNameW
    __declspec(naked) void __stdcall fixSetConsoleInputExeNameW(void) { __asm jmp dword ptr function_ptrs[1268 * 4] }
#endif
#ifndef FIX_SetConsoleKeyShortcuts
    __declspec(naked) void __stdcall fixSetConsoleKeyShortcuts(void) { __asm jmp dword ptr function_ptrs[1269 * 4] }
#endif
#ifndef FIX_SetConsoleLocalEUDC
    __declspec(naked) void __stdcall fixSetConsoleLocalEUDC(void) { __asm jmp dword ptr function_ptrs[1270 * 4] }
#endif
#ifndef FIX_SetConsoleMaximumWindowSize
    __declspec(naked) void __stdcall fixSetConsoleMaximumWindowSize(void) { __asm jmp dword ptr function_ptrs[1271 * 4] }
#endif
#ifndef FIX_SetConsoleMenuClose
    __declspec(naked) void __stdcall fixSetConsoleMenuClose(void) { __asm jmp dword ptr function_ptrs[1272 * 4] }
#endif
#ifndef FIX_SetConsoleMode
    __declspec(naked) void __stdcall fixSetConsoleMode(void) { __asm jmp dword ptr function_ptrs[1273 * 4] }
#endif
#ifndef FIX_SetConsoleNlsMode
    __declspec(naked) void __stdcall fixSetConsoleNlsMode(void) { __asm jmp dword ptr function_ptrs[1274 * 4] }
#endif
#ifndef FIX_SetConsoleNumberOfCommandsA
    __declspec(naked) void __stdcall fixSetConsoleNumberOfCommandsA(void) { __asm jmp dword ptr function_ptrs[1275 * 4] }
#endif
#ifndef FIX_SetConsoleNumberOfCommandsW
    __declspec(naked) void __stdcall fixSetConsoleNumberOfCommandsW(void) { __asm jmp dword ptr function_ptrs[1276 * 4] }
#endif
#ifndef FIX_SetConsoleOS2OemFormat
    __declspec(naked) void __stdcall fixSetConsoleOS2OemFormat(void) { __asm jmp dword ptr function_ptrs[1277 * 4] }
#endif
#ifndef FIX_SetConsoleOutputCP
    __declspec(naked) void __stdcall fixSetConsoleOutputCP(void) { __asm jmp dword ptr function_ptrs[1278 * 4] }
#endif
#ifndef FIX_SetConsolePalette
    __declspec(naked) void __stdcall fixSetConsolePalette(void) { __asm jmp dword ptr function_ptrs[1279 * 4] }
#endif
#ifndef FIX_SetConsoleScreenBufferInfoEx
    __declspec(naked) void __stdcall fixSetConsoleScreenBufferInfoEx(void) { __asm jmp dword ptr function_ptrs[1280 * 4] }
#endif
#ifndef FIX_SetConsoleScreenBufferSize
    __declspec(naked) void __stdcall fixSetConsoleScreenBufferSize(void) { __asm jmp dword ptr function_ptrs[1281 * 4] }
#endif
#ifndef FIX_SetConsoleTextAttribute
    __declspec(naked) void __stdcall fixSetConsoleTextAttribute(void) { __asm jmp dword ptr function_ptrs[1282 * 4] }
#endif
#ifndef FIX_SetConsoleTitleA
    __declspec(naked) void __stdcall fixSetConsoleTitleA(void) { __asm jmp dword ptr function_ptrs[1283 * 4] }
#endif
#ifndef FIX_SetConsoleTitleW
    __declspec(naked) void __stdcall fixSetConsoleTitleW(void) { __asm jmp dword ptr function_ptrs[1284 * 4] }
#endif
#ifndef FIX_SetConsoleWindowInfo
    __declspec(naked) void __stdcall fixSetConsoleWindowInfo(void) { __asm jmp dword ptr function_ptrs[1285 * 4] }
#endif
#ifndef FIX_SetCriticalSectionSpinCount
    __declspec(naked) void __stdcall fixSetCriticalSectionSpinCount(void) { __asm jmp dword ptr function_ptrs[1286 * 4] }
#endif
#ifndef FIX_SetCurrentConsoleFontEx
    __declspec(naked) void __stdcall fixSetCurrentConsoleFontEx(void) { __asm jmp dword ptr function_ptrs[1287 * 4] }
#endif
#ifndef FIX_SetCurrentDirectoryA
    __declspec(naked) void __stdcall fixSetCurrentDirectoryA(void) { __asm jmp dword ptr function_ptrs[1288 * 4] }
#endif
#ifndef FIX_SetCurrentDirectoryW
    __declspec(naked) void __stdcall fixSetCurrentDirectoryW(void) { __asm jmp dword ptr function_ptrs[1289 * 4] }
#endif
#ifndef FIX_SetDefaultCommConfigA
    __declspec(naked) void __stdcall fixSetDefaultCommConfigA(void) { __asm jmp dword ptr function_ptrs[1290 * 4] }
#endif
#ifndef FIX_SetDefaultCommConfigW
    __declspec(naked) void __stdcall fixSetDefaultCommConfigW(void) { __asm jmp dword ptr function_ptrs[1291 * 4] }
#endif
#ifndef FIX_SetDefaultDllDirectories
    __declspec(naked) void __stdcall fixSetDefaultDllDirectories(void) { __asm jmp dword ptr function_ptrs[1292 * 4] }
#endif
#ifndef FIX_SetDllDirectoryA
    __declspec(naked) void __stdcall fixSetDllDirectoryA(void) { __asm jmp dword ptr function_ptrs[1293 * 4] }
#endif
#ifndef FIX_SetDllDirectoryW
    __declspec(naked) void __stdcall fixSetDllDirectoryW(void) { __asm jmp dword ptr function_ptrs[1294 * 4] }
#endif
#ifndef FIX_SetDynamicTimeZoneInformation
    __declspec(naked) void __stdcall fixSetDynamicTimeZoneInformation(void) { __asm jmp dword ptr function_ptrs[1295 * 4] }
#endif
#ifndef FIX_SetEndOfFile
    __declspec(naked) void __stdcall fixSetEndOfFile(void) { __asm jmp dword ptr function_ptrs[1296 * 4] }
#endif
#ifndef FIX_SetEnvironmentStringsA
    __declspec(naked) void __stdcall fixSetEnvironmentStringsA(void) { __asm jmp dword ptr function_ptrs[1297 * 4] }
#endif
#ifndef FIX_SetEnvironmentStringsW
    __declspec(naked) void __stdcall fixSetEnvironmentStringsW(void) { __asm jmp dword ptr function_ptrs[1298 * 4] }
#endif
#ifndef FIX_SetEnvironmentVariableA
    __declspec(naked) void __stdcall fixSetEnvironmentVariableA(void) { __asm jmp dword ptr function_ptrs[1299 * 4] }
#endif
#ifndef FIX_SetEnvironmentVariableW
    __declspec(naked) void __stdcall fixSetEnvironmentVariableW(void) { __asm jmp dword ptr function_ptrs[1300 * 4] }
#endif
#ifndef FIX_SetErrorMode
    __declspec(naked) void __stdcall fixSetErrorMode(void) { __asm jmp dword ptr function_ptrs[1301 * 4] }
#endif
#ifndef FIX_SetEvent
    __declspec(naked) void __stdcall fixSetEvent(void) { __asm jmp dword ptr function_ptrs[1302 * 4] }
#endif
#ifndef FIX_SetEventWhenCallbackReturns
    __declspec(naked) void __stdcall fixSetEventWhenCallbackReturns(void) { __asm jmp dword ptr function_ptrs[1303 * 4] }
#endif
#ifndef FIX_SetFileApisToANSI
    __declspec(naked) void __stdcall fixSetFileApisToANSI(void) { __asm jmp dword ptr function_ptrs[1304 * 4] }
#endif
#ifndef FIX_SetFileApisToOEM
    __declspec(naked) void __stdcall fixSetFileApisToOEM(void) { __asm jmp dword ptr function_ptrs[1305 * 4] }
#endif
#ifndef FIX_SetFileAttributesA
    __declspec(naked) void __stdcall fixSetFileAttributesA(void) { __asm jmp dword ptr function_ptrs[1306 * 4] }
#endif
#ifndef FIX_SetFileAttributesTransactedA
    __declspec(naked) void __stdcall fixSetFileAttributesTransactedA(void) { __asm jmp dword ptr function_ptrs[1307 * 4] }
#endif
#ifndef FIX_SetFileAttributesTransactedW
    __declspec(naked) void __stdcall fixSetFileAttributesTransactedW(void) { __asm jmp dword ptr function_ptrs[1308 * 4] }
#endif
#ifndef FIX_SetFileAttributesW
    __declspec(naked) void __stdcall fixSetFileAttributesW(void) { __asm jmp dword ptr function_ptrs[1309 * 4] }
#endif
#ifndef FIX_SetFileBandwidthReservation
    __declspec(naked) void __stdcall fixSetFileBandwidthReservation(void) { __asm jmp dword ptr function_ptrs[1310 * 4] }
#endif
#ifndef FIX_SetFileCompletionNotificationModes
    __declspec(naked) void __stdcall fixSetFileCompletionNotificationModes(void) { __asm jmp dword ptr function_ptrs[1311 * 4] }
#endif
#ifndef FIX_SetFileInformationByHandle
    __declspec(naked) void __stdcall fixSetFileInformationByHandle(void) { __asm jmp dword ptr function_ptrs[1312 * 4] }
#endif
#ifndef FIX_SetFileIoOverlappedRange
    __declspec(naked) void __stdcall fixSetFileIoOverlappedRange(void) { __asm jmp dword ptr function_ptrs[1313 * 4] }
#endif
#ifndef FIX_SetFilePointer
    __declspec(naked) void __stdcall fixSetFilePointer(void) { __asm jmp dword ptr function_ptrs[1314 * 4] }
#endif
#ifndef FIX_SetFilePointerEx
    __declspec(naked) void __stdcall fixSetFilePointerEx(void) { __asm jmp dword ptr function_ptrs[1315 * 4] }
#endif
#ifndef FIX_SetFileShortNameA
    __declspec(naked) void __stdcall fixSetFileShortNameA(void) { __asm jmp dword ptr function_ptrs[1316 * 4] }
#endif
#ifndef FIX_SetFileShortNameW
    __declspec(naked) void __stdcall fixSetFileShortNameW(void) { __asm jmp dword ptr function_ptrs[1317 * 4] }
#endif
#ifndef FIX_SetFileTime
    __declspec(naked) void __stdcall fixSetFileTime(void) { __asm jmp dword ptr function_ptrs[1318 * 4] }
#endif
#ifndef FIX_SetFileValidData
    __declspec(naked) void __stdcall fixSetFileValidData(void) { __asm jmp dword ptr function_ptrs[1319 * 4] }
#endif
#ifndef FIX_SetFirmwareEnvironmentVariableA
    __declspec(naked) void __stdcall fixSetFirmwareEnvironmentVariableA(void) { __asm jmp dword ptr function_ptrs[1320 * 4] }
#endif
#ifndef FIX_SetFirmwareEnvironmentVariableExA
    __declspec(naked) void __stdcall fixSetFirmwareEnvironmentVariableExA(void) { __asm jmp dword ptr function_ptrs[1321 * 4] }
#endif
#ifndef FIX_SetFirmwareEnvironmentVariableExW
    __declspec(naked) void __stdcall fixSetFirmwareEnvironmentVariableExW(void) { __asm jmp dword ptr function_ptrs[1322 * 4] }
#endif
#ifndef FIX_SetFirmwareEnvironmentVariableW
    __declspec(naked) void __stdcall fixSetFirmwareEnvironmentVariableW(void) { __asm jmp dword ptr function_ptrs[1323 * 4] }
#endif
#ifndef FIX_SetHandleContext
    __declspec(naked) void __stdcall fixSetHandleContext(void) { __asm jmp dword ptr function_ptrs[1324 * 4] }
#endif
#ifndef FIX_SetHandleCount
    __declspec(naked) void __stdcall fixSetHandleCount(void) { __asm jmp dword ptr function_ptrs[1325 * 4] }
#endif
#ifndef FIX_SetHandleInformation
    __declspec(naked) void __stdcall fixSetHandleInformation(void) { __asm jmp dword ptr function_ptrs[1326 * 4] }
#endif
#ifndef FIX_SetInformationJobObject
    __declspec(naked) void __stdcall fixSetInformationJobObject(void) { __asm jmp dword ptr function_ptrs[1327 * 4] }
#endif
#ifndef FIX_SetIoRateControlInformationJobObject
    __declspec(naked) void __stdcall fixSetIoRateControlInformationJobObject(void) { __asm jmp dword ptr function_ptrs[1328 * 4] }
#endif
#ifndef FIX_SetLastConsoleEventActive
    __declspec(naked) void __stdcall fixSetLastConsoleEventActive(void) { __asm jmp dword ptr function_ptrs[1329 * 4] }
#endif
#ifndef FIX_SetLastError
    __declspec(naked) void __stdcall fixSetLastError(void) { __asm jmp dword ptr function_ptrs[1330 * 4] }
#endif
#ifndef FIX_SetLocalPrimaryComputerNameA
    __declspec(naked) void __stdcall fixSetLocalPrimaryComputerNameA(void) { __asm jmp dword ptr function_ptrs[1331 * 4] }
#endif
#ifndef FIX_SetLocalPrimaryComputerNameW
    __declspec(naked) void __stdcall fixSetLocalPrimaryComputerNameW(void) { __asm jmp dword ptr function_ptrs[1332 * 4] }
#endif
#ifndef FIX_SetLocalTime
    __declspec(naked) void __stdcall fixSetLocalTime(void) { __asm jmp dword ptr function_ptrs[1333 * 4] }
#endif
#ifndef FIX_SetLocaleInfoA
    __declspec(naked) void __stdcall fixSetLocaleInfoA(void) { __asm jmp dword ptr function_ptrs[1334 * 4] }
#endif
#ifndef FIX_SetLocaleInfoW
    __declspec(naked) void __stdcall fixSetLocaleInfoW(void) { __asm jmp dword ptr function_ptrs[1335 * 4] }
#endif
#ifndef FIX_SetMailslotInfo
    __declspec(naked) void __stdcall fixSetMailslotInfo(void) { __asm jmp dword ptr function_ptrs[1336 * 4] }
#endif
#ifndef FIX_SetMessageWaitingIndicator
    __declspec(naked) void __stdcall fixSetMessageWaitingIndicator(void) { __asm jmp dword ptr function_ptrs[1337 * 4] }
#endif
#ifndef FIX_SetNamedPipeAttribute
    __declspec(naked) void __stdcall fixSetNamedPipeAttribute(void) { __asm jmp dword ptr function_ptrs[1338 * 4] }
#endif
#ifndef FIX_SetNamedPipeHandleState
    __declspec(naked) void __stdcall fixSetNamedPipeHandleState(void) { __asm jmp dword ptr function_ptrs[1339 * 4] }
#endif
#ifndef FIX_SetPriorityClass
    __declspec(naked) void __stdcall fixSetPriorityClass(void) { __asm jmp dword ptr function_ptrs[1340 * 4] }
#endif
#ifndef FIX_SetProcessAffinityMask
    __declspec(naked) void __stdcall fixSetProcessAffinityMask(void) { __asm jmp dword ptr function_ptrs[1341 * 4] }
#endif
#ifndef FIX_SetProcessAffinityUpdateMode
    __declspec(naked) void __stdcall fixSetProcessAffinityUpdateMode(void) { __asm jmp dword ptr function_ptrs[1342 * 4] }
#endif
#ifndef FIX_SetProcessDEPPolicy
    __declspec(naked) void __stdcall fixSetProcessDEPPolicy(void) { __asm jmp dword ptr function_ptrs[1343 * 4] }
#endif
#ifndef FIX_SetProcessDefaultCpuSets
    __declspec(naked) void __stdcall fixSetProcessDefaultCpuSets(void) { __asm jmp dword ptr function_ptrs[1344 * 4] }
#endif
#ifndef FIX_SetProcessInformation
    __declspec(naked) void __stdcall fixSetProcessInformation(void) { __asm jmp dword ptr function_ptrs[1345 * 4] }
#endif
#ifndef FIX_SetProcessMitigationPolicy
    __declspec(naked) void __stdcall fixSetProcessMitigationPolicy(void) { __asm jmp dword ptr function_ptrs[1346 * 4] }
#endif
#ifndef FIX_SetProcessPreferredUILanguages
    __declspec(naked) void __stdcall fixSetProcessPreferredUILanguages(void) { __asm jmp dword ptr function_ptrs[1347 * 4] }
#endif
#ifndef FIX_SetProcessPriorityBoost
    __declspec(naked) void __stdcall fixSetProcessPriorityBoost(void) { __asm jmp dword ptr function_ptrs[1348 * 4] }
#endif
#ifndef FIX_SetProcessShutdownParameters
    __declspec(naked) void __stdcall fixSetProcessShutdownParameters(void) { __asm jmp dword ptr function_ptrs[1349 * 4] }
#endif
#ifndef FIX_SetProcessWorkingSetSize
    __declspec(naked) void __stdcall fixSetProcessWorkingSetSize(void) { __asm jmp dword ptr function_ptrs[1350 * 4] }
#endif
#ifndef FIX_SetProcessWorkingSetSizeEx
    __declspec(naked) void __stdcall fixSetProcessWorkingSetSizeEx(void) { __asm jmp dword ptr function_ptrs[1351 * 4] }
#endif
#ifndef FIX_SetProtectedPolicy
    __declspec(naked) void __stdcall fixSetProtectedPolicy(void) { __asm jmp dword ptr function_ptrs[1352 * 4] }
#endif
#ifndef FIX_SetSearchPathMode
    __declspec(naked) void __stdcall fixSetSearchPathMode(void) { __asm jmp dword ptr function_ptrs[1353 * 4] }
#endif
#ifndef FIX_SetStdHandle
    __declspec(naked) void __stdcall fixSetStdHandle(void) { __asm jmp dword ptr function_ptrs[1354 * 4] }
#endif
#ifndef FIX_SetStdHandleEx
    __declspec(naked) void __stdcall fixSetStdHandleEx(void) { __asm jmp dword ptr function_ptrs[1355 * 4] }
#endif
#ifndef FIX_SetSystemFileCacheSize
    __declspec(naked) void __stdcall fixSetSystemFileCacheSize(void) { __asm jmp dword ptr function_ptrs[1356 * 4] }
#endif
#ifndef FIX_SetSystemPowerState
    __declspec(naked) void __stdcall fixSetSystemPowerState(void) { __asm jmp dword ptr function_ptrs[1357 * 4] }
#endif
#ifndef FIX_SetSystemTime
    __declspec(naked) void __stdcall fixSetSystemTime(void) { __asm jmp dword ptr function_ptrs[1358 * 4] }
#endif
#ifndef FIX_SetSystemTimeAdjustment
    __declspec(naked) void __stdcall fixSetSystemTimeAdjustment(void) { __asm jmp dword ptr function_ptrs[1359 * 4] }
#endif
#ifndef FIX_SetTapeParameters
    __declspec(naked) void __stdcall fixSetTapeParameters(void) { __asm jmp dword ptr function_ptrs[1360 * 4] }
#endif
#ifndef FIX_SetTapePosition
    __declspec(naked) void __stdcall fixSetTapePosition(void) { __asm jmp dword ptr function_ptrs[1361 * 4] }
#endif
#ifndef FIX_SetTermsrvAppInstallMode
    __declspec(naked) void __stdcall fixSetTermsrvAppInstallMode(void) { __asm jmp dword ptr function_ptrs[1362 * 4] }
#endif
#ifndef FIX_SetThreadAffinityMask
    __declspec(naked) void __stdcall fixSetThreadAffinityMask(void) { __asm jmp dword ptr function_ptrs[1363 * 4] }
#endif
#ifndef FIX_SetThreadContext
    __declspec(naked) void __stdcall fixSetThreadContext(void) { __asm jmp dword ptr function_ptrs[1364 * 4] }
#endif
#ifndef FIX_SetThreadDescription
    __declspec(naked) void __stdcall fixSetThreadDescription(void) { __asm jmp dword ptr function_ptrs[1365 * 4] }
#endif
#ifndef FIX_SetThreadErrorMode
    __declspec(naked) void __stdcall fixSetThreadErrorMode(void) { __asm jmp dword ptr function_ptrs[1366 * 4] }
#endif
#ifndef FIX_SetThreadExecutionState
    __declspec(naked) void __stdcall fixSetThreadExecutionState(void) { __asm jmp dword ptr function_ptrs[1367 * 4] }
#endif
#ifndef FIX_SetThreadGroupAffinity
    __declspec(naked) void __stdcall fixSetThreadGroupAffinity(void) { __asm jmp dword ptr function_ptrs[1368 * 4] }
#endif
#ifndef FIX_SetThreadIdealProcessor
    __declspec(naked) void __stdcall fixSetThreadIdealProcessor(void) { __asm jmp dword ptr function_ptrs[1369 * 4] }
#endif
#ifndef FIX_SetThreadIdealProcessorEx
    __declspec(naked) void __stdcall fixSetThreadIdealProcessorEx(void) { __asm jmp dword ptr function_ptrs[1370 * 4] }
#endif
#ifndef FIX_SetThreadInformation
    __declspec(naked) void __stdcall fixSetThreadInformation(void) { __asm jmp dword ptr function_ptrs[1371 * 4] }
#endif
#ifndef FIX_SetThreadLocale
    __declspec(naked) void __stdcall fixSetThreadLocale(void) { __asm jmp dword ptr function_ptrs[1372 * 4] }
#endif
#ifndef FIX_SetThreadPreferredUILanguages
    __declspec(naked) void __stdcall fixSetThreadPreferredUILanguages(void) { __asm jmp dword ptr function_ptrs[1373 * 4] }
#endif
#ifndef FIX_SetThreadPriority
    __declspec(naked) void __stdcall fixSetThreadPriority(void) { __asm jmp dword ptr function_ptrs[1374 * 4] }
#endif
#ifndef FIX_SetThreadPriorityBoost
    __declspec(naked) void __stdcall fixSetThreadPriorityBoost(void) { __asm jmp dword ptr function_ptrs[1375 * 4] }
#endif
#ifndef FIX_SetThreadSelectedCpuSets
    __declspec(naked) void __stdcall fixSetThreadSelectedCpuSets(void) { __asm jmp dword ptr function_ptrs[1376 * 4] }
#endif
#ifndef FIX_SetThreadStackGuarantee
    __declspec(naked) void __stdcall fixSetThreadStackGuarantee(void) { __asm jmp dword ptr function_ptrs[1377 * 4] }
#endif
#ifndef FIX_SetThreadToken
    __declspec(naked) void __stdcall fixSetThreadToken(void) { __asm jmp dword ptr function_ptrs[1378 * 4] }
#endif
#ifndef FIX_SetThreadUILanguage
    __declspec(naked) void __stdcall fixSetThreadUILanguage(void) { __asm jmp dword ptr function_ptrs[1379 * 4] }
#endif
#ifndef FIX_SetThreadpoolStackInformation
    __declspec(naked) void __stdcall fixSetThreadpoolStackInformation(void) { __asm jmp dword ptr function_ptrs[1380 * 4] }
#endif
#ifndef FIX_SetThreadpoolThreadMaximum
    __declspec(naked) void __stdcall fixSetThreadpoolThreadMaximum(void) { __asm jmp dword ptr function_ptrs[1381 * 4] }
#endif
#ifndef FIX_SetThreadpoolThreadMinimum
    __declspec(naked) void __stdcall fixSetThreadpoolThreadMinimum(void) { __asm jmp dword ptr function_ptrs[1382 * 4] }
#endif
#ifndef FIX_SetThreadpoolTimer
    __declspec(naked) void __stdcall fixSetThreadpoolTimer(void) { __asm jmp dword ptr function_ptrs[1383 * 4] }
#endif
#ifndef FIX_SetThreadpoolTimerEx
    __declspec(naked) void __stdcall fixSetThreadpoolTimerEx(void) { __asm jmp dword ptr function_ptrs[1384 * 4] }
#endif
#ifndef FIX_SetThreadpoolWait
    __declspec(naked) void __stdcall fixSetThreadpoolWait(void) { __asm jmp dword ptr function_ptrs[1385 * 4] }
#endif
#ifndef FIX_SetThreadpoolWaitEx
    __declspec(naked) void __stdcall fixSetThreadpoolWaitEx(void) { __asm jmp dword ptr function_ptrs[1386 * 4] }
#endif
#ifndef FIX_SetTimeZoneInformation
    __declspec(naked) void __stdcall fixSetTimeZoneInformation(void) { __asm jmp dword ptr function_ptrs[1387 * 4] }
#endif
#ifndef FIX_SetTimerQueueTimer
    __declspec(naked) void __stdcall fixSetTimerQueueTimer(void) { __asm jmp dword ptr function_ptrs[1388 * 4] }
#endif
#ifndef FIX_SetUnhandledExceptionFilter
    __declspec(naked) void __stdcall fixSetUnhandledExceptionFilter(void) { __asm jmp dword ptr function_ptrs[1389 * 4] }
#endif
#ifndef FIX_SetUserGeoID
    __declspec(naked) void __stdcall fixSetUserGeoID(void) { __asm jmp dword ptr function_ptrs[1390 * 4] }
#endif
#ifndef FIX_SetUserGeoName
    __declspec(naked) void __stdcall fixSetUserGeoName(void) { __asm jmp dword ptr function_ptrs[1391 * 4] }
#endif
#ifndef FIX_SetVDMCurrentDirectories
    __declspec(naked) void __stdcall fixSetVDMCurrentDirectories(void) { __asm jmp dword ptr function_ptrs[1392 * 4] }
#endif
#ifndef FIX_SetVolumeLabelA
    __declspec(naked) void __stdcall fixSetVolumeLabelA(void) { __asm jmp dword ptr function_ptrs[1393 * 4] }
#endif
#ifndef FIX_SetVolumeLabelW
    __declspec(naked) void __stdcall fixSetVolumeLabelW(void) { __asm jmp dword ptr function_ptrs[1394 * 4] }
#endif
#ifndef FIX_SetVolumeMountPointA
    __declspec(naked) void __stdcall fixSetVolumeMountPointA(void) { __asm jmp dword ptr function_ptrs[1395 * 4] }
#endif
#ifndef FIX_SetVolumeMountPointW
    __declspec(naked) void __stdcall fixSetVolumeMountPointW(void) { __asm jmp dword ptr function_ptrs[1396 * 4] }
#endif
#ifndef FIX_SetVolumeMountPointWStub
    __declspec(naked) void __stdcall fixSetVolumeMountPointWStub(void) { __asm jmp dword ptr function_ptrs[1397 * 4] }
#endif
#ifndef FIX_SetWaitableTimer
    __declspec(naked) void __stdcall fixSetWaitableTimer(void) { __asm jmp dword ptr function_ptrs[1398 * 4] }
#endif
#ifndef FIX_SetWaitableTimerEx
    __declspec(naked) void __stdcall fixSetWaitableTimerEx(void) { __asm jmp dword ptr function_ptrs[1399 * 4] }
#endif
#ifndef FIX_SetXStateFeaturesMask
    __declspec(naked) void __stdcall fixSetXStateFeaturesMask(void) { __asm jmp dword ptr function_ptrs[1400 * 4] }
#endif
#ifndef FIX_SetupComm
    __declspec(naked) void __stdcall fixSetupComm(void) { __asm jmp dword ptr function_ptrs[1401 * 4] }
#endif
#ifndef FIX_ShowConsoleCursor
    __declspec(naked) void __stdcall fixShowConsoleCursor(void) { __asm jmp dword ptr function_ptrs[1402 * 4] }
#endif
#ifndef FIX_SignalObjectAndWait
    __declspec(naked) void __stdcall fixSignalObjectAndWait(void) { __asm jmp dword ptr function_ptrs[1403 * 4] }
#endif
#ifndef FIX_SizeofResource
    __declspec(naked) void __stdcall fixSizeofResource(void) { __asm jmp dword ptr function_ptrs[1404 * 4] }
#endif
#ifndef FIX_Sleep
    __declspec(naked) void __stdcall fixSleep(void) { __asm jmp dword ptr function_ptrs[1405 * 4] }
#endif
#ifndef FIX_SleepConditionVariableCS
    __declspec(naked) void __stdcall fixSleepConditionVariableCS(void) { __asm jmp dword ptr function_ptrs[1406 * 4] }
#endif
#ifndef FIX_SleepConditionVariableSRW
    __declspec(naked) void __stdcall fixSleepConditionVariableSRW(void) { __asm jmp dword ptr function_ptrs[1407 * 4] }
#endif
#ifndef FIX_SleepEx
    __declspec(naked) void __stdcall fixSleepEx(void) { __asm jmp dword ptr function_ptrs[1408 * 4] }
#endif
#ifndef FIX_SortCloseHandle
    __declspec(naked) void __stdcall fixSortCloseHandle(void) { __asm jmp dword ptr function_ptrs[1409 * 4] }
#endif
#ifndef FIX_SortGetHandle
    __declspec(naked) void __stdcall fixSortGetHandle(void) { __asm jmp dword ptr function_ptrs[1410 * 4] }
#endif
#ifndef FIX_StartThreadpoolIo
    __declspec(naked) void __stdcall fixStartThreadpoolIo(void) { __asm jmp dword ptr function_ptrs[1411 * 4] }
#endif
#ifndef FIX_SubmitThreadpoolWork
    __declspec(naked) void __stdcall fixSubmitThreadpoolWork(void) { __asm jmp dword ptr function_ptrs[1412 * 4] }
#endif
#ifndef FIX_SuspendThread
    __declspec(naked) void __stdcall fixSuspendThread(void) { __asm jmp dword ptr function_ptrs[1413 * 4] }
#endif
#ifndef FIX_SwitchToFiber
    __declspec(naked) void __stdcall fixSwitchToFiber(void) { __asm jmp dword ptr function_ptrs[1414 * 4] }
#endif
#ifndef FIX_SwitchToThread
    __declspec(naked) void __stdcall fixSwitchToThread(void) { __asm jmp dword ptr function_ptrs[1415 * 4] }
#endif
#ifndef FIX_SystemTimeToFileTime
    __declspec(naked) void __stdcall fixSystemTimeToFileTime(void) { __asm jmp dword ptr function_ptrs[1416 * 4] }
#endif
#ifndef FIX_SystemTimeToTzSpecificLocalTime
    __declspec(naked) void __stdcall fixSystemTimeToTzSpecificLocalTime(void) { __asm jmp dword ptr function_ptrs[1417 * 4] }
#endif
#ifndef FIX_SystemTimeToTzSpecificLocalTimeEx
    __declspec(naked) void __stdcall fixSystemTimeToTzSpecificLocalTimeEx(void) { __asm jmp dword ptr function_ptrs[1418 * 4] }
#endif
#ifndef FIX_TerminateJobObject
    __declspec(naked) void __stdcall fixTerminateJobObject(void) { __asm jmp dword ptr function_ptrs[1419 * 4] }
#endif
#ifndef FIX_TerminateProcess
    __declspec(naked) void __stdcall fixTerminateProcess(void) { __asm jmp dword ptr function_ptrs[1420 * 4] }
#endif
#ifndef FIX_TerminateThread
    __declspec(naked) void __stdcall fixTerminateThread(void) { __asm jmp dword ptr function_ptrs[1421 * 4] }
#endif
#ifndef FIX_TermsrvAppInstallMode
    __declspec(naked) void __stdcall fixTermsrvAppInstallMode(void) { __asm jmp dword ptr function_ptrs[1422 * 4] }
#endif
#ifndef FIX_TermsrvConvertSysRootToUserDir
    __declspec(naked) void __stdcall fixTermsrvConvertSysRootToUserDir(void) { __asm jmp dword ptr function_ptrs[1423 * 4] }
#endif
#ifndef FIX_TermsrvCreateRegEntry
    __declspec(naked) void __stdcall fixTermsrvCreateRegEntry(void) { __asm jmp dword ptr function_ptrs[1424 * 4] }
#endif
#ifndef FIX_TermsrvDeleteKey
    __declspec(naked) void __stdcall fixTermsrvDeleteKey(void) { __asm jmp dword ptr function_ptrs[1425 * 4] }
#endif
#ifndef FIX_TermsrvDeleteValue
    __declspec(naked) void __stdcall fixTermsrvDeleteValue(void) { __asm jmp dword ptr function_ptrs[1426 * 4] }
#endif
#ifndef FIX_TermsrvGetPreSetValue
    __declspec(naked) void __stdcall fixTermsrvGetPreSetValue(void) { __asm jmp dword ptr function_ptrs[1427 * 4] }
#endif
#ifndef FIX_TermsrvGetWindowsDirectoryA
    __declspec(naked) void __stdcall fixTermsrvGetWindowsDirectoryA(void) { __asm jmp dword ptr function_ptrs[1428 * 4] }
#endif
#ifndef FIX_TermsrvGetWindowsDirectoryW
    __declspec(naked) void __stdcall fixTermsrvGetWindowsDirectoryW(void) { __asm jmp dword ptr function_ptrs[1429 * 4] }
#endif
#ifndef FIX_TermsrvOpenRegEntry
    __declspec(naked) void __stdcall fixTermsrvOpenRegEntry(void) { __asm jmp dword ptr function_ptrs[1430 * 4] }
#endif
#ifndef FIX_TermsrvOpenUserClasses
    __declspec(naked) void __stdcall fixTermsrvOpenUserClasses(void) { __asm jmp dword ptr function_ptrs[1431 * 4] }
#endif
#ifndef FIX_TermsrvRestoreKey
    __declspec(naked) void __stdcall fixTermsrvRestoreKey(void) { __asm jmp dword ptr function_ptrs[1432 * 4] }
#endif
#ifndef FIX_TermsrvSetKeySecurity
    __declspec(naked) void __stdcall fixTermsrvSetKeySecurity(void) { __asm jmp dword ptr function_ptrs[1433 * 4] }
#endif
#ifndef FIX_TermsrvSetValueKey
    __declspec(naked) void __stdcall fixTermsrvSetValueKey(void) { __asm jmp dword ptr function_ptrs[1434 * 4] }
#endif
#ifndef FIX_TermsrvSyncUserIniFileExt
    __declspec(naked) void __stdcall fixTermsrvSyncUserIniFileExt(void) { __asm jmp dword ptr function_ptrs[1435 * 4] }
#endif
#ifndef FIX_Thread32First
    __declspec(naked) void __stdcall fixThread32First(void) { __asm jmp dword ptr function_ptrs[1436 * 4] }
#endif
#ifndef FIX_Thread32Next
    __declspec(naked) void __stdcall fixThread32Next(void) { __asm jmp dword ptr function_ptrs[1437 * 4] }
#endif
#ifndef FIX_TlsAlloc
    __declspec(naked) void __stdcall fixTlsAlloc(void) { __asm jmp dword ptr function_ptrs[1438 * 4] }
#endif
#ifndef FIX_TlsFree
    __declspec(naked) void __stdcall fixTlsFree(void) { __asm jmp dword ptr function_ptrs[1439 * 4] }
#endif
#ifndef FIX_TlsGetValue
    __declspec(naked) void __stdcall fixTlsGetValue(void) { __asm jmp dword ptr function_ptrs[1440 * 4] }
#endif
#ifndef FIX_TlsSetValue
    __declspec(naked) void __stdcall fixTlsSetValue(void) { __asm jmp dword ptr function_ptrs[1441 * 4] }
#endif
#ifndef FIX_Toolhelp32ReadProcessMemory
    __declspec(naked) void __stdcall fixToolhelp32ReadProcessMemory(void) { __asm jmp dword ptr function_ptrs[1442 * 4] }
#endif
#ifndef FIX_TransactNamedPipe
    __declspec(naked) void __stdcall fixTransactNamedPipe(void) { __asm jmp dword ptr function_ptrs[1443 * 4] }
#endif
#ifndef FIX_TransmitCommChar
    __declspec(naked) void __stdcall fixTransmitCommChar(void) { __asm jmp dword ptr function_ptrs[1444 * 4] }
#endif
#ifndef FIX_TryAcquireSRWLockExclusive
    __declspec(naked) void __stdcall fixTryAcquireSRWLockExclusive(void) { __asm jmp dword ptr function_ptrs[1445 * 4] }
#endif
#ifndef FIX_TryAcquireSRWLockShared
    __declspec(naked) void __stdcall fixTryAcquireSRWLockShared(void) { __asm jmp dword ptr function_ptrs[1446 * 4] }
#endif
#ifndef FIX_TryEnterCriticalSection
    __declspec(naked) void __stdcall fixTryEnterCriticalSection(void) { __asm jmp dword ptr function_ptrs[1447 * 4] }
#endif
#ifndef FIX_TrySubmitThreadpoolCallback
    __declspec(naked) void __stdcall fixTrySubmitThreadpoolCallback(void) { __asm jmp dword ptr function_ptrs[1448 * 4] }
#endif
#ifndef FIX_TzSpecificLocalTimeToSystemTime
    __declspec(naked) void __stdcall fixTzSpecificLocalTimeToSystemTime(void) { __asm jmp dword ptr function_ptrs[1449 * 4] }
#endif
#ifndef FIX_TzSpecificLocalTimeToSystemTimeEx
    __declspec(naked) void __stdcall fixTzSpecificLocalTimeToSystemTimeEx(void) { __asm jmp dword ptr function_ptrs[1450 * 4] }
#endif
#ifndef FIX_UTRegister
    __declspec(naked) void __stdcall fixUTRegister(void) { __asm jmp dword ptr function_ptrs[1451 * 4] }
#endif
#ifndef FIX_UTUnRegister
    __declspec(naked) void __stdcall fixUTUnRegister(void) { __asm jmp dword ptr function_ptrs[1452 * 4] }
#endif
#ifndef FIX_UnhandledExceptionFilter
    __declspec(naked) void __stdcall fixUnhandledExceptionFilter(void) { __asm jmp dword ptr function_ptrs[1453 * 4] }
#endif
#ifndef FIX_UnlockFile
    __declspec(naked) void __stdcall fixUnlockFile(void) { __asm jmp dword ptr function_ptrs[1454 * 4] }
#endif
#ifndef FIX_UnlockFileEx
    __declspec(naked) void __stdcall fixUnlockFileEx(void) { __asm jmp dword ptr function_ptrs[1455 * 4] }
#endif
#ifndef FIX_UnmapViewOfFile
    __declspec(naked) void __stdcall fixUnmapViewOfFile(void) { __asm jmp dword ptr function_ptrs[1456 * 4] }
#endif
#ifndef FIX_UnmapViewOfFileEx
    __declspec(naked) void __stdcall fixUnmapViewOfFileEx(void) { __asm jmp dword ptr function_ptrs[1457 * 4] }
#endif
#ifndef FIX_UnregisterApplicationRecoveryCallback
    __declspec(naked) void __stdcall fixUnregisterApplicationRecoveryCallback(void) { __asm jmp dword ptr function_ptrs[1458 * 4] }
#endif
#ifndef FIX_UnregisterApplicationRestart
    __declspec(naked) void __stdcall fixUnregisterApplicationRestart(void) { __asm jmp dword ptr function_ptrs[1459 * 4] }
#endif
#ifndef FIX_UnregisterBadMemoryNotification
    __declspec(naked) void __stdcall fixUnregisterBadMemoryNotification(void) { __asm jmp dword ptr function_ptrs[1460 * 4] }
#endif
#ifndef FIX_UnregisterConsoleIME
    __declspec(naked) void __stdcall fixUnregisterConsoleIME(void) { __asm jmp dword ptr function_ptrs[1461 * 4] }
#endif
#ifndef FIX_UnregisterWait
    __declspec(naked) void __stdcall fixUnregisterWait(void) { __asm jmp dword ptr function_ptrs[1462 * 4] }
#endif
#ifndef FIX_UnregisterWaitEx
    __declspec(naked) void __stdcall fixUnregisterWaitEx(void) { __asm jmp dword ptr function_ptrs[1463 * 4] }
#endif
#ifndef FIX_UnregisterWaitUntilOOBECompleted
    __declspec(naked) void __stdcall fixUnregisterWaitUntilOOBECompleted(void) { __asm jmp dword ptr function_ptrs[1464 * 4] }
#endif
#ifndef FIX_UpdateCalendarDayOfWeek
    __declspec(naked) void __stdcall fixUpdateCalendarDayOfWeek(void) { __asm jmp dword ptr function_ptrs[1465 * 4] }
#endif
#ifndef FIX_UpdateProcThreadAttribute
    __declspec(naked) void __stdcall fixUpdateProcThreadAttribute(void) { __asm jmp dword ptr function_ptrs[1466 * 4] }
#endif
#ifndef FIX_UpdateResourceA
    __declspec(naked) void __stdcall fixUpdateResourceA(void) { __asm jmp dword ptr function_ptrs[1467 * 4] }
#endif
#ifndef FIX_UpdateResourceW
    __declspec(naked) void __stdcall fixUpdateResourceW(void) { __asm jmp dword ptr function_ptrs[1468 * 4] }
#endif
#ifndef FIX_VDMConsoleOperation
    __declspec(naked) void __stdcall fixVDMConsoleOperation(void) { __asm jmp dword ptr function_ptrs[1469 * 4] }
#endif
#ifndef FIX_VDMOperationStarted
    __declspec(naked) void __stdcall fixVDMOperationStarted(void) { __asm jmp dword ptr function_ptrs[1470 * 4] }
#endif
#ifndef FIX_VerLanguageNameA
    __declspec(naked) void __stdcall fixVerLanguageNameA(void) { __asm jmp dword ptr function_ptrs[1471 * 4] }
#endif
#ifndef FIX_VerLanguageNameW
    __declspec(naked) void __stdcall fixVerLanguageNameW(void) { __asm jmp dword ptr function_ptrs[1472 * 4] }
#endif
#ifndef FIX_VerSetConditionMask
    __declspec(naked) void __stdcall fixVerSetConditionMask(void) { __asm jmp dword ptr function_ptrs[1473 * 4] }
#endif
#ifndef FIX_VerifyConsoleIoHandle
    __declspec(naked) void __stdcall fixVerifyConsoleIoHandle(void) { __asm jmp dword ptr function_ptrs[1474 * 4] }
#endif
#ifndef FIX_VerifyScripts
    __declspec(naked) void __stdcall fixVerifyScripts(void) { __asm jmp dword ptr function_ptrs[1475 * 4] }
#endif
#ifndef FIX_VerifyVersionInfoA
    __declspec(naked) void __stdcall fixVerifyVersionInfoA(void) { __asm jmp dword ptr function_ptrs[1476 * 4] }
#endif
#ifndef FIX_VerifyVersionInfoW
    __declspec(naked) void __stdcall fixVerifyVersionInfoW(void) { __asm jmp dword ptr function_ptrs[1477 * 4] }
#endif
#ifndef FIX_VirtualAlloc
    __declspec(naked) void __stdcall fixVirtualAlloc(void) { __asm jmp dword ptr function_ptrs[1478 * 4] }
#endif
#ifndef FIX_VirtualAllocEx
    __declspec(naked) void __stdcall fixVirtualAllocEx(void) { __asm jmp dword ptr function_ptrs[1479 * 4] }
#endif
#ifndef FIX_VirtualAllocExNuma
    __declspec(naked) void __stdcall fixVirtualAllocExNuma(void) { __asm jmp dword ptr function_ptrs[1480 * 4] }
#endif
#ifndef FIX_VirtualFree
    __declspec(naked) void __stdcall fixVirtualFree(void) { __asm jmp dword ptr function_ptrs[1481 * 4] }
#endif
#ifndef FIX_VirtualFreeEx
    __declspec(naked) void __stdcall fixVirtualFreeEx(void) { __asm jmp dword ptr function_ptrs[1482 * 4] }
#endif
#ifndef FIX_VirtualLock
    __declspec(naked) void __stdcall fixVirtualLock(void) { __asm jmp dword ptr function_ptrs[1483 * 4] }
#endif
#ifndef FIX_VirtualProtect
    __declspec(naked) void __stdcall fixVirtualProtect(void) { __asm jmp dword ptr function_ptrs[1484 * 4] }
#endif
#ifndef FIX_VirtualProtectEx
    __declspec(naked) void __stdcall fixVirtualProtectEx(void) { __asm jmp dword ptr function_ptrs[1485 * 4] }
#endif
#ifndef FIX_VirtualQuery
    __declspec(naked) void __stdcall fixVirtualQuery(void) { __asm jmp dword ptr function_ptrs[1486 * 4] }
#endif
#ifndef FIX_VirtualQueryEx
    __declspec(naked) void __stdcall fixVirtualQueryEx(void) { __asm jmp dword ptr function_ptrs[1487 * 4] }
#endif
#ifndef FIX_VirtualUnlock
    __declspec(naked) void __stdcall fixVirtualUnlock(void) { __asm jmp dword ptr function_ptrs[1488 * 4] }
#endif
#ifndef FIX_WTSGetActiveConsoleSessionId
    __declspec(naked) void __stdcall fixWTSGetActiveConsoleSessionId(void) { __asm jmp dword ptr function_ptrs[1489 * 4] }
#endif
#ifndef FIX_WaitCommEvent
    __declspec(naked) void __stdcall fixWaitCommEvent(void) { __asm jmp dword ptr function_ptrs[1490 * 4] }
#endif
#ifndef FIX_WaitForDebugEvent
    __declspec(naked) void __stdcall fixWaitForDebugEvent(void) { __asm jmp dword ptr function_ptrs[1491 * 4] }
#endif
#ifndef FIX_WaitForDebugEventEx
    __declspec(naked) void __stdcall fixWaitForDebugEventEx(void) { __asm jmp dword ptr function_ptrs[1492 * 4] }
#endif
#ifndef FIX_WaitForMultipleObjects
    __declspec(naked) void __stdcall fixWaitForMultipleObjects(void) { __asm jmp dword ptr function_ptrs[1493 * 4] }
#endif
#ifndef FIX_WaitForMultipleObjectsEx
    __declspec(naked) void __stdcall fixWaitForMultipleObjectsEx(void) { __asm jmp dword ptr function_ptrs[1494 * 4] }
#endif
#ifndef FIX_WaitForSingleObject
    __declspec(naked) void __stdcall fixWaitForSingleObject(void) { __asm jmp dword ptr function_ptrs[1495 * 4] }
#endif
#ifndef FIX_WaitForSingleObjectEx
    __declspec(naked) void __stdcall fixWaitForSingleObjectEx(void) { __asm jmp dword ptr function_ptrs[1496 * 4] }
#endif
#ifndef FIX_WaitForThreadpoolIoCallbacks
    __declspec(naked) void __stdcall fixWaitForThreadpoolIoCallbacks(void) { __asm jmp dword ptr function_ptrs[1497 * 4] }
#endif
#ifndef FIX_WaitForThreadpoolTimerCallbacks
    __declspec(naked) void __stdcall fixWaitForThreadpoolTimerCallbacks(void) { __asm jmp dword ptr function_ptrs[1498 * 4] }
#endif
#ifndef FIX_WaitForThreadpoolWaitCallbacks
    __declspec(naked) void __stdcall fixWaitForThreadpoolWaitCallbacks(void) { __asm jmp dword ptr function_ptrs[1499 * 4] }
#endif
#ifndef FIX_WaitForThreadpoolWorkCallbacks
    __declspec(naked) void __stdcall fixWaitForThreadpoolWorkCallbacks(void) { __asm jmp dword ptr function_ptrs[1500 * 4] }
#endif
#ifndef FIX_WaitNamedPipeA
    __declspec(naked) void __stdcall fixWaitNamedPipeA(void) { __asm jmp dword ptr function_ptrs[1501 * 4] }
#endif
#ifndef FIX_WaitNamedPipeW
    __declspec(naked) void __stdcall fixWaitNamedPipeW(void) { __asm jmp dword ptr function_ptrs[1502 * 4] }
#endif
#ifndef FIX_WakeAllConditionVariable
    __declspec(naked) void __stdcall fixWakeAllConditionVariable(void) { __asm jmp dword ptr function_ptrs[1503 * 4] }
#endif
#ifndef FIX_WakeConditionVariable
    __declspec(naked) void __stdcall fixWakeConditionVariable(void) { __asm jmp dword ptr function_ptrs[1504 * 4] }
#endif
#ifndef FIX_WerGetFlags
    __declspec(naked) void __stdcall fixWerGetFlags(void) { __asm jmp dword ptr function_ptrs[1505 * 4] }
#endif
#ifndef FIX_WerGetFlagsWorker
    __declspec(naked) void __stdcall fixWerGetFlagsWorker(void) { __asm jmp dword ptr function_ptrs[1506 * 4] }
#endif
#ifndef FIX_WerRegisterAdditionalProcess
    __declspec(naked) void __stdcall fixWerRegisterAdditionalProcess(void) { __asm jmp dword ptr function_ptrs[1507 * 4] }
#endif
#ifndef FIX_WerRegisterAppLocalDump
    __declspec(naked) void __stdcall fixWerRegisterAppLocalDump(void) { __asm jmp dword ptr function_ptrs[1508 * 4] }
#endif
#ifndef FIX_WerRegisterCustomMetadata
    __declspec(naked) void __stdcall fixWerRegisterCustomMetadata(void) { __asm jmp dword ptr function_ptrs[1509 * 4] }
#endif
#ifndef FIX_WerRegisterExcludedMemoryBlock
    __declspec(naked) void __stdcall fixWerRegisterExcludedMemoryBlock(void) { __asm jmp dword ptr function_ptrs[1510 * 4] }
#endif
#ifndef FIX_WerRegisterFile
    __declspec(naked) void __stdcall fixWerRegisterFile(void) { __asm jmp dword ptr function_ptrs[1511 * 4] }
#endif
#ifndef FIX_WerRegisterFileWorker
    __declspec(naked) void __stdcall fixWerRegisterFileWorker(void) { __asm jmp dword ptr function_ptrs[1512 * 4] }
#endif
#ifndef FIX_WerRegisterMemoryBlock
    __declspec(naked) void __stdcall fixWerRegisterMemoryBlock(void) { __asm jmp dword ptr function_ptrs[1513 * 4] }
#endif
#ifndef FIX_WerRegisterMemoryBlockWorker
    __declspec(naked) void __stdcall fixWerRegisterMemoryBlockWorker(void) { __asm jmp dword ptr function_ptrs[1514 * 4] }
#endif
#ifndef FIX_WerRegisterRuntimeExceptionModule
    __declspec(naked) void __stdcall fixWerRegisterRuntimeExceptionModule(void) { __asm jmp dword ptr function_ptrs[1515 * 4] }
#endif
#ifndef FIX_WerRegisterRuntimeExceptionModuleWorker
    __declspec(naked) void __stdcall fixWerRegisterRuntimeExceptionModuleWorker(void) { __asm jmp dword ptr function_ptrs[1516 * 4] }
#endif
#ifndef FIX_WerSetFlags
    __declspec(naked) void __stdcall fixWerSetFlags(void) { __asm jmp dword ptr function_ptrs[1517 * 4] }
#endif
#ifndef FIX_WerSetFlagsWorker
    __declspec(naked) void __stdcall fixWerSetFlagsWorker(void) { __asm jmp dword ptr function_ptrs[1518 * 4] }
#endif
#ifndef FIX_WerUnregisterAdditionalProcess
    __declspec(naked) void __stdcall fixWerUnregisterAdditionalProcess(void) { __asm jmp dword ptr function_ptrs[1519 * 4] }
#endif
#ifndef FIX_WerUnregisterAppLocalDump
    __declspec(naked) void __stdcall fixWerUnregisterAppLocalDump(void) { __asm jmp dword ptr function_ptrs[1520 * 4] }
#endif
#ifndef FIX_WerUnregisterCustomMetadata
    __declspec(naked) void __stdcall fixWerUnregisterCustomMetadata(void) { __asm jmp dword ptr function_ptrs[1521 * 4] }
#endif
#ifndef FIX_WerUnregisterExcludedMemoryBlock
    __declspec(naked) void __stdcall fixWerUnregisterExcludedMemoryBlock(void) { __asm jmp dword ptr function_ptrs[1522 * 4] }
#endif
#ifndef FIX_WerUnregisterFile
    __declspec(naked) void __stdcall fixWerUnregisterFile(void) { __asm jmp dword ptr function_ptrs[1523 * 4] }
#endif
#ifndef FIX_WerUnregisterFileWorker
    __declspec(naked) void __stdcall fixWerUnregisterFileWorker(void) { __asm jmp dword ptr function_ptrs[1524 * 4] }
#endif
#ifndef FIX_WerUnregisterMemoryBlock
    __declspec(naked) void __stdcall fixWerUnregisterMemoryBlock(void) { __asm jmp dword ptr function_ptrs[1525 * 4] }
#endif
#ifndef FIX_WerUnregisterMemoryBlockWorker
    __declspec(naked) void __stdcall fixWerUnregisterMemoryBlockWorker(void) { __asm jmp dword ptr function_ptrs[1526 * 4] }
#endif
#ifndef FIX_WerUnregisterRuntimeExceptionModule
    __declspec(naked) void __stdcall fixWerUnregisterRuntimeExceptionModule(void) { __asm jmp dword ptr function_ptrs[1527 * 4] }
#endif
#ifndef FIX_WerUnregisterRuntimeExceptionModuleWorker
    __declspec(naked) void __stdcall fixWerUnregisterRuntimeExceptionModuleWorker(void) { __asm jmp dword ptr function_ptrs[1528 * 4] }
#endif
#ifndef FIX_WerpGetDebugger
    __declspec(naked) void __stdcall fixWerpGetDebugger(void) { __asm jmp dword ptr function_ptrs[1529 * 4] }
#endif
#ifndef FIX_WerpInitiateRemoteRecovery
    __declspec(naked) void __stdcall fixWerpInitiateRemoteRecovery(void) { __asm jmp dword ptr function_ptrs[1530 * 4] }
#endif
#ifndef FIX_WerpLaunchAeDebug
    __declspec(naked) void __stdcall fixWerpLaunchAeDebug(void) { __asm jmp dword ptr function_ptrs[1531 * 4] }
#endif
#ifndef FIX_WerpNotifyLoadStringResourceWorker
    __declspec(naked) void __stdcall fixWerpNotifyLoadStringResourceWorker(void) { __asm jmp dword ptr function_ptrs[1532 * 4] }
#endif
#ifndef FIX_WerpNotifyUseStringResourceWorker
    __declspec(naked) void __stdcall fixWerpNotifyUseStringResourceWorker(void) { __asm jmp dword ptr function_ptrs[1533 * 4] }
#endif
#ifndef FIX_WideCharToMultiByte
    __declspec(naked) void __stdcall fixWideCharToMultiByte(void) { __asm jmp dword ptr function_ptrs[1534 * 4] }
#endif
#ifndef FIX_WinExec
    __declspec(naked) void __stdcall fixWinExec(void) { __asm jmp dword ptr function_ptrs[1535 * 4] }
#endif
#ifndef FIX_Wow64DisableWow64FsRedirection
    __declspec(naked) void __stdcall fixWow64DisableWow64FsRedirection(void) { __asm jmp dword ptr function_ptrs[1536 * 4] }
#endif
#ifndef FIX_Wow64EnableWow64FsRedirection
    __declspec(naked) void __stdcall fixWow64EnableWow64FsRedirection(void) { __asm jmp dword ptr function_ptrs[1537 * 4] }
#endif
#ifndef FIX_Wow64GetThreadContext
    __declspec(naked) void __stdcall fixWow64GetThreadContext(void) { __asm jmp dword ptr function_ptrs[1538 * 4] }
#endif
#ifndef FIX_Wow64GetThreadSelectorEntry
    __declspec(naked) void __stdcall fixWow64GetThreadSelectorEntry(void) { __asm jmp dword ptr function_ptrs[1539 * 4] }
#endif
#ifndef FIX_Wow64RevertWow64FsRedirection
    __declspec(naked) void __stdcall fixWow64RevertWow64FsRedirection(void) { __asm jmp dword ptr function_ptrs[1540 * 4] }
#endif
#ifndef FIX_Wow64SetThreadContext
    __declspec(naked) void __stdcall fixWow64SetThreadContext(void) { __asm jmp dword ptr function_ptrs[1541 * 4] }
#endif
#ifndef FIX_Wow64SuspendThread
    __declspec(naked) void __stdcall fixWow64SuspendThread(void) { __asm jmp dword ptr function_ptrs[1542 * 4] }
#endif
#ifndef FIX_Wow64Transition
    __declspec(naked) void __stdcall fixWow64Transition(void) { __asm jmp dword ptr function_ptrs[1543 * 4] }
#endif
#ifndef FIX_WriteConsoleA
    __declspec(naked) void __stdcall fixWriteConsoleA(void) { __asm jmp dword ptr function_ptrs[1544 * 4] }
#endif
#ifndef FIX_WriteConsoleInputA
    __declspec(naked) void __stdcall fixWriteConsoleInputA(void) { __asm jmp dword ptr function_ptrs[1545 * 4] }
#endif
#ifndef FIX_WriteConsoleInputVDMA
    __declspec(naked) void __stdcall fixWriteConsoleInputVDMA(void) { __asm jmp dword ptr function_ptrs[1546 * 4] }
#endif
#ifndef FIX_WriteConsoleInputVDMW
    __declspec(naked) void __stdcall fixWriteConsoleInputVDMW(void) { __asm jmp dword ptr function_ptrs[1547 * 4] }
#endif
#ifndef FIX_WriteConsoleInputW
    __declspec(naked) void __stdcall fixWriteConsoleInputW(void) { __asm jmp dword ptr function_ptrs[1548 * 4] }
#endif
#ifndef FIX_WriteConsoleOutputA
    __declspec(naked) void __stdcall fixWriteConsoleOutputA(void) { __asm jmp dword ptr function_ptrs[1549 * 4] }
#endif
#ifndef FIX_WriteConsoleOutputAttribute
    __declspec(naked) void __stdcall fixWriteConsoleOutputAttribute(void) { __asm jmp dword ptr function_ptrs[1550 * 4] }
#endif
#ifndef FIX_WriteConsoleOutputCharacterA
    __declspec(naked) void __stdcall fixWriteConsoleOutputCharacterA(void) { __asm jmp dword ptr function_ptrs[1551 * 4] }
#endif
#ifndef FIX_WriteConsoleOutputCharacterW
    __declspec(naked) void __stdcall fixWriteConsoleOutputCharacterW(void) { __asm jmp dword ptr function_ptrs[1552 * 4] }
#endif
#ifndef FIX_WriteConsoleOutputW
    __declspec(naked) void __stdcall fixWriteConsoleOutputW(void) { __asm jmp dword ptr function_ptrs[1553 * 4] }
#endif
#ifndef FIX_WriteConsoleW
    __declspec(naked) void __stdcall fixWriteConsoleW(void) { __asm jmp dword ptr function_ptrs[1554 * 4] }
#endif
#ifndef FIX_WriteFile
    __declspec(naked) void __stdcall fixWriteFile(void) { __asm jmp dword ptr function_ptrs[1555 * 4] }
#endif
#ifndef FIX_WriteFileEx
    __declspec(naked) void __stdcall fixWriteFileEx(void) { __asm jmp dword ptr function_ptrs[1556 * 4] }
#endif
#ifndef FIX_WriteFileGather
    __declspec(naked) void __stdcall fixWriteFileGather(void) { __asm jmp dword ptr function_ptrs[1557 * 4] }
#endif
#ifndef FIX_WritePrivateProfileSectionA
    __declspec(naked) void __stdcall fixWritePrivateProfileSectionA(void) { __asm jmp dword ptr function_ptrs[1558 * 4] }
#endif
#ifndef FIX_WritePrivateProfileSectionW
    __declspec(naked) void __stdcall fixWritePrivateProfileSectionW(void) { __asm jmp dword ptr function_ptrs[1559 * 4] }
#endif
#ifndef FIX_WritePrivateProfileStringA
    __declspec(naked) void __stdcall fixWritePrivateProfileStringA(void) { __asm jmp dword ptr function_ptrs[1560 * 4] }
#endif
#ifndef FIX_WritePrivateProfileStringW
    __declspec(naked) void __stdcall fixWritePrivateProfileStringW(void) { __asm jmp dword ptr function_ptrs[1561 * 4] }
#endif
#ifndef FIX_WritePrivateProfileStructA
    __declspec(naked) void __stdcall fixWritePrivateProfileStructA(void) { __asm jmp dword ptr function_ptrs[1562 * 4] }
#endif
#ifndef FIX_WritePrivateProfileStructW
    __declspec(naked) void __stdcall fixWritePrivateProfileStructW(void) { __asm jmp dword ptr function_ptrs[1563 * 4] }
#endif
#ifndef FIX_WriteProcessMemory
    __declspec(naked) void __stdcall fixWriteProcessMemory(void) { __asm jmp dword ptr function_ptrs[1564 * 4] }
#endif
#ifndef FIX_WriteProfileSectionA
    __declspec(naked) void __stdcall fixWriteProfileSectionA(void) { __asm jmp dword ptr function_ptrs[1565 * 4] }
#endif
#ifndef FIX_WriteProfileSectionW
    __declspec(naked) void __stdcall fixWriteProfileSectionW(void) { __asm jmp dword ptr function_ptrs[1566 * 4] }
#endif
#ifndef FIX_WriteProfileStringA
    __declspec(naked) void __stdcall fixWriteProfileStringA(void) { __asm jmp dword ptr function_ptrs[1567 * 4] }
#endif
#ifndef FIX_WriteProfileStringW
    __declspec(naked) void __stdcall fixWriteProfileStringW(void) { __asm jmp dword ptr function_ptrs[1568 * 4] }
#endif
#ifndef FIX_WriteTapemark
    __declspec(naked) void __stdcall fixWriteTapemark(void) { __asm jmp dword ptr function_ptrs[1569 * 4] }
#endif
#ifndef FIX_ZombifyActCtx
    __declspec(naked) void __stdcall fixZombifyActCtx(void) { __asm jmp dword ptr function_ptrs[1570 * 4] }
#endif
#ifndef FIX_ZombifyActCtxWorker
    __declspec(naked) void __stdcall fixZombifyActCtxWorker(void) { __asm jmp dword ptr function_ptrs[1571 * 4] }
#endif
#ifndef FIX__hread
    __declspec(naked) void __stdcall fix_hread(void) { __asm jmp dword ptr function_ptrs[1572 * 4] }
#endif
#ifndef FIX__hwrite
    __declspec(naked) void __stdcall fix_hwrite(void) { __asm jmp dword ptr function_ptrs[1573 * 4] }
#endif
#ifndef FIX__lclose
    __declspec(naked) void __stdcall fix_lclose(void) { __asm jmp dword ptr function_ptrs[1574 * 4] }
#endif
#ifndef FIX__lcreat
    __declspec(naked) void __stdcall fix_lcreat(void) { __asm jmp dword ptr function_ptrs[1575 * 4] }
#endif
#ifndef FIX__llseek
    __declspec(naked) void __stdcall fix_llseek(void) { __asm jmp dword ptr function_ptrs[1576 * 4] }
#endif
#ifndef FIX__lopen
    __declspec(naked) void __stdcall fix_lopen(void) { __asm jmp dword ptr function_ptrs[1577 * 4] }
#endif
#ifndef FIX__lread
    __declspec(naked) void __stdcall fix_lread(void) { __asm jmp dword ptr function_ptrs[1578 * 4] }
#endif
#ifndef FIX__lwrite
    __declspec(naked) void __stdcall fix_lwrite(void) { __asm jmp dword ptr function_ptrs[1579 * 4] }
#endif
#ifndef FIX_lstrcat
    __declspec(naked) void __stdcall fixlstrcat(void) { __asm jmp dword ptr function_ptrs[1580 * 4] }
#endif
#ifndef FIX_lstrcatA
    __declspec(naked) void __stdcall fixlstrcatA(void) { __asm jmp dword ptr function_ptrs[1581 * 4] }
#endif
#ifndef FIX_lstrcatW
    __declspec(naked) void __stdcall fixlstrcatW(void) { __asm jmp dword ptr function_ptrs[1582 * 4] }
#endif
#ifndef FIX_lstrcmp
    __declspec(naked) void __stdcall fixlstrcmp(void) { __asm jmp dword ptr function_ptrs[1583 * 4] }
#endif
#ifndef FIX_lstrcmpA
    __declspec(naked) void __stdcall fixlstrcmpA(void) { __asm jmp dword ptr function_ptrs[1584 * 4] }
#endif
#ifndef FIX_lstrcmpW
    __declspec(naked) void __stdcall fixlstrcmpW(void) { __asm jmp dword ptr function_ptrs[1585 * 4] }
#endif
#ifndef FIX_lstrcmpi
    __declspec(naked) void __stdcall fixlstrcmpi(void) { __asm jmp dword ptr function_ptrs[1586 * 4] }
#endif
#ifndef FIX_lstrcmpiA
    __declspec(naked) void __stdcall fixlstrcmpiA(void) { __asm jmp dword ptr function_ptrs[1587 * 4] }
#endif
#ifndef FIX_lstrcmpiW
    __declspec(naked) void __stdcall fixlstrcmpiW(void) { __asm jmp dword ptr function_ptrs[1588 * 4] }
#endif
#ifndef FIX_lstrcpy
    __declspec(naked) void __stdcall fixlstrcpy(void) { __asm jmp dword ptr function_ptrs[1589 * 4] }
#endif
#ifndef FIX_lstrcpyA
    __declspec(naked) void __stdcall fixlstrcpyA(void) { __asm jmp dword ptr function_ptrs[1590 * 4] }
#endif
#ifndef FIX_lstrcpyW
    __declspec(naked) void __stdcall fixlstrcpyW(void) { __asm jmp dword ptr function_ptrs[1591 * 4] }
#endif
#ifndef FIX_lstrcpyn
    __declspec(naked) void __stdcall fixlstrcpyn(void) { __asm jmp dword ptr function_ptrs[1592 * 4] }
#endif
#ifndef FIX_lstrcpynA
    __declspec(naked) void __stdcall fixlstrcpynA(void) { __asm jmp dword ptr function_ptrs[1593 * 4] }
#endif
#ifndef FIX_lstrcpynW
    __declspec(naked) void __stdcall fixlstrcpynW(void) { __asm jmp dword ptr function_ptrs[1594 * 4] }
#endif
#ifndef FIX_lstrlen
    __declspec(naked) void __stdcall fixlstrlen(void) { __asm jmp dword ptr function_ptrs[1595 * 4] }
#endif
#ifndef FIX_lstrlenA
    __declspec(naked) void __stdcall fixlstrlenA(void) { __asm jmp dword ptr function_ptrs[1596 * 4] }
#endif
#ifndef FIX_lstrlenW
    __declspec(naked) void __stdcall fixlstrlenW(void) { __asm jmp dword ptr function_ptrs[1597 * 4] }
#endif
#ifndef FIX_timeBeginPeriod
    __declspec(naked) void __stdcall fixtimeBeginPeriod(void) { __asm jmp dword ptr function_ptrs[1598 * 4] }
#endif
#ifndef FIX_timeEndPeriod
    __declspec(naked) void __stdcall fixtimeEndPeriod(void) { __asm jmp dword ptr function_ptrs[1599 * 4] }
#endif
#ifndef FIX_timeGetDevCaps
    __declspec(naked) void __stdcall fixtimeGetDevCaps(void) { __asm jmp dword ptr function_ptrs[1600 * 4] }
#endif
#ifndef FIX_timeGetSystemTime
    __declspec(naked) void __stdcall fixtimeGetSystemTime(void) { __asm jmp dword ptr function_ptrs[1601 * 4] }
#endif
#ifndef FIX_timeGetTime
    __declspec(naked) void __stdcall fixtimeGetTime(void) { __asm jmp dword ptr function_ptrs[1602 * 4] }
#endif
