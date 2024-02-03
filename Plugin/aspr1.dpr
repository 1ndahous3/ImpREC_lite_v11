// aspr.pas : Plugin for ImpREC to find asprotect 1.2x real API in its wrapped code
////////////////////////////////////////////////////////////////////////////////////////////
//
// Note that this example is not a tracer but just an opcode checker.
//
////////////////////////////////////////////////////////////////////////////////////////////

// Detection and fix some function added by Madness(m16384@pisem.net):
// 1) LockResource (new)
// 2) GetCommandLineA (fix: GetCommandLineA->GetVersion)
// 3) GetModuleHandleA (new)
// 4) GetCurrentProcessId (fix: GetCurrentProcessId->GetCurrentProcess (my bug: too much ByteToTrace))
library aspr1;
uses windows;

const bytetotrace=28; //how much bytes can be traced
// Global variables
////////////////////////////////////////////////////////////////////////////////////////////
var     g_temp :array[0..MAX_PATH] of char;		// Windows Temp directory
        g_ftmp :array[0..MAX_PATH] of char;		// Input File
        g_ftmp2 :array[0..MAX_PATH] of char;		// Output File
        g_time_out :DWORD;				// TimeOut
        g_pointer: DWORD;				// Pointer to trace (in VA)


// Exported function to use
////////////////////////////////////////////////////////////////////////////////////////////
//
// Parameters:
// -----------
// <param> : It will contain the name of the input file
//
// Returned value:
// ---------------
// Use a value greater or equal to 200. It will be shown by ImpREC if no output were created
//
function Trace(param:DWORD):DWORD;cdecl;
var i :DWORD;
    hFile :DWORD;
    BytesRead :DWORD;
    to_trace :array[0..bytetotrace-1] of BYTE;
    address :PDWORD;
    val :DWORD;
    found :BOOLEAN;
    BytesWritten :DWORD;
begin
	// Prepare input/output filenames
	lstrcpy(g_ftmp, g_temp);
	lstrcat(g_ftmp, '\');
	i := lstrlen(g_ftmp);
	movememory(addr(g_ftmp[i]),addr(param),4);
	g_ftmp[i+4] := chr(0);
	lstrcpy(g_ftmp2, g_ftmp);
	lstrcat(g_ftmp, '.tmp');
	lstrcat(g_ftmp2, '_.tmp');

	// Write what is the victim doing with GetProcAddress...
	hFile := CreateFile(g_ftmp, GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile = INVALID_HANDLE_VALUE) then begin
		// Cannot open/find the input file
		Trace := 201;
                exit;
	end;

	// Read the timeout value
	if not ReadFile(hFile, g_time_out, 4, BytesRead, nil) or (BytesRead <> 4) then begin
		// Cannot read the timeout
		CloseHandle(hFile);
                Trace := 203;
                exit;
	end;
	// Read the VA of the pointer to trace
	if not ReadFile(hFile, g_pointer, 4, BytesRead, nil) or (BytesRead <> 4) then begin
		// Cannot read the pointer to trace in
		CloseHandle(hFile);
                Trace := 203;
                exit;
	end;
	CloseHandle(hFile);

	// Check if we read a valid pointer
	if (IsBadReadPtr(pointer(g_pointer), 4)) then begin
		// Bad pointer!
                Trace := 205;
                exit;
	end;

	movememory(addr(to_trace),pointer(g_pointer),bytetotrace);

        //all different types of redirection code, a common one is mov eax,[xxxxxx].
        //check for this and the value at xxxxxx and try to guess it ;)

        found := false;
       // asm
       // db $cc
       // end;
        for i := 0 to bytetotrace-1 do
        begin
        if to_trace[i] = $A1 then
        begin
             //check all the possible mov eax,[xxxxxx] redirections
             address := pointer((@to_trace[i+1])^);
             val     := address^;
             //val = eax returned by redirection code. try to id emulated function
             if val = GetVersion then begin
                val := dword(GetProcAddress(GetModuleHandle('KERNEL32.DLL'),'GetVersion'));
                found := true;
             end;
             if val = dword(GetCommandLineA) then begin
                val := dword(GetProcAddress(GetModuleHandle('KERNEL32.DLL'),'GetCommandLineA'));
                found := true;
             end;
             if val = GetCurrentProcess then begin
                val := dword(GetProcAddress(GetModuleHandle('KERNEL32.DLL'),'GetCurrentProcess'));
                found := true;
             end;
             if val = GetCurrentProcessID then begin
                val := dword(GetProcAddress(GetModuleHandle('KERNEL32.DLL'),'GetCurrentProcessId'));
                found := true;
             end;
        end;
        if ((to_trace[i]=$FF) and (to_trace[i+1]=$35) and (to_trace[i+6]=$58) and (to_trace[i+7]=$C3))
        or ((to_trace[i]=$8B) and (to_trace[i+1]=$05) and (to_trace[i+6]=$C3)) then
        begin
             //check all the possible mov eax,[xxxxxx] redirections
             address := pointer((@to_trace[i+2])^);
             val     := address^;
             //val = eax returned by redirection code. try to id emulated function
             if val = GetVersion then begin
                val := dword(GetProcAddress(GetModuleHandle('KERNEL32.DLL'),'GetVersion'));
                found := true;
             end;
             if val = dword(GetCommandLineA) then begin
                val := dword(GetProcAddress(GetModuleHandle('KERNEL32.DLL'),'GetCommandLineA'));
                found := true;
             end;
             if val = GetCurrentProcess then begin
                val := dword(GetProcAddress(GetModuleHandle('KERNEL32.DLL'),'GetCurrentProcess'));
                found := true;
             end;
             if val = GetCurrentProcessID then begin
                val := dword(GetProcAddress(GetModuleHandle('KERNEL32.DLL'),'GetCurrentProcessId'));
                found := true;
             end;
        end;
        if found=true then break; //fix: GetCurrentProcessId->GetCurrentProcess  and some additional speed
        end;

        //check for ret 4 at certain position (lock/free resource)
        if (to_trace[4]=$C2) and (to_trace[5]=$04) then begin
                val := dword(GetProcAddress(GetModuleHandle('KERNEL32.DLL'),'FreeResource'));
                found := true;
        end;

        //check for call and ret 4 at certain position (freeresource->getversion)
        if (to_trace[3]=$E8) and (to_trace[10]=$04) then begin
                val := dword(GetProcAddress(GetModuleHandle('KERNEL32.DLL'),'FreeResource'));
                found := true;
        end;

        //check for lockresource
        if (to_trace[8]=$8B) and (to_trace[10]=$08) and (to_trace[11]=$5D) then begin
                val := dword(GetProcAddress(GetModuleHandle('KERNEL32.DLL'),'LockResource'));
                found := true;
        end;

          //check for lockresource
        if (to_trace[9]=$8B) and (to_trace[11]=$08) and (to_trace[12]=$5D) and (to_trace[13]=$C2) then begin
                val := dword(GetProcAddress(GetModuleHandle('KERNEL32.DLL'),'LockResource'));
                found := true;
        end;

        //check for mov eax,[xxxxxx] and ret 4 at certain position (lockresource)
        if (to_trace[3]=$8B) and (to_trace[7]=$C2) then begin
                val := dword(GetProcAddress(GetModuleHandle('KERNEL32.DLL'),'LockResource'));
                found := true;
        end;

        //check for GetProcAddress
        if (to_trace[5]=$C) and (to_trace[8]=$8) then begin
                val := dword(GetProcAddress(GetModuleHandle('KERNEL32.DLL'),'GetProcAddress'));
                found := true;
        end;

        //check for GetModuleHandle
        if (to_trace[5]=$8) and (to_trace[15]=$EB) then begin
                val := dword(GetProcAddress(GetModuleHandle('KERNEL32.DLL'),'GetModuleHandleA'));
                found := true;
        end;

        {check for GetModuleHandle
0167:00DF1360  55                  PUSH      EBP
0167:00DF1361  8BEC                MOV       EBP,ESP
0167:00DF1363  8B45>08<            MOV       EAX,[EBP+08]
0167:00DF1366  85C0                TEST      EAX,EAX
0167:00DF1368  7513                JNZ       DF137D
0167:00DF136A  813D7869DF0000004000CMP       DWORD PTR [DF6978],400000
0167:00DF1374  7507                JNZ       DF137D
0167:00DF1376  A17869DF00          MOV       EAX,[DF6978]
0167:00DF137B  >EB<06              JMP       DF1383
0167:00DF137D  50                  PUSH      EAX
0167:00DF137E  E8D53DFFFF          CALL      KERNEL32!GetModuleHandleA
0167:00DF1383  5D                  POP       EBP
0167:00DF1384  C20400              RET       4}
        if (to_trace[5]=$8) and (to_trace[27]=$EB) then begin
                val := dword(GetProcAddress(GetModuleHandle('KERNEL32.DLL'),'GetModuleHandleA'));
                found := true;
        end;

        //check for DialogBoxParamA
        if (to_trace[6]=$8) and (to_trace[9]=$18) then begin
                val := dword(GetProcAddress(GetModuleHandle('USER32.DLL'),'DialogBoxParamA'));
                found := true;
        end;

        if found then
        begin
             // Write this value to the output file
		hFile := CreateFile(g_ftmp2, GENERIC_WRITE, 0, nil, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile = INVALID_HANDLE_VALUE) then begin
			// Open for writing error
                        Trace := 207;
                        exit;
		end;
		if (not WriteFile(hFile, val, 4, BytesWritten, nil)) then begin
			// Write error?
			CloseHandle(hFile);
			Trace := 209;
                        exit;
		end;
		CloseHandle(hFile);

	        // OK
                Trace := 200;
	end
        else Trace := 300; //completed, but nothing found

end;

exports Trace;

begin
        // Initialize all you need
	// Get the Temp dir
	GetTempPath(MAX_PATH, g_temp);
end.
