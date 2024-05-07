# HelloJackHunter

Some research into WinSxS binaries and finding hijackable paths, more information on the workflow can be found on the [blog post here](https://blog.zsec.uk/hellojackhunter-exploring-winsxs/).

## Workflow
1. Hunt out binaries in WinSxS
2. Map out DLLs being called from $currentdir
3. Run HelloJackHunter and point it in a for loop at the DLLs

## Usage
To execute the binary simply download the sln file, compile it then run:

`Usage: HelloJackHunter.exe <path to DLL or directory> <output path>`

## Known Vulnerable Binaries;
| Binary Name | Path | DLL Name / Path |
| -----------|------|------------------|
|ngentask.exe|C:\Windows\WinSxS\amd64_netfx4-ngentask_exe_b03f5f7f11d50a3a_4.0.15912.0_none_d5e7146d665097c0\ngentask.exe|mscorsvc.dll|
|explorer.exe|C:\Windows\WinSxS\amd64_microsoft-windows-explorer_31bf3856ad364e35_10.0.22621.3235_none_31b295f9f540d278\explorer.exe|cscapi.dll|
|aspnet_wp.exe|C:\Windows\WinSxS\amd64_netfx4-aspnet_wp_exe_b03f5f7f11d50a3a_4.0.15912.0_none_107a08446d17dcf2\aspnet_wp.exe|webengine.dll, webengine4.dll|
|aspnet_regiis.exe| c:\Windows\WinSxS\amd64_netfx4-aspnet_regiis_exe_b03f5f7f11d50a3a_4.0.15912.0_none_833013222f03235e\aspnet_regiis.exe|webengine4.dll|












