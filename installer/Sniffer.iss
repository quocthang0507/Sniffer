#define AppName "Sniffer Network Analyzer"
#define AppVersion "2.0.0"
#define AppExeName "Sniffer Network Analyzer.exe"

[Setup]
AppId={{6D5E4EED-6359-491B-982A-0C4E8DEB39DE}
AppName={#AppName}
AppVersion={#AppVersion}
DefaultDirName={autopf}\Sniffer Network Analyzer
DefaultGroupName={#AppName}
OutputDir=..\artifacts\installer
OutputBaseFilename=Sniffer-Setup-win-x64
SetupIconFile=..\Sniffer\icon.ico
UninstallDisplayIcon={app}\{#AppExeName}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Files]
Source: "..\artifacts\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"

[Run]
Filename: "https://npcap.com/#download"; Description: "Open the official Npcap download page (required for live capture)"; Flags: postinstall shellexec skipifsilent unchecked
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: postinstall nowait skipifsilent unchecked
