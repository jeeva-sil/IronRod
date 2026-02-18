; ──────────────────────────────────────────────────────────────
; IronRod NSIS Installer Script for Windows
; ──────────────────────────────────────────────────────────────
; Requires NSIS 3.x — https://nsis.sourceforge.io/
;
; Build:
;   makensis /DVERSION=1.0.0 /DOUTFILE="dist\IronRod-Setup.exe" scripts\installer.nsi

!ifndef VERSION
    !define VERSION "1.0"
!endif
!ifndef OUTFILE
    !define OUTFILE "dist\IronRod-${VERSION}-Windows-Setup.exe"
!endif

!define APP_NAME "IronRod"
!define APP_EXE "IronRod.exe"
!define PUBLISHER "IronRod Team"
!define INSTALL_DIR "$PROGRAMFILES\${APP_NAME}"
!define UNINSTALLER "Uninstall.exe"

; ── General ──
Name "${APP_NAME} ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "${INSTALL_DIR}"
RequestExecutionLevel admin       ; Require admin for raw disk access
SetCompressor /SOLID lzma

; ── Modern UI ──
!include "MUI2.nsh"
!include "FileFunc.nsh"

!define MUI_ICON "assets\icon.ico"
!define MUI_UNICON "assets\icon.ico"
!define MUI_ABORTWARNING

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; ── Install Section ──
Section "Install"
    SetOutPath "$INSTDIR"

    ; Copy all files from the PyInstaller dist folder
    File /r "dist\${APP_NAME}\*.*"

    ; Create uninstaller
    WriteUninstaller "$INSTDIR\${UNINSTALLER}"

    ; Start Menu shortcut
    CreateDirectory "$SMPROGRAMS\${APP_NAME}"
    CreateShortCut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" \
        "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}" 0
    CreateShortCut "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk" \
        "$INSTDIR\${UNINSTALLER}" "" "$INSTDIR\${UNINSTALLER}" 0

    ; Desktop shortcut
    CreateShortCut "$DESKTOP\${APP_NAME}.lnk" \
        "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}" 0

    ; Registry — Add/Remove Programs
    WriteRegStr HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "DisplayName" "${APP_NAME} — Data Recovery"
    WriteRegStr HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "UninstallString" '"$INSTDIR\${UNINSTALLER}"'
    WriteRegStr HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "DisplayIcon" "$INSTDIR\${APP_EXE}"
    WriteRegStr HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "Publisher" "${PUBLISHER}"
    WriteRegStr HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "DisplayVersion" "${VERSION}"

    ; Calculate installed size
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" \
        "EstimatedSize" "$0"
SectionEnd

; ── Uninstall Section ──
Section "Uninstall"
    ; Remove files
    RMDir /r "$INSTDIR"

    ; Remove shortcuts
    Delete "$DESKTOP\${APP_NAME}.lnk"
    RMDir /r "$SMPROGRAMS\${APP_NAME}"

    ; Remove registry
    DeleteRegKey HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"
SectionEnd
