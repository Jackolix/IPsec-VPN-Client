; NSIS installer hooks for the VPN Client.
;
; Registering the broker creates a Windows service, which needs Administrator
; rights — so this only works because the installer is per-machine (see
; bundle.windows.nsis.installMode) and therefore runs elevated. In Tauri's
; default per-user mode the installer runs unelevated, the registration fails
; with access-denied, and the app — finding no broker — falls back to elevating
; charon-svc itself on every connect (a UAC prompt and a console window).
;
; With the service installed, the (unelevated) app drives charon and DNS through
; the broker over its named pipe, so a connect never raises a UAC prompt.
; Uninstalling removes the service again. The MSI registers the same service
; from a WiX fragment (installer.wxs).

; File types the OS may open with this app.
;
; Tauri registers the ones in bundle.fileAssociations (tauri.conf.json) itself,
; and does it by taking over the extension's default handler — right for .scx,
; .tgb and .pro, which belong to a VPN client or to nothing at all. On a machine
; that has Sophos Connect, .scx is *its* (`sc.ScxDocument.1`); taking it is the
; point, and APP_ASSOCIATE saves the previous handler so uninstalling gives it
; back. `.ini` is not like that: it is Windows' generic settings-file extension,
; and claiming it would repaint every .ini on the machine with our icon. So this
; installer only *offers* the app for a .ini — an entry under OpenWithProgids,
; which puts the app in Explorer's "Open with" list and lets the user promote it
; to the default if they want to — and leaves the system default alone.
!define INIPROGID "VPN Client.ini"

; The ProgIDs Tauri writes for the associations in tauri.conf.json: each one is
; that association's `name`, verbatim. Kept in step with that file by hand.
!define SCXPROGID "VPN Client.scx"
!define TGBPROGID "VPN Client.tgb"
!define PROPROGID "VPN Client.pro"

; Patch up one association Tauri has just written. Two things need it.
;
; The open command: APP_ASSOCIATE writes it as `$INSTDIR\<exe>.exe "%1"`, with no
; quotes around the program itself. Every path this app installs to has spaces in
; it ("C:\Program Files\VPN Client\vpn-desktop.exe"), so opening a profile would
; come down to CreateProcess guessing where the program name ends — and it tries
; "C:\Program Files\VPN.exe" before the real one. Quote it properly instead.
;
; The saved previous handler: APP_ASSOCIATE stores whatever the extension
; pointed at before, and APP_UNASSOCIATE puts it back on uninstall. On an
; upgrade the extension already pointed at *us*, so what gets saved is our own
; ProgID — and uninstalling would then hand the extension back to a ProgID the
; same uninstall has just deleted. Blank it in that case, so the extension ends
; up with no default rather than a dangling one.
!macro FixAssociation EXT PROGID
  ReadRegStr $R4 SHCTX "Software\Classes\${PROGID}\shell\open\command" ""
  ${If} $R4 != ""
    WriteRegStr SHCTX "Software\Classes\${PROGID}\shell\open\command" "" '"$INSTDIR\${MAINBINARYNAME}.exe" "%1"'
  ${EndIf}

  ReadRegStr $R4 SHCTX "Software\Classes\.${EXT}" "${PROGID}_backup"
  ${If} $R4 == "${PROGID}"
    WriteRegStr SHCTX "Software\Classes\.${EXT}" "${PROGID}_backup" ""
  ${EndIf}
!macroend

; Remove an installation made under a previous product name, so that installing
; this build upgrades it instead of landing beside it.
;
; Tauri's NSIS installer keys everything — the Add/Remove entry, the recorded
; install directory, the "a previous version is installed" page — on
; **productName**, not on the bundle identifier. Two past changes therefore look
; like a different product to it:
;
;   * v0.2.3 renamed the product "IPsec VPN Client" -> "VPN Client";
;   * v0.2.2 switched installMode currentUser -> perMachine, which moves the same
;     keys from HKCU to HKLM (so <= v0.2.1 installs are invisible even under the
;     old name).
;
; Without this, installing over such a machine leaves the old install in place
; with its own Add/Remove entry, and — because a Windows service is keyed by
; service name, which did not change — the `ipsec-vpn-broker` service keeps
; running the OLD directory's vpn-broker.exe against the new GUI.
;
; Inserted once per registry context; SHCTX selects which. The HKCU pass sees the
; hive of whoever the installer is elevated as, so a per-user install made by a
; different account is out of reach — `vpn-broker install` repointing the service
; is what covers that case.
!macro MigrateLegacyProduct LEGACYNAME
  ReadRegStr $R6 SHCTX "Software\Microsoft\Windows\CurrentVersion\Uninstall\${LEGACYNAME}" "UninstallString"
  ${If} $R6 != ""
    DetailPrint "Found a previous installation named ${LEGACYNAME}; removing it first..."

    ; Where it lives. Every Tauri NSIS install records this unquoted under the
    ; manufacturer key; InstallLocation is the fallback and *is* quoted.
    ReadRegStr $R5 SHCTX "${MANUKEY}\${LEGACYNAME}" ""
    ${If} $R5 == ""
      ReadRegStr $R5 SHCTX "Software\Microsoft\Windows\CurrentVersion\Uninstall\${LEGACYNAME}" "InstallLocation"
      StrCpy $R7 $R5 1
      ${If} $R7 == '$\"'
        StrCpy $R5 $R5 -1 1
      ${EndIf}
    ${EndIf}

    ${If} ${FileExists} "$R5\uninstall.exe"
      ; `/S` runs it without UI (and kills the old app if it is running).
      ; `_?=` keeps the uninstaller from relaunching itself out of $TEMP, which
      ; is what makes ExecWait actually wait for it to finish. Its own
      ; PREUNINSTALL hook removes the broker service, so POSTINSTALL below
      ; re-registers it from this directory. App data is left alone — that
      ; checkbox defaults to off — so profiles and saved credentials survive.
      ExecWait '"$R5\uninstall.exe" /S _?=$R5' $0
      DetailPrint "${LEGACYNAME} uninstaller exit code: $0"
      ; Let Windows release the image handles after the processes exit.
      Sleep 1000

      ${If} $0 == 0
        ; Because of `_?=`, the uninstaller could delete neither itself nor its
        ; directory; anything else left there is ours too (charon logs, a
        ; hand-made backup), and the whole point is to leave no second copy.
        Delete "$R5\uninstall.exe"
        ${If} $R5 != $INSTDIR
          RMDir /r /REBOOTOK "$R5"
        ${EndIf}
        DeleteRegKey SHCTX "Software\Microsoft\Windows\CurrentVersion\Uninstall\${LEGACYNAME}"
        DeleteRegKey SHCTX "${MANUKEY}\${LEGACYNAME}"
        ; Shortcuts under the old name, in case they point somewhere the
        ; uninstaller's own target check did not recognise.
        Delete "$SMPROGRAMS\${LEGACYNAME}.lnk"
        Delete "$SMPROGRAMS\${LEGACYNAME}\${LEGACYNAME}.lnk"
        RMDir "$SMPROGRAMS\${LEGACYNAME}"
        Delete "$DESKTOP\${LEGACYNAME}.lnk"
      ${Else}
        ; Deliberately leave the registry entry: it is the only remaining handle
        ; for removing that install by hand. Installing on top still works — the
        ; service registration below repoints the broker at this directory — so
        ; this is a warning, not a failure.
        ${IfNot} ${Silent}
          MessageBox MB_ICONEXCLAMATION|MB_OK "The previous installation ($\"${LEGACYNAME}$\") could not be removed automatically (exit code $0).$\r$\n$\r$\nSetup will continue, but the old entry stays in Settings > Apps and should be removed from there."
        ${EndIf}
      ${EndIf}
    ${Else}
      ; Uninstaller gone, only the Add/Remove entry left behind: drop the stale
      ; registration so Windows stops offering an uninstall that cannot run.
      DetailPrint "${LEGACYNAME} is registered but its uninstaller is missing; clearing the stale entry."
      DeleteRegKey SHCTX "Software\Microsoft\Windows\CurrentVersion\Uninstall\${LEGACYNAME}"
      DeleteRegKey SHCTX "${MANUKEY}\${LEGACYNAME}"
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREINSTALL
  ; Fold in any install made under the old product name (or under the old
  ; per-user install mode), so this one upgrades it rather than duplicating it.
  ; Both registry contexts, because the mode switch moved the keys between them.
  !insertmacro MigrateLegacyProduct "IPsec VPN Client"
  SetShellVarContext current
  !insertmacro MigrateLegacyProduct "IPsec VPN Client"
  !if "${INSTALLMODE}" == "perMachine"
    SetShellVarContext all
  !endif

  ; On an upgrade the previous broker service is still running, and it holds a
  ; lock on vpn-broker.exe (and the charon binaries it supervises) — so writing
  ; the new files fails with "file in use". Stop it first; its own shutdown
  ; reverts DNS and stops charon, releasing the locks. The service definition is
  ; left in place, so POSTINSTALL's "install" simply starts it again against the
  ; freshly written binary. A fresh install has no vpn-broker.exe here yet — the
  ; guard skips it, so this is a no-op the first time.
  ${If} ${FileExists} "$INSTDIR\vpn-broker.exe"
    DetailPrint "Stopping the running VPN broker service before upgrade..."
    nsExec::ExecToLog '"$INSTDIR\vpn-broker.exe" stop'
    Pop $0
    DetailPrint "vpn-broker stop exit code: $0"
    ; Give Windows a moment to release the image handles after the process exits.
    Sleep 1000
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "Registering the VPN broker service..."
  ; auto-start LocalSystem service; supervises charon-svc + applies VPN DNS.
  ; Idempotent: if the service already exists — including one left pointing at a
  ; previous install directory — this repoints it here and starts it.
  nsExec::ExecToLog '"$INSTDIR\vpn-broker.exe" install'
  Pop $0
  DetailPrint "vpn-broker install exit code: $0"
  ; Not fatal — the app still connects through its elevate-charon fallback — but
  ; a silently skipped registration is what leaves every connect asking for
  ; admin, so say it out loud instead of letting the user wonder. Except in a
  ; silent install, where there is nobody to click OK and the box hangs setup.
  ${If} $0 != 0
    ${IfNot} ${Silent}
      MessageBox MB_ICONEXCLAMATION|MB_OK "The VPN broker service could not be registered (exit code $0).$\r$\n$\r$\nThe app will still work, but every connect will ask for Administrator rights and open a console window."
    ${EndIf}
  ${EndIf}

  ; Tauri wrote the .scx/.tgb/.pro associations earlier in this same section;
  ; correct them (see FixAssociation).
  !insertmacro FixAssociation "scx" "${SCXPROGID}"
  !insertmacro FixAssociation "tgb" "${TGBPROGID}"
  !insertmacro FixAssociation "pro" "${PROPROGID}"

  ; Offer the app for .ini without claiming the extension: the ProgID below is
  ; ours and describes the NCP profiles that arrive as .ini files, but only
  ; OpenWithProgids points at it, so it shows up in "Open with" and nowhere else.
  DetailPrint "Registering the VPN profile file types..."
  WriteRegStr SHCTX "Software\Classes\${INIPROGID}" "" "NCP VPN profile"
  WriteRegStr SHCTX "Software\Classes\${INIPROGID}" "FriendlyTypeName" "NCP VPN profile"
  WriteRegStr SHCTX "Software\Classes\${INIPROGID}\DefaultIcon" "" "$INSTDIR\${MAINBINARYNAME}.exe,0"
  WriteRegStr SHCTX "Software\Classes\${INIPROGID}\shell" "" "open"
  WriteRegStr SHCTX "Software\Classes\${INIPROGID}\shell\open" "" "Open with ${PRODUCTNAME}"
  WriteRegStr SHCTX "Software\Classes\${INIPROGID}\shell\open\command" "" '"$INSTDIR\${MAINBINARYNAME}.exe" "%1"'
  WriteRegStr SHCTX "Software\Classes\.ini\OpenWithProgids" "${INIPROGID}" ""

  ; The same offer from the application's own side. This is what lists the app
  ; under "Open with" for every type it reads — including a profile someone saved
  ; under an extension we deliberately do not register.
  WriteRegStr SHCTX "Software\Classes\Applications\${MAINBINARYNAME}.exe" "FriendlyAppName" "${PRODUCTNAME}"
  WriteRegStr SHCTX "Software\Classes\Applications\${MAINBINARYNAME}.exe\shell\open\command" "" '"$INSTDIR\${MAINBINARYNAME}.exe" "%1"'
  WriteRegStr SHCTX "Software\Classes\Applications\${MAINBINARYNAME}.exe\SupportedTypes" ".ini" ""
  WriteRegStr SHCTX "Software\Classes\Applications\${MAINBINARYNAME}.exe\SupportedTypes" ".scx" ""
  WriteRegStr SHCTX "Software\Classes\Applications\${MAINBINARYNAME}.exe\SupportedTypes" ".tgb" ""
  WriteRegStr SHCTX "Software\Classes\Applications\${MAINBINARYNAME}.exe\SupportedTypes" ".pro" ""

  ; Explorer caches file associations; without this the new entries only appear
  ; after a sign-out. Tauri does not do it for the ones it writes either, so this
  ; covers those as well.
  System::Call "shell32::SHChangeNotify(i,i,i,i) (0x08000000, 0x1000, 0, 0)"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "Removing the VPN broker service..."
  nsExec::ExecToLog '"$INSTDIR\vpn-broker.exe" uninstall'
  Pop $0
  DetailPrint "vpn-broker uninstall exit code: $0"

  ; Withdraw the .ini offer. Only our own entries go — the extension's default
  ; was never taken, so there is nothing to put back (Tauri's own uninstall
  ; restores the .scx/.tgb/.pro defaults it replaced).
  DeleteRegValue SHCTX "Software\Classes\.ini\OpenWithProgids" "${INIPROGID}"
  DeleteRegKey SHCTX "Software\Classes\${INIPROGID}"
  DeleteRegKey SHCTX "Software\Classes\Applications\${MAINBINARYNAME}.exe"
  System::Call "shell32::SHChangeNotify(i,i,i,i) (0x08000000, 0x1000, 0, 0)"
!macroend
