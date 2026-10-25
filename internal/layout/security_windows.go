//go:build windows

package layout

import (
	"fmt"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

func hardenDirectory(directory Directory) error {
	// Use well-known SIDs instead of localized account names. The service runs
	// as LocalSystem by default and administrators retain recovery access.
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("resolve current Windows installer SID: %w", err)
	}
	currentSID := "*" + user.User.Sid.String() + ":(OI)(CI)F"
	output, err := exec.Command("icacls.exe", directory.Path, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", currentSID).CombinedOutput()
	if err != nil {
		return fmt.Errorf("harden managed directory ACL %s: %w: %s", directory.Path, err, output)
	}
	return nil
}

func checkDirectorySecurity(directory Directory, _ os.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(directory.Path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read managed directory ACL %s: %w", directory.Path, err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("managed directory %s must use a protected non-inherited DACL", directory.Path)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("managed directory %s has no restrictive DACL", directory.Path)
	}
	system, _ := windows.StringToSid("S-1-5-18")
	admins, _ := windows.StringToSid("S-1-5-32-544")
	current, tokenErr := windows.GetCurrentProcessToken().GetTokenUser()
	if tokenErr != nil {
		return tokenErr
	}
	seenSystem, seenAdmins := false, false
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(dacl, i, &ace); err != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("managed directory %s contains an unsupported ACL entry", directory.Path)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.Equals(system):
			seenSystem = true
		case sid.Equals(admins):
			seenAdmins = true
		case sid.Equals(current.User.Sid):
		default:
			return fmt.Errorf("managed directory %s grants access to unexpected SID %s", directory.Path, sid.String())
		}
	}
	if !seenSystem || !seenAdmins {
		return fmt.Errorf("managed directory %s must grant LocalSystem and Administrators", directory.Path)
	}
	return nil
}
