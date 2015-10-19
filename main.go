// +build linux,amd64
package main

/*
#include <shadow.h>
#include <stddef.h>
#include <stdlib.h>
*/
import "C"
import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"
	"unsafe"
)

const dateFormat = "Jan 02, 2006"

type ExpirationInfo struct {
	PasswordLastChanged time.Time
	PasswordInactive    time.Time
	PasswordExpires     time.Time
	AccountExpired      time.Time
	Min                 int
	Max                 int
	Warning             int
	Expirable           bool
}

type ExpirableLogin struct {
	Login      string
	Expiration *ExpirationInfo
}

func (e *ExpirableLogin) ShouldWarnNow() bool {
	if e.Expiration.Max == 99999 {
		return false
	}
	// how many days since last password changed
	elapsed := time.Since(e.Expiration.PasswordLastChanged)
	days := int(math.Ceil((elapsed.Seconds() / 86400)))
	// if warning days is satisfied but min value not reached yet
	// in effect the user got warning but not really able to change password
	// so we need to ensure both warning days satiesfied and reach the min days
	if days <= e.Expiration.Warning && days >= e.Expiration.Min {
		return true
	}

	return false
}

func daysDuration(d int) time.Duration {
	return time.Duration(d) * time.Duration(24*time.Hour)
}

func neverMarker() time.Time {
	return time.Date(1970, 1, 1, 0, 0, 0, 0, time.Local)
}

func timeFromEpoch(v int) time.Time {
	if v == -1 {
		return neverMarker()
	}
	dt := time.Date(1970, 1, 1, 0, 0, 0, 0, time.Local)
	dt = dt.Add(daysDuration(v))
	return dt
}

func getLoginExpiration(login string) *ExpirationInfo {
	cs := C.CString(login)
	defer C.free(unsafe.Pointer(cs))

	sp := C.getspnam(cs)
	if unsafe.Pointer(sp) == nil {
		return nil
	}

	exp := &ExpirationInfo{
		PasswordLastChanged: timeFromEpoch(int(sp.sp_lstchg)),
		PasswordInactive:    timeFromEpoch(int(sp.sp_inact)),
		AccountExpired:      timeFromEpoch(int(sp.sp_expire)),
		Warning:             int(sp.sp_warn),
		Max:                 int(sp.sp_max),
		Min:                 int(sp.sp_min),
		Expirable:           int(sp.sp_expire) > -1,
	}

	if exp.Max == 99999 {
		exp.PasswordExpires = neverMarker()
		exp.PasswordInactive = neverMarker()
	} else {
		// last changed + max ( in days )
		exp.PasswordExpires = exp.PasswordLastChanged.Add(daysDuration(exp.Max))
	}

	return exp
}

func listExpirableUsers() []*ExpirableLogin {
	f, err := os.Open("/etc/shadow")
	if err != nil {
		return nil
	}

	users := []*ExpirableLogin{}
	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err == io.EOF {
			break
		}
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		expInfo := getLoginExpiration(parts[0])
		if expInfo != nil {
			expLogin := &ExpirableLogin{parts[0], expInfo}
			if expInfo.Expirable {
				users = append(users, expLogin)
			}
		}
	}
	return users
}

func main() {
	// TODO: I have no idea the correct solution
	// List only the users that will get the warning during login *AND* they could
	// do the password change.
	// Because if we set the "warning" earlier than "min", the user will get the
	// warning but not really able to change the password
	for _, u := range listExpirableUsers() {
		passwordExpires := u.Expiration.PasswordExpires.Format(dateFormat)
		if u.Expiration.PasswordExpires == neverMarker() {
			passwordExpires = "Never"
		}

		lastPasswordChange := u.Expiration.PasswordLastChanged.Format(dateFormat)
		if u.Expiration.PasswordLastChanged == neverMarker() {
			lastPasswordChange = "Never"
		}

		fmt.Printf("Login: %s\n", u.Login)
		fmt.Printf("Last password change: %s\n", lastPasswordChange)
		fmt.Printf("Password expires: %s\n", passwordExpires)
		fmt.Printf("Warning: %d\n", u.Expiration.Warning)
		fmt.Printf("Min password change allowed: %d\n", u.Expiration.Min)
		fmt.Println("Is it effective to notify now? ", u.ShouldWarnNow())

		fmt.Println()
	}
}
