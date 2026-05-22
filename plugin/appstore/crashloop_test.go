package appstore

import "testing"

func TestRecordCrashSuspendsAfterCap(t *testing.T) {
	sup := newSupervisor(Config{InstallRoot: t.TempDir()}, Deps{}, newQuietLogger(t))

	// Crash exactly maxCrashesInWindow times — still in budget.
	for i := 0; i < maxCrashesInWindow; i++ {
		if suspended := sup.recordCrash("io.test.app"); suspended {
			t.Fatalf("suspended at crash %d, want to survive up to %d", i+1, maxCrashesInWindow)
		}
	}

	// One more crash flips the budget.
	if !sup.recordCrash("io.test.app") {
		t.Errorf("expected suspended after %d+1 crashes in window", maxCrashesInWindow)
	}
	if !sup.isSuspended("io.test.app") {
		t.Errorf("isSuspended should report true after crash-loop cap")
	}
}

func TestRecordCrashIndependentPerApp(t *testing.T) {
	sup := newSupervisor(Config{InstallRoot: t.TempDir()}, Deps{}, newQuietLogger(t))

	for i := 0; i < maxCrashesInWindow+1; i++ {
		sup.recordCrash("io.bad.app")
	}
	if !sup.isSuspended("io.bad.app") {
		t.Fatalf("bad app should be suspended")
	}
	if sup.isSuspended("io.good.app") {
		t.Errorf("good app should NOT be suspended — crash counters are per-app")
	}
}

func TestAppsReportsSuspendedFlag(t *testing.T) {
	// Build a supervisor with one installed app whose crash-budget has
	// been exceeded. Confirm Apps() surfaces the suspended flag.
	sup := newSupervisor(Config{InstallRoot: t.TempDir()}, Deps{}, newQuietLogger(t))
	// Inject an installed-app record without the disk machinery.
	sup.mu.Lock()
	sup.installed["io.suspended.app"] = &installedApp{
		Manifest: parseDummyManifest(t, "io.suspended.app"),
	}
	sup.mu.Unlock()

	for i := 0; i < maxCrashesInWindow+1; i++ {
		sup.recordCrash("io.suspended.app")
	}

	apps := sup.Apps()
	if len(apps) != 1 || !apps[0].Suspended {
		t.Errorf("Apps() should report suspended=true; got %+v", apps)
	}
}
