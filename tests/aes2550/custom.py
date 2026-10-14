#!/usr/bin/env python3

import sys
import traceback
import gi

gi.require_version('FPrint', '2.0')
from gi.repository import FPrint, GLib

# Exit with error on any exception, included those happening in async callbacks
sys.excepthook = lambda *args: (traceback.print_exception(*args), sys.exit(1))

if len(sys.argv) != 1:
    print("This test does not accept arguments")
    sys.exit(1)

ctx = GLib.main_context_default()

c = FPrint.Context()
c.enumerate()
devices = c.get_devices()

d = devices[0]
del devices

d.open_sync()

# We're testing that the device returns an error when only tapping the it.
print("Please tap the fingerprint reader, but do not swipe your finger across it.")
try:
    d.capture_sync(True)
except GLib.Error as error:
    assert error.matches(FPrint.device_retry_quark(),
                         FPrint.DeviceRetry.TOO_SHORT)
else:
    raise AssertionError("Capture did not raise FP_DEVICE_RETRY_TOO_SHORT")
finally:
    d.close_sync()

del d
del c
