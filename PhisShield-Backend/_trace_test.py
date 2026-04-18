import traceback
import main
try:
    main.build_legacy_analyze_result('Send your OTP immediately to restore access')
    print('OK')
except Exception:
    traceback.print_exc()
