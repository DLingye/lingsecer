MAINAME = "LingSecer_GetTime"
VERSION = "250808"
AUTHOR = "DONGFANG Lingye"
EMAIL = "ly@lingye.online"

import datetime, time

l_time = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
timezone = time.strftime('%Z', time.localtime())