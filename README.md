Apache2.4+ - Mod_bw v0.92

Author                : Sam Osheroff
Original Author       : Ivan Barrera A. (Bruce)

License      : Licensed under the Apache Software License v2.0
               It must be included as LICENSE in this package.

Platform     : Linux/x86         (Tested with Fedora Core 4, Suse, etc)
               Linux/x86_64      (Redhat Enterprise 4)
               FreeBSD/x86       (Tested on 5.2)
               MacOS X/Ppc x86   (Tested on both platforms)
               Solaris 8/sparc   (Some notes on compile)
               Microsoft Windows (Win XP, Win2003, Win7. Others should work)
               HP-UX 11          (Thanks to Soumendu Bhattacharya for testing)

Notes        : This fork is based on stable version 0.92 of mod_bw.  While it was written
               to address limitations with Windows, the changes could be useful to other
               platforms.

               In Windows, the sleep timer has a minimum resolution of 1ms but the necessary
               sleep duration to create the desired bandwidth could esaily be less than 1ms.
               The module now calculates roughly how many sleep cycles to "skip" to get 10ms
               to pass, then it sleeps for 10ms.  This sleep duration was selected because some
               Windows editions have a minimum 10ms resolution.

               The module now attempts to roughly calculate the client's bandwidth over a 15ms
               period.  If the client's appearant bandwidth is less than the available during
               the 15ms interval, no sleeping occurs, since the client's lower bandwidth is
               already the limiting factor.
               
               Some enhancements were made to the debug logging.
               
               Lastly, there was a bug in the hook function (used for forced operations)
               where modules that create subrequests caused the output filter to get installed
               twice.  Inserting the output filter is now skipped when the subrequest
               causes an internal redirect.
           
