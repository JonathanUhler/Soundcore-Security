# Problem Statement: Apple IPA Planning

After hitting several dead ends with bypassing the ijiami emulator detection (see the research
notes in `2026-08-30_App-Dex-Analysis` and `2026-08-31_Ijiami-Buffer-Scrape`), this project obtained
a semi-recent IPA file for the iOS version of the Soundcore app, which is in `./ipa/`.

The hope is that one of the following two things can be done with the IPA:

1. Defeat the certificate pinning to allow mitmproxy-based observations of the firmware "check
   for update" flow attempted in prior research sessions.
2. Inject Frida into the IPA, rebuild/resign it, and load it onto a non-rooted iPhone for even
   more accessible dynamic testing
   
As of now, the downloaded IPA has not been loaded onto iPhone hardware yet, although there's no
reason to believe that it wouldn't work unmodified.

## Goal 0: Verify the Unmodified IPA

The first goal is to try to load the IPA file as it sits in `./ipa/` onto a phone and demonstrate
that it can run. Your only task for this goal is to provide guidance on what specific steps to
execute to achieve that.

You may also want to perform some read-only analysis of the IPA to verify that everything checks
out. If you see anything that seems corrupt, broken, or would otherwise prevent the IPA from running
unmodified, you should report that.

Once the user reports that the unmodified IPA is running successfully, more specific goals will be
given.
