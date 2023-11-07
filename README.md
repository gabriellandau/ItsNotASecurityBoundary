# It's Not A Security Boundary

By [Gabriel Landau](https://twitter.com/GabrielLandau) at [Elastic Security](https://www.elastic.co/security-labs/).

Presented at [BlueHat IL 2024](https://x.com/BlueHatIL/status/1792626026230456546) ([abstract](https://www.microsoftrnd.co.il/bluehatil/conference/abstracts#collapse-12)) and REcon Montreal 2024 ([abstract](https://cfp.recon.cx/recon2024/talk/337QFH/)).

## False File Immutability

This repository demonstrates a long-standing class of vulnerabilities which I'm calling **False File Immutability** (FFI).  FFI occurs when code assumes that files cannot be modified because they were opened without `FILE_SHARE_WRITE`.  In some situations, it's possible for attackers to modify files even when write sharing is denied.  When this occurs, any code that reads the same value/offset within a file more than once may be subject to double-read vulnerabilities.  FFI can occur with both traditional I/O (e.g. `ReadFile`) or memory-mapped I/O (e.g. `MapViewOfFile`), and can affect both user- and kernel-mode code.

For more information on False File Immutability, see my talks and slides (once posted).

## It's Not A Security Boundary

ItsNotASecurityBoundary is an exploit that leverages False File Immutability assumptions in Windows Code Integrity (`ci.dll`) to trick it into accepting an improperly-signed security catalog containing fraudulent authentihashes.  With attacker-controlled authentihashes loaded and trusted by CI, the kernel will load any driver of the attacker's choosing, even unsigned ones.

To exploit this bug in CI, an attacker first plants a security catalog on an attacker-controlled storage device, which CI then loads and parses.  As CI is processing the catalog, the attacker rapidly injects a malicious [authentihash](https://virustotal.readme.io/reference/authentihash) between CI's signature validation and catalog parsing phases.  Further, the attacker must force the memory-mapped catalog pages to be discarded in this tight window.  Because of this tight race, it's a non-deterministic exploit.  You may have to run it 5+ times in order for it to succeed.

ItsNotASecurityBoundary's name is an homage to MSRC's policy that "[Administrator-to-kernel is not a security boundary.](https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria)"

For more details on the ItsNotASecurityBoundary exploit, see my talks and slides (once posted).

Here is a diagram from the slides outlining the attack:

![image](https://github.com/gabriellandau/ItsNotASecurityBoundary/assets/42078554/82c16f4a-d112-46e0-a1e1-428203b58eb7)

## Fine, But We Can Still Easily Stop It

FineButWeCanStillEasilyStopIt is a kernel driver that demonstrates how to detect and stop the ItsNotASecurityBoundary exploit.  Because a third-party kernel driver cannot safely modify the internal workings of Code Integrity, it must use a someone-complicated process to identify and block the exploit while minimizing false positives that can interrupt benign system behavior.  A proper fix within CI itself would be much simpler.

### Disclosure Timeline and Fix

* 2024-02-14 I reported ItsNotASecurityBoundary and FineButWeCanStillEasilyStopIt to MSRC, suggesting two simple low-risk mitigations.
* 2024-02-29 The Windows Defender team reached out to coordinate disclosure.
* 2024-04-23 Microsoft releases [KB5036980](https://support.microsoft.com/en-us/topic/april-23-2024-kb5036980-os-builds-22621-3527-and-22631-3527-preview-5a0d6c49-e42e-4eb4-8541-33a7139281ed) Preview with one of the suggested fixes.
* 2024-05-14 Fix reaches GA for Windows 11 23H2 as [KB5037771](https://support.microsoft.com/en-us/topic/may-14-2024-kb5037771-os-builds-22621-3593-and-22631-3593-e633ff2f-a021-4abb-bd2e-7f3687f166fe).  I have not tested any other platforms (Win10, Server, etc).
* 2024-05-20 I presented this research at BlueHat IL.
* 2024-06-14 MSRC closed the case: “We have completed our investigation and determined that the case doesn't meet our bar for servicing at this time. As a result, we have opened a next-version candidate bug for the issue, and it will be evaluated for upcoming releases. Thanks, again, for sharing this report with us.”
* 2024-06-30 I presented this research at REcon Montreal.

## Frequently Asked Questions

##### With ItsNotASecurityBoundary fixed, does FFI still matter?

ItsNotASecurityBoundary is neither the first nor last FFI vulnerability.  Last year, I released [PPLFault](https://github.com/gabriellandau/PPLFault) which exploited FFI assumptions in the Windows kernel, achieving admin-to-PPL (to-kernel via AngryOrchard), but I didn't name the vulnerability class at the time.  Now with two public vulnerabilities in the same class, it seemed appropriate to formally describe and name it.

ItsNotASecurityBoundary is not the end of FFI.  There _are_ other exploitable FFI vulnerabilities out there.

##### Why does Admin-to-Kernel matter?

ItsNotASecurityBoundary allows an attacker to instantly terminate any security software on the system, simultaneously blinding security telemetry and disabling security controls that can stop and/or quarantine malware.  Normally such instant-kill attacks are not possible due to [Windows Anti-Malware Process Protections](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-).

##### Can't an attacker just use a vulnerable driver?

Microsoft acknowledges that vulnerable drivers are a problem, and is actively working to mitigate this risk via the Vulnerable Driver Blocklist, which is has been [enforced by default](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules#microsoft-vulnerable-driver-blocklist) since Windows 11 22H2.  Admin-to-kernel exploits can achieve the same effects as vulnerable drivers, but MSRC does not prioritize them, so they can remain exploitable for years.  For example, the [PPLsystem exploit](https://github.com/Slowerzs/PPLSystem) released in May 2024 leverages the `IRundown::DoCallback` vulnerability first reported by James Forshaw in November 2018.  **That's roughly 2000 days, and the vulnerability still isn't patched as of this writing (2024-06-18).**

For more perspective on admin-to-kernel vulnerabilities, see [this editorial](https://www.elastic.co/security-labs/forget-vulnerable-drivers-admin-is-all-you-need) I wrote last year.

##### Why do you care so much?

I help build the [Elastic Endpoint Security](https://www.elastic.co/security/endpoint-security) EDR.  We have a duty to protect our customers.  Windows vulnerabilities like this leave our customers vulnerable.

## License

This project is covered by the [ELv2 license](LICENSE.txt).  It uses [phnt](https://github.com/winsiderss/systeminformer/tree/25846070780183848dc8d8f335a54fa6e636e281/phnt) from SystemInformer under the [MIT license]([phnt/LICENSE.txt](https://github.com/winsiderss/systeminformer/blob/25846070780183848dc8d8f335a54fa6e636e281/LICENSE.txt)).

## Credits
Special thanks to the Windows Defender team for rapidly fixing [non-security-boundary](https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria) vulnerabilities in a reasonable timeframe (90 days), even when MSRC won't take the case.
