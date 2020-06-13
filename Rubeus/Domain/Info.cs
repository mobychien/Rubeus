using System;

namespace TDNite.Domain
{
    public static class Info
    {
        public static void ShowLogo()
        {
            Console.WriteLine("\r\n   TDNite  AD Configuration Tool    ");
       /*     Console.WriteLine("  (_____ \\      | |                     ");
            Console.WriteLine("   _____) )_   _| |__  _____ _   _  ___ ");
            Console.WriteLine("  |  __  /| | | |  _ \\| ___ | | | |/___)");
            Console.WriteLine("  | |  \\ \\| |_| | |_) ) ____| |_| |___ |");
            Console.WriteLine("  |_|   |_|____/|____/|_____)____/(___/\r\n");
       */
            Console.WriteLine("  v3.5.1 \r\n");
        }

        public static void ShowUsage()
        {
            string usage = @"
 Ticket requests and renewals:

    Retrieve a TGT based on a user password/hash, optionally saving to a file or applying to the current logon session or a specific LUID:
        TDNite.exe asktgt /user:USER </password:PASSWORD [/enctype:DES|RC4|AES128|AES256] | /des:HASH | /rc4:HASH | /aes128:HASH | /aes256:HASH> [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/outfile:FILENAME] [/ptt] [/luid] [/nowrap]

    Retrieve a TGT based on a user password/hash, start a /netonly process, and to apply the ticket to the new process/logon session:
        TDNite.exe asktgt /user:USER </password:PASSWORD [/enctype:DES|RC4|AES128|AES256] | /des:HASH | /rc4:HASH | /aes128:HASH | /aes256:HASH> /createnetonly:C:\Windows\System32\cmd.exe [/show] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/nowrap]

    Retrieve a service ticket for one or more SPNs, optionally saving or applying the ticket:
        TDNite.exe asktgs </ticket:BASE64 | /ticket:FILE.KIRBI> </service:SPN1,SPN2,...> [/enctype:DES|RC4|AES128|AES256] [/dc:DOMAIN_CONTROLLER] [/outfile:FILENAME] [/ptt] [/nowrap]

    Renew a TGT, optionally applying the ticket, saving it, or auto-renewing the ticket up to its renew-till limit:
        TDNite.exe renew </ticket:BASE64 | /ticket:FILE.KIRBI> [/dc:DOMAIN_CONTROLLER] [/outfile:FILENAME] [/ptt] [/autorenew] [/nowrap]

    Perform a Kerberos-based password bruteforcing attack:
        TDNite.exe brute </password:PASSWORD | /passwords:PASSWORDS_FILE> [/user:USER | /users:USERS_FILE] [/domain:DOMAIN] [/creduser:DOMAIN\\USER & /credpassword:PASSWORD] [/ou:ORGANIZATION_UNIT] [/dc:DOMAIN_CONTROLLER] [/outfile:RESULT_PASSWORD_FILE] [/noticket] [/verbose] [/nowrap]


 Constrained delegation abuse:

    Perform S4U CDA:
        TDNite.exe s4u </ticket:BASE64 | /ticket:FILE.KIRBI> </impersonateuser:USER | /tgs:BASE64 | /tgs:FILE.KIRBI> /msdsspn:SERVICE/SERVER [/altservice:SERVICE] [/dc:DOMAIN_CONTROLLER] [/outfile:FILENAME] [/ptt] [/nowrap]
        TDNite.exe s4u /user:USER </rc4:HASH | /aes256:HASH> [/domain:DOMAIN] </impersonateuser:USER | /tgs:BASE64 | /tgs:FILE.KIRBI> /msdsspn:SERVICE/SERVER [/altservice:SERVICE] [/dc:DOMAIN_CONTROLLER] [/outfile:FILENAME] [/ptt] [/nowrap]

    Perform S4U CDA across domains:
        TDNite.exe s4u /user:USER </rc4:HASH | /aes256:HASH> [/domain:DOMAIN] </impersonateuser:USER | /tgs:BASE64 | /tgs:FILE.KIRBI> /msdsspn:SERVICE/SERVER /targetdomain:DOMAIN.LOCAL /targetdc:DC.DOMAIN.LOCAL [/altservice:SERVICE] [/dc:DOMAIN_CONTROLLER] [/nowrap]


 Ticket management:

    Submit a TGT, optionally targeting a specific LUID (if elevated):
        TDNite.exe ptt </ticket:BASE64 | /ticket:FILE.KIRBI> [/luid:LOGINID]

    Purge tickets from the current logon session, optionally targeting a specific LUID (if elevated):
        TDNite.exe purge [/luid:LOGINID]

    Parse and describe a ticket (service ticket or TGT):
        TDNite.exe describe </ticket:BASE64 | /ticket:FILE.KIRBI>


 Ticket extraction and harvesting:

    Triage all current tickets (if elevated, list for all users), optionally targeting a specific LUID, username, or service:
        TDNite.exe triage [/luid:LOGINID] [/user:USER] [/service:krbtgt] [/server:BLAH.DOMAIN.COM]

    List all current tickets in detail (if elevated, list for all users), optionally targeting a specific LUID:
        TDNite.exe klist [/luid:LOGINID] [/user:USER] [/service:krbtgt] [/server:BLAH.DOMAIN.COM]

    Dump all current ticket data (if elevated, dump for all users), optionally targeting a specific service/LUID:
        TDNite.exe dump [/luid:LOGINID] [/user:USER] [/service:krbtgt] [/server:BLAH.DOMAIN.COM] [/nowrap]

    Retrieve a usable TGT .kirbi for the current user (w/ session key) without elevation by abusing the Kerberos GSS-API, faking delegation:
        TDNite.exe tgtdeleg [/target:SPN]

    Monitor every /interval SECONDS (default 60) for new TGTs:
        TDNite.exe monitor [/interval:SECONDS] [/targetuser:USER] [/nowrap] [/registry:SOFTWARENAME]

    Monitor every /monitorinterval SECONDS (default 60) for new TGTs, auto-renew TGTs, and display the working cache every /displayinterval SECONDS (default 1200):
        TDNite.exe harvest [/monitorinterval:SECONDS] [/displayinterval:SECONDS] [/targetuser:USER] [/nowrap] [/registry:SOFTWARENAME]


 Roasting:

    Perform Kerberoasting Attack:
        TDNite.exe kerberoast [/spn:""blah/blah""] [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:""OU=,...""] [/nowrap]

    Perform Kerberoasting, outputting hashes to a file:
        TDNite.exe kerberoast /outfile:hashes.txt [/spn:""blah/blah""] [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:""OU=,...""]

    Perform Kerberoasting, outputting hashes in the file output format, but to the console:
        TDNite.exe kerberoast /simple [/spn:""blah/blah""] [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:""OU=,...""] [/nowrap]

    Perform Kerberoasting with alternate credentials:
        TDNite.exe kerberoast /creduser:DOMAIN.FQDN\USER /credpassword:PASSWORD [/spn:""blah/blah""] [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:""OU=,...""] [/nowrap]

    Perform Kerberoasting with an existing TGT:
        TDNite.exe kerberoast /spn:""blah/blah"" </ticket:BASE64 | /ticket:FILE.KIRBI> [/nowrap]

    Perform Kerberoasting using the tgtdeleg ticket to request service tickets - requests RC4 for AES accounts:
        TDNite.exe kerberoast /usetgtdeleg [/nowrap]

    Perform ""opsec"" Kerberoasting, using tgtdeleg, and filtering out AES-enabled accounts:
        TDNite.exe kerberoast /rc4opsec [/nowrap]

    List statistics about found Kerberoastable accounts without actually sending ticket requests:
        TDNite.exe kerberoast /stats [/nowrap]

    Perform Kerberoasting, requesting tickets only for accounts with an admin count of 1 (custom LDAP filter):
        TDNite.exe kerberoast /ldapfilter:'admincount=1' [/nowrap]

    Perform Kerberoasting, requesting tickets only for accounts whose password was last set between 01-31-2005 and 03-29-2010, returning up to 5 service tickets:
        TDNite.exe kerberoast /pwdsetafter:01-31-2005 /pwdsetbefore:03-29-2010 /resultlimit:5 [/nowrap]
        
    Perform AES Kerberoasting:
        TDNite.exe kerberoast /aes [/nowrap]

    Perform AS-REP ""roasting"" for any users without preauth:
        TDNite.exe asreproast [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:""OU=,...""] [/nowrap]

    Perform AS-REP ""roasting"" for any users without preauth, outputting Hashcat format to a file:
        TDNite.exe asreproast /outfile:hashes.txt /format:hashcat [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:""OU=,...""]

    Perform AS-REP ""roasting"" for any users without preauth using alternate credentials:
        TDNite.exe asreproast /creduser:DOMAIN.FQDN\USER /credpassword:PASSWORD [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:""OU,...""] [/nowrap]


 Miscellaneous:

    Create a hidden program (unless /show is passed) with random /netonly credentials, displaying the PID and LUID:
        TDNite.exe createnetonly /program:""C:\Windows\System32\cmd.exe"" [/show]

    Reset a user's password from a supplied TGT (AoratoPw):
        TDNite.exe changepw </ticket:BASE64 | /ticket:FILE.KIRBI> /new:PASSWORD [/dc:DOMAIN_CONTROLLER]

    Calculate rc4_hmac, aes128_cts_hmac_sha1, aes256_cts_hmac_sha1, and des_cbc_md5 hashes:
        TDNite.exe hash /password:X [/user:USER] [/domain:DOMAIN]

    Substitute an sname or SPN into an existing service ticket:
        TDNite.exe tgssub </ticket:BASE64 | /ticket:FILE.KIRBI> /altservice:ldap [/ptt] [/luid] [/nowrap]
        TDNite.exe tgssub </ticket:BASE64 | /ticket:FILE.KIRBI> /altservice:cifs/computer.domain.com [/ptt] [/luid] [/nowrap]
    
    Display the current user's LUID:
        TDNite.exe currentluid

    The ""/consoleoutfile:C:\FILE.txt"" argument redirects all console output to the file specified.

    The ""/nowrap"" flag prevents any base64 ticket blobs from being column wrapped for any function.


 NOTE: Base64 ticket blobs can be decoded with :

    [IO.File]::WriteAllBytes(""ticket.kirbi"", [Convert]::FromBase64String(""aabbcc...""))

";
            Console.WriteLine(usage);
        }
    }
}
