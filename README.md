# backup.elf

iLO 5 supports the backup and restore of system configuration. The backup file
is encrypted with a password. Backup and restore is implemented in backup.elf.


## backup file format

### 0x90-byte header

 offset | type          | description
--------|---------------|----------------------
  `00`  | u32           | magic value 0x42fa4c49
  `04`  | u32           | 0x101
  `08`  | u32           | file size
  `10`  | u8[0x10]      | MD5 hash of content, see below
  `20`  | u32           | 1
  `30`  | u8[?]         | firmware version as string
  `50`  | u8[?]         | 'iLO 5 Backup file'
  `70`  | u8[0x10]      | MD5 hash of the password

#### content hash

The content MD5 sum is calculated by hashing 0x200 bytes of a repeating
0x00..0x4c pattern and the content of the encrypted backup file starting at
offset 0x90.

```c
    MD5_CTX ctx;
    char result[16];
    char buf[0x200];
    FILE *file = fopen("backup.enc", "r");

    for (int i = 0; i < 0x200; i++) {
        buf[i] = i % 0x4d;
    }

    MD5_Init(&ctx);
    MD5_Update(&ctx, buf, 0x200);

    fseek(file, 0x90, SEEK_SET);
    while (fread(buf, 1, 0x200, file) != 0) {
        // NOTE: in case the last fread returns less than 0x200 bytes,
        // the hash is still calculated over the entire buffer
        MD5_Update(&ctx, buf, 0x200);
    }

    MD5_Final(result, &ctx);
```

### keys

Starting at offset 0x90, five encrypted keys follow:

 offset  | type          | description
---------|---------------|----------------------
   `+00` | u8[0x40]      | salt
   `+40` | u32           | length of encrypted key, big endian
   `+44` | u8[0x100]     | encrypted key
  `+144` | u8[0x10]      | iv; it is the same for all five keys

The first key is derived from the BMC's chip id, the second and third from
data from SMBIOS (if available), all remaining keys are generated from
random data. There may be facilities to add custom keys.

For encryption, AES 256 CBC is used.

The first key is calculated by generating 0x40 bytes random salt, feeding it
together with the chip id into OpenSSL's PKCS5_PBKDF2_HMAC and using its result's
first 31 bits to initialize libc's rand(). A function to generate random bytes
by calling rand()&0xff for every byte is set as OpenSSL's random number generator.
Using this RNG, a 2048 bit RSA key is generated.

The 8-byte chip id is found at 0x01f20010 or via web interface at
/xmldata?item=all in <CID> tags.

```c
    RAND_METHOD ilo_rand = {
        ilo_rand_seed,
        ilo_rand_get_bytes,
        NULL,
        NULL,
        NULL,
        NULL,
    };

    SSL_library_init();
    RAND_cleanup();
    RAND_set_rand_method(&ilo_rand);

    char chip_id[16] = /* chip id */;
    char salt[0x40] = /* random data */;
    char pbkdf2_result[0x80];
    PKCS5_PBKDF2_HMAC(chip_id, 16, salt, 0x40, 0x2f59, EVP_sha384(), 0x80, pbkdf2_result);

    RAND_seed(pbkdf2_result, 4);
    RSA *key = RSA_generate_key(0x800, 0x10001, NULL, NULL);
```

iLO's rand() uses a LCG with 31 bits of internal state, yielding values
between 0 and 0x78f0e07. It has an optimal period length of 0x78f0e079.

```c
bool rng_seeded = false;
uint32_t rng_state;

void srand(unsigned int seed)
{
    rng_state = seed & 0x7fffffff;
}

int rand(void)
{
    if (!rng_seeded) {
        rng_seeded = true;
        rng_state = 1;
    }
    rng_state = ((uint64_t)rng_state * 0x3aa8 + 0xf4627) % 0x78f0e079;
    return rng_state >> 4;
}
```

## content

The encrypted backup file contents are gzip compressed and
_must start with these eight bytes_: `1f 8b 08 00 00 00 00 00`
This means that the contents must be deflate compressed, not
contain the original file name, and not contain the timestamp
of creation.

The decompressed contents are a packed series of the following structure:

 offset | type          | description
--------|---------------|----------------------
  `00`  | u32           | magic value 0x42fa4c49
  `04`  | u32           | 0x101
  `08`  | u32           | file length
  `30`  | u8[32]        | absolute directory path
  `50`  | u8[32]        | file name
  `90`  |               | file content

## file list

iLO 5 firmware 1.40 knows the following files:


 description      | directory           | filename                | flags
------------------|---------------------|-------------------------|---------
 Firmware version | i:/vol0/cfg         | version.bin             | 00000001
 Serial Number    | i:/vol0/cfg         | eeprom.bin              | 00000003
 License          | i:/vol0/cfg         | license.bin             | 00000001
 LicenseCI        | i:/vol0/cfg         | lic_owner.bin           | 00000001
 Network (kernel) | i:/vol0/cfg         | nwcfg.bin               | 00000003
 Security Manager | i:/vol0/cfg         | secmgr.bin              | 00000001
 Security CAC     | i:/vol0/cfg         | secmgrnk.bin            | 00000001
 User DB          | i:/vol0/cfg         | cfg_users.bin           | 00000001
 User DB Keys     | i:/vol0/cfg         | cfg_users_key.bin       | 00000001
 User CAC         | i:/vol0/cfg         | cfg_cac.bin             | 00000001
 AHS cfg          | i:/vol0/cfg         | blackbox.bin            | 00000001
 AHS cfg (NAND)   | /mnt/blackbox       | blackbox.bin            | 00000001
 Beacon cfg       | i:/vol0/cfg         | beacon.bin              | 00000001
 iLO CFG          | i:/vol0/cfg         | ilo.bin                 | 00000001
 Webserver        | i:/vol0/cfg         | webserv.bin             | 00000001
 RIB-CL           | i:/vol0/cfg         | ribcl.bin               | 00000001
 SMSSO            | i:/vol0/cfg         | smsso.bin               | 00000001
 SRV INFO         | i:/vol0/cfg         | srvinfo.bin             | 00000001
 ROM PS           | i:/vol0/cfg         | rom_ps.bin              | 00000000
 IPv6 ET0         | i:/vol0/cfg         | ipv6_et0.bin            | 00000001
 IPv6 ET1         | i:/vol0/cfg         | ipv6_et1.bin            | 00000001
 FSS              | i:/vol0/cfg         | fss_cfg.bin             | 00000000
 AlertMail        | i:/vol0/cfg         | alertmail.bin           | 00000001
 AlertMail EKey   | i:/vol0/cfg         | amail_ekey.bin          | 00000001
 SecurEST         | i:/vol0/cfg         | securest.bin            | 00000000
 DVI              | i:/vol0/cfg         | dvi.bin                 | 00000001
 USB VM           | i:/vol0/cfg         | usbvms.bin              | 00000001
 rSYSLOG          | i:/vol0/cfg         | rsyslog.bin             | 00000001
 LINKDET          | i:/vol0/cfg         | linkdet.bin             | 00000001
 FW SCAN          | i:/vol0/cfg         | fw_scan.bin             | 00000001
 CLI.BIN          | i:/vol0/cfg         | cli.bin                 | 00000001
 ERS PEM          | i:/vol0/cfg         | ers.pem                 | 00000001
 ERS REG TOKEN    | i:/vol0/cfg         | ers_reg_token.bin       | 00000001
 ERS BIN          | i:/vol0/cfg         | ers.bin                 | 00000001
 ERS KEY          | i:/vol0/cfg         | ers_key.bin             | 00000001
 ERS IML          | i:/vol0/cfg         | ersiml.bin              | 00000000
 LDAP             | i:/vol0/cfg         | cfg_ldap.bin            | 00000001
 DIRGRP           | i:/vol0/cfg         | cfg_dirgrp.bin          | 00000001
 PWR              | i:/vol0/cfg         | pwr.bin                 | 00000001
 SNTPdn0          | i:/vol0/cfg         | sntpsdn0.bin            | 00000001
 SNTPdn1          | i:/vol0/cfg         | sntpsdn1.bin            | 00000001
 Timezone         | i:/vol0/cfg         | tz.bin                  | 00000001
 Key Manager      | i:/vol0/cfg         | keymgr.bin              | 00000001
 CPU              | i:/vol0/cfg         | cpu.bin                 | 00000000
 SNMP CFG         | i:/vol0/cfg         | snmp.bin                | 00000001
 SNMPD            | i:/vol0/cfg         | snmpd.conf              | 00000001
 SNMPV3           | i:/vol0/cfg         | snmpv3.bin              | 00000000
 SNMPZ            | i:/vol0/cfg         | snmp_extn.z             | 00000000
 RESTSERVER       | i:/vol0/cfg         | restserv.bin            | 00000000
 Kerberos         | i:/vol0/cfg         | kerberos.bin            | 00000001
 VSP              | i:/vol0/cfg         | vsp.bin                 | 00000001
 Server FQDN      | i:/vol0/cfg         | srvfqdn.z               | 00000001
 HP SSO           | i:/vol0/cfg         | hpsso.bin               | 00000001
 Random Pool      | i:/vol0/cfg         | random.bin              | 00000000
 RIS Subscrbers?  | i:/vol0/cfg         | ris_subscr.bin          | 00000000
 RIS Tasks        | i:/vol0/cfg         | ris_tasks.bin           | 00000000
 RIS Tasks (DIMM) | i:/vol0/cfg         | dimmcfg.bin             | 00000000
 RDP              | i:/vol0/cfg         | rdp.bin                 | 00000001
 Server Signing   | i:/vol0/cfg         | srvsig.bin              | 00000000
 MCTP             | i:/vol0/cfg         | mctp.bin                | 00000001
 BMC cfg          | i:/vol0/cfg         | bmc_nvcfg.bin           | 00000001
 BMC cfg2         | i:/vol0/cfg         | bmc_nvcfg2.z            | 00000001
 BMC PoH          | i:/vol0/cfg         | bmc_nvpoh.z             | 00000000
 EH cfg a0        | i:/vol0/cfg         | eh_nvcfg_a0.z           | 00000001
 Virt. NIC        | i:/vol0/cfg         | vnic.bin                | 00000001
 ROM IST Settings | i:/vol0/cfg         | rom_ist.bin             | 00000001
 IST Thresholds   | i:/vol0/cfg         | ist_sens_threshold.bin  | 00000001
 IST data         | i:/vol0/cfg         | ist_cust_dura_samp.bin  | 00000001
 IST data         | i:/vol0/cfg         | ist_1day_samples.bin    | 00000000
 IST data         | i:/vol0/cfg         | ist_30m_1hr_samples.bin | 00000000
 SECERASE         | i:/vol0/cfg         | syserase.bin            | 00000000
 Sec Dashboard    | i:/vol0/cfg         | secdbcfg.bin            | 00000001
 EVs              | i:/vol0/evs         | evs.bin                 | 00000001
 Web SSL Cert     | i:/vol0/certs       | sslcert.der             | 10000101
 WEB Certs        | i:/vol0/certs       | sslcsr.der              | 10000101
 WEB Certs        | i:/vol0/certs       | tfacert.pem             | 10000101
 ESKM             | i:/vol0/certs       | eskm_ca.pem             | 10000101
 ESKM DER         | i:/vol0/certs       | sslcert.der             | 10000101
 SSH Key          | i:/vol0/certs       | mp_sshkey.bin           | 10000101
 LDAP Cert        | i:/vol0/certs       | ldapcacert.der          | 10000101
 KRB5 Config      | i:/vol0/kerberos    | krb5.conf               | 00000101
 KRB5 keytab      | i:/vol0/kerberos    | krb5.keytab             | 00000101
 EV LOG           | i:/vol0/cfg         | evlog.bin               | 00000000
 SMBIOS           | i:/vol0/cfg         | smbios.bin              | 00000000
 SMBIOS .Z        | i:/vol0/cfg         | smbios_3.z              | 00000000
 PowerAlloc       | i:/vol0/cfg         | rckmgmt.bin             | 00000000
 Backup           | i:/vol0/cfg         | backup.bin              | 00000000
 Login CFG        | i:/vol0/cfg         | logincfg.bin            | 00000001
 CAC stuff        | /mnt/ilostore/certs | 0cacert.der             | 00000101
 CAC stuff        | /mnt/ilostore/certs | 1cacert.der             | 00000101
 CAC stuff        | /mnt/ilostore/certs | 2cacert.der             | 00000101
 CAC stuff        | /mnt/ilostore/certs | 3cacert.der             | 00000101

The LSB of `flags` means that the file shall not be backuped.
