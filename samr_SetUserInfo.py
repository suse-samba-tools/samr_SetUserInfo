#!/usr/bin/python3
import optparse
from samba import getopt as options
from samba.dcerpc import samr, security, lsa
from samba.net import Net
from samba.credentials import Credentials
from samba.dcerpc import nbt
from samba import samdb
from samba.auth import system_session
from samba.ndr import ndr_unpack
from ldb import SCOPE_BASE
from samba import NTSTATUSError

if __name__ == "__main__":
    parser = optparse.OptionParser('samr_SetUserInfo [options]')
    sambaopts = options.SambaOptions(parser)
    parser.add_option_group(sambaopts)
    parser.add_option_group(options.VersionOptions(parser))
    credopts = options.CredentialsOptions(parser)
    parser.add_option_group(credopts)
    parser.add_option('-S', '--sAMAccountName', action='store', dest='name', help='The sAMAccountName of the object to manipulate')

    (opts, args) = parser.parse_args()

    if opts.__dict__['name'] is None:
        parser.error('Parameter --sAMAccountName is required')

    lp = sambaopts.get_loadparm()
    creds = credopts.get_credentials(lp)
    realm = lp.get('realm')

    net = Net(creds)
    cldap_ret = net.finddc(domain=realm, flags=(nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS | nbt.NBT_SERVER_WRITABLE))
    host = cldap_ret.pdc_dns_name

    ldb = samdb.SamDB(url='ldap://%s' % host, lp=lp, credentials=creds, session_info=system_session())

    domain_sid = security.dom_sid(ldb.get_domain_sid())
    s = samr.samr("ncacn_ip_tcp:%s[seal]" % host, lp, creds)
    samr_handle = s.Connect2(None, security.SEC_FLAG_MAXIMUM_ALLOWED)
    samr_domain = s.OpenDomain(samr_handle, security.SEC_FLAG_MAXIMUM_ALLOWED, domain_sid)

    try:
        (rids, _) = s.LookupNames(samr_domain, [lsa.String(opts.name)])
    except NTSTATUSError:
        print('%s not found!' % opts.name)
        exit(1)
    samr_user = s.OpenUser(samr_domain, security.SEC_FLAG_MAXIMUM_ALLOWED, rids.ids[0])

    flags = samr.UserInfo16()
    flags.acct_flags = samr.ACB_PWNOEXP | samr.ACB_WSTRUST
    s.SetUserInfo2(samr_user, 16, flags)
    s.Close(samr_user)
