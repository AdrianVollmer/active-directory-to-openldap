#!/usr/bin/python
import argparse
import os
import subprocess


def dump_base(base, args, schema=None):
    schema = schema or "starttls"
    extra_args = []

    if schema == "starttls":
        schema = "ldap"
        extra_args = "-ZZ"

    dn = ",".join("DC=" + dc for dc in args.target_domain.split("."))

    cmd = [
        "ldapsearch",
        "-H",
        schema + "://" + args.target_host,
        "-D",
        args.user + "@" + args.domain,
        "-w",
        args.password,
        "-b",
        base + dn,
        "-x",
        "-o",
        "ldif-wrap=no",
        "-E",
        "pr=1000/noprompt",
        "-E",
        "!1.2.840.113556.1.4.801=::MAMCAQc=",
        "-LLL",
        "(objectClass=*)",
        *extra_args,
    ]

    if base:
        filename = os.path.join(args.output_dir, "schema.ldif")
    else:
        filename = os.path.join(args.output_dir, "base.ldif")

    os.makedirs(args.output_dir, exist_ok=True)

    with open(filename, "w") as fp:
        subprocess.run(
            cmd,
            env=dict(LDAPTLS_REQCERT="never"),
            stdout=fp,
            text=True,
            check=True,
        )


def dump_ldif(args):
    bases = ["", "CN=Schema,CN=Configuration,"]

    for base in bases:
        try:
            dump_base(base, args)
        except subprocess.CalledProcessError:
            dump_base(base, args, "ldaps")
        except subprocess.CalledProcessError:
            dump_base(base, args, "ldap")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="",
    )
    parser.add_argument("--user", help="Username")
    parser.add_argument("--domain", help="User's domain")
    parser.add_argument("--password", help="User's Password")
    parser.add_argument("--target-host", help="LDAP hostname")
    parser.add_argument("--target-domain", help="Target domain")
    parser.add_argument("--output-dir", help="Output directory")
    args = parser.parse_args()

    dump_ldif(args)
