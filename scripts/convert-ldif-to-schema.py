#!/usr/bin/python

import argparse

from ldif import LDIFParser


CLASS = """
objectclass ( %(class_id)s
 NAME '%(class_name)s'
 SUP '%(sup)s'
 %(class_category)s
 MUST ( %(must)s )
 MAY ( %(may)s )
 )
"""

ATTRIBUTE = """
attributetype ( %(attribute_id)s
 NAME %(attribute_name)s
 SYNTAX '%(attribute_syntax)s'
 %(flags)s
 )
"""

objectclassMappings = {
    "top": "mstop",
    #  "user": "customActiveDirectoryUser",
    #  "group": "customActiveDirectoryGroup",
    #  "attributeSchema": "olcSchemaConfig",
    #  "configuration": "olcGlobal",
    #  "contact": "customActiveDirectoryContact",
}

# Resources:
#  https://technet.microsoft.com/en-us/library/cc961740.aspx
#  https://github.com/jelmer/samba/blob/master/source4/setup/schema-map-openldap-2.3
# Note: Printable String in OpenLDAP does not allow underscore. Use Octet
# String instead.
mapMSSyntaxToOpenLdap = {
    "2.5.5.1": "1.3.6.1.4.1.1466.115.121.1.12",  # DN
    "2.5.5.2": "1.3.6.1.4.1.1466.115.121.1.40",  # OID -> Octet String
    "2.5.5.3": "1.3.6.1.4.1.1466.115.121.1.40",  # Case-sensitive string (a.k.a. case-exact string) -> Octet String
    "2.5.5.4": "1.3.6.1.4.1.1466.115.121.1.40",  # Case-ignore string (teletex) -> Octet String
    "2.5.5.5": "1.3.6.1.4.1.1466.115.121.1.15",  # Octet String -> Directory String
    "2.5.5.6": "1.3.6.1.4.1.1466.115.121.1.36",  # Numeric String
    "2.5.5.7": "1.3.6.1.4.1.1466.115.121.1.15",  # OR Name -> Directory String
    "2.5.5.8": "1.3.6.1.4.1.1466.115.121.1.7",  # Boolean
    "2.5.5.9": "1.3.6.1.4.1.1466.115.121.1.27",  # INTEGER
    "2.5.5.10": "1.3.6.1.4.1.1466.115.121.1.40",  # Octet String
    "2.5.5.11": "1.3.6.1.4.1.1466.115.121.1.24",  # UTC TIME -> General Time
    "2.5.5.12": "1.3.6.1.4.1.1466.115.121.1.15",  # Directory String
    "2.5.5.13": "1.3.6.1.4.1.1466.115.121.1.43",  # Presentation Address
    "2.5.5.14": "1.3.6.1.4.1.1466.115.121.1.40",  # DN with Unicode string -> Octet String
    "2.5.5.15": "1.3.6.1.4.1.1466.115.121.1.40",  # Windows NT security descriptor -> Octet String
    "2.5.5.16": "1.3.6.1.4.1.1466.115.121.1.27",  # Large integer (a.k.a. INTEGER8) -> INTEGER
    "2.5.5.17": "1.3.6.1.4.1.1466.115.121.1.40",  # Octet String (again)
}

# Resources:
#  https://msdn.microsoft.com/en-us/library/ms679014%28v=vs.85%29.aspx
mapMSObjectClassCategoryToOpenLdapKind = {
    "0": "STRUCTURAL",  # Class 88 -> STRUCTURAL
    "1": "STRUCTURAL",  # Structural
    "2": "ABSTRACT",  # Abstract
    "3": "AUXILIARY",  # Auxiliary
}

aliases = {"sn": "surname"}

indices = {
    "samaccountname": ["EQUALITY caseIgnoreMatch", "SUBSTR caseIgnoreSubstringsMatch"],
    "surname": ["EQUALITY caseIgnoreMatch", "SUBSTR caseIgnoreSubstringsMatch"],
    "givenname": ["EQUALITY caseIgnoreMatch", "SUBSTR caseIgnoreSubstringsMatch"],
    "objectcategory": [
        "EQUALITY distinguishedNameMatch",
        "SUBSTR caseIgnoreSubstringsMatch",
    ],
    "ou": ["EQUALITY caseIgnoreMatch", "SUBSTR caseIgnoreSubstringsMatch"],
    "loginshell": ["EQUALITY caseIgnoreMatch", "SUBSTR caseIgnoreSubstringsMatch"],
    "memberuid": ["EQUALITY caseIgnoreMatch", "SUBSTR caseIgnoreSubstringsMatch"],
    "nismapname": ["EQUALITY caseIgnoreMatch", "SUBSTR caseIgnoreSubstringsMatch"],
    "nismapentry": ["EQUALITY caseIgnoreMatch", "SUBSTR caseIgnoreSubstringsMatch"],
    "mail": ["EQUALITY caseIgnoreMatch", "SUBSTR caseIgnoreSubstringsMatch"],
    "dc": ["EQUALITY caseIgnoreMatch", "SUBSTR caseIgnoreSubstringsMatch"],
}

# OIDs from:
# https://github.com/openldap/openldap/blob/a979b396d14c9b32847251151c0f325d31ba5c87/servers/slapd/schema_prep.c
# Predefined by openldap
PREDEFINED_IDs = dict(
    [
        ("top", "2.5.6.0"),
        ("extensibleObject", "1.3.6.1.4.1.1466.101.120.111"),
        ("alias", "2.5.6.1"),
        ("referral", "2.16.840.1.113730.3.2.6"),
        ("LDAProotDSE", "1.3.6.1.4.1.4203.1.4.1"),
        ("subentry", "2.5.17.0"),
        ("subschema", "2.5.20.1"),
        ("collectiveAttributeSubentry", "2.5.17.2"),
        ("dynamicObject", "1.3.6.1.4.1.1466.101.119.2"),
        ("glue", "1.3.6.1.4.1.4203.666.3.4"),
        ("syncConsumerSubentry", "1.3.6.1.4.1.4203.666.3.5"),
        ("syncProviderSubentry", "1.3.6.1.4.1.4203.666.3.6"),
        ("objectClass", "2.5.4.0"),
        ("structuralObjectClass", "2.5.21.9"),
        ("createTimestamp", "2.5.18.1"),
        ("modifyTimestamp", "2.5.18.2"),
        ("creatorsName", "2.5.18.3"),
        ("modifiersName", "2.5.18.4"),
        ("hasSubordinates", "2.5.18.9"),
        ("subschemaSubentry", "2.5.18.10"),
        ("collectiveAttributeSubentries", "2.5.18.12"),
        ("collectiveExclusions", "2.5.18.7"),
        ("entryDN", "1.3.6.1.1.20"),
        ("entryUUID", "1.3.6.1.1.16.4"),
        ("entryCSN", "1.3.6.1.4.1.4203.666.1.7"),
        ("namingCSN", "1.3.6.1.4.1.4203.666.1.13"),
        ("superiorUUID", "1.3.6.1.4.1.4203.666.1.11"),
        ("syncreplCookie", "1.3.6.1.4.1.4203.666.1.23"),
        ("contextCSN", "1.3.6.1.4.1.4203.666.1.25"),
        ("syncTimestamp", "1.3.6.1.4.1.4203.666.1.26"),
        ("altServer", "1.3.6.1.4.1.1466.101.120.6"),
        ("namingContexts", "1.3.6.1.4.1.1466.101.120.5"),
        ("supportedControl", "1.3.6.1.4.1.1466.101.120.13"),
        ("supportedExtension", "1.3.6.1.4.1.1466.101.120.7"),
        ("supportedLDAPVersion", "1.3.6.1.4.1.1466.101.120.15"),
        ("supportedSASLMechanisms", "1.3.6.1.4.1.1466.101.120.14"),
        ("supportedFeatures", "1.3.6.1.4.1.4203.1.3.5"),
        ("monitorContext", "1.3.6.1.4.1.4203.666.1.10"),
        ("configContext", "1.3.6.1.4.1.4203.1.12.2.1"),
        ("vendorName", "1.3.6.1.1.4"),
        ("vendorVersion", "1.3.6.1.1.5"),
        ("administrativeRole", "2.5.18.5"),
        ("subtreeSpecification", "2.5.18.6"),
        ("dITStructureRules", "2.5.21.1"),
        ("dITContentRules", "2.5.21.2"),
        ("matchingRules", "2.5.21.4"),
        ("attributeTypes", "2.5.21.5"),
        ("objectClasses", "2.5.21.6"),
        ("nameForms", "2.5.21.7"),
        ("matchingRuleUse", "2.5.21.8"),
        ("ldapSyntaxes", "1.3.6.1.4.1.1466.101.120.16"),
        ("aliasedObjectName", "2.5.4.1"),
        ("ref", "2.16.840.1.113730.3.1.34"),
        ("entry", "1.3.6.1.4.1.4203.1.3.1"),
        ("children", "1.3.6.1.4.1.4203.1.3.2"),
        ("authzTo", "1.3.6.1.4.1.4203.666.1.8"),
        ("authzFrom", "1.3.6.1.4.1.4203.666.1.9"),
        ("entryTtl", "1.3.6.1.4.1.1466.101.119.3"),
        ("dynamicSubtrees", "1.3.6.1.4.1.1466.101.119.4"),
        ("distinguishedName", "2.5.4.49"),
        ("name", "2.5.4.41"),
        ("cn", "2.5.4.3"),
        ("uid", "0.9.2342.19200300.100.1.1"),
        ("uidNumber", "1.3.6.1.1.1.1.0"),
        ("gidNUmber", "1.3.6.1.1.1.1.1"),
        ("userPassword", "2.5.4.35"),
        ("labeledURI", "1.3.6.1.4.1.250.1.57"),
        ("authPassword", "1.3.6.1.4.1.4203.1.3.4"),
        ("supportedAuthPasswordSchemes", "1.3.6.1.4.1.4203.1.3.3"),
        ("description", "2.5.4.13"),
        ("seeAlso", "2.5.4.34"),
        ("pKCS8PrivateKey", "1.3.6.1.4.1.4203.666.1.60"),
        ("pwdLastSuccess", "1.3.6.1.4.1.42.2.27.8.1.29"),
    ]
)

OPERATIONAL_ATTRIBUTES = [
    "structuralObjectClass",
    "isRecycled",
    "createTimeStamp",
    "modifyTimeStamp",
    "subSchemaSubEntry",
]  # TODO!!!


def parse_attribute(record, attribute_list):
    if "lDAPDisplayName" in record:
        name = record["lDAPDisplayName"][0]
    else:
        name = record["cn"][0]

    attribute_id = record["attributeID"][0]
    attribute_syntax = mapMSSyntaxToOpenLdap[record["attributeSyntax"][0]]

    if attribute_id.lower() in PREDEFINED_IDs.values():
        attribute_id = "999." + attribute_id

    if name.lower() in map(lambda x: x.lower(), PREDEFINED_IDs.keys()):
        return

    flags = []
    if record.get("isSingleValued", ["false"])[0].lower() == "true":
        flags.append("SINGLE-VALUE")

    if name.lower() in indices:
        flags.extend(indices[name.lower()])

    if aliases.get(name.lower(), "").lower() in indices:
        flags.extend(indices[aliases.get(name.lower(), "").lower()])

    if name.lower() in aliases:
        name = f"( '{name}' '{aliases[name]}' )"
    else:
        name = f"'{name}'"

    out = ATTRIBUTE % dict(
        attribute_name=name,
        attribute_id=attribute_id,
        attribute_syntax=attribute_syntax,
        flags="\n ".join(flags),
    )

    # Remove empty lines
    out = out.replace("\n \n", "\n")
    attribute_list.append(out)


def parse_class(record, class_tree):
    if "lDAPDisplayName" in record:
        name = record["lDAPDisplayName"][0]
    else:
        name = record["cn"][0]

    must = record.get("systemMustContain", []) + record.get("mustContain", [])
    may = record.get("systemMayContain", []) + record.get("mayContain", [])

    parent = record["subClassOf"][0]
    class_id = record["governsID"][0]

    name = objectclassMappings.get(name, name)
    if not (name == "mstop" and parent == "top"):
        parent = objectclassMappings.get(parent, parent)

    if class_id in PREDEFINED_IDs.values():
        class_id = "999." + class_id

    if name.lower() in map(lambda x: x.lower(), PREDEFINED_IDs.keys()):
        return

    block = dict(
        class_name=name,
        class_id=class_id,
        sup=parent,
        class_category=mapMSObjectClassCategoryToOpenLdapKind[
            record["objectClassCategory"][0]
        ],
        may=may + must,
        must=[],
        # Note: AD returns objects where `must` fields are missing. I don't
        # give a F*CK anymore, make them all optional.
        auxiliary_class=(
            record.get("systemAuxiliaryClass", []) + record.get("auxiliaryClass", [])
        ),
    )

    class_tree[name] = {
        "parent": parent,
        "block": block,
    }


def parse_record(record, class_tree, attribute_list):
    if "attributeSchema" in record["objectClass"]:
        parse_attribute(record, attribute_list)

    elif "classSchema" in record["objectClass"]:
        parse_class(record, class_tree)


def resolve_auxiliary_classes(tree):
    # Merge attributes because openLDAP does not support this kind of auxiliary
    # class. Do this recursively.

    def merge_attributes_from_auxiliary_classes(block):
        for cls in block["auxiliary_class"]:
            merge_attributes_from_auxiliary_classes(tree[cls]["block"])
            block["may"].extend(tree[cls]["block"]["may"])
            block["must"].extend(tree[cls]["block"]["must"])

    for name, node in tree.items():
        merge_attributes_from_auxiliary_classes(node["block"])


def write_class_block(fp, tree, name):
    """Write class schema to file, but if it has a parent class, write that
    first"""

    node = tree[name]
    parent = node["parent"]
    block = node["block"]

    if not block:
        return

    if parent in tree and parent != name and tree[parent]["block"]:
        write_class_block(fp, tree, parent)

    # Write to file
    must = list(set(block["must"]) - set(OPERATIONAL_ATTRIBUTES))
    may = list(set(block["may"]) - set(OPERATIONAL_ATTRIBUTES))
    block.update(
        dict(
            may=" $\n ".join(sorted(may)),
            must=" $\n ".join(sorted(must)),
        )
    )

    out = CLASS % block
    # Remove empty lines
    out = out.replace("\n \n", "\n")

    fp.write(out)
    node["block"] = None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="",
    )

    parser.add_argument("--src", help="Source ldif")
    parser.add_argument("--dst-attr", help="Destination attributes")
    parser.add_argument("--dst-class", help="Destination classes")

    args = parser.parse_args()

    parser = LDIFParser(open(args.src, "rb"))
    attribute_list = []
    class_tree = {}

    for dn, record in parser.parse():
        parse_record(record, class_tree, attribute_list)

    resolve_auxiliary_classes(class_tree)

    with open(args.dst_class, "w") as fp_class:
        for name in class_tree:
            write_class_block(fp_class, class_tree, name)

    with open(args.dst_attr, "w") as fp_attr:
        for block in attribute_list:
            fp_attr.write(block)
