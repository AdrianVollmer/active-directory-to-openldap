#!/usr/bin/python

import argparse
import base64
from collections import OrderedDict

from ldif import LDIFParser, LDIFWriter


class IndexParser(LDIFParser):

    def parse(self):
        """Build the index, which is a dict mapping the DN to the position in
        the file"""

        self.index = OrderedDict()

        pos = 0
        for block in self._iter_blocks():
            first_line = block[0].partition(b"\n")[0]

            if first_line.startswith(b"dn: "):
                dn = first_line[4:].decode()
            elif first_line.startswith(b"dn:: "):
                dn = first_line[5:]
                dn = base64.b64decode(dn).decode()
            else:
                raise RuntimeError("Parsing error at position %d" % pos)

            self.index[dn] = pos
            pos = self.byte_counter

        self._input_file.seek(0)

        # Sort by length of dn. This way ensures that parent objects will be
        # inserted before child objects.
        self.index = OrderedDict(sorted(self.index.items(), key=lambda x: len(x[0])))

    def __getitem__(self, dn):
        """Access the entry in the file"""
        try:
            self._input_file.seek(self.index[dn])
        except AttributeError:
            raise RuntimeError("Index has not been built yet")

        block = next(self._iter_blocks())
        return self._parse_entry_record(block)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="",
    )

    parser.add_argument("--src", metavar="SOURCE", help="Source ldif")
    parser.add_argument("--dst", metavar="DESTINATION", help="Destination ldif")

    args = parser.parse_args()

    parser = IndexParser(open(args.src, "rb"))
    parser.parse()

    writer = LDIFWriter(open(args.dst, "wb"))

    for dn in parser.index:
        entry = parser[dn]

        # Sometimes AD returns objects with ONLY a dn. OpenLDAP won't import
        # that. Add OU as dummy.

        if "objectClass" not in entry[1]:
            entry[1]["objectClass"] = ["top", "organizationalUnit"]

        writer.unparse(dn, entry[1])
