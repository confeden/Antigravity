"""Offline narrow importer tests; no network or repository mutation."""
import importlib.util
import pathlib
import unittest

SPEC = importlib.util.spec_from_file_location("policy_generate", pathlib.Path(__file__).with_name("generate.py"))
GEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN)


def xml(records):
    return (f'<registry xmlns="http://www.iana.org/assignments" id="iana-ipv4-special-registry">'
            f'<updated>2025-10-09</updated><registry>{records}</registry></registry>').encode()


def row(prefix="192.0.0.0/24", destination="True", forwardable="True", global_="True", reserved="False", termination=""):
    return (f'<record><address>{prefix}</address><destination>{destination}</destination>'
            f'<forwardable>{forwardable}</forwardable><global>{global_}</global><reserved>{reserved}</reserved>'
            f'{termination}</record>')


class ImportTests(unittest.TestCase):
    def parse(self, data):
        return GEN.parse_registry(data, 4, "iana-ipv4-special-registry")

    def test_complete_snapshots_and_deterministic_render(self):
        sources, rows, checksum = GEN.load_bundled(pathlib.Path(__file__).parent)
        self.assertEqual([len(GEN.parse_registry(s["raw"], s["family"], s["id"])[1]) for s in sources], [26, 25])
        self.assertEqual(len(rows), 51)
        self.assertEqual(GEN.render(sources, rows, checksum), GEN.render(sources, rows, checksum))

    def test_unknown_flags_overlap_termination_and_comma_prefixes_are_retained(self):
        data=xml(row()+row("192.0.0.9/32, 192.0.0.10/32",global_="N/A",termination="<termination>2015-03</termination>")+row("192.0.0.11/32",global_="future-token"))
        _, records=self.parse(data)
        self.assertEqual(len(records),4)
        self.assertEqual(records[1][1],(2,2,0,1))
        self.assertEqual(records[1][2],"2015-03")
        self.assertEqual(records[3][1][2],0)
        _, blank=self.parse(xml(row(global_="")))
        self.assertEqual(blank[0][1][2],0)

    def test_duplicate_semantics_deduplicate_but_conflicts_fail(self):
        self.assertEqual(len(self.parse(xml(row()+row()))[1]),1)
        with self.assertRaises(ValueError): self.parse(xml(row()+row(global_="False")))

    def test_malformed_sources_are_never_partially_adopted(self):
        bad=[xml(row("192.0.0.1/24")),xml(row("::1/128")),xml(row().replace("<global>True</global>","")),xml(row()).replace(b"</registry>",b"",1),xml(row("not-a-prefix")),xml(row(termination="<termination>tomorrow</termination>")),xml(row(global_="<other>True</other>")),b'<!DOCTYPE registry [<!ENTITY x "True">]>'+xml(row())]
        for data in bad:
            with self.subTest(data=data):
                with self.assertRaises(ValueError): self.parse(data)


if __name__=="__main__": unittest.main()
