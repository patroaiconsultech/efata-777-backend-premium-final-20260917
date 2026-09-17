#!/usr/bin/env python3
import os,sys,stat,zipfile,tempfile,shutil,unittest
from pathlib import Path
PAYLOAD=Path(__file__).resolve().parents[1]/"payload"; sys.path.insert(0,str(PAYLOAD))
from preflight import *; import runner
def z(path,items,modes=None):
    modes=modes or {}
    with zipfile.ZipFile(path,"w") as q:
        for n,v in items:
            i=zipfile.ZipInfo(n)
            if n in modes: i.external_attr=(modes[n]&0xffff)<<16
            q.writestr(i,v)
class T(unittest.TestCase):
    def setUp(self): self.d=Path(tempfile.mkdtemp())
    def tearDown(self): shutil.rmtree(self.d,ignore_errors=True)
    def cli(self,r):
        p=r/"cli/railway"; shutil.copyfile(PAYLOAD/"fake_railway.py",p); os.chmod(p,0o700); return p
    def test_01_happy(self):
        r=runner.mkroot(str(self.d)); self.assertEqual(runner.fake_cycle(r,self.cli(r)),"PASS_LOCAL")
    def test_02_token(self):
        r=runner.mkroot(str(self.d)); self.assertNotIn("RAILWAY_TOKEN",runner.env(r))
    def test_03_home(self):
        r=runner.mkroot(str(self.d)); self.assertTrue(runner.env(r)["HOME"].startswith(str(r)))
    def test_04_xdg(self):
        r=runner.mkroot(str(self.d)); self.assertTrue(runner.env(r)["XDG_CONFIG_HOME"].startswith(str(r)))
    def test_05_path(self):
        r=runner.mkroot(str(self.d)); self.assertEqual(runner.env(r)["PATH"],"/usr/bin:/bin")
    def test_06_swap(self):
        p=self.d/"x";p.write_text("a");b=ident(p);p.write_text("b")
        with self.assertRaises(E): revalidate(p,b)
    def test_07_symlink(self):
        p=self.d/"x";p.write_text("a");q=self.d/"q";q.symlink_to(p)
        with self.assertRaises(E): ident(q)
    def test_08_traversal(self):
        p=self.d/"x.zip";z(p,[("../x","1")])
        with self.assertRaises(E):inspect_zip(p)
    def test_09_zip_symlink(self):
        p=self.d/"x.zip";z(p,[("x","1")],{"x":stat.S_IFLNK|0o777})
        with self.assertRaises(E):inspect_zip(p)
    def test_10_collision(self):
        p=self.d/"x.zip";z(p,[("A","1"),("a","2")])
        with self.assertRaises(E):inspect_zip(p)
    def test_11_drive(self):
        p=self.d/"x.zip";z(p,[("C:/x","1")])
        with self.assertRaises(E):inspect_zip(p)
    def test_12_backslash(self):
        p=self.d/"x.zip";z(p,[("a\\b","1")])
        with self.assertRaises(E):inspect_zip(p)
    def test_13_setuid(self):
        p=self.d/"x.zip";z(p,[("x","1")],{"x":stat.S_IFREG|0o4755})
        with self.assertRaises(E):inspect_zip(p)
    def test_14_special(self):
        p=self.d/"x.zip";z(p,[("x","1")],{"x":stat.S_IFCHR|0o600})
        with self.assertRaises(E):inspect_zip(p)
    def test_15_unicode(self):
        p=self.d/"x.zip";z(p,[("e\u0301","1"),("\u00e9","2")])
        with self.assertRaises(E):inspect_zip(p)
    def test_16_lock(self):
        r=runner.mkroot(str(self.d));fd=runner.lock(r)
        try:
            with self.assertRaises(FileExistsError):runner.lock(r)
        finally:os.close(fd)
    def test_17_bad_query(self):
        r=runner.mkroot(str(self.d));c=self.cli(r);e=runner.env(r);runner.run([str(c),"login"],e,2,True);x=runner.run([str(c),"api","bad"],e,2);self.assertNotEqual(x["exit"],0)
    def test_18_login_stderr_not_persisted(self):
        r=runner.mkroot(str(self.d));x=runner.run(["/bin/sh","-c","echo secret >&2; exit 1"],runner.env(r),2,True);self.assertFalse(x["stderr_content_persisted"])
    def test_19_timeout(self):
        r=runner.mkroot(str(self.d));x=runner.run(["/bin/sh","-c","sleep 2"],runner.env(r),.1,True);self.assertTrue(x["timeout"])
    def test_20_reap(self):
        r=runner.mkroot(str(self.d));x=runner.run(["/bin/true"],runner.env(r),2);self.assertTrue(x["parent_reaped"])
    def test_21_group_absent(self):
        r=runner.mkroot(str(self.d));x=runner.run(["/bin/true"],runner.env(r),2);self.assertTrue(x["group_absent"])
    def test_22_tmp(self):
        r=runner.mkroot(str(self.d));self.assertTrue(runner.env(r)["TMPDIR"].startswith(str(r)))
    def test_23_railway_home(self):
        r=runner.mkroot(str(self.d));self.assertTrue(runner.env(r)["RAILWAY_HOME"].startswith(str(r)))
    def test_24_fake_no_network_contract(self):
        s=(PAYLOAD/"fake_railway.py").read_text();self.assertNotIn("requests",s);self.assertNotIn("urllib",s);self.assertNotIn("socket.",s)
    def test_25_mutate_between(self):
        r=runner.mkroot(str(self.d));c=self.cli(r);b=ident(c);c.write_text(c.read_text()+"\n#mut")
        with self.assertRaises(E):revalidate(c,b)
if __name__=="__main__":unittest.main(verbosity=2)
