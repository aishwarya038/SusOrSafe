"""SusOrSafe administrator tool. Run from the terminal only: the website cannot do any of this.

  python admin_tools.py show-audit          list audit entries
  python admin_tools.py clear-audit         permanently delete ALL audit entries (asks you to type YES)
  python admin_tools.py clear-audit --yes   same, without the question
"""
import os, sys, sqlite3

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "susorsafe.db")

def main():
    a = sys.argv[1:]
    if not a or a[0] not in ("show-audit", "clear-audit"): sys.exit(__doc__)
    if not os.path.exists(DB): sys.exit(f"Database not found: {DB}")
    con = sqlite3.connect(DB)
    if not con.execute("select 1 from sqlite_master where name='audit_logs'").fetchone(): sys.exit("No audit trail yet (start app.py once first).")
    n = con.execute("select count(*) from audit_logs").fetchone()[0]
    if a[0] == "show-audit":
        for r in con.execute("select id,ts,action,detail,actor from audit_logs order by id desc limit 50"): print(*r, sep=" | ")
        print(f"\n{n} entries in total (newest 50 shown)"); return
    if not n: sys.exit("Audit trail is already empty.")
    if "--yes" not in a and input(f"This permanently deletes all {n} audit entries. Type YES to continue: ").strip() != "YES": sys.exit("Cancelled. Nothing was deleted.")
    con.execute("delete from audit_logs"); con.execute("delete from sqlite_sequence where name='audit_logs'"); con.commit()
    print(f"Deleted {n} audit entries.")

main()