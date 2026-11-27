"""Make notice.txt of every case again from its recorded apt output with the CURRENT scripts/manage.py (offline, nothing is run):
the probes always answer "does not work", as in record.py, apt-get answers what was recorded.
usage: renotice.py <worktree>"""
import importlib.util, pathlib, re, sys

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('manage', sys.argv[1] + '/scripts/manage.py')
m = importlib.util.module_from_spec(spec)
sys.dont_write_bytecode = True
spec.loader.exec_module(m)
m.print = lambda *args, **kwargs: None


def answers(folder, kind):
    return (int((folder / f'{kind}.rc').read_text()), (folder / f'{kind}.out').read_text(), (folder / f'{kind}.err').read_text())


for folder in sorted(p for p in here.iterdir() if p.is_dir()):
    if not (folder / 'install.rc').exists():
        continue
    update, install = answers(folder, 'update'), answers(folder, 'install')

    def runner(argv, update=update, install=install):
        if argv[0] != m.APT_GET:
            return 127, '', ''
        return update if argv == list(m.APT_UPDATE) else install

    report = m.HostTools(runner).ensure()
    notice = (report.get('notices') or ['(no notice: ' + str(report) + ')'])[0]
    (folder / 'notice.txt').write_text(notice + '\n')
    print(folder.name, '->', (re.search(r'自動補裝沒有成功：(.*?)。更新照常進行', notice) or [None, notice[:80]])[1][:70])
