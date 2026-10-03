"""Never execute repository files. Extract only bounded regular files into private storage."""
from pathlib import Path, PurePosixPath
import stat
import zipfile

MAX_ARCHIVE=64*1024*1024
MAX_TOTAL=128*1024*1024
MAX_FILE=512*1024
MAX_FILES=2000
EXCLUDED={'.git','node_modules','venv','.venv','dist','build','target','__pycache__','.idea','.gradle','vendor'}
TEXT_EXTENSIONS={'.py','.js','.jsx','.mjs','.cjs','.java','.html','.htm','.json','.yaml','.yml','.properties','.xml','.gradle','.txt','.ini','.cfg','.conf','.pem','.key','.env','.sql','.sh','.md','.toml'}


class ArchiveError(ValueError):
    pass


def extract_archive(archive,destination):
    archive=Path(archive);destination=Path(destination)
    if archive.stat().st_size>MAX_ARCHIVE:
        raise ArchiveError('Compressed repository exceeds 64 MiB.')
    try:
        destination.mkdir(mode=0o700,parents=True,exist_ok=False)
    except OSError:
        raise ArchiveError('Extraction requires a new private directory.') from None
    inventory={'files':0,'bytes':0,'excluded':0,'oversized_files':0,'binary_files':0,'unsupported_files':0}
    paths=[]
    try:
        with zipfile.ZipFile(archive) as bundle:
            members=bundle.infolist()
            if len(members)>5000:
                raise ArchiveError('Archive contains too many entries.')
            roots=set();seen=set();declared=0
            # Validate every path/type, including excluded entries, before creating files.
            for member in members:
                name=member.filename
                parts=PurePosixPath(name).parts
                if not parts or name.startswith('/') or '\\' in name or ':' in name or any(ord(c)<32 for c in name) or any(part in ('.','..') for part in name.split('/') if part) or len(name)>400 or len(parts)>30:
                    raise ArchiveError('Unsafe archive path rejected.')
                mode=member.external_attr>>16
                kind=stat.S_IFMT(mode)
                if kind not in (0,stat.S_IFREG,stat.S_IFDIR) or member.flag_bits & 1:
                    raise ArchiveError('Symlinks, special files and encrypted archive members are rejected.')
                normalized='/'.join(parts).casefold()
                if normalized in seen:
                    raise ArchiveError('Duplicate or case-colliding archive paths rejected.')
                seen.add(normalized);roots.add(parts[0]);declared+=member.file_size
                if declared>MAX_TOTAL or (member.file_size>1024*1024 and member.file_size/max(1,member.compress_size)>100):
                    raise ArchiveError('Expanded repository size or compression ratio limit exceeded.')
            if len(roots)!=1:
                raise ArchiveError('Repository archive must have one top-level directory.')
            for member in members:
                parts=PurePosixPath(member.filename).parts[1:]
                if member.is_dir() or not parts:
                    continue
                if any(part in EXCLUDED for part in parts):
                    inventory['excluded']+=1;continue
                if member.file_size>MAX_FILE:
                    inventory['oversized_files']+=1;continue
                relative=Path(*parts)
                if relative.suffix.lower() not in TEXT_EXTENSIONS and not relative.name.startswith('.env') and relative.name not in ('Dockerfile','requirements.txt','yarn.lock','Gemfile','Gemfile.lock','go.mod','go.sum','poetry.lock','uv.lock'):
                    inventory['unsupported_files']+=1;continue
                if inventory['files']>=MAX_FILES:
                    raise ArchiveError('Repository exceeds the 2,000 analyzable-file limit.')
                with bundle.open(member) as source:
                    content=source.read(MAX_FILE+1)
                if len(content)>MAX_FILE:
                    raise ArchiveError('Archive member exceeded its declared size limit.')
                if b'\0' in content:
                    inventory['binary_files']+=1;continue
                try:
                    content.decode('utf-8-sig')
                except UnicodeError:
                    inventory['binary_files']+=1;continue
                target=destination/relative
                target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                # Destination is new private storage; exclusive create also rejects path collisions.
                with target.open('xb') as handle:
                    handle.write(content)
                target.chmod(0o600)
                paths.append(relative.as_posix())
                inventory['files']+=1;inventory['bytes']+=len(content)
    except ArchiveError:
        raise
    except (OSError,zipfile.BadZipFile,RuntimeError,ValueError):
        raise ArchiveError('Repository archive is malformed or could not be safely extracted.') from None
    return sorted(paths),inventory
