//go:build linux

package sqlite

import "golang.org/x/sys/unix"

// Filesystems whose locks or shared memory SQLite's WAL cannot trust. FUSE
// covers virtiofs, sshfs and most Docker Desktop bind mounts.
var remoteMagic = map[int64]string{
	0x6969:     "nfs",
	0x517b:     "smb",
	0xff534d42: "cifs",
	0xfe534d42: "smb2",
	0x65735546: "fuse",
	0x01021997: "9p",
	0x5346414f: "afs",
	0x73757245: "coda",
	0x564c:     "ncp",
	0x00c36400: "ceph",
	0x47504653: "gpfs",
	0x0bd00bd0: "lustre",
}

var localMagic = map[int64]bool{
	0xef53:     true, // ext2/3/4
	0x58465342: true, // xfs
	0x9123683e: true, // btrfs
	0x01021994: true, // tmpfs
	0x794c7630: true, // overlayfs
	0x2fc12fc1: true, // zfs
	0xf2f52010: true, // f2fs
	0x3153464a: true, // jfs
	0x52654973: true, // reiserfs
	0x4d44:     true, // vfat
	0x5346544e: true, // ntfs
	0x7366746e: true, // ntfs3
	0xde5e81e4: true, // efivarfs (never a database, but local)
}

func filesystem(dir string) (string, fsKind, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return "", fsUnknown, err
	}
	return classifyMagic(int64(st.Type))
}

func classifyMagic(magic int64) (string, fsKind, error) {
	magic &= 0xffffffff
	if name, ok := remoteMagic[magic]; ok {
		return name, fsRemote, nil
	}
	if localMagic[magic] {
		return "", fsLocal, nil
	}
	return "", fsUnknown, nil
}
